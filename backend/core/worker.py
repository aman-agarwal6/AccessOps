"""Durable at-least-once provider jobs; observations never become permissions."""

import os
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from . import audit
from .models import AssistantTask, ChangeRequest, EvidenceRun, Grant, OutboxJob, Principal, Resource
from .services import policy_state


def claim_job():
    with transaction.atomic():
        policy_state(lock=True)
        now = timezone.now()
        job = (
            OutboxJob.objects.select_for_update()
            .filter(available_at__lte=now)
            .filter(Q(status__in=["pending", "retry"]) | Q(status="running", lease_until__lt=now))
            .order_by("created_at")
            .first()
        )
        if not job:
            return None
        job.status, job.lease_until = "running", now + timedelta(minutes=2)
        job.attempts += 1
        job.save(update_fields=["status", "lease_until", "attempts"])
        return job


def desired_operation(job):
    identity = Principal.objects.get(pk=job.desired["identityId"])
    resource = (
        job.request.resource
        if job.request_id
        else Resource.objects.filter(pk=job.desired.get("resourceId")).first()
    )
    kind = job.desired.get("action", "offboard")
    if kind in ("grant", "revoke"):
        valid = (
            Grant.objects.filter(identity=identity, resource=resource, status="active")
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
            .exists()
        )
        kind = (
            "grant"
            if valid
            and identity.status == "active"
            and (
                identity.kind != "agent"
                or identity.sponsor_id
                and identity.sponsor.status == "active"
            )
            else "revoke"
        )
    if kind == "transfer":
        kind = "offboard"  # Transfer deliberately suspends execution until fresh enablement.
    resource_data = (
        {"providerGroup": resource.provider_group, "desiredMember": kind == "grant"}
        if resource
        else None
    )
    return (
        {"id": str(job.pk), "kind": kind, "permission": job.desired.get("permission", "read")},
        {"providerSubject": identity.subject, "kind": identity.kind, "status": identity.status},
        resource_data,
    )


def run_assistant(job):
    from integrations.security import ExecutorClient
    from integrations.transport import client as http_client
    from integrations.transport import json_response

    task = AssistantTask.objects.get(pk=job.assistant_task_id)
    if task.status == "completed":
        return {"verified": True, "observed": {"taskStatus": "completed"}}
    if task.status != "active" or task.expires_at <= timezone.now():
        return {"verified": False, "observed": {"taskStatus": "inactive"}}
    executor = ExecutorClient()
    try:
        token = executor.token()
    finally:
        executor.http.close()
    with http_client() as http:
        for index, payload in enumerate(
            [
                {"tool": "list_entitlements"},
                {"tool": "read_evidence", "resourceId": task.resource_ids[0]},
                {"tool": "create_draft"},
            ]
        ):
            response = http.post(
                settings.INTERNAL_API_URL + f"/api/v1/agent/tasks/{task.pk}/tools",
                json=payload,
                headers={
                    "Authorization": "Bearer " + token,
                    "Idempotency-Key": f"{job.pk}:step:{index}",
                },
            )
            if response.status_code != 200:
                raise RuntimeError("assistant_call_rejected")
            json_response(response, limit=131072)
    task.refresh_from_db()
    return {
        "verified": task.status == "completed",
        "observed": {"taskStatus": task.status, "callsUsed": task.calls_used},
    }


def run_reconcile(job, connector):
    from integrations.errors import ConnectorError

    observations = []
    if Principal.objects.filter(issuer=settings.WORKFORCE_ISSUER).count() > 500:
        raise RuntimeError("reconciliation_inventory_limit")
    for resource in Resource.objects.filter(project__in=job.desired["projects"]):
        for identity in Principal.objects.filter(issuer=settings.WORKFORCE_ISSUER):
            # Long inventory reads renew a fenced lease between bounded calls.
            if not OutboxJob.objects.filter(
                pk=job.pk, status="running", attempts=job.attempts
            ).update(lease_until=timezone.now() + timedelta(minutes=2)):
                raise RuntimeError("worker_lease_lost")
            if identity.subject.startswith("pending:"):
                observations.append(
                    {
                        "identityId": str(identity.pk),
                        "resourceId": str(resource.pk),
                        "drift": None,
                        "status": "unavailable",
                        "observed": {"binding": "pending"},
                    }
                )
                continue
            desired_member = (
                identity.status == "active"
                and Grant.objects.filter(identity=identity, resource=resource, status="active")
                .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
                .exists()
            )
            try:
                result = connector.reconcile(
                    {
                        "providerSubject": identity.subject,
                        "kind": identity.kind,
                        "status": identity.status,
                    },
                    {"providerGroup": resource.provider_group, "desiredMember": desired_member},
                )
                observed = result.get("observed") if isinstance(result, dict) else None
                if (
                    not isinstance(observed, dict)
                    or type(result.get("drift")) is not bool
                    or type(observed.get("active")) is not bool
                    or resource.provider_group
                    and type(observed.get("member")) is not bool
                ):
                    raise ConnectorError("Provider observation is incomplete")
            except ConnectorError:
                # One unavailable principal must not erase independent readings.
                # Unknown is not a verified match, a drift fact, or permission.
                observations.append(
                    {
                        "identityId": str(identity.pk),
                        "resourceId": str(resource.pk),
                        "status": "unavailable",
                        "drift": None,
                        "observed": {"availability": "unknown"},
                    }
                )
                continue
            observations.append(
                {
                    "identityId": str(identity.pk),
                    "resourceId": str(resource.pk),
                    "status": "observed",
                    "drift": result["drift"],
                    "observed": {
                        key: observed[key] for key in ("active", "member") if key in observed
                    },
                }
            )
    return {
        "verified": bool(observations) and all(o["status"] == "observed" for o in observations),
        "observed": {
            "observations": observations,
            "driftCount": sum(o["drift"] is True for o in observations),
            "unknownCount": sum(o["status"] == "unavailable" for o in observations),
        },
    }


def finish_reconciliation(job):
    if (
        job.kind != "reconcile"
        or "runId" not in job.desired
        or job.status not in ("verified", "failed")
    ):
        return
    run = EvidenceRun.objects.get(pk=job.desired["runId"])
    observations = job.observed.get("observations", [])
    drift_count = job.observed.get("driftCount", 0)
    unknown_count = job.observed.get("unknownCount", 0)
    run.status = (
        "passed"
        if observations and job.status == "verified" and drift_count == 0 and unknown_count == 0
        else "failed"
    )
    run.finished_at = timezone.now()
    run.summary = (
        f"{drift_count} mismatch(es); {len(observations) - unknown_count} observed pair(s); "
        f"{unknown_count} unavailable. No provider state adopted."
        if observations
        else "Provider observations unavailable; no provider state adopted."
    )
    run.checks = [
        {
            "name": "Provider observation coverage",
            "status": "passed" if job.status == "verified" and unknown_count == 0 else "failed",
            "detail": run.summary,
        },
        {
            "name": "Backed provider access",
            "status": "passed"
            if observations and drift_count == 0 and unknown_count == 0
            else "failed",
            "detail": f"{drift_count} measured mismatch(es); unknown observations are never adopted.",
        },
    ]
    run.manifest = {
        "origin": "connected",
        "policyVersion": policy_state().version,
        "policySha256": os.getenv("ACCESSOPS_POLICY_SHA256", "unrecorded"),
        "sourceCommit": os.getenv("ACCESSOPS_SOURCE_COMMIT", "unrecorded"),
        "jobId": str(job.pk),
        "observations": observations,
        "driftCount": drift_count,
        "unknownCount": unknown_count,
        "adoptedChanges": 0,
    }
    run.save()


def process_one(connector=None):
    job = claim_job()
    if not job:
        return False
    owned_connector = False
    try:
        if job.kind == "assistant":
            result = run_assistant(job)
        else:
            if connector is None:
                from integrations.keycloak import KeycloakConnector

                connector, owned_connector = KeycloakConnector(), True
            if job.kind == "enroll":
                from .enrollment import process_enrollment_job

                result = process_enrollment_job(job, connector)
            elif job.desired.get("action") == "department_transfer":
                from .enrollment import process_department_job

                result = process_department_job(job, connector)
            elif job.kind == "reconcile":
                result = run_reconcile(job, connector)
            else:
                with transaction.atomic():
                    policy_state(lock=True)
                    operation, identity, resource = desired_operation(job)
                # Every delivery, especially an ambiguous retry, reads first.
                observed = connector.reconcile(identity, resource)
                satisfied = (
                    observed.get("observed", {}).get("member") is (operation["kind"] == "grant")
                    if operation["kind"] in ("grant", "revoke")
                    else observed.get("observed", {}).get("active") is False
                )
                result = (
                    {"verified": True, "observed": observed["observed"]}
                    if satisfied
                    else connector.apply(operation, identity, resource)
                )
        with transaction.atomic():
            policy_state(lock=True)
            current = OutboxJob.objects.select_for_update().get(pk=job.pk)
            if current.attempts != job.attempts or current.status != "running":
                return True
            current.observed = result.get("observed", {})
            if (
                job.kind not in ("assistant", "reconcile", "enroll")
                and job.desired.get("action") != "department_transfer"
            ):
                # Remote delivery can overlap a committed local revocation. Do
                # not claim convergence against an obsolete desired snapshot.
                fresh_operation, _, _ = desired_operation(current)
                if fresh_operation["kind"] in ("grant", "revoke"):
                    result["verified"] = current.observed.get("member") is (
                        fresh_operation["kind"] == "grant"
                    )
                else:
                    result["verified"] = current.observed.get("active") is False
            current.status = "verified" if result.get("verified") is True else "retry"
            if current.status == "retry" and current.attempts >= 5:
                current.status = "failed"
            current.lease_until = None
            current.available_at = timezone.now() + timedelta(seconds=min(2**job.attempts, 60))
            current.save(update_fields=["observed", "status", "lease_until", "available_at"])
            finish_reconciliation(current)
            if current.status == "verified" and job.request_id:
                change = ChangeRequest.objects.get(pk=job.request_id)
                change.status = "verified"
                change.save(update_fields=["status"])
            audit.append(
                "worker",
                "provider." + current.status,
                job.request_id or job.pk,
                {"jobId": str(job.pk), "attempt": job.attempts, "kind": job.kind},
            )
    except Exception:
        with transaction.atomic():
            policy_state(lock=True)
            current = OutboxJob.objects.select_for_update().get(pk=job.pk)
            if current.attempts != job.attempts or current.status != "running":
                return True
            current.status = "failed" if job.attempts >= 5 else "retry"
            current.last_error = (
                "provider_outcome_unknown" if job.kind != "assistant" else "assistant_unavailable"
            )
            current.lease_until = None
            current.available_at = timezone.now() + timedelta(seconds=min(2**job.attempts, 60))
            current.save(update_fields=["status", "last_error", "lease_until", "available_at"])
            finish_reconciliation(current)
            audit.append(
                "worker",
                "job." + current.status,
                job.request_id or job.pk,
                {"jobId": str(job.pk), "reason": current.last_error},
            )
    finally:
        if owned_connector:
            connector.http.close()
    return True
