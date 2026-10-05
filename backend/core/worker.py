"""Durable at-least-once provider jobs; observations never become permissions."""

import os
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from . import audit
from .models import (
    ADEnrollment,
    AssistantTask,
    ChangeRequest,
    EntraEnrollment,
    EvidenceRun,
    Grant,
    OffboardingCase,
    OutboxJob,
    Principal,
    Resource,
)
from .services import policy_state


def account_contained(observed):
    """A contained workforce account is disabled and holds no Keycloak session."""
    return (
        isinstance(observed, dict)
        and observed.get("active") is False
        and type(observed.get("sessions")) is int
        and observed["sessions"] == 0
    )


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
                        "observedAt": timezone.now().isoformat(),
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
                observed_at = timezone.now().isoformat()
                observed = result.get("observed") if isinstance(result, dict) else None
                if (
                    not isinstance(observed, dict)
                    or type(result.get("drift")) is not bool
                    or type(observed.get("active")) is not bool
                    or type(observed.get("sessions")) is not int
                    or observed["sessions"] < 0
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
                        "observedAt": timezone.now().isoformat(),
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
                        key: observed[key]
                        for key in ("active", "sessions", "member")
                        if key in observed
                    },
                    "observedAt": observed_at,
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


def directory_job_binding(job):
    """The durable payload cannot retarget a trusted, already-contained case."""
    from integrations.ad import normalize_binding

    desired = job.desired
    if (
        job.request_id is not None
        or not isinstance(desired, dict)
        or set(desired) != {"caseId", "identityId", "binding"}
    ):
        raise RuntimeError("directory_job_invalid")
    binding = normalize_binding(desired["binding"])
    case = OffboardingCase.objects.select_related("identity").get(pk=desired["caseId"])
    enrollment = ADEnrollment.objects.get(identity_id=case.identity_id)
    if (
        str(case.identity_id) != desired["identityId"]
        or case.identity.status != "offboarded"
        or case.containment_request_id is None
        or case.effective_at > timezone.now()
        or case.closed_at is not None
        or case.ad_binding != binding
        or enrollment.binding != binding
    ):
        raise RuntimeError("directory_job_binding_changed")
    return binding


ENTRA_KINDS = ("entra_offboard", "entra_observe")


def entra_job_binding(job):
    """Like directory_job_binding, for the Entra enrollment frozen on the case.
    Returns the binding and the departure time that session revocation must follow."""
    from integrations.entra import normalize_binding

    desired = job.desired
    if (
        job.request_id is not None
        or not isinstance(desired, dict)
        or set(desired) != {"caseId", "identityId", "binding"}
    ):
        raise RuntimeError("entra_job_invalid")
    binding = normalize_binding(desired["binding"])
    case = OffboardingCase.objects.select_related("identity").get(pk=desired["caseId"])
    enrollment = EntraEnrollment.objects.get(identity_id=case.identity_id)
    if (
        str(case.identity_id) != desired["identityId"]
        or case.identity.status != "offboarded"
        or case.containment_request_id is None
        or case.effective_at > timezone.now()
        or case.closed_at is not None
        or case.entra_binding != binding
        or enrollment.binding != binding
    ):
        raise RuntimeError("entra_job_binding_changed")
    return binding, case.effective_at


def process_one(connector=None):
    job = claim_job()
    if not job:
        return False
    owned_connector = False
    try:
        if job.kind == "assistant":
            result = run_assistant(job)
        elif job.kind in ("ad_offboard", "ad_observe"):
            from integrations.ad import ADDirectoryConnector, verified_result

            with transaction.atomic():
                policy_state(lock=True)
                binding = directory_job_binding(job)
            if connector is None:
                connector, owned_connector = ADDirectoryConnector(), True
            if job.kind == "ad_observe":
                observed = connector.validate_binding(binding)
                result = {"verified": verified_result(binding, observed), "observed": observed}
            else:
                result = connector.offboard(binding)
        elif job.kind in ENTRA_KINDS:
            from integrations.entra import EntraConnector
            from integrations.entra import verified_result as entra_verified

            with transaction.atomic():
                policy_state(lock=True)
                binding, departed_at = entra_job_binding(job)
            if connector is None:
                connector, owned_connector = EntraConnector(), True
            if job.kind == "entra_observe":
                observed = connector.validate_binding(binding)
                result = {
                    "verified": entra_verified(binding, observed, departed_at),
                    "observed": observed,
                }
            else:
                result = connector.offboard(binding, departed_at)
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
                if operation["kind"] in ("grant", "revoke"):
                    # Every delivery, especially an ambiguous retry, reads first.
                    observed = connector.observe_membership(identity, resource)
                    result = (
                        {"verified": True, "observed": observed["observed"]}
                        if observed.get("observed", {}).get("member")
                        is (operation["kind"] == "grant")
                        else connector.apply(operation, identity, resource)
                    )
                else:
                    # Containment always re-applies: disabling and ending sessions
                    # are idempotent, and a disabled account can still hold sessions.
                    result = connector.apply(operation, identity, resource)
        # Capture the reading before waiting for the database serialization gate.
        # The later audit timestamp records completion, not provider freshness.
        result_read_at = timezone.now().isoformat()
        with transaction.atomic():
            policy_state(lock=True)
            current = OutboxJob.objects.select_for_update().get(pk=job.pk)
            if current.attempts != job.attempts or current.status != "running":
                return True
            current.observed = result.get("observed", {})
            contained_subject = None
            if job.kind in ("ad_offboard", "ad_observe"):
                from integrations.ad import verified_result

                result["verified"] = verified_result(
                    directory_job_binding(current), current.observed
                )
            if job.kind in ENTRA_KINDS:
                from integrations.entra import verified_result as entra_verified

                binding, departed_at = entra_job_binding(current)
                result["verified"] = entra_verified(binding, current.observed, departed_at)
            if (
                job.kind
                not in (
                    "assistant",
                    "reconcile",
                    "enroll",
                    "ad_offboard",
                    "ad_observe",
                    *ENTRA_KINDS,
                )
                and job.desired.get("action") != "department_transfer"
            ):
                # Remote delivery can overlap a committed local revocation. Do
                # not claim convergence against an obsolete desired snapshot.
                fresh_operation, fresh_identity, _ = desired_operation(current)
                if fresh_operation["kind"] in ("grant", "revoke"):
                    result["verified"] = current.observed.get("member") is (
                        fresh_operation["kind"] == "grant"
                    )
                else:
                    result["verified"] = account_contained(current.observed)
                    contained_subject = fresh_identity["providerSubject"]
            if job.kind != "assistant":
                current.observed["observedAt"] = result_read_at
            current.status = "verified" if result.get("verified") is True else "retry"
            if current.status == "verified" and contained_subject:
                from . import ssf

                ssf.signal_containment(current, contained_subject)
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
            if job.kind in ("ad_offboard", "ad_observe", *ENTRA_KINDS):
                connector.close()
            else:
                connector.http.close()
    return True
