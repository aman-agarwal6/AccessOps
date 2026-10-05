import os
import re
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from . import audit
from .errors import DomainError
from .models import (
    Approval,
    AssistantTask,
    ChangeRequest,
    EvidenceRun,
    Grant,
    IdempotencyRecord,
    OutboxJob,
    PolicyState,
    Principal,
    Resource,
    SponsorAcceptance,
)


def policy_state(lock=False):
    state, _ = PolicyState.objects.get_or_create(
        pk=1, defaults={"version": settings.POLICY_VERSION}
    )
    return PolicyState.objects.select_for_update().get(pk=1) if lock else state


def active(principal):
    if (
        principal.status != "active"
        or principal.workforce_identity_id
        and principal.workforce_identity.status != "active"
    ):
        raise DomainError("principal_inactive", "This identity is inactive.", 403)


def scope_resource(actor, resource):
    active(actor)
    if resource.project not in actor.project_ids:
        raise DomainError(
            "object_scope_denied", "This resource is outside the permitted scope.", 403
        )


def scope_identity(actor, identity):
    projects = set(identity.project_ids) | set(
        Grant.objects.filter(identity=identity).values_list("resource__project", flat=True)
    )
    if not projects or not projects.issubset(set(actor.project_ids)):
        raise DomainError(
            "object_scope_denied", "This identity is outside the permitted scope.", 403
        )


def offboarding_projects(identity):
    affected = [identity, *Principal.objects.filter(sponsor=identity, kind="agent")]
    return {project for principal in affected for project in principal.project_ids} | set(
        Grant.objects.filter(identity_id__in=[principal.pk for principal in affected]).values_list(
            "resource__project", flat=True
        )
    )


def scope_offboarding(actor, identity):
    projects = offboarding_projects(identity)
    if not projects or not projects.issubset(actor.project_ids):
        raise DomainError(
            "object_scope_denied",
            "Departure coverage includes identities or historical grants outside your project scope.",
            403,
        )
    return projects


def require_policy(actor, action, resource=None, change=None, context=None):
    active(actor)
    if resource:
        scope_resource(actor, resource)
    role = {
        "request": "operator",
        "execute": "operator",
        "review": "operator",
        "reconcile": "operator",
        "approve": "approver",
        "departure_close": "approver",
        "departure_intake": "hr_intake",
    }.get(action)
    if actor.kind == "agent" and action not in ("agent_tool", "resource_read"):
        raise DomainError(
            "agent_authority_denied", "Agents may only use their approved task tools.", 403
        )
    if actor.kind == "service":
        # The HR feed may open a departure and contain it. Statements, approval,
        # closure and every other change stay with people.
        if not (
            action == "departure_intake"
            or action == "execute"
            and change is not None
            and change.payload.get("action") == "offboard"
        ):
            raise DomainError(
                "service_authority_denied",
                "This service may only open and contain departures.",
                403,
            )
        role = "hr_intake"
    elif action == "departure_intake":
        raise DomainError("role_denied", "Departure intake is reserved for the HR feed.", 403)
    owner_role = (
        "resource_owner" in actor.roles
        and resource
        and resource.owner_id == actor.pk
        and action in ("request", "approve")
    )
    if role and role not in actor.roles and not owner_role:
        raise DomainError("role_denied", "This operation requires a different role.", 403)
    if action == "snapshot" and not set(actor.roles).intersection(
        {"operator", "approver", "auditor", "resource_owner"}
    ):
        raise DomainError("role_denied", "This identity has no console role.", 403)
    state = policy_state()
    data = {
        "action": action,
        "subject": {
            "id": str(actor.pk),
            "kind": actor.kind,
            "status": actor.status,
            "roles": actor.roles,
            "project_ids": actor.project_ids,
        },
        "resource": {
            "id": str(resource.pk),
            "project": resource.project,
            "owner_id": str(resource.owner_id),
        }
        if resource
        else None,
        "request": {
            "requester_id": str(change.requester_id),
            "action": change.payload["action"],
            "policy_version": change.policy_version,
        }
        if change
        else None,
        "context": {
            "policy_version": state.version,
            "approval_valid": False,
            "grant_active": False,
            "sponsor_active": False,
            "within_budget": False,
            **(context or {}),
        },
    }
    try:
        from integrations.policy import evaluate

        result = evaluate(data)
    except Exception:
        raise DomainError(
            "policy_unavailable", "Authorization policy is unavailable; no change was made.", 503
        ) from None
    if not isinstance(result, dict) or result.get("allow") is not True:
        unavailable = isinstance(result, dict) and result.get("reason") == "policy_unavailable"
        raise DomainError(
            "policy_unavailable" if unavailable else "policy_denied",
            "Authorization policy did not allow this operation.",
            503 if unavailable else 403,
        )
    if result.get("policy_version") != state.version:
        raise DomainError(
            "policy_version_mismatch",
            "Loaded policy does not match the approved policy version.",
            503,
        )
    expected_bundle = os.environ.get("ACCESSOPS_POLICY_SHA256")
    if expected_bundle and result.get("bundle_sha256") != expected_bundle:
        raise DomainError(
            "policy_bundle_mismatch", "Loaded policy bundle does not match this deployment.", 503
        )
    return result


def mutation(actor, key, operation, payload, check, handler):
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", key):
        raise DomainError("idempotency_required", "Supply an 8–128 character Idempotency-Key.", 400)
    fingerprint = audit.digest({"operation": operation, "payload": payload})
    # One small lab-wide gate gives a defined serialization order for revoke,
    # approval, execution, audit append and agent effects. PostgreSQL enforces it.
    with transaction.atomic():
        policy_state(lock=True)
        actor = Principal.objects.select_for_update().get(pk=actor.pk)
        active(actor)
        check(actor)
        old = IdempotencyRecord.objects.filter(principal=actor, key=key).first()
        if old:
            if old.fingerprint != fingerprint:
                raise DomainError(
                    "idempotency_conflict",
                    "This key was already used for a different operation.",
                    409,
                )
            return old.response, old.status_code
        if (
            IdempotencyRecord.objects.filter(
                principal=actor, created_at__gt=timezone.now() - timedelta(minutes=1)
            ).count()
            >= 30
        ):
            raise DomainError(
                "rate_limited", "The mutation rate limit has been reached. Retry later.", 429
            )
        result, code = handler(actor)
        # Persist the result in the same transaction as the effect and audit.
        IdempotencyRecord.objects.create(
            principal=actor, key=key, fingerprint=fingerprint, response=result, status_code=code
        )
        return result, code


def create_request(actor, data):
    identity = Principal.objects.select_for_update().get(pk=data["identityId"])
    if identity.issuer != settings.WORKFORCE_ISSUER:
        raise DomainError("workforce_required", "Select an enrolled workforce identity.", 403)
    resource = Resource.objects.get(pk=data["resourceId"]) if data.get("resourceId") else None
    action = data["action"]
    if action in ("grant", "revoke") and resource is None:
        raise DomainError("resource_required", "A resource is required for this change.")
    if action == "offboard":
        scope_offboarding(actor, identity)
    elif action == "transfer":
        scope_identity(actor, identity)
    if resource:
        scope_resource(actor, resource)
    if action == "transfer" and identity.kind != "agent":
        raise DomainError("invalid_transfer", "Sponsor transfers apply to agent identities.")
    if action == "grant" and (identity.status != "active" or policy_state().frozen):
        raise DomainError("grant_denied", "This identity cannot receive a grant.", 403)
    if action == "grant" and (
        resource.project not in identity.project_ids or data.get("permission", "read") != "read"
    ):
        raise DomainError(
            "grant_scope_denied", "This resource or permission is outside the identity scope.", 403
        )
    sponsor_id = data.get("newSponsorId")
    if action == "transfer":
        sponsor = Principal.objects.filter(pk=sponsor_id, kind="human", status="active").first()
        if not sponsor:
            raise DomainError("invalid_sponsor", "Select an active human sponsor.")
        scope_identity(actor, sponsor)
    payload = {
        key: str(data[key]) if key.endswith("Id") and data[key] else data[key]
        for key in ("identityId", "resourceId", "action", "reason", "permission", "newSponsorId")
        if key in data
    }
    payload["identityRevision"] = identity.revision
    request = ChangeRequest.objects.create(
        identity=identity,
        resource=resource,
        requester=actor,
        payload=payload,
        payload_hash=audit.digest(payload),
        policy_version=policy_state().version,
    )
    audit.append(
        actor,
        "request.created",
        request.pk,
        {
            "action": action,
            "identityId": str(identity.pk),
            "project": resource.project if resource else None,
        },
    )
    return request


def approve(actor, request):
    request = ChangeRequest.objects.select_for_update().get(pk=request.pk)
    if request.requester_id == actor.pk:
        raise DomainError(
            "self_approval", "A different authorized operator must approve this request.", 403
        )
    if request.requester.kind != "human":
        raise DomainError("agent_approval", "Agent proposals are never approvals.", 403)
    if request.status != "pending" or Approval.objects.filter(request=request).exists():
        raise DomainError("request_state", "This request is no longer awaiting approval.", 409)
    if request.policy_version != policy_state().version or request.payload_hash != audit.digest(
        request.payload
    ):
        raise DomainError("stale_request", "The request no longer matches the current policy.", 409)
    if request.identity.revision != request.payload["identityRevision"]:
        raise DomainError("stale_identity", "Identity state changed; create a new request.", 409)
    Approval.objects.create(
        request=request,
        approver=actor,
        payload_hash=request.payload_hash,
        policy_version=request.policy_version,
        expires_at=timezone.now() + timedelta(minutes=15),
    )
    request.status = "approved"
    request.save(update_fields=["status"])
    audit.append(
        actor,
        "request.approved",
        request.pk,
        {"payloadHash": request.payload_hash, "policyVersion": request.policy_version},
    )
    return request


def approval_valid(request):
    approval = Approval.objects.filter(request=request).select_related("approver").first()
    if not approval:
        return False
    approver = approval.approver
    current_role = (
        "approver" in approver.roles
        or request.resource_id
        and request.resource.owner_id == approver.pk
        and "resource_owner" in approver.roles
    )
    projects = (
        {request.resource.project}
        if request.resource_id
        else set(request.identity.project_ids) | set(request.payload.get("targetProjects", []))
    )
    linked_active = (
        not approver.workforce_identity_id or approver.workforce_identity.status == "active"
    )
    return bool(
        approval.expires_at > timezone.now()
        and approver.status == "active"
        and linked_active
        and current_role
        and projects.issubset(approver.project_ids)
        and request.requester.status == "active"
        and (
            not request.requester.workforce_identity_id
            or request.requester.workforce_identity.status == "active"
        )
        and approval.approver_id != request.requester_id
        and approval.payload_hash == audit.digest(request.payload) == request.payload_hash
        and approval.policy_version == request.policy_version == policy_state().version
    )


def revoke_for(identity_ids):
    Grant.objects.filter(identity_id__in=identity_ids, status="active").update(status="revoked")
    AssistantTask.objects.filter(
        Q(agent_id__in=identity_ids) | Q(requester_id__in=identity_ids), status="active"
    ).update(status="revoked")


def execute(actor, request):
    request = (
        ChangeRequest.objects.select_for_update(of=("self",))
        .select_related("identity", "resource")
        .get(pk=request.pk)
    )
    action = request.payload["action"]
    containment = action in ("revoke", "offboard")
    if (containment and request.status not in ("pending", "approved")) or (
        not containment and (request.status != "approved" or not approval_valid(request))
    ):
        raise DomainError(
            "approval_invalid",
            "Approval is missing, expired, revoked, or does not match the exact change.",
            409,
        )
    if request.payload_hash != audit.digest(request.payload):
        raise DomainError("intent_changed", "The request intent changed.", 409)
    identity = Principal.objects.select_for_update().get(pk=request.identity_id)
    if identity.revision != request.payload["identityRevision"]:
        raise DomainError("stale_identity", "Identity state changed; request fresh approval.", 409)
    if action == "grant":
        if (
            identity.status != "active"
            or policy_state().frozen
            or identity.kind == "agent"
            and (not identity.sponsor_id or identity.sponsor.status != "active")
        ):
            raise DomainError(
                "grant_denied", "Identity or sponsor is inactive, or execution is frozen.", 403
            )
        permission = request.payload.get("permission", "read")
        if (
            Grant.objects.filter(
                identity=identity, resource=request.resource, permission=permission, status="active"
            )
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
            .exists()
        ):
            raise DomainError("grant_exists", "An active grant already exists.", 409)
        Grant.objects.create(
            identity=identity,
            resource=request.resource,
            permission=permission,
            source_request=request,
            purpose=request.payload["reason"],
            expires_at=timezone.now() + timedelta(minutes=10) if identity.kind == "agent" else None,
            max_calls=6 if identity.kind == "agent" else None,
        )
    elif action == "revoke":
        Grant.objects.filter(identity=identity, resource=request.resource, status="active").update(
            status="revoked"
        )
        for task in AssistantTask.objects.filter(agent=identity, status="active"):
            if str(request.resource_id) in task.resource_ids:
                task.status = "revoked"
                task.save(update_fields=["status"])
    elif action == "offboard":
        scope_offboarding(actor, identity)
        identity.status = "offboarded"
        identity.revision += 1
        identity.save(update_fields=["status", "revision", "updated_at"])
        agents = list(
            Principal.objects.select_for_update()
            .filter(sponsor=identity, kind="agent")
            .values_list("id", flat=True)
        )
        Principal.objects.filter(pk__in=agents).update(
            status="suspended", revision=F("revision") + 1
        )
        # Historical grants remain evidence of known managed memberships. A
        # repeated departure must not skip them merely because local access was
        # revoked by an earlier case whose remote outcome is still unresolved.
        remote_pairs = (
            Grant.objects.filter(identity_id__in=[identity.pk, *agents])
            .exclude(resource__provider_group="")
            .values_list("identity_id", "resource_id")
            .distinct()
        )
        for identity_id, resource_id in remote_pairs:
            OutboxJob.objects.create(
                kind="entitlement_revoke",
                desired={
                    "identityId": str(identity_id),
                    "resourceId": str(resource_id),
                    "action": "revoke",
                    "containmentRequestId": str(request.pk),
                },
                available_at=timezone.now(),
            )
        revoke_for([identity.pk, *agents])
        # Disabling a sponsor also becomes a separate durable provider operation.
        for agent_id in agents:
            OutboxJob.objects.create(
                kind="suspend",
                desired={"identityId": str(agent_id), "active": False},
                available_at=timezone.now(),
            )
    elif action == "transfer":
        sponsor = Principal.objects.select_for_update().get(pk=request.payload["newSponsorId"])
        if not SponsorAcceptance.objects.filter(
            request=request, sponsor=sponsor, payload_hash=request.payload_hash
        ).exists():
            raise DomainError(
                "acceptance_required",
                "The successor must accept this exact sponsorship change.",
                409,
            )
        if sponsor.status != "active" or sponsor.kind != "human":
            raise DomainError("sponsor_inactive", "New sponsor is not active.", 409)
        identity.sponsor = sponsor
        identity.status = "suspended"
        identity.revision += 1
        identity.save(update_fields=["sponsor", "status", "revision", "updated_at"])
        revoke_for([identity.pk])
    elif action == "department_transfer":
        from .enrollment import apply_department_transfer

        apply_department_transfer(actor, identity, request)
    request.status = "applied"
    request.applied_at = timezone.now()
    request.save(update_fields=["status", "applied_at"])
    OutboxJob.objects.create(
        request=request,
        kind="lifecycle",
        desired={
            "identityId": str(identity.pk),
            "action": action,
            "permission": request.payload.get("permission", "read"),
        },
        available_at=timezone.now(),
    )
    audit.append(
        actor,
        "request.applied",
        request.pk,
        {"action": action, "localEffect": "committed", "providerEffect": "pending"},
    )
    return request


def start_review(actor, review):
    if policy_state().frozen:
        raise DomainError("execution_frozen", "Agent execution is frozen.", 403)
    resources = list(review.resources.all())
    for resource in resources:
        scope_resource(actor, resource)
    if not resources:
        raise DomainError("review_empty", "The review has no resources.", 409)
    # JSON filtering differs between supported test and lab databases. Match the
    # dedicated executor identity, never an arbitrary caller-controlled subject.
    agent = next(
        (
            p
            for p in Principal.objects.filter(
                kind="agent", issuer=settings.WORKFORCE_ISSUER, status="active"
            )
            if "review_assistant" in p.roles
        ),
        None,
    )
    if not agent or not agent.sponsor_id or agent.sponsor.status != "active":
        raise DomainError(
            "agent_unavailable", "The review assistant needs an active identity and sponsor.", 409
        )
    if not {r.project for r in resources}.issubset(set(agent.project_ids)):
        raise DomainError(
            "agent_scope_denied", "The assistant is not authorized for these review projects.", 403
        )
    if AssistantTask.objects.filter(
        review=review, status="active", expires_at__gt=timezone.now()
    ).exists():
        raise DomainError("review_running", "A review task is already active.", 409)
    run = EvidenceRun.objects.create(
        name="Bounded access review",
        scenario="access-review",
        project_ids=sorted({r.project for r in resources}),
    )
    task = AssistantTask.objects.create(
        review=review,
        run=run,
        agent=agent,
        requester=actor,
        expires_at=timezone.now() + timedelta(minutes=10),
        policy_version=policy_state().version,
        resource_ids=[str(r.pk) for r in resources],
    )
    OutboxJob.objects.create(
        kind="assistant",
        assistant_task=task,
        desired={"taskId": str(task.pk)},
        available_at=timezone.now(),
    )
    audit.append(
        actor,
        "assistant.task.created",
        task.pk,
        {
            "runId": str(run.pk),
            "maxCalls": 6,
            "maxDrafts": 1,
            "expiresAt": task.expires_at.isoformat(),
        },
    )
    return task


def check_task(actor, task, replay=False):
    active(actor)
    task = (
        AssistantTask.objects.select_for_update()
        .select_related("agent", "review", "run")
        .get(pk=task.pk)
    )
    if actor.pk != task.agent_id or actor.kind != "agent":
        raise DomainError("task_identity_mismatch", "This task belongs to another executor.", 403)
    sponsor = Principal.objects.select_for_update().filter(pk=actor.sponsor_id).first()
    allowed_status = ("active", "completed") if replay else ("active",)
    if (
        policy_state().frozen
        or task.status not in allowed_status
        or task.expires_at <= timezone.now()
        or task.policy_version != policy_state().version
    ):
        raise DomainError("task_inactive", "This task is inactive or stale.", 403)
    if (
        not sponsor
        or sponsor.status != "active"
        or task.requester.status != "active"
        or task.requester.workforce_identity_id
        and task.requester.workforce_identity.status != "active"
    ):
        raise DomainError("sponsor_inactive", "The sponsor or requester is inactive.", 403)
    if not replay and task.calls_used >= 6:
        raise DomainError("budget_exhausted", "The six-call task budget is exhausted.", 403)
    for resource in Resource.objects.filter(pk__in=task.resource_ids):
        scope_resource(actor, resource)
        scope_resource(task.requester, resource)
        require_policy(
            actor,
            "agent_tool",
            resource,
            context={"grant_active": True, "sponsor_active": True, "within_budget": True},
        )
    return task


def agent_tool(actor, task, tool, resource_id=None):
    task = check_task(actor, task)
    if tool not in ("list_entitlements", "read_evidence", "create_draft"):
        raise DomainError("tool_not_allowed", "This tool is outside the task grant.", 403)
    if resource_id and str(resource_id) not in task.resource_ids:
        raise DomainError("object_scope_denied", "This resource is outside the task grant.", 403)
    resources = list(Resource.objects.filter(pk__in=task.resource_ids))
    task.calls_used += 1
    result = {}
    if tool == "list_entitlements":
        result = {
            "entitlements": [
                {
                    "identityId": str(g.identity_id),
                    "resourceId": str(g.resource_id),
                    "permission": g.permission,
                    "identityStatus": g.identity.status,
                    "status": g.status,
                }
                for g in Grant.objects.filter(resource_id__in=task.resource_ids).select_related(
                    "identity"
                )[:100]
            ]
        }
    elif tool == "read_evidence":
        if not resource_id:
            raise DomainError("resource_required", "Select a resource inside the task grant.")
        resource = next(r for r in resources if str(r.pk) == str(resource_id))
        result = {
            "resourceId": str(resource.pk),
            "content": resource.evidence[:4000],
            "trust": "untrusted-evidence",
        }
    else:
        if task.drafts_created:
            raise DomainError("draft_limit", "Only one draft is permitted per task.", 403)
        # No prose is interpreted as an instruction. Findings are computed from
        # server-side lifecycle facts; neither tool arguments nor model output
        # can select an approval, a new permission, or a provider operation.
        findings = []
        for grant in Grant.objects.filter(
            resource_id__in=task.resource_ids, status="active"
        ).select_related("identity")[:100]:
            if (
                grant.identity.status != "active"
                or grant.expires_at
                and grant.expires_at <= timezone.now()
            ):
                findings.append(
                    {
                        "id": str(grant.pk),
                        "identityId": str(grant.identity_id),
                        "resourceId": str(grant.resource_id),
                        "severity": "high",
                        "title": "Stale entitlement requires human review",
                        "detail": "An entitlement conflicts with current lifecycle or expiry state.",
                        "evidence": [
                            "grant:" + str(grant.pk),
                            "identity:" + str(grant.identity_id),
                        ],
                    }
                )
        task.review.findings = findings
        task.review.status = "draft_ready"
        task.review.save(update_fields=["findings", "status"])
        task.drafts_created = 1
        task.status = "completed"
        task.run.status = "passed"
        task.run.finished_at = timezone.now()
        task.run.summary = f"Draft created with {len(findings)} findings; no entitlement changes."
        task.run.checks = [
            {
                "name": "Task budget",
                "status": "passed",
                "detail": f"{task.calls_used}/6 calls and 1/1 draft; checked before this transaction.",
            },
            {
                "name": "Lifecycle gates",
                "status": "passed",
                "detail": "Active sponsor, requester, task expiry and policy version checked for this call.",
            },
        ]
        task.run.manifest = {
            "origin": "connected",
            "mode": "deterministic",
            "taskId": str(task.pk),
            "sourceCommit": os.getenv("ACCESSOPS_SOURCE_COMMIT", "unrecorded"),
            "policySha256": os.getenv("ACCESSOPS_POLICY_SHA256", "unrecorded"),
            "policyVersion": task.policy_version,
            "calls": task.calls_used,
            "drafts": 1,
            "limits": {"maxCalls": 6, "maxDrafts": 1, "expiresAt": task.expires_at.isoformat()},
        }
        task.run.save()
        result = {
            "draftId": str(task.review_id),
            "findingCount": len(findings),
            "status": "draft_ready",
        }
    task.save(update_fields=["calls_used", "drafts_created", "status"])
    audit.append(
        actor,
        "assistant.tool",
        task.pk,
        {"tool": tool, "callsUsed": task.calls_used, "draftsCreated": task.drafts_created},
    )
    return result
