from django.db.models import Q
from django.utils import timezone

from .models import (
    Approval,
    AuditEvent,
    ChangeRequest,
    EvidenceRun,
    Grant,
    OutboxJob,
    Principal,
    Resource,
    Review,
    SponsorAcceptance,
)
from .services import policy_state


def iso(value):
    return value.isoformat() if value else None


def identity(p):
    provider_binding = "pending" if p.subject.startswith("pending:") else "bound"
    credential_binding = "not-applicable"
    if p.kind == "agent":
        credential_binding = (
            "pending"
            if provider_binding == "pending" or not p.roles
            else "configured"
            if p.status == "active"
            else "recovery-required"
        )
    return {
        "id": str(p.pk),
        "name": p.name,
        "kind": p.kind,
        "department": p.department,
        "email": p.email,
        "status": p.status,
        "roles": p.roles,
        "role": ", ".join(p.roles),
        "projectIds": p.project_ids,
        "sponsorId": str(p.sponsor_id) if p.sponsor_id else None,
        "providerSubject": p.subject,
        "providerBinding": provider_binding,
        "credentialBinding": credential_binding,
        "updatedAt": iso(p.updated_at),
    }


def resource(r):
    return {
        "id": str(r.pk),
        "name": r.name,
        "project": r.project,
        "ownerId": str(r.owner_id),
        "description": r.description,
        "sensitivity": r.sensitivity,
    }


def grant(g):
    return {
        "id": str(g.pk),
        "identityId": str(g.identity_id),
        "resourceId": str(g.resource_id),
        "permission": g.permission,
        "status": "expired"
        if g.status == "active" and g.expires_at and g.expires_at <= timezone.now()
        else g.status,
        "expiresAt": iso(g.expires_at),
        "sourceRequestId": str(g.source_request_id) if g.source_request_id else None,
        "purpose": g.purpose,
        "maxCalls": g.max_calls,
        "callsUsed": g.calls_used,
    }


def change(r):
    approval = Approval.objects.filter(request=r).first()
    acceptance = SponsorAcceptance.objects.filter(request=r, payload_hash=r.payload_hash).first()
    events = [
        {
            "at": iso(r.created_at),
            "label": "Request recorded",
            "status": "complete",
            "detail": "Exact intent stored.",
        }
    ]
    if approval:
        events.append(
            {
                "at": iso(approval.approved_at),
                "label": "Independent approval",
                "status": "complete",
                "detail": "Bound to intent hash and policy version.",
            }
        )
    if acceptance:
        events.append(
            {
                "at": iso(acceptance.accepted_at),
                "label": "Successor accepted",
                "status": "complete",
                "detail": "Enrolled successor accepted this exact sponsorship intent.",
            }
        )
    if r.applied_at:
        events.append(
            {
                "at": iso(r.applied_at),
                "label": "Local state applied",
                "status": "complete",
                "detail": "Provider verification is tracked separately.",
            }
        )
    job = OutboxJob.objects.filter(request=r).first()
    provider = None
    if job:
        observed = {
            key: value
            for key, value in job.observed.items()
            if key in ("member", "active", "binding", "groupId") and isinstance(value, (str, bool))
        }
        provider = {
            "status": job.status,
            "attempts": job.attempts,
            "observed": observed,
            "lastError": job.last_error or None,
        }
        detail = f"{job.attempts} attempt(s); provider status {job.status}."
        if "member" in observed:
            detail += " Observed membership: " + ("present." if observed["member"] else "absent.")
        if "active" in observed:
            detail += " Observed account: " + ("active." if observed["active"] else "disabled.")
        if job.last_error:
            detail += " Outcome unknown; reconciliation required."
        observation = (
            AuditEvent.objects.filter(
                target_id=str(r.pk),
                action__in=[
                    "provider.verified",
                    "provider.retry",
                    "provider.failed",
                    "job.retry",
                    "job.failed",
                ],
            )
            .order_by("-sequence")
            .first()
        )
        events.append(
            {
                "at": iso(observation.at if observation else job.created_at),
                "label": "Provider observation" if observation else "Provider job queued",
                "status": "complete"
                if job.status == "verified"
                else "failed"
                if job.status == "failed"
                else "pending",
                "detail": detail,
            }
        )
    events.sort(key=lambda event: event["at"])
    return {
        "id": str(r.pk),
        **r.payload,
        "status": r.status,
        "requesterId": str(r.requester_id),
        "approverId": str(approval.approver_id) if approval else None,
        "acceptedBy": str(acceptance.sponsor_id) if acceptance else None,
        "acceptedAt": iso(acceptance.accepted_at) if acceptance else None,
        "createdAt": iso(r.created_at),
        "approvalExpiresAt": iso(approval.expires_at) if approval else None,
        "policyVersion": r.policy_version,
        "events": events,
        "provider": provider,
    }


def review(r):
    return {
        "id": str(r.pk),
        "name": r.name,
        "resourceIds": [str(k) for k in r.resources.values_list("pk", flat=True)],
        "assignedTo": str(r.assigned_to_id),
        "status": r.status,
        "dueAt": iso(r.due_at),
        "findings": r.findings,
    }


def run(r):
    return {
        "id": str(r.pk),
        "name": r.name,
        "scenario": r.scenario,
        "status": r.status,
        "origin": "connected",
        "startedAt": iso(r.started_at),
        "finishedAt": iso(r.finished_at),
        "summary": r.summary,
        "checks": r.checks,
        "manifest": r.manifest,
    }


def snapshot(actor):
    resources = list(Resource.objects.filter(project__in=actor.project_ids))
    resource_ids = [r.pk for r in resources]
    identities = [
        p
        for p in Principal.objects.all()
        if p.project_ids and set(p.project_ids).issubset(actor.project_ids)
    ]
    requests = ChangeRequest.objects.filter(
        Q(resource_id__in=resource_ids)
        | Q(resource__isnull=True, identity_id__in=[p.pk for p in identities])
    )
    requests = [
        r
        for r in requests.order_by("-created_at")[:200]
        if r.resource_id or set(r.identity.project_ids).issubset(actor.project_ids)
    ]
    reviews = [
        r
        for r in Review.objects.all()
        if set(r.resources.values_list("pk", flat=True)).issubset(resource_ids)
    ]
    runs = [
        r
        for r in EvidenceRun.objects.order_by("-started_at")[:100]
        if set(r.project_ids).issubset(actor.project_ids)
    ]
    target_ids = {str(v.pk) for v in [*resources, *identities, *requests, *reviews, *runs]}
    # Events lacking an object scope are shown only to full-scope auditors.
    audit_events = [
        e
        for e in AuditEvent.objects.order_by("-sequence")[:500]
        if e.target_id in target_ids or e.actor_id == str(actor.pk)
    ]
    pending = (
        OutboxJob.objects.filter(Q(request__in=requests) | Q(assistant_task__review__in=reviews))
        .exclude(status__in=["verified", "cancelled"])
        .count()
    )
    state = policy_state()
    return {
        "identities": [identity(p) for p in identities],
        "resources": [resource(r) for r in resources],
        "requests": [change(r) for r in requests],
        "grants": [grant(g) for g in Grant.objects.filter(resource_id__in=resource_ids)],
        "reviews": [review(r) for r in reviews],
        "runs": [run(r) for r in runs],
        "audit": [
            {
                "id": str(e.pk),
                "at": iso(e.at),
                "actorId": e.actor_id,
                "action": e.action,
                "targetId": e.target_id,
                "detail": e.detail,
                "hash": e.hash,
            }
            for e in audit_events
        ],
        "policies": [
            {
                "id": "accessops",
                "name": "AccessOps authorization",
                "version": state.version,
                "description": "Fail-closed server policy with exact approvals and bounded task grants.",
                "rules": [
                    "Independent approval for new access",
                    "Immediate authorized revocation",
                    "Active sponsor required",
                    "Agent tools: ten minutes, six calls, one draft",
                ],
            }
        ],
        "health": [
            {"name": "Application database", "status": "healthy", "detail": "Connected"},
            {
                "name": "Provider synchronization",
                "status": "pending" if pending else "healthy",
                "detail": f"{pending} jobs awaiting verification",
            },
            {
                "name": "Execution",
                "status": "unavailable" if state.frozen else "healthy",
                "detail": "Frozen by local containment" if state.frozen else "Enabled",
            },
        ],
    }
