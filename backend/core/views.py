from django.conf import settings
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from . import audit
from . import presentation as present
from . import services as svc
from .auth import ExecutorAuthentication, OptionalExecutorAuthentication
from .errors import DomainError
from .models import (
    AssistantTask,
    ChangeRequest,
    EvidenceRun,
    Grant,
    OutboxJob,
    Principal,
    Resource,
    Review,
    SponsorAcceptance,
)
from .serializers import EmptyInput, ProposeInput, RequestInput, ReviewInput, ToolInput, validate


def actor_of(request):
    actor = get_object_or_404(
        Principal, user=request.user, issuer=settings.OIDC_ISSUER, kind="human"
    )
    svc.active(actor)
    return actor


def serial_payload(value):
    return {k: str(v) if k.endswith("Id") and v is not None else v for k, v in value.items()}


def change_policy(actor, action, change):
    if not change.resource_id:
        svc.scope_identity(actor, change.identity)
    context = {
        "approval_valid": svc.approval_valid(change),
        "identity_project_ids": change.identity.project_ids,
    }
    if change.payload["action"] == "department_transfer":
        context["identity_project_ids"] = sorted(
            set(change.identity.project_ids) | set(change.payload["targetProjects"])
        )
    return svc.require_policy(actor, action, change.resource, change, context)


@api_view(["GET"])
@permission_classes([AllowAny])
def session(request):
    data = {
        "authenticated": bool(request.user and request.user.is_authenticated),
        "mode": "connected",
        "csrfToken": get_token(request),
    }
    if data["authenticated"]:
        actor = actor_of(request)
        data["principal"] = {"id": str(actor.pk), "name": actor.name, "roles": actor.roles}
    return Response(data)


@api_view(["GET"])
@permission_classes([AllowAny])
@authentication_classes([])
def health(request):
    return Response({"status": "ok", "mode": "connected"})


@api_view(["GET"])
def snapshot(request):
    actor = actor_of(request)
    svc.require_policy(actor, "snapshot")
    return Response(present.snapshot(actor))


@api_view(["POST"])
def requests(request):
    data = validate(RequestInput, request.data)
    actor = actor_of(request)
    identity = get_object_or_404(Principal, pk=data["identityId"], issuer=settings.WORKFORCE_ISSUER)
    resource = (
        get_object_or_404(Resource, pk=data["resourceId"]) if data.get("resourceId") else None
    )

    def check(a):
        if not resource:
            svc.scope_identity(a, identity)
        svc.require_policy(
            a, "request", resource, context={"identity_project_ids": identity.project_ids}
        )

    def handler(a):
        return {"result": present.change(svc.create_request(a, data))}, 201

    result, status = svc.mutation(
        actor,
        request.headers.get("Idempotency-Key"),
        "request.create",
        serial_payload(data),
        check,
        handler,
    )
    return Response(result, status=status)


@api_view(["POST"])
def request_action(request, request_id, action):
    validate(EmptyInput, request.data)
    actor = actor_of(request)
    change = get_object_or_404(ChangeRequest, pk=request_id)
    if action not in ("approve", "execute", "accept"):
        raise DomainError("not_found", "Unknown operation.", 404)

    def check(a):
        if action == "accept":
            if change.payload["action"] != "transfer" or str(
                a.workforce_identity_id
            ) != change.payload.get("newSponsorId"):
                raise DomainError(
                    "successor_required", "Only the enrolled successor may accept.", 403
                )
            svc.require_policy(a, "snapshot")
            svc.scope_identity(a, change.identity)
        else:
            change_policy(a, action, change)

    def handler(a):
        if action == "accept":
            if change.status not in ("pending", "approved") or change.payload_hash != audit.digest(
                change.payload
            ):
                raise DomainError(
                    "request_state", "This sponsorship request is no longer current.", 409
                )
            SponsorAcceptance.objects.create(
                request=change, sponsor=a.workforce_identity, payload_hash=change.payload_hash
            )
            audit.append(a, "sponsor.accepted", change.pk, {"payloadHash": change.payload_hash})
            result = change
        else:
            result = getattr(svc, action)(a, change)
        return {"result": present.change(result)}, 200

    result, status = svc.mutation(
        actor,
        request.headers.get("Idempotency-Key"),
        f"request.{action}:{request_id}",
        {},
        check,
        handler,
    )
    return Response(result, status=status)


@api_view(["POST"])
def review_action(request, review_id, action):
    review = get_object_or_404(Review, pk=review_id)
    actor = actor_of(request)
    if action not in ("run", "propose"):
        raise DomainError("not_found", "Unknown operation.", 404)
    data = validate(ReviewInput if action == "run" else ProposeInput, request.data)

    def check(a):
        for resource in review.resources.all():
            svc.require_policy(a, "review", resource)

    def handler(a):
        if action == "run":
            task = svc.start_review(a, review)
            return {"result": present.run(task.run)}, 202
        if not review.resources.filter(pk=data["resourceId"]).exists():
            raise DomainError("object_scope_denied", "Resource is outside this review.", 403)
        if not any(
            f["identityId"] == str(data["identityId"])
            and f["resourceId"] == str(data["resourceId"])
            for f in review.findings
        ):
            raise DomainError("finding_required", "A measured review finding is required.", 409)
        change = svc.create_request(a, {**data, "action": "revoke", "permission": "read"})
        return {"result": present.change(change)}, 201

    result, status = svc.mutation(
        actor,
        request.headers.get("Idempotency-Key"),
        f"review.{action}:{review_id}",
        serial_payload(data),
        check,
        handler,
    )
    return Response(result, status=status)


@api_view(["POST"])
def reconcile(request):
    validate(EmptyInput, request.data)
    actor = actor_of(request)

    def handler(a):
        run = EvidenceRun.objects.create(
            name="Provider drift reconciliation",
            scenario="provider-drift",
            project_ids=a.project_ids,
        )
        job = OutboxJob.objects.create(
            kind="reconcile",
            desired={"projects": a.project_ids, "runId": str(run.pk)},
            available_at=timezone.now(),
        )
        audit.append(a, "reconcile.requested", job.pk, {"projects": a.project_ids})
        return {"result": present.run(run)}, 202

    result, status = svc.mutation(
        actor,
        request.headers.get("Idempotency-Key"),
        "reconcile",
        {},
        lambda a: svc.require_policy(a, "reconcile"),
        handler,
    )
    return Response(result, status=status)


@api_view(["GET"])
def evidence(request, run_id):
    actor = actor_of(request)
    svc.require_policy(actor, "snapshot")
    run = get_object_or_404(EvidenceRun, pk=run_id)
    if not set(run.project_ids).issubset(actor.project_ids):
        raise DomainError("object_scope_denied", "Evidence is outside the permitted scope.", 403)
    return Response(present.run(run))


@api_view(["POST"])
@authentication_classes([ExecutorAuthentication])
@permission_classes([AllowAny])
def agent_tools(request, task_id):
    data = validate(ToolInput, request.data)
    task = get_object_or_404(AssistantTask, pk=task_id)
    actor = request.user

    def check(a):
        if a.pk != task.agent_id:
            raise DomainError(
                "task_identity_mismatch", "This task belongs to another executor.", 403
            )
        svc.check_task(a, task, replay=True)

    def handler(a):
        return {"result": svc.agent_tool(a, task, data["tool"], data.get("resourceId"))}, 200

    result, status = svc.mutation(
        actor,
        request.headers.get("Idempotency-Key"),
        f"agent.tool:{task_id}",
        serial_payload(data),
        check,
        handler,
    )
    return Response(result, status=status)


@api_view(["POST"])
@authentication_classes([OptionalExecutorAuthentication, SessionAuthentication])
@permission_classes([AllowAny])
def resource_read(request, resource_id):
    """Actual protected synthetic data; old sessions/tokens face live DB grants."""
    validate(EmptyInput, request.data)
    if isinstance(request.user, Principal):
        actor = request.user
    elif request.user and request.user.is_authenticated:
        actor = actor_of(request)
    else:
        raise DomainError("authentication_required", "Authentication is required.", 401)
    resource = get_object_or_404(Resource, pk=resource_id)

    def current_grant(a):
        identity = a if a.kind == "agent" else a.workforce_identity
        if not identity:
            raise DomainError(
                "workforce_binding_required", "An enrolled workforce binding is required.", 403
            )
        svc.active(identity)
        svc.scope_resource(a, resource)
        svc.scope_resource(identity, resource)
        if identity.kind == "agent" and (
            not identity.sponsor_id or identity.sponsor.status != "active"
        ):
            raise DomainError("sponsor_inactive", "An active sponsor is required.", 403)
        if svc.policy_state().frozen and identity.kind == "agent":
            raise DomainError("execution_frozen", "Agent execution is frozen.", 403)
        grants = (
            Grant.objects.select_for_update()
            .filter(
                identity=identity,
                resource=resource,
                status="active",
                permission__in=["read", "write"],
            )
            .order_by("id")
        )
        grant = next(
            (
                g
                for g in grants
                if (not g.expires_at or g.expires_at > timezone.now())
                and (g.max_calls is None or g.calls_used <= g.max_calls)
            ),
            None,
        )
        if not grant:
            raise DomainError(
                "grant_inactive", "No current resource grant permits this access.", 403
            )
        svc.require_policy(
            identity,
            "resource_read",
            resource,
            context={
                "grant_active": True,
                "sponsor_active": identity.kind == "human" or identity.sponsor.status == "active",
                "within_budget": True,
            },
        )
        return grant

    def handler(a):
        grant = current_grant(a)
        if grant.max_calls is not None and grant.calls_used >= grant.max_calls:
            raise DomainError(
                "budget_exhausted", "The resource grant call budget is exhausted.", 403
            )
        grant.calls_used += 1
        grant.save(update_fields=["calls_used"])
        audit.append(a, "resource.read", resource.pk, {"grantId": str(grant.pk), "synthetic": True})
        return {
            "result": {
                "resourceId": str(resource.pk),
                "records": [
                    {
                        "id": "synthetic-record-001",
                        "title": resource.name + " example record",
                        "classification": "synthetic",
                    }
                ],
                "grantId": str(grant.pk),
            }
        }, 200

    result, status = svc.mutation(
        actor,
        request.headers.get("Idempotency-Key"),
        f"resource.read:{resource_id}",
        {},
        current_grant,
        handler,
    )
    return Response(result, status=status)
