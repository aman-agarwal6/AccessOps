"""Inventory enrollment and approval-bound department transfers.

Registration grants no resource access or machine credentials. Real provider
binding is observed asynchronously with a deterministic, app-owned username.
"""

import uuid

from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.response import Response

from . import audit
from . import presentation as present
from . import services as svc
from .errors import DomainError
from .models import ChangeRequest, Grant, OutboxJob, Principal, Resource
from .serializers import StrictSerializer, validate

DEPARTMENTS = {"Engineering": ["Atlas"], "Operations": ["Pulse"]}


class EnrollmentInput(StrictSerializer):
    name = serializers.CharField(min_length=2, max_length=120, trim_whitespace=True)
    email = serializers.EmailField(required=False, allow_blank=True, max_length=200)
    kind = serializers.ChoiceField(choices=["human", "agent"])
    department = serializers.ChoiceField(choices=list(DEPARTMENTS))
    projectIds = serializers.ListField(
        child=serializers.ChoiceField(choices=["Atlas", "Pulse"]), min_length=1, max_length=2
    )
    sponsorId = serializers.UUIDField(required=False, allow_null=True)

    def validate(self, data):
        if len(set(data["projectIds"])) != len(data["projectIds"]):
            raise serializers.ValidationError("Duplicate projects are not allowed.")
        if data["kind"] == "human" and set(data["projectIds"]) != set(
            DEPARTMENTS[data["department"]]
        ):
            raise serializers.ValidationError(
                "Human inventory scope must match the selected department."
            )
        if data["kind"] == "agent" and not data.get("sponsorId"):
            raise serializers.ValidationError("An active human sponsor is required.")
        if data["kind"] == "human" and data.get("sponsorId"):
            raise serializers.ValidationError("Human identities cannot have an agent sponsor.")
        if data.get("email") and not data["email"].rsplit("@", 1)[-1].endswith(
            (".test", ".example")
        ):
            raise serializers.ValidationError(
                "Use a synthetic .test or .example email in this reference lab."
            )
        return data


class DepartmentInput(StrictSerializer):
    department = serializers.ChoiceField(choices=list(DEPARTMENTS))
    reason = serializers.CharField(min_length=8, max_length=255, trim_whitespace=True)


def _actor(request):
    from .views import actor_of

    return actor_of(request)


def enroll(actor, data):
    if not set(data["projectIds"]).issubset(set(actor.project_ids)):
        raise DomainError("object_scope_denied", "Enrollment is outside your project scope.", 403)
    sponsor = None
    if data["kind"] == "agent":
        sponsor = (
            Principal.objects.select_for_update()
            .filter(
                pk=data["sponsorId"],
                issuer=settings.WORKFORCE_ISSUER,
                kind="human",
                status="active",
            )
            .first()
        )
        if not sponsor or not set(data["projectIds"]).issubset(set(sponsor.project_ids)):
            raise DomainError(
                "invalid_sponsor", "Sponsor must be active and own the selected project scope.", 403
            )
        svc.scope_identity(actor, sponsor)
    identifier = uuid.uuid4()
    identity = Principal.objects.create(
        id=identifier,
        issuer=settings.WORKFORCE_ISSUER,
        subject="pending:" + str(identifier),
        name=data["name"],
        email=data.get("email", ""),
        kind=data["kind"],
        department=data["department"],
        project_ids=data["projectIds"],
        status="suspended" if data["kind"] == "agent" else "active",
        sponsor=sponsor,
        roles=[],
    )
    OutboxJob.objects.create(
        kind="enroll",
        desired={
            "identityId": str(identity.pk),
            "userName": "accessops-" + identifier.hex,
            "active": data["kind"] == "human",
        },
        available_at=timezone.now(),
    )
    audit.append(
        actor,
        "identity.registered",
        identity.pk,
        {
            "kind": identity.kind,
            "providerEffect": "pending",
            "resourceGrants": 0,
            "credentialBinding": "pending" if identity.kind == "agent" else "not-applicable",
        },
    )
    return identity


@api_view(["POST"])
def identities(request):
    data = validate(EnrollmentInput, request.data)
    payload = {k: str(v) if k == "sponsorId" and v else v for k, v in data.items()}

    def check(actor):
        if not set(data["projectIds"]).issubset(set(actor.project_ids)):
            raise DomainError(
                "object_scope_denied", "Enrollment is outside your project scope.", 403
            )
        svc.require_policy(actor, "request", context={"identity_project_ids": data["projectIds"]})

    def handler(actor):
        identity = enroll(actor, data)
        return {
            "result": {
                **present.identity(identity),
                "providerBinding": "pending",
                "credentialBinding": "pending" if identity.kind == "agent" else "not-applicable",
            }
        }, 201

    result, status = svc.mutation(
        _actor(request),
        request.headers.get("Idempotency-Key"),
        "identity.enroll",
        payload,
        check,
        handler,
    )
    return Response(result, status=status)


def request_department_transfer(actor, identity, data):
    identity = Principal.objects.select_for_update().get(pk=identity.pk)
    svc.scope_identity(actor, identity)
    if identity.kind != "human" or identity.status != "active":
        raise DomainError(
            "invalid_transfer", "Only active human workforce identities can change department.", 409
        )
    projects = DEPARTMENTS[data["department"]]
    if not set(projects).issubset(set(actor.project_ids)):
        raise DomainError(
            "object_scope_denied", "The destination department is outside your scope.", 403
        )
    if identity.department == data["department"]:
        raise DomainError("unchanged_department", "Select a different department.", 409)
    payload = {
        "identityId": str(identity.pk),
        "resourceId": None,
        "action": "department_transfer",
        "reason": data["reason"],
        "targetDepartment": data["department"],
        "sourceDepartment": identity.department,
        "sourceProjects": identity.project_ids,
        "targetProjects": projects,
        "identityRevision": identity.revision,
    }
    change = ChangeRequest.objects.create(
        identity=identity,
        requester=actor,
        payload=payload,
        payload_hash=audit.digest(payload),
        policy_version=svc.policy_state().version,
    )
    audit.append(
        actor,
        "department.transfer.requested",
        change.pk,
        {
            "source": identity.department,
            "destination": data["department"],
            "newAccess": "requires-separate-approved-grant",
        },
    )
    return change


@api_view(["POST"])
def transfer_department(request, identity_id):
    data = validate(DepartmentInput, request.data)
    identity = get_object_or_404(Principal, pk=identity_id, issuer=settings.WORKFORCE_ISSUER)

    def check(actor):
        svc.scope_identity(actor, identity)
        projects = sorted(set(identity.project_ids) | set(DEPARTMENTS[data["department"]]))
        svc.require_policy(actor, "request", context={"identity_project_ids": projects})

    def handler(actor):
        return {"result": present.change(request_department_transfer(actor, identity, data))}, 201

    result, status = svc.mutation(
        _actor(request),
        request.headers.get("Idempotency-Key"),
        "identity.department-transfer:" + str(identity_id),
        data,
        check,
        handler,
    )
    return Response(result, status=status)


def apply_department_transfer(actor, identity, change):
    """Called only inside the serialized approved execution transaction."""
    payload = change.payload
    if payload.get("targetProjects") != DEPARTMENTS.get(payload.get("targetDepartment")):
        raise DomainError(
            "invalid_transfer", "Destination scope no longer matches the approved change.", 409
        )
    if set(payload.get("sourceProjects", []) + payload["targetProjects"]) - set(actor.project_ids):
        raise DomainError("object_scope_denied", "Transfer is outside your project scope.", 403)
    old_projects = set(payload["sourceProjects"]) - set(payload["targetProjects"])
    from .models import AssistantTask

    Grant.objects.filter(
        identity=identity, resource__project__in=old_projects, status="active"
    ).update(status="revoked")
    sponsored = list(Principal.objects.select_for_update().filter(sponsor=identity, kind="agent"))
    for agent in sponsored:
        if old_projects.intersection(agent.project_ids):
            agent.status = "suspended"
            agent.revision += 1
            agent.save(update_fields=["status", "revision", "updated_at"])
            svc.revoke_for([agent.pk])
            OutboxJob.objects.create(
                kind="suspend",
                desired={"identityId": str(agent.pk), "active": False},
                available_at=timezone.now(),
            )
    AssistantTask.objects.filter(requester=identity, status="active").update(status="revoked")
    identity.department = payload["targetDepartment"]
    identity.project_ids = payload["targetProjects"]
    identity.revision += 1
    identity.save(update_fields=["department", "project_ids", "revision", "updated_at"])
    audit.append(
        actor,
        "department.transfer.applied",
        identity.pk,
        {
            "department": identity.department,
            "oldAccess": "revoked",
            "newAccess": "not-granted",
            "providerEffect": "pending",
        },
    )


def process_enrollment_job(job, connector):
    """Observe a deterministic username before POST after an unknown outcome."""
    from django.db import transaction

    from integrations.errors import ConnectorError

    identity = Principal.objects.get(pk=job.desired["identityId"])
    username = job.desired["userName"]
    listing = connector.list_resources(
        "Users", filter_expression="userName eq " + audit.canonical(username), count=2
    )
    candidates = listing.get("Resources", [])
    if len(candidates) > 1:
        raise ConnectorError("Ambiguous enrollment binding")
    if candidates:
        observed = candidates[0]
        if observed.get("userName") != username:
            raise ConnectorError("Provider binding mismatch")
    else:
        parts = identity.name.split(" ", 1)
        observed = connector.create_user(
            username,
            external_id=str(identity.pk),
            given_name=parts[0],
            family_name=parts[1] if len(parts) > 1 else "",
            email=identity.email or None,
        )
    subject = observed.get("id")
    if not isinstance(subject, str) or not subject or len(subject) > 128:
        raise ConnectorError("Provider returned an invalid binding")
    # Remote calls must not hold the application-wide revocation gate. A late
    # remote result is bound but never labeled verified against newer state;
    # durable correction makes provider convergence explicit.
    desired_active = identity.status == "active" and identity.kind == "human"
    connector.patch_user(subject, [{"op": "replace", "path": "active", "value": desired_active}])
    actual = connector.get_user(subject)
    if actual.get("id") != subject or type(actual.get("active")) is not bool:
        raise ConnectorError("Enrollment could not be observed")
    with transaction.atomic():
        svc.policy_state(lock=True)
        identity = Principal.objects.select_for_update().get(pk=identity.pk)
        current_active = identity.status == "active" and identity.kind == "human"
        if not identity.subject.startswith("pending:") and identity.subject != subject:
            raise ConnectorError("Established provider binding cannot be replaced")
        identity.subject = subject
        identity.save(update_fields=["subject", "updated_at"])
        verified = actual["active"] is current_active
        if not verified and not current_active:
            OutboxJob.objects.create(
                kind="suspend",
                desired={"identityId": str(identity.pk), "active": False},
                available_at=timezone.now(),
            )
        audit.append(
            "worker",
            "identity.provider.bound",
            identity.pk,
            {
                "providerEffect": "verified" if verified else "pending-correction",
                "active": current_active,
            },
        )
    return {
        "desired": {"active": current_active},
        "observed": {"active": actual["active"], "binding": "verified"},
        "verified": verified,
    }


def process_department_job(job, connector):
    change = job.request
    identity = change.identity
    previous = set(change.payload["sourceProjects"]) - set(change.payload["targetProjects"])
    verified = True
    observed = []
    desired_records = []
    for resource in Resource.objects.filter(project__in=previous):

        def desired_membership():
            from django.db.models import Q

            return (
                Grant.objects.filter(identity=identity, resource=resource, status="active")
                .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
                .exists()
            )

        desired = desired_membership()
        mapping = {"providerGroup": resource.provider_group, "desiredMember": desired}
        observed_before = connector.reconcile(
            {"providerSubject": identity.subject, "status": identity.status}, mapping
        )
        if observed_before.get("observed", {}).get("member") is desired:
            result = {"verified": True, "observed": observed_before["observed"]}
        else:
            result = connector.apply(
                {"action": "grant" if desired else "revoke"},
                {"providerSubject": identity.subject},
                mapping,
            )
        # A newer approved exception wins over a queued department cleanup.
        current_desired = desired_membership()
        matches = result.get("observed", {}).get("member") is current_desired
        if not matches:
            OutboxJob.objects.create(
                kind="reconcile",
                desired={"projects": [resource.project]},
                available_at=timezone.now(),
            )
        verified = verified and result.get("verified") is True and matches
        observed.append(
            {"resourceId": str(resource.pk), "member": result.get("observed", {}).get("member")}
        )
        desired_records.append({"resourceId": str(resource.pk), "member": current_desired})
    return {
        "desired": {"resources": desired_records, "automaticNewAccess": False},
        "observed": {"resources": observed},
        "verified": verified,
    }
