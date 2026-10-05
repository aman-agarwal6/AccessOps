"""Departure case work: separate local effects, snapshots and owner statements."""

import re
from datetime import timedelta
from uuid import UUID

from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.response import Response

from . import audit
from . import services as svc
from .errors import DomainError
from .models import (
    ADEnrollment,
    AuditEvent,
    Grant,
    OffboardingCase,
    OutboxJob,
    PlatformImport,
    Principal,
    Resource,
)
from .serializers import EmptyInput, StrictSerializer, validate
from .views import actor_of
from .worker import account_contained

TASKS = (
    ("local-containment", "accessops", "local", "Revoke local access and contain sponsored agents"),
    ("keycloak-directory", "keycloak", "directory", "Observe workforce account disabled"),
    ("entra-directory", "entra", "directory", "Block Microsoft Entra sign-in"),
    ("entra-sessions", "entra", "sessions", "Record sign-in and application session handoff"),
    ("github-org", "github", "directory", "Remove GitHub organization access"),
    (
        "github-repositories",
        "github",
        "directory",
        "Check repository and outside-collaborator access",
    ),
    (
        "credentials",
        "github",
        "credentials",
        "Transfer automation ownership and rotate shared credentials",
    ),
    ("m365-handover", "m365", "data", "Review Microsoft 365 data retention, handover and licenses"),
    ("legacy-scope", "legacy", "legacy", "Confirm AD and legacy application coverage"),
)
AD_TASK = (
    "ad-directory",
    "legacy",
    "directory",
    "Disable scoped Samba AD account and remove mapped group memberships",
)
LIMITATIONS = [
    "Administrative closure records reviewed evidence; it does not prove every remote access path ended.",
    "Imported snapshots are not authenticated live observations made by this application.",
    "Keycloak session revocation ends the sessions Keycloak holds and rejects earlier tokens when apps ask Keycloak; an app that validates access tokens itself accepts one already issued until it expires (2 minutes in the lab).",
    "Entra directory state does not prove application-owned sessions or guest home-tenant sessions ended.",
    "GitHub removal does not erase clones, unknown repositories or every token/key.",
    "Data retention, licensing and legacy actions are owner attestations, not automatic platform writes.",
    "Optional Samba AD observations cover the enrolled account and mapped groups, not existing sessions/tickets or Microsoft interoperability.",
]
CAPABILITIES = [
    "account_enabled",
    "organization_membership",
    "outside_collaborator",
    "repository_collaborator",
    "session_revocation",
    "credential_revocation",
]


class UTCField(serializers.DateTimeField):
    def to_internal_value(self, value):
        if not isinstance(value, str) or len(value) > 40:
            self.fail("invalid", format="ISO-8601 with timezone")
        try:
            parsed = parse_datetime(value)
        except ValueError:
            parsed = None
        if parsed is None or timezone.is_naive(parsed):
            self.fail("invalid", format="ISO-8601 with timezone")
        return super().to_internal_value(value)


class BindingInput(StrictSerializer):
    provider = serializers.ChoiceField(choices=["entra", "github"])
    tenantId = serializers.CharField(max_length=64)
    subjectId = serializers.CharField(max_length=64)

    def validate(self, data):
        if data["provider"] == "entra":
            try:
                data["tenantId"] = str(UUID(data["tenantId"]))
                data["subjectId"] = str(UUID(data["subjectId"]))
            except ValueError as error:
                raise serializers.ValidationError("Entra bindings require stable UUIDs.") from error
        elif any(not re.fullmatch(r"[1-9][0-9]{0,19}", data[k]) for k in ("tenantId", "subjectId")):
            raise serializers.ValidationError("GitHub bindings require stable numeric IDs.")
        return data


class CreateInput(StrictSerializer):
    identityId = serializers.UUIDField()
    employmentType = serializers.ChoiceField(choices=["employee", "contractor"])
    hrEventId = serializers.RegexField(r"^[A-Za-z0-9._:-]{8,64}$")
    hrSource = serializers.CharField(min_length=3, max_length=64)
    effectiveAt = UTCField()
    reason = serializers.CharField(min_length=8, max_length=255)
    bindings = BindingInput(many=True, max_length=2)

    def validate(self, data):
        providers = [b["provider"] for b in data["bindings"]]
        if len(providers) != len(set(providers)):
            raise serializers.ValidationError("Bind each platform at most once.")
        if abs((data["effectiveAt"] - timezone.now()).total_seconds()) > 366 * 86400:
            raise serializers.ValidationError("Departure date must be within a year.")
        return data


class ObservationInput(BindingInput):
    observedAt = UTCField()
    capability = serializers.ChoiceField(choices=CAPABILITIES)
    status = serializers.ChoiceField(choices=["observed", "unknown"])
    value = serializers.JSONField(allow_null=True)
    scope = serializers.CharField(min_length=1, max_length=120)
    reasonCode = serializers.RegexField(r"^[a-zA-Z0-9._:-]{1,80}$")

    def validate(self, data):
        data = super().validate(data)
        if (
            data["status"] == "unknown"
            and data["value"] is not None
            or data["status"] == "observed"
            and type(data["value"]) is not bool
        ):
            raise serializers.ValidationError(
                "Observed values must be booleans; unknown must be null."
            )
        if (
            data["provider"] == "github"
            and data["capability"] == "account_enabled"
            or data["provider"] == "entra"
            and data["capability"] in CAPABILITIES[1:4]
        ):
            raise serializers.ValidationError("Capability does not belong to the platform.")
        return data


class ReportInput(StrictSerializer):
    schemaVersion = serializers.IntegerField(min_value=1, max_value=1)
    collectionMethod = serializers.ChoiceField(
        choices=["synthetic_fixture", "read_only_api", "manual_export"]
    )
    collectedAt = UTCField()
    observations = ObservationInput(many=True, min_length=1, max_length=100)
    limitations = serializers.ListField(child=serializers.CharField(max_length=240), max_length=20)

    def validate(self, data):
        now = timezone.now()
        if data["collectedAt"] > now + timedelta(seconds=5):
            raise serializers.ValidationError("Snapshot capture cannot be in the future.")
        seen = set()
        for observation in data["observations"]:
            key = tuple(
                observation[k] for k in ("provider", "tenantId", "subjectId", "capability", "scope")
            )
            if key in seen:
                raise serializers.ValidationError("Duplicate capability/scope reading.")
            seen.add(key)
            if observation["observedAt"] > min(now, data["collectedAt"]) + timedelta(seconds=5):
                raise serializers.ValidationError(
                    "Observation cannot follow snapshot capture or be in the future."
                )
        return data


class ImportInput(StrictSerializer):
    report = ReportInput()


class AttestInput(StrictSerializer):
    reference = serializers.CharField(min_length=8, max_length=120)
    summary = serializers.CharField(min_length=20, max_length=500)


class CloseInput(StrictSerializer):
    expectedRevision = serializers.IntegerField(min_value=1)
    packetHash = serializers.RegexField(r"^[a-f0-9]{64}$")


def json_value(value):
    if isinstance(value, dict):
        return {k: json_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_value(v) for v in value]
    if isinstance(value, UUID):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def case_scope(actor, case, write=False, closing=False):
    projects = svc.scope_offboarding(actor, case.identity)
    svc.require_policy(
        actor,
        "departure_close" if closing else "request" if write else "snapshot",
        context={
            "identity_project_ids": sorted(projects),
            "case_owner_id": str(case.owner_id),
        },
    )


def open_case(case):
    if case.closed_at:
        raise DomainError(
            "case_closed", "The closure packet is immutable. Create a new departure event.", 409
        )


def import_receipt(item):
    providers = {o["provider"] for o in item.report["observations"]}
    return {
        "id": str(item.pk),
        "platform": next(iter(providers)) if len(providers) == 1 else "mixed",
        "capturedAt": item.captured_at.isoformat(),
        "importedAt": item.imported_at.isoformat(),
        "recordCount": len(item.report["observations"]),
        "sha256": item.sha256,
        "collectionMethod": item.report["collectionMethod"],
        "limitations": item.report["limitations"],
    }


def read_time(value):
    try:
        at = parse_datetime(value) if isinstance(value, str) and len(value) <= 40 else None
    except ValueError:
        at = None
    return at if at and timezone.is_aware(at) else None


def fresh_read(value, case, now):
    at = read_time(value)
    return at if at and case.effective_at <= at <= now and now - at <= timedelta(hours=2) else None


def latest_readings(candidates):
    """Keep unsafe ties: completion order never resolves a conflicting reading."""
    if not candidates:
        return []
    latest = max(at for at, _ in candidates)
    return [proof for at, proof in candidates if at == latest]


def keycloak_reading(case, now):
    """Use the latest bounded, timestamped reading of this workforce account.

    A failed inventory can contain valid independent account readings. A later
    unknown/positive reading must supersede earlier lifecycle success.
    """
    candidates = {}

    def add(scope, value, event, safe, destination=None):
        at = read_time(value)
        valid_time = at is not None and at <= now and at <= event.at
        # An unknown attempt may be ordered by completion, but completion can
        # never make its observation fresh or turn it into a positive proof.
        order_at = at if valid_time else event.at
        proof = fresh_read(value, case, now) if safe and valid_time else None
        (candidates if destination is None else destination).setdefault(scope, []).append(
            (order_at, proof)
        )

    removal_jobs = (
        list(
            OutboxJob.objects.filter(
                kind="entitlement_revoke",
                desired__containmentRequestId=str(case.containment_request_id),
            )
        )
        if case.containment_request_id
        else []
    )
    affected_identities = [
        case.identity_id,
        *Principal.objects.filter(sponsor_id=case.identity_id, kind="agent").values_list(
            "pk", flat=True
        ),
    ]
    known_pairs = (
        Grant.objects.filter(identity_id__in=affected_identities)
        .exclude(resource__provider_group="")
        .values_list("identity_id", "resource_id")
        .distinct()
    )
    removals = {(str(identity), str(resource)): [] for identity, resource in known_pairs}
    actions = ["provider.verified", "provider.failed", "provider.retry", "job.failed", "job.retry"]
    for job in removal_jobs:
        if job.status in ("pending", "running", "retry"):
            return None
        pair = (job.desired.get("identityId"), job.desired.get("resourceId"))
        removals.setdefault(pair, [])
        event = (
            AuditEvent.objects.filter(
                target_id=str(job.pk), action__in=actions, detail__jobId=str(job.pk)
            )
            .order_by("-sequence")
            .first()
        )
        if event:
            add(
                pair,
                None if event.action.startswith("job.") else job.observed.get("observedAt"),
                event,
                job.status == "verified"
                and event.action == "provider.verified"
                and job.observed.get("member") is False,
                removals,
            )
    pair_projects = {
        str(r.pk): r.project for r in Resource.objects.filter(pk__in=[pair[1] for pair in removals])
    }
    affected_projects = set(case.identity.project_ids) | set(pair_projects.values())

    if case.containment_request_id:
        for job in OutboxJob.objects.filter(request_id=case.containment_request_id):
            if job.status in ("pending", "running", "retry"):
                return None
            event = (
                AuditEvent.objects.filter(
                    target_id=str(case.containment_request_id),
                    action__in=["provider.verified", "provider.failed", "job.failed", "job.retry"],
                    detail__jobId=str(job.pk),
                )
                .order_by("-sequence")
                .first()
            )
            if event:
                add(
                    "account",
                    None if event.action.startswith("job.") else job.observed.get("observedAt"),
                    event,
                    job.status == "verified"
                    and account_contained(job.observed)
                    and event.action == "provider.verified",
                )
    active_jobs = list(
        OutboxJob.objects.filter(kind="reconcile", status__in=["pending", "running", "retry"])[:501]
    )
    if len(active_jobs) > 500:
        return None
    for job in active_jobs:
        if set(job.desired.get("projects", [])) & affected_projects:
            return None
    events = list(
        AuditEvent.objects.filter(action__in=actions, at__gte=now - timedelta(hours=2)).order_by(
            "-sequence"
        )[:501]
    )
    if len(events) > 500:
        return None
    latest_events = {}
    for event in events:
        if isinstance(event.detail.get("jobId"), str):
            latest_events.setdefault(event.detail["jobId"], event)
    # Select by recent outcome, not job creation: a slow old job may finish last.
    job_ids = [value for value in latest_events if re.fullmatch(r"[a-f0-9-]{36}", value)]
    for job in OutboxJob.objects.filter(kind="reconcile", pk__in=job_ids):
        scoped = bool(set(job.desired.get("projects", [])) & set(case.identity.project_ids))
        observations = [
            o
            for o in job.observed.get("observations", [])
            if o.get("identityId") == str(case.identity_id)
        ]
        event = latest_events[str(job.pk)]
        if event.target_id != str(job.pk):
            continue
        inventory = job.observed.get("observations", [])
        for pair in removals:
            pair_readings = [
                o for o in inventory if (o.get("identityId"), o.get("resourceId")) == pair
            ]
            if event.action.startswith("job.") or not pair_readings:
                if pair_projects.get(pair[1]) in job.desired.get("projects", []):
                    add(pair, None, event, False, removals)
            else:
                for o in pair_readings:
                    add(
                        pair,
                        o.get("observedAt"),
                        event,
                        o.get("status") == "observed"
                        and o.get("observed", {}).get("member") is False,
                        removals,
                    )
        if event.action.startswith("job."):
            if scoped or observations:
                add("account", None, event, False)
            continue
        if not observations and scoped:
            add("account", None, event, False)
        for o in observations:
            add(
                o.get("resourceId", "account"),
                o.get("observedAt"),
                event,
                event.action.startswith("provider.")
                and o.get("status") == "observed"
                and account_contained(o.get("observed")),
            )
    if not candidates:
        return None
    account_at = max((at for at, _ in candidates.get("account", [])), default=None)
    resource_at = max(
        (at for scope, values in candidates.items() if scope != "account" for at, _ in values),
        default=None,
    )
    proofs = []
    for scope, readings in candidates.items():
        if (
            scope == "account"
            and resource_at is not None
            and account_at is not None
            and resource_at > account_at
        ):
            continue
        if scope != "account" and account_at is not None:
            readings = [(at, proof) for at, proof in readings if at >= account_at]
        proofs.extend(latest_readings(readings))
    for readings in removals.values():
        if not readings:
            return None
        proofs.extend(latest_readings(readings))
    return min(proofs) if proofs and all(proofs) else None


def ad_reading(case, now):
    jobs = OutboxJob.objects.filter(
        kind__in=["ad_offboard", "ad_observe"], desired__caseId=str(case.pk)
    )
    if jobs.filter(status__in=["pending", "running", "retry"]).exists():
        return None
    candidates = []
    for job in jobs:
        event = (
            AuditEvent.objects.filter(
                target_id=str(job.pk),
                detail__jobId=str(job.pk),
                action__in=[
                    "provider.verified",
                    "provider.failed",
                    "provider.retry",
                    "job.failed",
                    "job.retry",
                ],
            )
            .order_by("-sequence")
            .first()
        )
        at = (
            read_time(job.observed.get("observedAt"))
            if event and event.action.startswith("provider.")
            else None
        )
        if not event:
            return None
        candidates.append((at if at and at <= event.at and at <= now else event.at, job, event))
    if not candidates:
        return None
    latest_at = max(at for at, _, _ in candidates)
    latest_candidates = [(job, event) for at, job, event in candidates if at == latest_at]
    proofs = [ad_job_reading(case, now, job, event) for job, event in latest_candidates]
    return min(proofs) if proofs and all(proofs) else None


def ad_job_reading(case, now, latest, event):
    if (
        not latest
        or latest.status != "verified"
        or latest.desired.get("binding") != case.ad_binding
    ):
        return None
    observed = latest.observed
    if not isinstance(observed, dict):
        return None
    groups = observed.get("groups", [])
    if (
        observed.get("provider") != "samba_ad"
        or observed.get("domainGuid") != case.ad_binding["domainGuid"]
        or observed.get("userGuid") != case.ad_binding["userGuid"]
        or observed.get("active") is not False
        or not isinstance(groups, list)
        or len(groups) != len(case.ad_binding["groupGuids"])
        or any(
            not isinstance(g, dict)
            or not isinstance(g.get("groupGuid"), str)
            or g.get("member") is not False
            for g in groups
        )
        or {g.get("groupGuid") for g in groups} != set(case.ad_binding["groupGuids"])
    ):
        return None
    at = fresh_read(observed.get("observedAt"), case, now)
    return at if event.action == "provider.verified" and at and at <= event.at else None


def assess(case):
    if case.closed_at:
        return case.closed_packet["case"]
    now = timezone.now()
    imports = list(case.platform_imports.order_by("-imported_at"))
    readings = {}
    for item in imports:
        for observation in item.report["observations"]:
            key = tuple(
                observation[k] for k in ("provider", "tenantId", "subjectId", "capability", "scope")
            )
            previous = readings.get(key)
            if previous is None or parse_datetime(observation["observedAt"]) > parse_datetime(
                previous[1]["observedAt"]
            ):
                readings[key] = (item, observation)
    identity = Principal.objects.get(pk=case.identity_id)
    agents = list(Principal.objects.filter(sponsor=identity, kind="agent"))
    local_contained = (
        bool(case.containment_request_id)
        and identity.status == "offboarded"
        and all(a.status != "active" for a in agents)
        and not Grant.objects.filter(
            identity_id__in=[identity.pk, *(a.pk for a in agents)], status="active"
        ).exists()
    )
    provider_at = keycloak_reading(case, now)
    directory_at = ad_reading(case, now) if case.ad_binding else None
    tasks, blockers = [], []
    for key, platform, boundary, title in (*TASKS, *((AD_TASK,) if case.ad_binding else ())):
        task = {
            "id": key,
            "platform": platform,
            "boundary": boundary,
            "title": title,
            "ownerId": str(case.owner_id),
            "dueAt": case.due_at.isoformat(),
            "required": True,
            "status": "pending",
            "evidenceKind": "none",
        }
        statement = case.attestations.get(key)
        if key == "local-containment" and local_contained:
            task.update(
                status="observed",
                evidenceKind="provider_observation",
                evidenceSummary="Current database state: identity offboarded, grants revoked and sponsored agents contained.",
                observedAt=case.containment_request.applied_at.isoformat(),
            )
        elif key == "keycloak-directory" and provider_at:
            task.update(
                status="observed",
                evidenceKind="provider_observation",
                evidenceSummary="Fresh Keycloak readings observed the workforce account disabled with no active sessions, and known managed grant memberships absent. Keycloak rejects tokens issued before containment and sent back-channel logout to registered apps; credentials and unknown access paths are separate.",
                observedAt=provider_at.isoformat(),
            )
        elif key == "ad-directory" and directory_at:
            task.update(
                status="observed",
                evidenceKind="provider_observation",
                evidenceSummary="Samba AD-compatible lab worker observed the exact enrolled account disabled and every mapped group membership absent; existing tickets/sessions are separate.",
                observedAt=directory_at.isoformat(),
            )
        elif key == "entra-directory":
            account_readings = [
                o
                for _, o in readings.values()
                if o["provider"] == "entra" and o["capability"] == "account_enabled"
            ]
            if account_readings:
                if all(
                    case.effective_at <= parse_datetime(o["observedAt"]) <= now
                    and now - parse_datetime(o["observedAt"]) <= timedelta(hours=2)
                    and o["status"] == "observed"
                    and o["value"] is False
                    for o in account_readings
                ):
                    task.update(
                        status="observed",
                        evidenceKind="imported_snapshot",
                        evidenceSummary="Matched imported snapshot reports accountEnabled:false. External state is independently unverified.",
                        observedAt=min(o["observedAt"] for o in account_readings),
                    )
        if (
            task["status"] == "pending"
            and statement
            and key not in ("local-containment", "keycloak-directory", "ad-directory")
        ):
            task.update(
                status="attested",
                evidenceKind="owner_attestation",
                evidenceSummary=statement["summary"],
                evidenceReference=statement["reference"],
                completedAt=statement["completedAt"],
                submittedById=statement["submittedById"],
            )
        if task["status"] == "pending":
            blockers.append(title + ": evidence is missing, incomplete or stale.")
        tasks.append(task)
    if case.effective_at > now:
        blockers.insert(0, "The HR departure is not effective yet.")
    # Positive observations captured after an owner statement reopen that platform.
    for item, observation in readings.values():
        if observation["status"] != "observed" or observation["value"] is not True:
            continue
        related = (
            "entra-directory"
            if observation["capability"] == "account_enabled"
            else "github-org"
            if observation["capability"] == "organization_membership"
            else "github-repositories"
            if observation["capability"] in ("outside_collaborator", "repository_collaborator")
            else None
        )
        statement = case.attestations.get(related)
        if related and (
            not statement
            or parse_datetime(statement["completedAt"]) <= parse_datetime(observation["observedAt"])
        ):
            message = (
                f"Residual {observation['provider']} access is reported in {observation['scope']}."
            )
            if message not in blockers:
                blockers.append(message)
    dto = {
        "id": str(case.pk),
        "identityId": str(identity.pk),
        "title": f"{identity.name} — departure closure",
        "employmentType": case.employment_type,
        "hrEventId": case.hr_event_id,
        "hrSource": case.hr_source,
        "reason": case.reason,
        "effectiveAt": case.effective_at.isoformat(),
        "ownerId": str(case.owner_id),
        "dueAt": case.due_at.isoformat(),
        "status": "blocked"
        if blockers and case.containment_request_id
        else "in_progress"
        if case.platform_imports.exists()
        else "open",
        "createdAt": case.created_at.isoformat(),
        "updatedAt": case.updated_at.isoformat(),
        "revision": case.revision,
        "policyVersion": svc.policy_state().version,
        "bindings": case.bindings,
        "tasks": tasks,
        "imports": [import_receipt(item) for item in imports],
        "blockers": blockers,
        "evidenceLimitations": LIMITATIONS,
    }
    if case.containment_request_id:
        dto["containmentRequestId"] = str(case.containment_request_id)
    if case.ad_binding:
        dto["adBinding"] = case.ad_binding
    if case.intake_source_id:
        dto["intakeSourceId"] = str(case.intake_source_id)
    dto["packetHash"] = audit.digest(dto)
    return dto


def visible_cases(actor):
    values = []
    for case in OffboardingCase.objects.select_related(
        "identity", "owner", "containment_request"
    ).order_by("-created_at")[:200]:
        projects = svc.offboarding_projects(case.identity)
        if projects.issubset(actor.project_ids) and projects:
            values.append(assess(case))
            if len(values) == 50:
                break
    return values


@api_view(["POST"])
def create(request):
    data = validate(CreateInput, request.data)
    actor = actor_of(request)
    identity = get_object_or_404(
        Principal, pk=data["identityId"], issuer=settings.WORKFORCE_ISSUER, kind="human"
    )

    def check(a):
        current = Principal.objects.get(pk=identity.pk)
        projects = svc.scope_offboarding(a, current)
        svc.require_policy(a, "request", context={"identity_project_ids": sorted(projects)})

    def handle(a):
        if identity.pk == a.workforce_identity_id:
            raise DomainError(
                "independent_owner_required", "Assign another operator to your own departure.", 403
            )
        if OffboardingCase.objects.filter(
            hr_source=data["hrSource"], hr_event_id=data["hrEventId"]
        ).exists():
            raise DomainError("departure_exists", "This HR event already has a case.", 409)
        enrollment = ADEnrollment.objects.filter(identity_id=identity.pk).first()
        case = OffboardingCase.objects.create(
            identity=identity,
            owner=a,
            employment_type=data["employmentType"],
            hr_event_id=data["hrEventId"],
            hr_source=data["hrSource"],
            effective_at=data["effectiveAt"],
            due_at=data["effectiveAt"] + timedelta(hours=4),
            reason=data["reason"],
            bindings=data["bindings"],
            ad_binding=enrollment.binding if enrollment else {},
        )
        audit.append(
            a,
            "departure.created",
            case.pk,
            {"identityId": str(identity.pk), "hrEventId": case.hr_event_id},
        )
        return {"result": assess(case)}, 201

    result, status = svc.mutation(
        actor,
        request.headers.get("Idempotency-Key"),
        "departure.create",
        json_value(data),
        check,
        handle,
    )
    return Response(result, status=status)


def import_snapshot(actor, case, report):
    normalized = json_value(report)
    if len(audit.canonical(normalized).encode()) > 100_000 or case.platform_imports.count() >= 20:
        raise DomainError("snapshot_limit", "Snapshot size or per-case history limit reached.", 400)
    bindings = {(b["provider"], b["tenantId"], b["subjectId"]) for b in case.bindings}
    if any(
        tuple(o[k] for k in ("provider", "tenantId", "subjectId")) not in bindings
        for o in normalized["observations"]
    ):
        raise DomainError(
            "account_binding_mismatch",
            "Every observation must match an explicit case account binding.",
            409,
        )
    item = PlatformImport.objects.create(
        case=case,
        actor=actor,
        captured_at=report["collectedAt"],
        report=normalized,
        sha256=audit.digest(normalized),
    )
    case.attestations = {}
    audit.append(
        actor,
        "departure.snapshot_imported",
        case.pk,
        {
            "importId": str(item.pk),
            "sha256": item.sha256,
            "recordCount": len(normalized["observations"]),
        },
    )


def contain(actor, case):
    if case.effective_at > timezone.now():
        raise DomainError("departure_not_effective", "The HR departure is not effective yet.", 409)
    if case.containment_request_id:
        return
    change = svc.create_request(
        actor,
        {
            "identityId": str(case.identity_id),
            "action": "offboard",
            "reason": f"Departure {case.hr_event_id}: {case.reason}"[:255],
        },
    )
    svc.require_policy(
        actor, "execute", change=change, context={"identity_project_ids": case.identity.project_ids}
    )
    change = svc.execute(actor, change)
    case.containment_request = change
    if case.ad_binding:
        OutboxJob.objects.create(
            kind="ad_offboard",
            desired={
                "caseId": str(case.pk),
                "identityId": str(case.identity_id),
                "binding": case.ad_binding,
            },
            available_at=timezone.now(),
        )


def attest(actor, case, task_id, data):
    if task_id not in {task[0] for task in TASKS} or task_id in (
        "local-containment",
        "keycloak-directory",
        "ad-directory",
    ):
        raise DomainError(
            "observation_required", "This task requires its actual local/provider observation.", 409
        )
    if actor.pk != case.owner_id:
        raise DomainError(
            "owner_required", "Only the accountable case owner can record external work.", 403
        )
    if case.effective_at > timezone.now():
        raise DomainError(
            "departure_not_effective",
            "Wait until the departure is effective to attest completed work.",
            409,
        )
    case.attestations[task_id] = {
        **data,
        "completedAt": timezone.now().isoformat(),
        "submittedById": str(actor.pk),
    }
    audit.append(
        actor,
        "departure.owner_attested",
        case.pk,
        {"taskId": task_id, "statementHash": audit.digest(case.attestations[task_id])},
    )


def close(actor, case, data):
    dto = assess(case)
    if (
        "approver" not in actor.roles
        or actor.pk == case.owner_id
        or any(s["submittedById"] == str(actor.pk) for s in case.attestations.values())
    ):
        raise DomainError(
            "independent_reviewer_required",
            "An independent approver must review the current closure evidence.",
            403,
        )
    if dto["revision"] != data["expectedRevision"] or dto["packetHash"] != data["packetHash"]:
        raise DomainError(
            "stale_case", "Case evidence changed. Refresh and review the new packet.", 409
        )
    if dto["blockers"]:
        raise DomainError(
            "closure_blocked",
            "Required departure actions or current evidence remain unresolved.",
            409,
        )
    case.closed_at, case.closed_by = timezone.now(), actor
    dto.update(
        status="closed",
        closedAt=case.closed_at.isoformat(),
        closedById=str(actor.pk),
        closureBasis="reviewed_evidence",
        revision=case.revision + 1,
    )
    dto.pop("packetHash")
    packet = {
        "schemaVersion": 1,
        "origin": "connected_case",
        "reviewedInputHash": data["packetHash"],
        "case": dto,
        "limitations": LIMITATIONS,
    }
    dto["packetHash"] = audit.digest(packet)
    case.closed_packet = packet
    audit.append(
        actor,
        "departure.closed",
        case.pk,
        {
            "reviewedInputHash": data["packetHash"],
            "packetHash": dto["packetHash"],
            "revision": dto["revision"],
        },
    )


@api_view(["POST"])
def action(request, case_id, operation, task_id=None):
    serializers_by_action = {
        "import": ImportInput,
        "contain": EmptyInput,
        "attest": AttestInput,
        "close": CloseInput,
        "observe-directory": EmptyInput,
    }
    if operation not in serializers_by_action:
        raise DomainError("not_found", "Unknown departure operation.", 404)
    data = validate(serializers_by_action[operation], request.data)
    actor = actor_of(request)
    case = get_object_or_404(OffboardingCase, pk=case_id)

    def check(a):
        current = OffboardingCase.objects.select_related("identity").get(pk=case.pk)
        case_scope(a, current, write=operation != "close", closing=operation == "close")

    def handle(a):
        current = OffboardingCase.objects.select_for_update().get(pk=case.pk)
        open_case(current)
        if operation == "import":
            import_snapshot(a, current, data["report"])
        elif operation == "contain":
            contain(a, current)
        elif operation == "attest":
            attest(a, current, task_id, data)
        elif operation == "observe-directory":
            if (
                not current.ad_binding
                or not current.containment_request_id
                or current.effective_at > timezone.now()
            ):
                raise DomainError(
                    "directory_not_ready",
                    "Directory evidence refresh requires an effective, locally contained and enrolled departure.",
                    409,
                )
            if not OutboxJob.objects.filter(
                kind__in=["ad_offboard", "ad_observe"],
                desired__caseId=str(current.pk),
                status__in=["pending", "running", "retry"],
            ).exists():
                job = OutboxJob.objects.create(
                    kind="ad_observe",
                    desired={
                        "caseId": str(current.pk),
                        "identityId": str(current.identity_id),
                        "binding": current.ad_binding,
                    },
                    available_at=timezone.now(),
                )
                audit.append(
                    a,
                    "departure.directory_observation_requested",
                    current.pk,
                    {"jobId": str(job.pk)},
                )
        else:
            close(a, current, data)
        current.revision += 1
        current.save()
        return {"result": assess(current)}, 200

    result, status = svc.mutation(
        actor,
        request.headers.get("Idempotency-Key"),
        f"departure.{operation}:{case_id}:{task_id or ''}",
        json_value(data),
        check,
        handle,
    )
    return Response(result, status=status)


@api_view(["GET"])
def packet(request, case_id):
    actor = actor_of(request)
    case = get_object_or_404(OffboardingCase, pk=case_id)
    case_scope(actor, case)
    if case.closed_at:
        return Response(case.closed_packet)
    return Response(
        {
            "schemaVersion": 1,
            "origin": "connected_case_draft",
            "case": assess(case),
            "limitations": LIMITATIONS,
        }
    )
