import copy
import secrets
from datetime import timedelta
from uuid import uuid4

import pytest
from core import audit
from core.models import (
    ADEnrollment,
    AuditEvent,
    Grant,
    OffboardingCase,
    OutboxJob,
    PlatformImport,
    Principal,
)
from core.offboarding import TASKS, assess
from django.utils import timezone

pytestmark = pytest.mark.django_db
PREFIX = "/api/v1/offboarding-cases"
BINDING = {
    "provider": "entra",
    "tenantId": "11111111-1111-4111-8111-111111111111",
    "subjectId": "22222222-2222-4222-8222-222222222222",
}


def post(client, path, data=None):
    return client.post(path, data or {}, format="json", HTTP_IDEMPOTENCY_KEY=secrets.token_hex(12))


def create_case(org, client, **extra):
    response = post(
        client,
        PREFIX,
        {
            "identityId": str(org["sponsor"].pk),
            "employmentType": "contractor",
            "hrEventId": "HR-TEST-" + secrets.token_hex(4),
            "hrSource": "Synthetic HR export",
            "effectiveAt": (timezone.now() - timedelta(minutes=15)).isoformat(),
            "reason": "Contract engagement ended; close all scoped access work.",
            "bindings": [BINDING],
            **extra,
        },
    )
    assert response.status_code == 201, response.data
    return OffboardingCase.objects.get(pk=response.data["result"]["id"])


def report(value=False, at=None):
    at = at or timezone.now()
    return {
        "schemaVersion": 1,
        "collectionMethod": "synthetic_fixture",
        "collectedAt": at.isoformat(),
        "observations": [
            {
                **BINDING,
                "observedAt": at.isoformat(),
                "capability": "account_enabled",
                "status": "observed",
                "value": value,
                "scope": "tenant-account",
                "reasonCode": "synthetic_account_read",
            }
        ],
        "limitations": ["Synthetic fixture; no tenant contacted."],
    }


def complete_case(org, client, **extra):
    case = create_case(org, client, **extra)
    assert post(client, f"{PREFIX}/{case.pk}/contain").status_code == 200
    case.refresh_from_db()
    # Isolated test of the persisted observation gate, not a live Keycloak run.
    OutboxJob.objects.filter(request=case.containment_request).update(
        status="verified", observed={"active": False, "observedAt": timezone.now().isoformat()}
    )
    job = OutboxJob.objects.get(request=case.containment_request)
    audit.append("worker", "provider.verified", case.containment_request_id, {"jobId": str(job.pk)})
    for removal in OutboxJob.objects.filter(
        kind="entitlement_revoke", desired__containmentRequestId=str(case.containment_request_id)
    ):
        removal.status, removal.observed = (
            "verified",
            {"member": False, "observedAt": timezone.now().isoformat()},
        )
        removal.save()
        audit.append("worker", "provider.verified", removal.pk, {"jobId": str(removal.pk)})
    assert post(client, f"{PREFIX}/{case.pk}/import", {"report": report()}).status_code == 200
    for key, *_ in TASKS:
        if key not in ("local-containment", "keycloak-directory", "entra-directory"):
            response = post(
                client,
                f"{PREFIX}/{case.pk}/tasks/{key}/attest",
                {
                    "reference": "TASK-TEST-001",
                    "summary": "Synthetic owner confirms scoped action and records remaining limitations.",
                },
            )
            assert response.status_code == 200, response.data
    case.refresh_from_db()
    return case


def close_input(case):
    value = assess(case)
    return {"expectedRevision": value["revision"], "packetHash": value["packetHash"]}


def test_departure_case_contains_sponsor_and_keeps_cloud_work_pending(org, client_for):
    client = client_for(org["alice"])
    case = create_case(org, client)
    response = post(client, f"{PREFIX}/{case.pk}/contain")
    assert response.status_code == 200
    org["sponsor"].refresh_from_db()
    org["agent"].refresh_from_db()
    assert org["sponsor"].status == "offboarded" and org["agent"].status == "suspended"
    tasks = {t["id"]: t for t in response.data["result"]["tasks"]}
    assert tasks["local-containment"]["status"] == "observed"
    assert tasks["keycloak-directory"]["status"] == "pending"
    assert tasks["entra-sessions"]["status"] == "pending"
    assert (
        post(
            client,
            f"{PREFIX}/{case.pk}/tasks/keycloak-directory/attest",
            {
                "reference": "TASK-00101",
                "summary": "An owner cannot replace actual provider observation.",
            },
        ).status_code
        == 409
    )


def test_offboard_queues_each_backed_remote_membership_once_including_sponsored_agents(
    org, client_for
):
    for permission in ("read", "write"):
        Grant.objects.create(
            identity=org["agent"],
            resource=org["atlas"],
            permission=permission,
            purpose="Isolated backed grant fixture",
        )
    involved = [org["sponsor"].pk, org["agent"].pk]
    expected = set(
        Grant.objects.filter(identity_id__in=involved, status="active").values_list(
            "identity_id", "resource_id"
        )
    )
    owner = client_for(org["alice"])
    case = create_case(org, owner)
    assert post(owner, f"{PREFIX}/{case.pk}/contain").status_code == 200
    case.refresh_from_db()
    jobs = list(
        OutboxJob.objects.filter(
            kind="entitlement_revoke",
            desired__containmentRequestId=str(case.containment_request_id),
        )
    )
    assert len(jobs) == len(expected)
    assert {(j.desired["identityId"], j.desired["resourceId"]) for j in jobs} == {
        (str(identity), str(resource)) for identity, resource in expected
    }
    assert all(
        j.status == "pending" and j.request_id is None and j.desired["action"] == "revoke"
        for j in jobs
    )
    assert not Grant.objects.filter(identity_id__in=involved, status="active").exists()
    assert post(owner, f"{PREFIX}/{case.pk}/contain").status_code == 200
    assert OutboxJob.objects.filter(
        kind="entitlement_revoke", desired__containmentRequestId=str(case.containment_request_id)
    ).count() == len(expected)


def test_directory_account_proof_cannot_replace_membership_removal_and_reconciliation_refreshes_it(
    org, client_for
):
    case = complete_case(org, client_for(org["alice"]))
    removal = OutboxJob.objects.get(
        kind="entitlement_revoke", desired__containmentRequestId=str(case.containment_request_id)
    )
    removal.status = "failed"
    removal.observed = {"member": True, "observedAt": timezone.now().isoformat()}
    removal.save()
    audit.append("worker", "provider.failed", removal.pk, {"jobId": str(removal.pk)})
    assert keycloak_task(case)["status"] == "pending"
    refresh = OutboxJob.objects.create(
        kind="reconcile",
        status="verified",
        desired={"projects": ["Pulse"]},
        available_at=timezone.now(),
        observed={
            "observations": [
                {
                    "identityId": str(case.identity_id),
                    "resourceId": str(org["pulse"].pk),
                    "status": "observed",
                    "observedAt": timezone.now().isoformat(),
                    "observed": {"active": False, "member": False},
                }
            ]
        },
    )
    audit.append("worker", "provider.verified", refresh.pk, {"jobId": str(refresh.pk)})
    assert keycloak_task(case)["status"] == "observed"


def test_second_departure_cannot_hide_unresolved_previously_revoked_membership(org, client_for):
    owner = client_for(org["alice"])
    first = complete_case(org, owner)
    removal = OutboxJob.objects.get(
        kind="entitlement_revoke", desired__containmentRequestId=str(first.containment_request_id)
    )
    removal.status, removal.observed = (
        "failed",
        {"member": True, "observedAt": timezone.now().isoformat()},
    )
    removal.save()
    audit.append("worker", "provider.failed", removal.pk, {"jobId": str(removal.pk)})
    second = create_case(org, owner)
    assert post(owner, f"{PREFIX}/{second.pk}/contain").status_code == 200
    second.refresh_from_db()
    assert (
        OutboxJob.objects.filter(
            kind="entitlement_revoke",
            desired__containmentRequestId=str(second.containment_request_id),
        ).count()
        == 1
    )
    native = OutboxJob.objects.get(request=second.containment_request)
    native.status, native.observed = (
        "verified",
        {"active": False, "observedAt": timezone.now().isoformat()},
    )
    native.save()
    audit.append(
        "worker", "provider.verified", second.containment_request_id, {"jobId": str(native.pk)}
    )
    assert keycloak_task(second)["status"] == "pending"


def test_old_contained_case_without_removal_jobs_requires_current_membership_observation(
    org, client_for
):
    case = complete_case(org, client_for(org["alice"]))
    # Isolated pre-extension persisted-state fixture, not application cleanup.
    OutboxJob.objects.filter(
        kind="entitlement_revoke", desired__containmentRequestId=str(case.containment_request_id)
    ).delete()
    assert keycloak_task(case)["status"] == "pending"


def test_service_account_membership_revoke_does_not_depend_on_user_visibility(org, client_for):
    from unittest.mock import Mock

    from core.worker import process_one

    from integrations.errors import ConnectorError
    from integrations.keycloak import GROUP, KeycloakConnector

    Grant.objects.create(
        identity=org["agent"],
        resource=org["atlas"],
        permission="read",
        purpose="Isolated backed service-account membership",
    )
    case = complete_case(org, client_for(org["alice"]))
    job = OutboxJob.objects.get(
        kind="entitlement_revoke",
        desired__containmentRequestId=str(case.containment_request_id),
        desired__identityId=str(org["agent"].pk),
    )
    OutboxJob.objects.exclude(pk=job.pk).update(status="cancelled")
    job.status, job.available_at = "pending", timezone.now()
    job.save()
    connector = KeycloakConnector(
        http=Mock(), issuer="https://id.accessops.test/realms/accessops-workforce"
    )
    member = org["agent"].subject
    group_id = org["atlas"].provider_group
    members = [{"value": member}]
    writes = []

    def call(method, path, **kwargs):
        if path.startswith("/Users/"):
            raise ConnectorError("Isolated service-account user is unobservable")
        assert path == "/Groups/" + group_id
        if method == "PATCH":
            assert kwargs["body"]["Operations"][0]["op"] == "remove"
            writes.append(path)
            members.clear()
        return {
            "schemas": [GROUP],
            "id": group_id,
            "displayName": "accessops-atlas-reader",
            "members": list(members),
        }

    connector._call = call
    assert process_one(connector)
    job.refresh_from_db()
    assert job.status == "verified" and job.observed["member"] is False
    assert writes == ["/Groups/" + group_id]
    job.status, job.available_at = "pending", timezone.now()
    job.save()
    assert process_one(connector)
    job.refresh_from_db()
    assert job.status == "verified" and len(writes) == 1


@pytest.mark.parametrize("unsafe", ["positive", "missing", "unknown", "tie"])
def test_latest_pair_unknown_positive_or_conflicting_tie_reopens_membership_gate(
    org, client_for, unsafe
):
    case = complete_case(org, client_for(org["alice"]))
    removal = OutboxJob.objects.get(
        kind="entitlement_revoke", desired__containmentRequestId=str(case.containment_request_id)
    )
    at = removal.observed["observedAt"] if unsafe == "tie" else timezone.now().isoformat()
    row = {
        "identityId": str(case.identity_id),
        "resourceId": str(org["pulse"].pk),
        "status": "unavailable" if unsafe == "unknown" else "observed",
        "observedAt": at,
        "observed": {"active": False},
    }
    if unsafe in ("positive", "tie"):
        row["observed"]["member"] = True
    refresh = OutboxJob.objects.create(
        kind="reconcile",
        status="failed",
        desired={"projects": ["Pulse"]},
        available_at=timezone.now(),
        observed={"observations": [row]},
    )
    audit.append("worker", "provider.failed", refresh.pk, {"jobId": str(refresh.pk)})
    assert keycloak_task(case)["status"] == "pending"


def test_transferred_sponsor_retains_agent_history_scope_for_departure(org, client_for):
    from core import enrollment, services
    from django.conf import settings

    human = Principal.objects.create(
        issuer=settings.WORKFORCE_ISSUER,
        subject=str(uuid4()),
        name="Synthetic department mover",
        kind="human",
        department="Engineering",
        project_ids=["Atlas"],
        roles=[],
    )
    agent = Principal.objects.create(
        issuer=settings.WORKFORCE_ISSUER,
        subject=str(uuid4()),
        name="Synthetic sponsored agent",
        kind="agent",
        department="Engineering",
        project_ids=["Atlas"],
        sponsor=human,
        roles=[],
    )
    grant = Grant.objects.create(
        identity=agent,
        resource=org["atlas"],
        permission="read",
        purpose="Legitimate transfer-history fixture",
    )
    change = enrollment.request_department_transfer(
        org["alice"],
        human,
        {"department": "Operations", "reason": "Approved transfer from Engineering to Operations."},
    )
    services.approve(org["clara"], change)
    change.refresh_from_db()
    services.execute(org["alice"], change)
    human.refresh_from_db()
    grant.refresh_from_db()
    assert human.project_ids == ["Pulse"] and grant.status == "revoked"
    org["bob"].project_ids = ["Pulse"]
    org["bob"].save(update_fields=["project_ids"])
    limited = client_for(org["bob"])
    before = OutboxJob.objects.count()
    denied = post(
        limited,
        PREFIX,
        {
            "identityId": str(human.pk),
            "employmentType": "employee",
            "hrEventId": "HR-MOVED-0001",
            "hrSource": "Synthetic HR",
            "effectiveAt": timezone.now().isoformat(),
            "reason": "Departure after approved department transfer.",
            "bindings": [],
        },
    )
    assert denied.status_code == 403 and OutboxJob.objects.count() == before
    full = client_for(org["alice"])
    case = create_case({**org, "sponsor": human}, full)
    assert post(limited, f"{PREFIX}/{case.pk}/contain").status_code == 403
    assert human.status == "active" and OutboxJob.objects.count() == before
    assert limited.get(f"{PREFIX}/{case.pk}/packet").status_code == 403
    assert not any(
        c["id"] == str(case.pk) for c in limited.get("/api/v1/snapshot").data["offboardingCases"]
    )
    assert post(full, f"{PREFIX}/{case.pk}/contain").status_code == 200


def test_snapshot_is_imported_evidence_and_requires_current_exact_account(org, client_for):
    client = client_for(org["alice"])
    case = create_case(org, client)
    value = report()
    response = post(client, f"{PREFIX}/{case.pk}/import", {"report": value})
    assert response.status_code == 200
    task = next(t for t in response.data["result"]["tasks"] if t["id"] == "entra-directory")
    assert task["status"] == "observed" and task["evidenceKind"] == "imported_snapshot"
    assert (
        PlatformImport.objects.get(case=case).sha256
        == response.data["result"]["imports"][0]["sha256"]
    )
    value["observations"][0]["subjectId"] = "33333333-3333-4333-8333-333333333333"
    assert post(client, f"{PREFIX}/{case.pk}/import", {"report": value}).status_code == 409
    assert case.platform_imports.count() == 1


@pytest.mark.parametrize(
    "change",
    ["future", "duplicate", "malformed_date", "coerced_bool", "secret_field", "wrong_capability"],
)
def test_malformed_report_denies_without_partial_import(org, client_for, change):
    client = client_for(org["alice"])
    case = create_case(org, client)
    value = report()
    if change == "future":
        value = report(at=timezone.now() + timedelta(hours=1))
    elif change == "duplicate":
        value["observations"].append(copy.deepcopy(value["observations"][0]))
    elif change == "malformed_date":
        value["collectedAt"] = "2026-99-99T99:00:00Z"
    elif change == "coerced_bool":
        value["observations"][0]["value"] = "false"
    elif change == "secret_field":
        value["observations"][0]["authorization"] = "NONFUNCTIONAL_TEST_PLACEHOLDER"
    else:
        value["observations"][0]["capability"] = "organization_membership"
    assert post(client, f"{PREFIX}/{case.pk}/import", {"report": value}).status_code == 400
    assert not case.platform_imports.exists()


@pytest.mark.parametrize("mode", ["unknown", "stale", "before_departure"])
def test_unknown_or_old_reading_cannot_complete_observed_task(org, client_for, mode):
    client = client_for(org["alice"])
    case = create_case(org, client)
    value = report(
        at=timezone.now() - timedelta(hours=3)
        if mode == "stale"
        else timezone.now() - timedelta(minutes=30)
        if mode == "before_departure"
        else timezone.now()
    )
    if mode == "unknown":
        value["observations"][0].update(status="unknown", value=None)
    response = post(client, f"{PREFIX}/{case.pk}/import", {"report": value})
    assert response.status_code == 200
    task = next(t for t in response.data["result"]["tasks"] if t["id"] == "entra-directory")
    assert task["status"] == "pending"


def test_later_disabled_reading_supersedes_old_positive_and_import_resets_attestations(
    org, client_for
):
    client = client_for(org["alice"])
    case = create_case(org, client)
    before = report(True, timezone.now() - timedelta(minutes=1))
    assert post(client, f"{PREFIX}/{case.pk}/import", {"report": before}).status_code == 200
    assert (
        post(
            client,
            f"{PREFIX}/{case.pk}/tasks/entra-sessions/attest",
            {
                "reference": "TASK-SESSION-01",
                "summary": "Owner records the session handoff and explains the remaining application boundary.",
            },
        ).status_code
        == 200
    )
    response = post(client, f"{PREFIX}/{case.pk}/import", {"report": report(False)})
    assert response.status_code == 200
    assert not any("Residual entra" in b for b in response.data["result"]["blockers"])
    assert (
        next(t for t in response.data["result"]["tasks"] if t["id"] == "entra-sessions")["status"]
        == "pending"
    )


def test_future_departure_cannot_contain_or_attest(org, client_for):
    client = client_for(org["alice"])
    case = create_case(org, client, effectiveAt=(timezone.now() + timedelta(days=1)).isoformat())
    assert post(client, f"{PREFIX}/{case.pk}/contain").status_code == 409
    assert (
        post(
            client,
            f"{PREFIX}/{case.pk}/tasks/entra-sessions/attest",
            {
                "reference": "TASK-FUTURE-1",
                "summary": "Future completed work cannot be asserted before the departure.",
            },
        ).status_code
        == 409
    )
    org["sponsor"].refresh_from_db()
    assert org["sponsor"].status == "active"


def test_scope_owner_and_policy_denials_apply_to_case_and_packet(org, client_for, monkeypatch):
    client = client_for(org["alice"])
    case = create_case(org, client)
    org["clara"].project_ids = ["Atlas"]
    org["clara"].save(update_fields=["project_ids"])
    other = client_for(org["clara"])
    assert other.get(f"{PREFIX}/{case.pk}/packet").status_code == 403
    assert all(
        v["id"] != str(case.pk) for v in other.get("/api/v1/snapshot").data["offboardingCases"]
    )
    assert (
        post(
            client_for(org["bob"]),
            f"{PREFIX}/{case.pk}/tasks/entra-sessions/attest",
            {
                "reference": "TASK-WRONGOWNER",
                "summary": "A different operator cannot assert work as the assigned owner.",
            },
        ).status_code
        == 403
    )
    monkeypatch.setattr("integrations.policy.evaluate", lambda _: {"allow": False})
    assert post(client, f"{PREFIX}/{case.pk}/contain").status_code == 403
    assert not case.containment_request_id


def test_independent_closure_is_exact_and_frozen(org, client_for):
    owner = client_for(org["alice"])
    case = complete_case(org, owner)
    assert assess(case)["blockers"] == []
    assert post(owner, f"{PREFIX}/{case.pk}/close", close_input(case)).status_code == 403
    reviewer = client_for(org["clara"])
    stale = close_input(case)
    stale["expectedRevision"] -= 1
    assert post(reviewer, f"{PREFIX}/{case.pk}/close", stale).status_code == 409
    correct = close_input(case)
    response = post(reviewer, f"{PREFIX}/{case.pk}/close", correct)
    assert response.status_code == 200, response.data
    packet = reviewer.get(f"{PREFIX}/{case.pk}/packet").data
    assert (
        packet["case"]["status"] == "closed"
        and packet["reviewedInputHash"] == correct["packetHash"]
    )
    original_hash = packet["case"].pop("packetHash")
    assert audit.digest(packet) == original_hash
    assert post(owner, f"{PREFIX}/{case.pk}/import", {"report": report()}).status_code == 409
    case.refresh_from_db()
    assert (
        AuditEvent.objects.get(action="departure.closed").detail["revision"]
        == case.revision
        == response.data["result"]["revision"]
    )
    case.reason = "An attempt to change the closed packet"
    with pytest.raises(ValueError, match="immutable"):
        case.save()
    assert audit.verify_chain()


def test_incomplete_case_cannot_close_or_approve_its_own_departure(org, client_for):
    owner = client_for(org["alice"])
    case = create_case(org, owner)
    assert (
        post(client_for(org["clara"]), f"{PREFIX}/{case.pk}/close", close_input(case)).status_code
        == 409
    )
    response = post(
        owner,
        PREFIX,
        {
            "identityId": str(org["employee"].pk),
            "employmentType": "employee",
            "hrEventId": "HR-SELF-0001",
            "hrSource": "Synthetic HR",
            "effectiveAt": timezone.now().isoformat(),
            "reason": "The departing person cannot own the closure work.",
            "bindings": [],
        },
    )
    assert response.status_code == 403


def test_conflicting_entra_scopes_do_not_complete_directory_task(org, client_for):
    client = client_for(org["alice"])
    case = create_case(org, client)
    value = report()
    conflict = copy.deepcopy(value["observations"][0])
    conflict.update(scope="another-tenant-account", value=True)
    value["observations"].append(conflict)
    response = post(client, f"{PREFIX}/{case.pk}/import", {"report": value})
    task = next(t for t in response.data["result"]["tasks"] if t["id"] == "entra-directory")
    assert task["status"] == "pending"
    assert any("Residual entra" in b for b in response.data["result"]["blockers"])


def test_keycloak_proof_expires_and_later_unknown_or_positive_reopens(org, client_for):
    client = client_for(org["alice"])
    case = complete_case(org, client)

    def keycloak():
        return next(t for t in assess(case)["tasks"] if t["id"] == "keycloak-directory")

    assert keycloak()["status"] == "observed"
    # Deliberate isolated stale persisted-event fixture, not a provider measurement.
    AuditEvent.objects.filter(action="provider.verified").update(
        at=timezone.now() - timedelta(hours=3)
    )
    assert keycloak()["status"] == "pending"
    job = OutboxJob.objects.create(
        kind="reconcile",
        available_at=timezone.now(),
        status="failed",
        desired={"projects": ["Pulse"]},
        observed={
            "observations": [
                {
                    "identityId": str(case.identity_id),
                    "resourceId": str(org["pulse"].pk),
                    "status": "observed",
                    "observedAt": timezone.now().isoformat(),
                    "observed": {"active": False, "member": False},
                },
                {
                    "identityId": "different-unavailable-identity",
                    "status": "unavailable",
                    "observed": {},
                },
            ]
        },
    )
    audit.append("worker", "provider.failed", job.pk, {"jobId": str(job.pk)})
    assert keycloak()["status"] == "observed"
    job.observed["observations"][0] = {
        "identityId": str(case.identity_id),
        "status": "unavailable",
        "observed": {},
    }
    job.save()
    audit.append("worker", "provider.retry", job.pk, {"jobId": str(job.pk)})
    assert keycloak()["status"] == "pending"
    job.observed["observations"][0] = {
        "identityId": str(case.identity_id),
        "status": "observed",
        "observed": {"active": True},
    }
    job.save()
    audit.append("worker", "provider.failed", job.pk, {"jobId": str(job.pk)})
    assert keycloak()["status"] == "pending"
    job.observed["observations"][0] = {
        "identityId": str(case.identity_id),
        "status": "observed",
        "observed": {"active": False},
    }
    job.save()
    audit.append("worker", "job.failed", job.pk, {"jobId": str(job.pk)})
    assert keycloak()["status"] == "pending"


def test_case_api_requires_session_csrf_and_operation_bound_idempotency(org, client_for):
    from rest_framework.test import APIClient

    assert APIClient().post(PREFIX, {}, format="json").status_code == 403
    owner = client_for(org["alice"])
    case = create_case(org, owner)
    protected = client_for(org["alice"], csrf=True)
    assert post(protected, f"{PREFIX}/{case.pk}/contain").status_code == 403
    path = f"{PREFIX}/{case.pk}/import"
    key = "case-idempotency-regression-0001"
    value = {"report": report()}
    first = owner.post(path, value, format="json", HTTP_IDEMPOTENCY_KEY=key)
    replay = owner.post(path, value, format="json", HTTP_IDEMPOTENCY_KEY=key)
    assert first.status_code == replay.status_code == 200 and first.data == replay.data
    changed = {"report": report(True)}
    assert owner.post(path, changed, format="json", HTTP_IDEMPOTENCY_KEY=key).status_code == 409
    assert case.platform_imports.count() == 1


AD_BINDING = {
    "domainGuid": "44444444-4444-4444-8444-444444444444",
    "userGuid": "55555555-5555-4555-8555-555555555555",
    "groupGuids": ["66666666-6666-4666-8666-666666666666"],
}


def enroll_directory(org):
    return ADEnrollment.objects.create(
        identity=org["sponsor"],
        domain_guid=AD_BINDING["domainGuid"],
        user_guid=AD_BINDING["userGuid"],
        group_guids=AD_BINDING["groupGuids"],
    )


def observed_directory(case):
    job = OutboxJob.objects.get(kind="ad_offboard", desired__caseId=str(case.pk))
    job.status = "verified"
    job.observed = {
        "provider": "samba_ad",
        "domainGuid": AD_BINDING["domainGuid"],
        "userGuid": AD_BINDING["userGuid"],
        "active": False,
        "observedAt": timezone.now().isoformat(),
        "groups": [{"groupGuid": AD_BINDING["groupGuids"][0], "member": False}],
    }
    job.save()
    audit.append("worker", "provider.verified", job.pk, {"jobId": str(job.pk)})
    return job


def directory_task(case):
    return next(t for t in assess(case)["tasks"] if t["id"] == "ad-directory")


def test_directory_binding_is_server_enrolled_and_containment_job_is_frozen(org, client_for):
    owner = client_for(org["alice"])
    enrollment = enroll_directory(org)
    response = post(
        owner,
        PREFIX,
        {
            "identityId": str(org["sponsor"].pk),
            "employmentType": "contractor",
            "hrEventId": "HR-DIRECTORY-01",
            "hrSource": "Synthetic HR",
            "effectiveAt": timezone.now().isoformat(),
            "reason": "Client AD retarget must not grant directory authority.",
            "bindings": [],
            "adBinding": AD_BINDING,
        },
    )
    assert response.status_code == 400
    case = create_case(org, owner)
    assert case.ad_binding == enrollment.binding
    assert directory_task(case)["status"] == "pending"
    post(owner, f"{PREFIX}/{case.pk}/contain")
    post(owner, f"{PREFIX}/{case.pk}/contain")
    assert OutboxJob.objects.filter(kind="ad_offboard", desired__caseId=str(case.pk)).count() == 1
    job = OutboxJob.objects.get(kind="ad_offboard", desired__caseId=str(case.pk))
    assert job.desired == {
        "caseId": str(case.pk),
        "identityId": str(case.identity_id),
        "binding": enrollment.binding,
    }
    assert (
        post(
            owner,
            f"{PREFIX}/{case.pk}/tasks/ad-directory/attest",
            {
                "reference": "AD-TASK-0001",
                "summary": "Owner statements cannot override actual directory observation.",
            },
        ).status_code
        == 409
    )
    enrollment.group_guids = []
    with pytest.raises(ValueError, match="immutable"):
        enrollment.save()


@pytest.mark.parametrize(
    "invalid",
    ["domain", "user", "group", "missing_group", "duplicate_group", "enabled", "boolean_string"],
)
def test_directory_observation_requires_exact_complete_disabled_scope(org, client_for, invalid):
    owner = client_for(org["alice"])
    enroll_directory(org)
    case = complete_case(org, owner)
    job = observed_directory(case)
    assert directory_task(case)["status"] == "observed"
    if invalid == "domain":
        job.observed["domainGuid"] = "wrong-domain"
    elif invalid == "user":
        job.observed["userGuid"] = "wrong-user"
    elif invalid == "group":
        job.observed["groups"][0]["groupGuid"] = "wrong-group"
    elif invalid == "missing_group":
        job.observed["groups"] = []
    elif invalid == "duplicate_group":
        job.observed["groups"] *= 2
    elif invalid == "enabled":
        job.observed["active"] = True
    else:
        job.observed["groups"][0]["member"] = "false"
    job.save()
    assert directory_task(case)["status"] == "pending"
    assert (
        post(client_for(org["clara"]), f"{PREFIX}/{case.pk}/close", close_input(case)).status_code
        == 409
    )


def test_directory_refresh_is_read_only_and_supersedes_old_success(org, client_for):
    owner = client_for(org["alice"])
    enroll_directory(org)
    case = create_case(org, owner)
    assert post(owner, f"{PREFIX}/{case.pk}/observe-directory").status_code == 409
    assert post(owner, f"{PREFIX}/{case.pk}/contain").status_code == 200
    case.refresh_from_db()
    job = observed_directory(case)
    assert directory_task(case)["status"] == "observed"
    AuditEvent.objects.filter(target_id=str(job.pk), action="provider.verified").update(
        at=timezone.now() - timedelta(hours=3)
    )
    assert directory_task(case)["status"] == "pending"
    assert post(owner, f"{PREFIX}/{case.pk}/observe-directory").status_code == 200
    refreshed = OutboxJob.objects.get(kind="ad_observe", desired__caseId=str(case.pk))
    assert refreshed.request_id is None and refreshed.desired["binding"] == case.ad_binding
    assert directory_task(case)["status"] == "pending"
    refreshed.status, refreshed.observed = "failed", {}
    refreshed.save()
    assert directory_task(case)["status"] == "pending"


def keycloak_task(case):
    return next(t for t in assess(case)["tasks"] if t["id"] == "keycloak-directory")


@pytest.mark.parametrize("tie", [False, True])
def test_newer_positive_or_unsafe_tie_cannot_be_hidden_by_late_old_completion(org, client_for, tie):
    case = complete_case(org, client_for(org["alice"]))
    lifecycle = OutboxJob.objects.get(request=case.containment_request)
    old_at = timezone.now() - timedelta(minutes=2)
    later_at = old_at if tie else old_at + timedelta(minutes=1)
    lifecycle.observed["observedAt"] = old_at.isoformat()
    lifecycle.save()
    reconcile = OutboxJob.objects.create(
        kind="reconcile",
        status="failed",
        available_at=timezone.now(),
        desired={"projects": ["Atlas"]},
        observed={
            "observations": [
                {
                    "identityId": str(case.identity_id),
                    "resourceId": str(org["atlas"].pk),
                    "status": "observed",
                    "observedAt": later_at.isoformat(),
                    "observed": {"active": True},
                }
            ]
        },
    )
    audit.append("worker", "provider.failed", reconcile.pk, {"jobId": str(reconcile.pk)})
    # Old provider reading completes after the newer unsafe read.
    audit.append(
        "worker", "provider.verified", case.containment_request_id, {"jobId": str(lifecycle.pk)}
    )
    assert keycloak_task(case)["status"] == "pending"
    lifecycle.observed["observedAt"] = timezone.now().isoformat()
    lifecycle.save()
    audit.append(
        "worker", "provider.verified", case.containment_request_id, {"jobId": str(lifecycle.pk)}
    )
    assert keycloak_task(case)["status"] == "observed"


def test_late_audit_completion_does_not_refresh_an_expired_provider_read(org, client_for):
    owner = client_for(org["alice"])
    case = complete_case(org, owner, effectiveAt=(timezone.now() - timedelta(hours=4)).isoformat())
    job = OutboxJob.objects.get(request=case.containment_request)
    job.observed["observedAt"] = (timezone.now() - timedelta(hours=3)).isoformat()
    job.save()
    audit.append("worker", "provider.verified", case.containment_request_id, {"jobId": str(job.pk)})
    assert keycloak_task(case)["status"] == "pending"
    refresh = OutboxJob.objects.create(
        kind="reconcile",
        status="failed",
        available_at=timezone.now(),
        desired={"projects": ["Atlas", "Pulse"]},
        observed={
            "observations": [
                {
                    "identityId": str(case.identity_id),
                    "resourceId": str(org[resource].pk),
                    "status": "observed",
                    "observedAt": timezone.now().isoformat(),
                    "observed": {"active": False, "member": False},
                }
                for resource in ("atlas", "pulse")
            ]
        },
    )
    audit.append("worker", "provider.failed", refresh.pk, {"jobId": str(refresh.pk)})
    assert keycloak_task(case)["status"] == "observed"
    # A later failed attempt cannot borrow data retained from its older read.
    audit.append("worker", "job.failed", refresh.pk, {"jobId": str(refresh.pk)})
    assert keycloak_task(case)["status"] == "pending"


@pytest.mark.parametrize(
    "time_value", [None, "malformed", "2026-01-01T00:00:00", "future", "stale"]
)
def test_directory_missing_invalid_or_expired_read_time_never_verifies(org, client_for, time_value):
    enroll_directory(org)
    case = complete_case(org, client_for(org["alice"]))
    job = observed_directory(case)
    if time_value == "future":
        time_value = (timezone.now() + timedelta(minutes=1)).isoformat()
    elif time_value == "stale":
        time_value = (timezone.now() - timedelta(hours=3)).isoformat()
    job.observed["observedAt"] = time_value
    job.save()
    audit.append("worker", "provider.verified", job.pk, {"jobId": str(job.pk)})
    assert directory_task(case)["status"] == "pending"


def test_directory_actual_read_order_overrides_creation_and_completion_order(org, client_for):
    enroll_directory(org)
    case = complete_case(org, client_for(org["alice"]))
    older_job = observed_directory(case)
    old_at = timezone.now() - timedelta(minutes=2)
    older_job.observed.update(active=True, observedAt=(old_at + timedelta(minutes=1)).isoformat())
    older_job.status = "failed"
    older_job.save()
    audit.append("worker", "provider.failed", older_job.pk, {"jobId": str(older_job.pk)})
    later_job = OutboxJob.objects.create(
        kind="ad_observe",
        status="verified",
        desired=older_job.desired,
        available_at=timezone.now(),
        observed={**older_job.observed, "active": False, "observedAt": old_at.isoformat()},
    )
    audit.append("worker", "provider.verified", later_job.pk, {"jobId": str(later_job.pk)})
    assert directory_task(case)["status"] == "pending"
    older_job.observed["observedAt"] = old_at.isoformat()
    older_job.save()
    assert directory_task(case)["status"] == "pending"  # Unsafe tie also denies.


def test_directory_pending_health_and_case_audit_respect_project_scope(org, client_for):
    owner = client_for(org["alice"])
    enroll_directory(org)
    case = complete_case(org, owner)
    reviewer = client_for(org["clara"])
    visible = reviewer.get("/api/v1/snapshot").data
    assert (
        next(h for h in visible["health"] if h["name"] == "Provider synchronization")["detail"]
        == "1 jobs awaiting verification"
    )
    assert any(
        e["action"] == "departure.created" and e["targetId"] == str(case.pk)
        for e in visible["audit"]
    )
    org["clara"].project_ids = ["Unrelated"]
    org["clara"].save(update_fields=["project_ids"])
    hidden = reviewer.get("/api/v1/snapshot").data
    assert (
        next(h for h in hidden["health"] if h["name"] == "Provider synchronization")["status"]
        == "healthy"
    )
    assert not any(e["targetId"] == str(case.pk) for e in hidden["audit"])


def prepared_directory_worker(org, client_for):
    from unittest.mock import Mock

    enroll_directory(org)
    case = complete_case(org, client_for(org["alice"]))
    job = OutboxJob.objects.get(kind="ad_offboard", desired__caseId=str(case.pk))
    # Cancel unrelated fixture deliveries so this unit test exercises exactly
    # the scoped job; these are isolated database fixtures, not provider proof.
    OutboxJob.objects.exclude(pk=job.pk).update(status="cancelled")
    observed = {
        "provider": "samba_ad",
        "domainGuid": AD_BINDING["domainGuid"],
        "userGuid": AD_BINDING["userGuid"],
        "active": False,
        "groups": [{"groupGuid": AD_BINDING["groupGuids"][0], "member": False}],
    }
    connector = Mock()
    connector.offboard.return_value = {"verified": True, "observed": observed}
    connector.validate_binding.return_value = observed
    return case, job, connector


@pytest.mark.parametrize(
    "tamper", ["binding", "identity", "future", "active", "uncontained", "enrollment"]
)
def test_directory_worker_denies_retarget_and_invalid_local_state_before_effect(
    org, client_for, tamper
):
    from core.worker import process_one

    case, job, connector = prepared_directory_worker(org, client_for)
    if tamper == "binding":
        job.desired["binding"] = {**AD_BINDING, "userGuid": "77777777-7777-4777-8777-777777777777"}
        job.save()
    elif tamper == "identity":
        job.desired["identityId"] = str(org["employee"].pk)
        job.save()
    elif tamper == "future":
        OffboardingCase.objects.filter(pk=case.pk).update(
            effective_at=timezone.now() + timedelta(days=1)
        )
    elif tamper == "active":
        type(org["sponsor"]).objects.filter(pk=case.identity_id).update(status="active")
    elif tamper == "uncontained":
        OffboardingCase.objects.filter(pk=case.pk).update(containment_request=None)
    else:
        ADEnrollment.objects.filter(identity_id=case.identity_id).update(group_guids=[])
    assert process_one(connector)
    connector.offboard.assert_not_called()
    connector.validate_binding.assert_not_called()
    job.refresh_from_db()
    assert job.status == "retry" and job.last_error == "provider_outcome_unknown"


def test_directory_worker_observe_is_read_only_and_requires_complete_readback(org, client_for):
    from core.worker import process_one

    case, job, connector = prepared_directory_worker(org, client_for)
    job.kind = "ad_observe"
    job.save()
    assert process_one(connector)
    connector.offboard.assert_not_called()
    connector.validate_binding.assert_called_once_with(case.ad_binding)
    job.refresh_from_db()
    assert job.status == "verified" and job.observed["observedAt"]
    assert directory_task(case)["status"] == "observed"
    job.status, job.available_at = "pending", timezone.now()
    job.save()
    connector.validate_binding.return_value = {
        **connector.validate_binding.return_value,
        "groups": [],
    }
    assert process_one(connector)
    job.refresh_from_db()
    assert job.status == "retry" and directory_task(case)["status"] == "pending"


def test_directory_worker_rechecks_binding_after_remote_delivery(org, client_for):
    from core.worker import process_one

    case, job, connector = prepared_directory_worker(org, client_for)
    valid_result = connector.offboard.return_value

    def deliver(_):
        # Isolated race fixture: enrollment is not editable through the application.
        ADEnrollment.objects.filter(identity_id=case.identity_id).update(group_guids=[])
        return valid_result

    connector.offboard.side_effect = deliver
    assert process_one(connector)
    job.refresh_from_db()
    assert job.status == "retry" and job.last_error == "provider_outcome_unknown"
