"""Entra-enrolled departure cases with the Graph connector replaced; synthetic IDs."""

from datetime import timedelta

import pytest
from core.management.commands import enroll_entra
from core.models import EntraEnrollment, OutboxJob, Principal
from core.offboarding import assess
from core.worker import process_one
from django.conf import settings
from django.core.management import CommandError, call_command
from django.utils import timezone
from tests.test_offboarding_cases import PREFIX, complete_case, create_case, post

from integrations.errors import ConnectorError

pytestmark = pytest.mark.django_db
TENANT = "11111111-1111-4111-8111-111111111111"
USER = "33333333-3333-4333-8333-333333333333"
GROUP = "55555555-5555-4555-8555-555555555555"
BINDING = {"tenantId": TENANT, "userId": USER, "groupIds": [GROUP]}


def enroll(identity):
    return EntraEnrollment.objects.create(
        identity=identity, tenant_id=TENANT, user_id=USER, group_ids=[GROUP]
    )


def reading(**changes):
    value = {
        "provider": "entra",
        "tenantId": TENANT,
        "userId": USER,
        "active": False,
        "privileged": False,
        "groups": [{"groupId": GROUP, "member": False}],
        "sessionsValidFrom": timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    value.update(changes)
    return value


class FakeEntra:
    def __init__(self, observed=None):
        self.observed, self.calls = observed or reading(), []

    def offboard(self, binding, not_before):
        self.calls.append(("offboard", binding, not_before))
        return {"verified": True, "observed": dict(self.observed)}

    def validate_binding(self, binding):
        self.calls.append(("observe", binding))
        return dict(self.observed)

    def close(self):
        pass


def entra_task(case):
    return next(t for t in assess(case)["tasks"] if t["id"] == "entra-directory")


def only_entra_jobs_pending():
    OutboxJob.objects.exclude(kind__startswith="entra_").filter(
        status__in=["pending", "retry"]
    ).update(status="cancelled")


def test_binding_is_frozen_on_the_case_and_containment_queues_one_job(org, client_for):
    enroll(org["sponsor"])
    owner = client_for(org["alice"])
    case = create_case(org, owner)
    assert case.entra_binding == BINDING and assess(case)["entraBinding"] == BINDING
    post(owner, f"{PREFIX}/{case.pk}/contain")
    post(owner, f"{PREFIX}/{case.pk}/contain")
    (job,) = OutboxJob.objects.filter(kind="entra_offboard", desired__caseId=str(case.pk))
    assert job.desired == {
        "caseId": str(case.pk),
        "identityId": str(case.identity_id),
        "binding": BINDING,
    }


def test_a_verified_graph_reading_is_provider_evidence_and_imports_no_longer_count(org, client_for):
    enroll(org["sponsor"])
    case = complete_case(org, client_for(org["alice"]))
    # complete_case imported a snapshot with accountEnabled:false; bound cases need Graph.
    assert entra_task(case)["status"] == "pending"
    only_entra_jobs_pending()
    fake = FakeEntra()
    assert process_one(fake)
    assert fake.calls[0][0] == "offboard" and fake.calls[0][2] == case.effective_at
    job = OutboxJob.objects.get(kind="entra_offboard", desired__caseId=str(case.pk))
    assert job.status == "verified" and "observedAt" in job.observed
    task = entra_task(case)
    assert task["status"] == "observed" and task["evidenceKind"] == "provider_observation"
    assert "Microsoft Graph read back" in task["evidenceSummary"]


@pytest.mark.parametrize(
    "changes",
    [
        {"sessionsValidFrom": "2020-01-01T00:00:00Z"},
        {"groups": [{"groupId": GROUP, "member": True}]},
        {"active": True},
        {"privileged": True},
        {"sessionsValidFrom": None},
    ],
    ids=["revoked-before-departure", "still-member", "enabled", "privileged", "never-revoked"],
)
def test_a_reading_that_does_not_prove_containment_never_verifies(org, client_for, changes):
    enroll(org["sponsor"])
    case = complete_case(org, client_for(org["alice"]))
    only_entra_jobs_pending()
    # The connector claims success, but the worker re-checks the reading itself.
    assert process_one(FakeEntra(reading(**changes)))
    job = OutboxJob.objects.get(kind="entra_offboard", desired__caseId=str(case.pk))
    assert job.status == "retry"
    assert entra_task(case)["status"] == "pending"


def test_the_owner_cannot_attest_a_bound_entra_task(org, client_for):
    enroll(org["sponsor"])
    owner = client_for(org["alice"])
    case = complete_case(org, owner)
    response = post(
        owner,
        f"{PREFIX}/{case.pk}/tasks/entra-directory/attest",
        {"reference": "ENTRA-0001", "summary": "Owner statements cannot replace Graph readings."},
    )
    assert response.status_code == 409


def test_a_job_cannot_be_retargeted_to_another_user(org, client_for):
    enroll(org["sponsor"])
    case = complete_case(org, client_for(org["alice"]))
    only_entra_jobs_pending()
    job = OutboxJob.objects.get(kind="entra_offboard", desired__caseId=str(case.pk))
    job.desired = {**job.desired, "binding": {**BINDING, "userId": GROUP}}
    job.save()
    fake = FakeEntra()
    assert process_one(fake)
    assert fake.calls == []
    job.refresh_from_db()
    assert job.status in ("retry", "failed")


def test_refresh_queues_a_read_only_entra_observation(org, client_for):
    enroll(org["sponsor"])
    owner = client_for(org["alice"])
    case = complete_case(org, owner)
    only_entra_jobs_pending()
    process_one(FakeEntra())
    assert post(owner, f"{PREFIX}/{case.pk}/observe-directory").status_code == 200
    job = OutboxJob.objects.get(kind="entra_observe", desired__caseId=str(case.pk))
    fake = FakeEntra()
    assert process_one(fake)
    assert [call[0] for call in fake.calls] == ["observe"]
    job.refresh_from_db()
    assert job.status == "verified"


class EnrollEntra(FakeEntra):
    config = {"tenantId": TENANT}

    def __init__(self, observed=None, refuse=False):
        super().__init__(
            observed or reading(active=True, groups=[{"groupId": GROUP, "member": True}])
        )
        self.refuse = refuse

    def validate_binding(self, binding):
        if self.refuse:
            raise ConnectorError("Entra object outside the connector's scope")
        return super().validate_binding(binding)


def workforce_human(org, label):
    """A fresh, enrollable workforce identity: active, bound, no roles, no case."""
    return Principal.objects.create(
        issuer=settings.WORKFORCE_ISSUER,
        subject=f"entra-{label}-" + timezone.now().strftime("%H%M%S%f"),
        kind="human",
        name="Synthetic " + label.title(),
        email=label + "@fixture.test",
        status="active",
        project_ids=org["sponsor"].project_ids,
    )


def enroll_command(identity, connector, monkeypatch):
    monkeypatch.setattr(enroll_entra, "EntraConnector", lambda: connector)
    call_command("enroll_entra", identity_id=str(identity.pk), user_id=USER, group_id=[GROUP])


def test_enrollment_records_an_exact_binding_for_an_active_test_user(org, monkeypatch):
    person = workforce_human(org, "leaver")
    enroll_command(person, EnrollEntra(), monkeypatch)
    assert EntraEnrollment.objects.get(identity=person).binding == BINDING


@pytest.mark.parametrize(
    "connector",
    [
        EnrollEntra(refuse=True),
        EnrollEntra(reading(active=False, groups=[{"groupId": GROUP, "member": True}])),
        EnrollEntra(reading(active=True)),
    ],
    ids=["outside-scope-or-protected", "disabled", "not-in-group"],
)
def test_enrollment_is_refused_without_changing_anything(org, monkeypatch, connector):
    with pytest.raises(CommandError):
        enroll_command(workforce_human(org, "refused"), connector, monkeypatch)
    assert not EntraEnrollment.objects.exists()


def test_a_test_user_is_reused_only_after_its_earlier_identity_is_offboarded(org, monkeypatch):
    first, later = workforce_human(org, "first"), workforce_human(org, "rehire")
    enroll_command(first, EnrollEntra(), monkeypatch)
    with pytest.raises(CommandError):
        enroll_command(later, EnrollEntra(), monkeypatch)
    Principal.objects.filter(pk=first.pk).update(status="offboarded")
    enroll_command(later, EnrollEntra(), monkeypatch)
    assert EntraEnrollment.objects.filter(user_id=USER).count() == 2


def test_containment_waits_for_an_effective_departure(org, client_for):
    enroll(org["sponsor"])
    owner = client_for(org["alice"])
    case = create_case(org, owner, effectiveAt=(timezone.now() + timedelta(hours=1)).isoformat())
    assert post(owner, f"{PREFIX}/{case.pk}/contain").status_code == 409
    assert not OutboxJob.objects.filter(kind="entra_offboard").exists()
