import uuid

import pytest
from core import enrollment
from core.models import ChangeRequest, Grant, OutboxJob, Principal, Resource
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db


@pytest.fixture
def enrolled_actor():
    user = get_user_model().objects.create_user(username="enrollment-operator")
    return Principal.objects.create(
        user=user,
        issuer=settings.OIDC_ISSUER,
        subject="enrollment-operator",
        name="Enrollment operator",
        kind="human",
        status="active",
        roles=["operator", "approver"],
        project_ids=["Atlas", "Pulse"],
    )


@pytest.fixture
def enrollment_policy(monkeypatch):
    monkeypatch.setattr(
        "integrations.policy.evaluate",
        lambda data: {"allow": True, "policy_version": "accessops-v1", "reason": "allowed"},
    )


@pytest.fixture
def enrollment_client(enrolled_actor, enrollment_policy):
    client = APIClient()
    client.force_authenticate(enrolled_actor.user)
    return client


def body(**changes):
    return {
        "name": "Synthetic teammate",
        "email": "teammate@northstar.test",
        "kind": "human",
        "department": "Engineering",
        "projectIds": ["Atlas"],
        **changes,
    }


def test_registration_has_no_access_and_is_idempotent(enrollment_client):
    first = enrollment_client.post(
        "/api/v1/identities", body(), format="json", HTTP_IDEMPOTENCY_KEY="NONFUNCTIONAL_ENROLL_001"
    )
    second = enrollment_client.post(
        "/api/v1/identities", body(), format="json", HTTP_IDEMPOTENCY_KEY="NONFUNCTIONAL_ENROLL_001"
    )
    assert first.status_code == second.status_code == 201
    assert first.data == second.data
    identity = Principal.objects.get(pk=first.data["result"]["id"])
    assert identity.subject.startswith("pending:")
    assert identity.roles == []
    assert Grant.objects.filter(identity=identity).count() == 0
    assert OutboxJob.objects.filter(kind="enroll").count() == 1


def test_registration_rejects_role_injection(enrollment_client):
    result = enrollment_client.post(
        "/api/v1/identities",
        body(roles=["operator"]),
        format="json",
        HTTP_IDEMPOTENCY_KEY="NONFUNCTIONAL_ENROLL_002",
    )
    assert result.status_code == 400
    assert OutboxJob.objects.count() == 0


def test_registration_requires_operator_role(enrollment_client, enrolled_actor):
    enrolled_actor.roles = ["auditor"]
    enrolled_actor.save(update_fields=["roles"])
    result = enrollment_client.post(
        "/api/v1/identities", body(), format="json", HTTP_IDEMPOTENCY_KEY="NONFUNCTIONAL_ENROLL_003"
    )
    assert result.status_code == 403
    assert OutboxJob.objects.count() == 0


def test_registration_denies_cross_project(enrollment_client, enrolled_actor):
    enrolled_actor.project_ids = ["Atlas"]
    enrolled_actor.save(update_fields=["project_ids"])
    result = enrollment_client.post(
        "/api/v1/identities",
        body(department="Operations", projectIds=["Pulse"]),
        format="json",
        HTTP_IDEMPOTENCY_KEY="NONFUNCTIONAL_ENROLL_004",
    )
    assert result.status_code == 403


def test_reference_lab_rejects_nonsynthetic_email(enrollment_client):
    result = enrollment_client.post(
        "/api/v1/identities",
        body(email="person@real-domain.invalid"),
        format="json",
        HTTP_IDEMPOTENCY_KEY="NONFUNCTIONAL_ENROLL_005",
    )
    assert result.status_code == 400


def test_agent_registration_does_not_mint_credentials(enrollment_client):
    sponsor = Principal.objects.create(
        issuer=settings.WORKFORCE_ISSUER,
        subject="sponsor",
        name="Synthetic sponsor",
        kind="human",
        status="active",
        project_ids=["Atlas"],
    )
    result = enrollment_client.post(
        "/api/v1/identities",
        body(kind="agent", sponsorId=str(sponsor.pk)),
        format="json",
        HTTP_IDEMPOTENCY_KEY="NONFUNCTIONAL_ENROLL_006",
    )
    assert result.status_code == 201
    identity = Principal.objects.get(pk=result.data["result"]["id"])
    assert identity.status == "suspended" and identity.roles == []
    assert result.data["result"]["credentialBinding"] == "pending"


def test_inactive_sponsor_cannot_register_agent(enrollment_client):
    sponsor = Principal.objects.create(
        issuer=settings.WORKFORCE_ISSUER,
        subject="inactive-sponsor",
        name="Synthetic sponsor",
        kind="human",
        status="offboarded",
        project_ids=["Atlas"],
    )
    result = enrollment_client.post(
        "/api/v1/identities",
        body(kind="agent", sponsorId=str(sponsor.pk)),
        format="json",
        HTTP_IDEMPOTENCY_KEY="NONFUNCTIONAL_ENROLL_007",
    )
    assert result.status_code == 403
    assert OutboxJob.objects.count() == 0


def test_department_request_is_not_automatic_new_access(enrollment_client, enrolled_actor):
    identity = Principal.objects.create(
        issuer=settings.WORKFORCE_ISSUER,
        subject="mover",
        name="Synthetic mover",
        kind="human",
        department="Engineering",
        status="active",
        project_ids=["Atlas"],
    )
    result = enrollment_client.post(
        f"/api/v1/identities/{identity.pk}/transfer-department",
        {"department": "Operations", "reason": "Approved department move"},
        format="json",
        HTTP_IDEMPOTENCY_KEY="NONFUNCTIONAL_MOVE_001",
    )
    assert result.status_code == 201
    assert result.data["result"]["status"] == "pending"
    assert result.data["result"]["action"] == "department_transfer"
    identity.refresh_from_db()
    assert identity.department == "Engineering"
    assert not OutboxJob.objects.exists()


def test_unknown_provider_outcome_is_observed_before_create(enrolled_actor):
    identity = enrollment.enroll(enrolled_actor, body())
    job = OutboxJob.objects.get(kind="enroll")
    subject = str(uuid.uuid4())

    class Connector:
        creates = 0

        def list_resources(self, *args, **kwargs):
            return {
                "Resources": [{"id": subject, "userName": job.desired["userName"], "active": True}]
            }

        def create_user(self, *args, **kwargs):
            self.creates += 1
            raise AssertionError("Duplicate remote user would be created")

        def patch_user(self, *args, **kwargs):
            return {}

        def get_user(self, user_id):
            return {"id": user_id, "active": True}

    connector = Connector()
    result = enrollment.process_enrollment_job(job, connector)
    identity.refresh_from_db()
    assert connector.creates == 0 and result["verified"]
    assert identity.subject == subject


def test_late_enrollment_cannot_reactivate_offboarded_identity(enrolled_actor):
    identity = enrollment.enroll(enrolled_actor, body())
    identity.status = "offboarded"
    identity.save(update_fields=["status"])
    job = OutboxJob.objects.get(kind="enroll")
    subject = str(uuid.uuid4())

    class Connector:
        active = True

        def list_resources(self, *args, **kwargs):
            return {"Resources": [{"id": subject, "userName": job.desired["userName"]}]}

        def patch_user(self, user_id, operations):
            self.active = operations[0]["value"]

        def get_user(self, user_id):
            return {"id": user_id, "active": self.active}

    connector = Connector()
    result = enrollment.process_enrollment_job(job, connector)
    assert connector.active is False and result["verified"]


def test_lifecycle_change_during_remote_enrollment_requires_correction(enrolled_actor):
    identity = enrollment.enroll(enrolled_actor, body())
    job = OutboxJob.objects.get(kind="enroll")
    subject = str(uuid.uuid4())

    class Connector:
        def list_resources(self, *args, **kwargs):
            return {"Resources": [{"id": subject, "userName": job.desired["userName"]}]}

        def patch_user(self, user_id, operations):
            Principal.objects.filter(pk=identity.pk).update(status="offboarded")

        def get_user(self, user_id):
            return {"id": user_id, "active": True}

    result = enrollment.process_enrollment_job(job, Connector())
    identity.refresh_from_db()
    assert result["verified"] is False
    assert identity.status == "offboarded"
    assert OutboxJob.objects.filter(kind="suspend", desired__identityId=str(identity.pk)).exists()


def test_stale_department_cleanup_preserves_current_backed_grant(enrolled_actor):
    identity = Principal.objects.create(
        issuer=settings.WORKFORCE_ISSUER,
        subject=str(uuid.uuid4()),
        name="Mover",
        kind="human",
        department="Operations",
        project_ids=["Pulse"],
    )
    resource = Resource.objects.create(
        name="Prior project",
        project="Atlas",
        owner=enrolled_actor,
        provider_group=str(uuid.uuid4()),
    )
    change = ChangeRequest.objects.create(
        identity=identity,
        requester=enrolled_actor,
        payload={
            "action": "department_transfer",
            "sourceProjects": ["Atlas"],
            "targetProjects": ["Pulse"],
        },
        payload_hash="test",
        policy_version="accessops-v1",
    )
    Grant.objects.create(
        identity=identity, resource=resource, status="active", source_request=change
    )
    job = OutboxJob.objects.create(
        request=change, kind="lifecycle", desired={}, available_at=timezone.now()
    )

    class Connector:
        def reconcile(self, identity, mapping):
            assert mapping["desiredMember"] is True
            return {"observed": {"member": True}, "drift": False}

        def apply(self, *args, **kwargs):
            raise AssertionError("An already-correct backed grant must not be removed")

    result = enrollment.process_department_job(job, Connector())
    assert result["verified"] and result["desired"]["resources"][0]["member"] is True
