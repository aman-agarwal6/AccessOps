from datetime import timedelta
from unittest.mock import Mock

import pytest
from core import services as svc
from core.models import Grant, OutboxJob, Principal
from core.worker import process_one
from django.conf import settings
from django.utils import timezone
from rest_framework.test import APIClient
from test_security import approved, payload, post, request

pytestmark = pytest.mark.django_db


@pytest.fixture
def executor(org, monkeypatch):
    claims = {"iss": settings.WORKFORCE_ISSUER, "sub": org["agent"].subject}
    monkeypatch.setattr("integrations.security.verify_executor_token", lambda *a, **k: claims)
    requester = Mock()
    requester.introspect.return_value = {"active": True, "sub": claims["sub"]}
    monkeypatch.setattr("integrations.security.ExecutorClient", lambda: requester)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Bearer synthetic-token-for-boundary-test")
    return client, requester, claims


def test_old_operator_session_denied_after_local_revoke_provider_down(org, client_for, monkeypatch):
    client = client_for(org["alice"])
    url = f"/api/v1/resources/{org['atlas'].pk}/read"
    assert post(client, url, {}, "resource-before-001").status_code == 200
    change = request(org, payload(org, "revoke", resourceId=str(org["atlas"].pk)))
    svc.execute(org["alice"], change)
    assert post(client, url, {}, "resource-after-001").status_code == 403
    assert post(client, url, {}, "resource-before-001").status_code == 403
    assert OutboxJob.objects.get().status == "pending"


def test_old_executor_token_and_replayed_response_denied_after_revoke(org, executor):
    client, introspector, _ = executor
    grant = Grant.objects.create(
        identity=org["agent"],
        resource=org["atlas"],
        permission="read",
        expires_at=timezone.now() + timedelta(minutes=10),
        max_calls=6,
    )
    url = f"/api/v1/resources/{org['atlas'].pk}/read"
    assert post(client, url, {}, "executor-read-001").status_code == 200
    grant.status = "revoked"
    grant.save()
    assert post(client, url, {}, "executor-read-002").status_code == 403
    assert post(client, url, {}, "executor-read-001").status_code == 403
    assert introspector.introspect.call_count == 3


def test_introspection_outage_inactive_and_wrong_sub_fail_closed(org, executor):
    client, introspector, _ = executor
    url = f"/api/v1/resources/{org['atlas'].pk}/read"
    for result in [{"active": False}, {"active": True, "sub": "different-subject"}]:
        introspector.introspect.return_value = result
        assert post(client, url, {}).status_code == 401
    introspector.introspect.side_effect = TimeoutError("synthetic provider outage")
    assert post(client, url, {}).status_code == 401


def test_issuer_and_subject_both_required_for_executor_mapping(org, executor):
    client, _, claims = executor
    claims["iss"] = settings.OIDC_ISSUER
    assert post(client, f"/api/v1/resources/{org['atlas'].pk}/read", {}).status_code == 401


def test_agent_tool_replay_reauthorizes_sponsor(org, executor):
    client, _, _ = executor
    task = svc.start_review(org["alice"], org["review"])
    url = f"/api/v1/agent/tasks/{task.pk}/tools"
    assert post(client, url, {"tool": "list_entitlements"}, "agent-list-001").status_code == 200
    Principal.objects.filter(pk=org["sponsor"].pk).update(status="offboarded")
    assert post(client, url, {"tool": "list_entitlements"}, "agent-list-001").status_code == 403


def test_tool_cross_task_input_injection_rejected(org, executor):
    client, _, _ = executor
    task = svc.start_review(org["alice"], org["review"])
    url = f"/api/v1/agent/tasks/{task.pk}/tools"
    assert post(client, url, {"tool": "create_draft", "approve": True}).status_code == 400
    assert post(client, url, {"tool": "execute"}).status_code == 400
    task.refresh_from_db()
    assert task.calls_used == 0


def test_live_revocation_race_during_remote_delivery_is_not_verified(org):
    change = approved(org)
    svc.execute(org["alice"], change)
    connector = Mock()
    connector.observe_membership.return_value = {"observed": {"member": False}}

    def late_remote(*args):
        Grant.objects.filter(source_request=change).update(status="revoked")
        return {"verified": True, "observed": {"member": True}}

    connector.apply.side_effect = late_remote
    process_one(connector)
    job = OutboxJob.objects.get()
    assert job.status == "retry"
    assert job.observed["member"] is True
    change.refresh_from_db()
    assert change.status == "applied"


def test_successor_acceptance_independent_approval_and_suspend(org, client_for):
    change = approved(
        org,
        payload(
            org,
            "transfer",
            identityId=str(org["agent"].pk),
            resourceId=None,
            newSponsorId=str(org["employee"].pk),
        ),
    )
    operator = client_for(org["bob"])
    assert post(operator, f"/api/v1/requests/{change.pk}/execute", {}).status_code == 409
    successor = client_for(org["alice"])
    assert (
        post(
            successor, f"/api/v1/requests/{change.pk}/accept", {}, "accept-successor-001"
        ).status_code
        == 200
    )
    assert (
        post(
            operator, f"/api/v1/requests/{change.pk}/execute", {}, "execute-transfer-001"
        ).status_code
        == 200
    )
    org["agent"].refresh_from_db()
    assert org["agent"].sponsor_id == org["employee"].pk
    assert org["agent"].status == "suspended"
