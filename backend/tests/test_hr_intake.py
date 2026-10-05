"""Signed HR leaver intake; isolated database and synthetic secrets only."""

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import timedelta

import pytest
from core import services as svc
from core.errors import DomainError
from core.intake import SOURCE_LABEL, contain_due_departures
from core.management.commands.seed_demo import uid
from core.models import AuditEvent, OffboardingCase, Principal
from django.utils import timezone
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db
URL = "/api/v1/hr-events"
SECRET = "whsec_" + base64.b64encode(b"synthetic-test-key-for-hr-intake").decode()


@pytest.fixture
def leaver(org):
    # Clara Ellis has no seeded departure case; Bob Chen already has one open.
    return Principal.objects.get(pk=uid("clara-ellis"))


@pytest.fixture
def feed(org, settings):
    settings.HR_WEBHOOK_SECRET = SECRET
    return Principal.objects.get(pk=uid("hr-feed"))


def event(worker, *, effective=None, event_id=None, **changes):
    value = {
        "type": "worker.departed",
        "eventId": event_id or "HR-EVT-" + secrets.token_hex(4),
        "workerId": str(worker.pk),
        "employmentType": "employee",
        "effectiveAt": (effective or timezone.now() - timedelta(minutes=1)).isoformat(),
        "reason": "Synthetic resignation from the HR feed",
    }
    value.update(changes)
    return value


def send(payload, *, message_id=None, stamp=None, secret=SECRET, signature=None, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    message_id = message_id or "msg_" + secrets.token_hex(8)
    stamp = str(int(time.time()) if stamp is None else stamp)
    key = base64.b64decode(secret.removeprefix("whsec_"))
    signed = base64.b64encode(
        hmac.new(key, f"{message_id}.{stamp}.".encode() + body, hashlib.sha256).digest()
    ).decode()
    return APIClient().post(
        URL,
        body,
        content_type="application/json",
        HTTP_WEBHOOK_ID=message_id,
        HTTP_WEBHOOK_TIMESTAMP=stamp,
        HTTP_WEBHOOK_SIGNATURE=signature if signature is not None else "v1," + signed,
    )


def test_effective_event_opens_and_contains_without_a_person(org, feed, leaver):
    worker = leaver
    response = send(event(worker))
    assert response.status_code == 201
    assert set(response.json()["result"]) == {"caseId", "state", "effectiveAt"}
    assert response.json()["result"]["state"] == "contained"
    case = OffboardingCase.objects.get(pk=response.json()["result"]["caseId"])
    assert case.intake_source == feed and case.hr_source == SOURCE_LABEL
    assert case.owner_id == uid("operator-alice")
    assert case.containment_request.requester == feed
    worker.refresh_from_db()
    assert worker.status == "offboarded"
    actions = AuditEvent.objects.filter(actor_id=str(feed.pk)).values_list("action", flat=True)
    assert {"departure.intake", "departure.contained"} <= set(actions)


def test_redelivery_returns_the_original_result_and_one_case(org, feed, leaver):
    payload = event(leaver)
    first = send(payload, message_id="msg_redelivered")
    again = send(payload, message_id="msg_redelivered")
    other_delivery = send(payload)
    assert first.status_code == 201 and again.status_code == 201
    assert again.json() == first.json()
    assert other_delivery.status_code == 200
    assert other_delivery.json()["result"]["caseId"] == first.json()["result"]["caseId"]
    assert OffboardingCase.objects.filter(hr_event_id=payload["eventId"]).count() == 1


def test_reused_ids_with_different_content_conflict(org, feed, leaver):
    payload = event(leaver)
    assert send(payload, message_id="msg_reused").status_code == 201
    changed = {**payload, "reason": "A different synthetic reason text"}
    assert send(changed, message_id="msg_reused").json()["error"]["code"] == (
        "idempotency_conflict"
    )
    moved = {**payload, "effectiveAt": (timezone.now() - timedelta(hours=1)).isoformat()}
    assert send(moved).json()["error"]["code"] == "event_conflict"
    second = event(leaver)
    assert send(second).json()["error"]["code"] == "departure_open"
    assert OffboardingCase.objects.filter(identity=leaver).count() == 1


@pytest.mark.parametrize(
    "tamper",
    ["missing", "wrong_secret", "body", "stale", "future", "malformed", "version", "id"],
)
def test_unsigned_or_altered_events_change_nothing(org, feed, leaver, tamper):
    payload = event(leaver)
    other = "whsec_" + base64.b64encode(b"a-different-synthetic-signing-key").decode()
    options = {
        "missing": {"signature": ""},
        "wrong_secret": {"secret": other},
        "stale": {"stamp": int(time.time()) - 400},
        "future": {"stamp": int(time.time()) + 400},
        "malformed": {"signature": "v1,not-base64"},
        "version": {"signature": "v2,abc"},
        "id": {"message_id": "bad id with spaces"},
    }.get(tamper, {})
    if tamper == "body":
        response = APIClient().post(
            URL,
            json.dumps({**payload, "workerId": str(org["employee"].pk)}),
            content_type="application/json",
            HTTP_WEBHOOK_ID="msg_tampered",
            HTTP_WEBHOOK_TIMESTAMP=str(int(time.time())),
            HTTP_WEBHOOK_SIGNATURE=send_signature(payload, "msg_tampered"),
        )
    else:
        response = send(payload, **options)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "signature_invalid"
    assert not OffboardingCase.objects.filter(hr_event_id=payload["eventId"]).exists()
    assert not AuditEvent.objects.filter(actor_id=str(feed.pk)).exists()


def send_signature(payload, message_id):
    stamp = str(int(time.time()))
    key = base64.b64decode(SECRET.removeprefix("whsec_"))
    body = json.dumps(payload).encode()
    return (
        "v1,"
        + base64.b64encode(
            hmac.new(key, f"{message_id}.{stamp}.".encode() + body, hashlib.sha256).digest()
        ).decode()
    )


def test_any_listed_v1_signature_may_match_during_secret_rotation(org, feed, leaver):
    payload = event(leaver)
    good = send_signature(payload, "msg_rotation")
    response = APIClient().post(
        URL,
        json.dumps(payload),
        content_type="application/json",
        HTTP_WEBHOOK_ID="msg_rotation",
        HTTP_WEBHOOK_TIMESTAMP=str(int(time.time())),
        HTTP_WEBHOOK_SIGNATURE="v1,b2xkLXNlY3JldA== " + good,
    )
    assert response.status_code == 201


def test_intake_refuses_every_event_without_a_secret(org, feed, leaver, settings):
    settings.HR_WEBHOOK_SECRET = ""
    response = send(event(leaver))
    assert response.status_code == 503
    assert not OffboardingCase.objects.filter(identity=leaver).exists()


@pytest.mark.parametrize("worker", ["unknown", "agent", "operator"])
def test_only_enrolled_workforce_people_can_be_named(org, feed, worker):
    target = {
        "unknown": Principal(pk="99999999-9999-4999-8999-999999999999"),
        "agent": org["agent"],
        "operator": org["alice"],
    }[worker]
    response = send(event(target))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "worker_unknown"


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", json.dumps({"type": "worker.departed", "extra": True}).encode()],
)
def test_signed_but_invalid_bodies_are_rejected(org, feed, body):
    assert send(None, raw=body).status_code == 400


def test_oversized_event_is_rejected_before_parsing(org, feed):
    assert send(None, raw=b"{" + b" " * 17000 + b"}").status_code == 413


def test_future_event_is_scheduled_then_contained_by_the_feed_when_due(org, feed, leaver):
    worker = leaver
    response = send(event(worker, effective=timezone.now() + timedelta(hours=1)))
    assert response.status_code == 201 and response.json()["result"]["state"] == "scheduled"
    case = OffboardingCase.objects.get(pk=response.json()["result"]["caseId"])
    assert contain_due_departures() == 0
    worker.refresh_from_db()
    assert worker.status == "active" and case.containment_request_id is None
    # Isolated clock fixture: the departure becomes effective.
    OffboardingCase.objects.filter(pk=case.pk).update(
        effective_at=timezone.now() - timedelta(seconds=1)
    )
    assert contain_due_departures() == 1
    assert contain_due_departures() == 0
    case.refresh_from_db()
    worker.refresh_from_db()
    assert case.containment_request.requester == feed and worker.status == "offboarded"
    assert AuditEvent.objects.filter(
        actor_id=str(feed.pk), action="departure.contained", target_id=str(case.pk)
    ).exists()


def test_refused_scheduled_containment_is_recorded_once_and_left_to_the_owner(org, feed, leaver):
    response = send(event(leaver, effective=timezone.now() + timedelta(hours=1)))
    case_id = response.json()["result"]["caseId"]
    OffboardingCase.objects.filter(pk=case_id).update(
        effective_at=timezone.now() - timedelta(seconds=1)
    )
    Principal.objects.filter(pk=feed.pk).update(status="suspended")
    assert contain_due_departures() == 0
    assert contain_due_departures() == 0
    failures = AuditEvent.objects.filter(action="departure.auto_contain_failed", target_id=case_id)
    assert failures.count() == 1
    assert OffboardingCase.objects.get(pk=case_id).containment_request_id is None


@pytest.mark.parametrize("problem", ["no_sponsor", "sponsor_not_operator", "own_departure"])
def test_case_needs_an_independent_active_operator_owner(org, feed, leaver, problem):
    worker = leaver
    if problem == "no_sponsor":
        Principal.objects.filter(pk=feed.pk).update(sponsor=None)
    elif problem == "sponsor_not_operator":
        Principal.objects.filter(pk=feed.pk).update(sponsor=org["clara"])
    else:
        worker = org["employee"]  # Alice Morgan is the feed owner's own workforce identity.
    response = send(event(worker))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == (
        "independent_owner_required" if problem == "own_departure" else "intake_owner_unavailable"
    )
    assert not OffboardingCase.objects.filter(identity=worker).exists()


@pytest.mark.parametrize(
    "action", ["request", "approve", "departure_close", "snapshot", "reconcile", "review"]
)
def test_feed_has_no_authority_beyond_intake_and_containment(org, feed, action):
    with pytest.raises(DomainError) as error:
        svc.require_policy(feed, action, context={"identity_project_ids": ["Atlas"]})
    assert error.value.code == "service_authority_denied"


def test_feed_cannot_execute_a_grant_and_operators_cannot_use_intake(org, feed):
    from core.models import ChangeRequest

    grant = ChangeRequest(payload={"action": "grant"}, requester=feed)
    with pytest.raises(DomainError) as error:
        svc.require_policy(feed, "execute", change=grant)
    assert error.value.code == "service_authority_denied"
    with pytest.raises(DomainError) as error:
        svc.require_policy(org["alice"], "departure_intake")
    assert error.value.code == "role_denied"


def test_snapshot_names_the_feed_as_a_service_not_an_identity(org, feed, client_for):
    data = client_for(org["alice"]).get("/api/v1/snapshot").json()
    assert str(feed.pk) not in {item["id"] for item in data["identities"]}
    assert {"id": str(feed.pk), "name": feed.name} in data["services"]
