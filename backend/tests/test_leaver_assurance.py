"""Post-departure activity watch and signed leaver signals; synthetic data only."""

import copy
import logging
import secrets
from datetime import timedelta

import jwt
import pytest
from core import assurance, audit, ssf
from core.models import ActivityCheck, AuditEvent, OffboardingCase, SecurityEvent
from core.offboarding import assess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.utils import timezone
from rest_framework.test import APIClient
from tests.test_offboarding_cases import (
    PREFIX,
    close_input,
    complete_case,
    create_case,
    post,
    record_reading,
)

from integrations.errors import ConnectorError

pytestmark = pytest.mark.django_db
TOKEN = "synthetic-receiver-token-" + "x" * 24
ATLAS_TOKEN = "synthetic-atlas-token-" + "y" * 24
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
RISC = "https://schemas.openid.net/secevent/risc/event-type/"
NOT_CONFIGURED = (
    "Sign-ins after departure can't be checked: the read-only Keycloak events client"
    " isn't configured."
)
PENDING = "Waiting for the first sign-in check after departure."
UNAVAILABLE = "The latest sign-in check after departure failed; closure waits for a successful one."
STALE = "No successful sign-in check in the last 90 seconds; closure waits for a current one."
FINISHING = "Waiting for the final sign-in check covering the full day after departure."


@pytest.fixture
def signer(settings, tmp_path):
    key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (tmp_path / "signing.pem").write_bytes(key)
    settings.SSF_SIGNING_KEY_FILE = str(tmp_path / "signing.pem")
    settings.SSF_RECEIVER_TOKEN = TOKEN
    settings.SSF_ATLAS_TOKEN = ""
    ssf.signing_key.cache_clear()
    yield
    ssf.signing_key.cache_clear()


class Reader:
    def __init__(self, events=(), fail=False):
        self.events, self.fail, self.calls = list(events), fail, []

    def sign_in_events(self, subject, since_ms):
        self.calls.append((subject, since_ms))
        if self.fail:
            raise ConnectorError("Event observation unavailable")
        return [event for event in self.events if event["time"] >= since_ms]


def event(case, kind, seconds=60, error=""):
    at = int((case.effective_at + timedelta(seconds=seconds)).timestamp() * 1000)
    return {"time": at, "type": kind, "clientId": "atlas-app", "error": error}


def keycloak_task(case, key="keycloak-directory"):
    return next((t for t in assess(case)["tasks"] if t["id"] == key), None)


def verify(token, audience="urn:accessops:soc-receiver"):
    key = jwt.PyJWK.from_dict(APIClient().get("/api/v1/ssf/jwks").json()["keys"][0])
    assert jwt.get_unverified_header(token)["typ"] == "secevent+jwt"
    return jwt.decode(token, key.key, algorithms=["ES256"], audience=audience)


def poll(body=None, token=TOKEN):
    return APIClient().post(
        "/api/v1/ssf/poll", body or {}, format="json", HTTP_AUTHORIZATION="Bearer " + token
    )


def close(org, client_for, case, value=None):
    """An independent reviewer closes the case on the given (or current) packet."""
    return post(client_for(org["clara"]), f"{PREFIX}/{case.pk}/close", value or close_input(case))


def move_departure(case, **ago):
    # Isolated fixture: departure intent is immutable through the application.
    OffboardingCase.objects.filter(pk=case.pk).update(
        effective_at=timezone.now() - timedelta(**ago)
    )
    case.refresh_from_db()


def test_verified_containment_emits_signed_risc_and_caep_events_once(org, client_for, signer):
    case = complete_case(org, client_for(org["alice"]))
    job = case.containment_request.outboxjob
    ssf.signal_containment(job, case.identity.subject)
    ssf.signal_containment(job, case.identity.subject)
    events = SecurityEvent.objects.filter(case=case)
    assert sorted(events.values_list("event_type", flat=True)) == [
        "account-disabled",
        "session-revoked",
    ]
    for item in events:
        claims = verify(item.token)
        assert claims["iss"] == "https://accessops.test:8443"
        assert claims["sub_id"] == {
            "format": "iss_sub",
            "iss": case.identity.issuer,
            "sub": case.identity.subject,
        }
        assert set(claims["events"]) <= {RISC + "account-disabled", CAEP + "session-revoked"}
        assert "name" not in str(claims) and case.identity.email not in str(claims)


def test_no_signing_key_means_no_events(org, client_for, settings, tmp_path):
    settings.SSF_SIGNING_KEY_FILE = str(tmp_path / "missing.pem")
    ssf.signing_key.cache_clear()
    case = complete_case(org, client_for(org["alice"]))
    ssf.signal_containment(case.containment_request.outboxjob, case.identity.subject)
    assert not SecurityEvent.objects.exists()
    assert APIClient().get("/api/v1/ssf/jwks").json() == {"keys": []}


@pytest.mark.parametrize("token", ["", "wrong-" + TOKEN])
def test_poll_requires_the_receiver_token(org, signer, token):
    response = poll(token=token)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "receiver_unauthorized"


def test_poll_refuses_everything_when_unconfigured(org, settings):
    settings.SSF_RECEIVER_TOKEN = ""
    assert poll().status_code == 503


def test_poll_offers_unacknowledged_events_until_acknowledged(org, signer):
    for index in range(3):
        ssf.emit("session-revoked", f"subject-{index}", f"test:{index}")
    first = poll({"maxEvents": 2}).json()
    assert len(first["sets"]) == 2 and first["moreAvailable"] is True
    assert poll({"maxEvents": 2}).json()["sets"].keys() == first["sets"].keys()
    second = poll({"maxEvents": 2, "ack": list(first["sets"])}).json()
    assert len(second["sets"]) == 1 and second["moreAvailable"] is False
    (last,) = second["sets"]
    final = poll({"setErrs": {last: {"err": "invalid_key"}}}).json()
    assert final == {"sets": {}, "moreAvailable": False}
    assert SecurityEvent.objects.get(jti=last).receiver_error == "invalid_key"


@pytest.mark.parametrize(
    "body",
    [{"maxEvents": 51}, {"ack": ["not-a-jti"]}, {"unexpected": True}, {"maxEvents": -1}],
)
def test_poll_input_is_bounded(org, signer, body):
    assert poll(body).status_code == 400


def test_transmitter_metadata_names_poll_delivery_and_keys(org):
    data = APIClient().get("/.well-known/ssf-configuration").json()
    assert data["issuer"] == "https://accessops.test:8443"
    assert data["delivery_methods_supported"] == ["urn:ietf:rfc:8936"]
    assert data["jwks_uri"].endswith("/api/v1/ssf/jwks")


def test_clean_reading_counts_refusals_and_is_shown_on_the_keycloak_task(org, client_for):
    case = complete_case(org, client_for(org["alice"]), watched=False)
    reader = Reader(
        [event(case, "LOGIN_ERROR", error="user_disabled"), event(case, "REFRESH_TOKEN_ERROR")]
    )
    assert assurance.watch_departures(reader) == 1
    check = ActivityCheck.objects.get(case=case)
    assert check.status == "observed" and check.refused == 2 and check.successes == []
    assert "refused 2 attempt(s)" in keycloak_task(case)["evidenceSummary"]
    assert keycloak_task(case, "post-departure-access") is None
    assert not SecurityEvent.objects.exists()


def test_sign_in_after_departure_opens_a_blocking_task_and_signals_once(
    org, client_for, signer, monkeypatch
):
    monkeypatch.setattr(assurance, "INTERVAL", timedelta(0))
    case = complete_case(org, client_for(org["alice"]))
    reader = Reader([event(case, "LOGIN"), event(case, "LOGIN_ERROR")])
    assurance.watch_departures(reader)
    assurance.watch_departures(reader)
    task = keycloak_task(case, "post-departure-access")
    assert task["status"] == "pending" and task["platform"] == "keycloak"
    assert any("after departure" in line for line in assess(case)["blockers"])
    assert "no successful sign-in" not in keycloak_task(case)["evidenceSummary"]
    (signal,) = SecurityEvent.objects.filter(event_type="session-established")
    claims = verify(signal.token)
    assert claims["events"][CAEP + "session-established"]["event_timestamp"] == (
        reader.events[0]["time"] // 1000
    )


def test_investigation_statement_covers_only_sign_ins_read_before_it(org, client_for, monkeypatch):
    monkeypatch.setattr(assurance, "INTERVAL", timedelta(0))
    alice = client_for(org["alice"])
    case = complete_case(org, alice)
    reader = Reader([event(case, "LOGIN", seconds=30)])
    assurance.watch_departures(reader)
    statement = {
        "reference": "INC-SYN-0001",
        "summary": "Synthetic investigation: re-enabled by mistake, contained again, no data accessed.",
    }
    path = f"{PREFIX}/{case.pk}/tasks/post-departure-access/attest"
    assert post(alice, path, statement).status_code == 200
    case.refresh_from_db()
    assert keycloak_task(case, "post-departure-access")["status"] == "attested"
    reader.events.append(
        {
            "time": int(timezone.now().timestamp() * 1000) + 5000,
            "type": "LOGIN",
            "clientId": "x",
            "error": "",
        }
    )
    assurance.watch_departures(reader)
    assert keycloak_task(case, "post-departure-access")["status"] == "pending"


def test_post_departure_task_cannot_be_attested_without_observed_access(org, client_for):
    alice = client_for(org["alice"])
    case = complete_case(org, alice)
    response = post(
        alice,
        f"{PREFIX}/{case.pk}/tasks/post-departure-access/attest",
        {
            "reference": "INC-SYN-0002",
            "summary": "Synthetic statement that should be refused without evidence.",
        },
    )
    assert response.status_code == 409


def test_unavailable_reading_is_recorded_without_any_claim(org, client_for):
    case = complete_case(org, client_for(org["alice"]), watched=False)
    assurance.watch_departures(Reader(fail=True))
    assert ActivityCheck.objects.get(case=case).status == "unavailable"
    assert "Since the departure" not in keycloak_task(case)["evidenceSummary"]


def test_the_watch_starts_with_containment_and_is_outside_the_packet(org, client_for):
    owner = client_for(org["alice"])
    case = create_case(org, owner)
    value = assess(case)
    assert value["watch"] == {
        "status": "not_started",
        "windowEndsAt": (case.effective_at + timedelta(hours=24)).isoformat(),
        "lastReadAt": None,
        "lastAttemptAt": None,
        "refused": None,
        "successes": 0,
        "afterClosure": 0,
    }
    assert not any("sign-in check" in line for line in value["blockers"])
    reader = Reader()
    assert assurance.watch_departures(reader) == 0 and reader.calls == []
    assert post(owner, f"{PREFIX}/{case.pk}/contain").status_code == 200
    case.refresh_from_db()
    value = assess(case)
    assert value["watch"]["status"] == "pending" and PENDING in value["blockers"]
    packet_hash = value.pop("packetHash")
    del value["signals"], value["watch"]
    assert audit.digest(value) == packet_hash


def test_identical_readings_keep_the_packet_and_the_reviewed_hash_still_closes(
    org, client_for, monkeypatch
):
    monkeypatch.setattr(assurance, "INTERVAL", timedelta(0))
    case = complete_case(org, client_for(org["alice"]), watched=False)
    reader = Reader([event(case, "LOGIN_ERROR", error="user_disabled")])
    assurance.watch_departures(reader)
    reviewed = close_input(case)
    first = ActivityCheck.objects.get(case=case).checked_at
    # The next reading lands while the reviewer reads the packet.
    assurance.watch_departures(reader)
    assert close_input(case) == reviewed
    watch = assess(case)["watch"]
    assert watch["status"] == "watching" and watch["refused"] == 1
    assert watch["lastReadAt"] > first.isoformat()
    response = close(org, client_for, case, reviewed)
    assert response.status_code == 200, response.json()


def test_a_new_refused_attempt_is_evidence_and_changes_the_packet(org, client_for, monkeypatch):
    monkeypatch.setattr(assurance, "INTERVAL", timedelta(0))
    case = complete_case(org, client_for(org["alice"]), watched=False)
    reader = Reader([event(case, "LOGIN_ERROR", error="user_disabled")])
    assurance.watch_departures(reader)
    reviewed = close_input(case)
    reader.events.append(event(case, "LOGIN_ERROR", seconds=90, error="user_disabled"))
    assurance.watch_departures(reader)
    assert "refused 2 attempt(s)" in keycloak_task(case)["evidenceSummary"]
    response = close(org, client_for, case, reviewed)
    assert response.status_code == 409 and response.json()["error"]["code"] == "stale_case"


def test_a_failed_latest_reading_blocks_closure_until_a_successful_one(
    org, client_for, monkeypatch
):
    monkeypatch.setattr(assurance, "INTERVAL", timedelta(0))
    case = complete_case(org, client_for(org["alice"]))
    # More than 200 events since departure also make a reading unavailable.
    assurance.watch_departures(Reader(fail=True))
    value = assess(case)
    assert value["blockers"] == [UNAVAILABLE]
    assert value["watch"]["status"] == "unavailable"
    assert value["watch"]["lastAttemptAt"] > value["watch"]["lastReadAt"]
    response = close(org, client_for, case)
    assert response.status_code == 409 and response.json()["error"]["code"] == "closure_blocked"
    assurance.watch_departures(Reader())
    assert assess(case)["blockers"] == []
    assert close(org, client_for, case).status_code == 200


@pytest.mark.parametrize(
    ("age", "status", "blocker"),
    [(None, "pending", PENDING), (91, "stale", STALE)],
    ids=["no-reading-yet", "older-than-90-seconds"],
)
def test_a_missing_or_old_reading_blocks_closure(org, client_for, age, status, blocker):
    case = complete_case(org, client_for(org["alice"]), watched=False)
    if age:
        record_reading(case, timezone.now() - timedelta(seconds=age))
    value = assess(case)
    assert value["blockers"] == [blocker] and value["watch"]["status"] == status
    response = close(org, client_for, case)
    assert response.status_code == 409 and response.json()["error"]["code"] == "closure_blocked"


def test_without_an_events_client_secret_the_watch_is_off_and_blocks_closure(
    org, client_for, settings, caplog
):
    settings.EVENTS_CLIENT_SECRET = ""
    case = complete_case(org, client_for(org["alice"]), watched=False)
    value = assess(case)
    assert value["blockers"] == [NOT_CONFIGURED]
    assert value["watch"]["status"] == "not_configured"
    response = close(org, client_for, case)
    assert response.status_code == 409 and response.json()["error"]["code"] == "closure_blocked"
    assurance.warn_unconfigured.cache_clear()
    with caplog.at_level(logging.WARNING, logger="core.assurance"):
        assert assurance.watch_departures() == 0
        assert assurance.watch_departures() == 0
    assert not ActivityCheck.objects.exists()
    (record,) = [item for item in caplog.records if item.name == "core.assurance"]
    assert record.levelno == logging.WARNING and "not configured" in record.getMessage()


def test_after_the_window_closure_waits_for_the_final_reading(org, client_for, monkeypatch):
    # No interval: only the final reading may stop the watch.
    monkeypatch.setattr(assurance, "INTERVAL", timedelta(0))
    case = complete_case(org, client_for(org["alice"]), watched=False)
    move_departure(case, hours=25)
    record_reading(case, case.effective_at + timedelta(hours=23, minutes=59))
    assert assurance.due_cases(timezone.now(), 10) == [case]
    value = assess(case)
    assert value["blockers"] == [FINISHING] and value["watch"]["status"] == "finishing"
    assert value["watch"]["windowEndsAt"] == (case.effective_at + timedelta(hours=24)).isoformat()
    assert assurance.watch_departures(Reader()) == 1
    value = assess(case)
    assert value["watch"]["status"] == "complete" and value["blockers"] == []
    reader = Reader()
    assert assurance.watch_departures(reader) == 0 and reader.calls == []
    assert close(org, client_for, case).status_code == 200


def test_a_watch_that_never_covered_the_window_is_stated_but_does_not_block(org, client_for):
    # Containment came too late: the watch window and its grace day have passed.
    case = complete_case(org, client_for(org["alice"]), watched=False)
    move_departure(case, hours=49)
    reader = Reader()
    assert assurance.watch_departures(reader) == 0 and reader.calls == []
    assert (
        "The sign-in watch never completed a reading covering the full day after departure."
        in keycloak_task(case)["evidenceSummary"]
    )
    value = assess(case)
    assert value["watch"]["status"] == "missed" and value["blockers"] == []
    assert close(org, client_for, case).status_code == 200


def test_closure_freezes_the_watch_state_and_assess_returns_a_copy(org, client_for):
    case = complete_case(org, client_for(org["alice"]))
    reviewed = close_input(case)
    reviewer = client_for(org["clara"])
    assert post(reviewer, f"{PREFIX}/{case.pk}/close", reviewed).status_code == 200
    case.refresh_from_db()
    value = assess(case)
    value["status"] = "reopened"
    value["tasks"].clear()
    stored = case.closed_packet["case"]
    assert stored["status"] == "closed" and stored["tasks"] and "watch" not in stored
    assert assess(case)["watch"]["status"] == "watching"
    packet = reviewer.get(f"{PREFIX}/{case.pk}/packet").json()
    at_closure = packet["watchAtClosure"]
    assert at_closure["status"] == "watching" and at_closure["lastReadAt"]
    assert at_closure["afterClosure"] == 0 and "watch" not in packet["case"]
    assert packet["reviewedInputHash"] == reviewed["packetHash"]
    packet_hash = packet["case"].pop("packetHash")
    assert audit.digest(packet) == packet_hash


def test_a_closed_case_is_still_watched_and_access_after_closure_is_signalled(
    org, client_for, signer, monkeypatch
):
    monkeypatch.setattr(assurance, "INTERVAL", timedelta(0))
    case = complete_case(org, client_for(org["alice"]))
    assert close(org, client_for, case).status_code == 200
    case.refresh_from_db()
    frozen = copy.deepcopy(case.closed_packet)
    # The account is re-enabled outside AccessOps and used after closure.
    at = int(timezone.now().timestamp() * 1000) + 1000
    reader = Reader([{"time": at, "type": "LOGIN", "clientId": "atlas-app", "error": ""}])
    assert assurance.watch_departures(reader) == 1
    (signal,) = SecurityEvent.objects.filter(case=case, event_type="session-established")
    assert verify(signal.token)["events"][CAEP + "session-established"]["event_timestamp"] == (
        at // 1000
    )
    (finding,) = AuditEvent.objects.filter(action="departure.access_after_closure")
    assert finding.target_id == str(case.pk) and finding.detail == {"count": 1, "firstAt": at}
    assert not AuditEvent.objects.filter(action="departure.access_after_departure").exists()
    case.refresh_from_db()
    assert case.closed_packet == frozen
    value = assess(case)
    assert value["status"] == "closed" and keycloak_task(case, "post-departure-access") is None
    assert value["watch"]["successes"] == value["watch"]["afterClosure"] == 1
    # Read again: the same sign-in is neither signalled nor counted twice.
    assert assurance.watch_departures(reader) == 1
    assert SecurityEvent.objects.filter(event_type="session-established").count() == 1
    assert assess(case)["watch"]["afterClosure"] == 1


def test_open_cases_are_read_before_closed_ones(org, client_for, monkeypatch):
    monkeypatch.setattr(assurance, "INTERVAL", timedelta(0))
    owner = client_for(org["alice"])
    closed = complete_case(org, owner)
    assert close(org, client_for, closed).status_code == 200
    opened = complete_case(org, owner)
    assert closed.effective_at < opened.effective_at
    assert assurance.due_cases(timezone.now(), 1) == [opened]
    assert assurance.due_cases(timezone.now(), 2) == [opened, closed]


def test_a_reading_that_began_before_closure_is_taken_again(org, client_for, monkeypatch):
    monkeypatch.setattr(assurance, "INTERVAL", timedelta(0))
    case = complete_case(org, client_for(org["alice"]))
    reviewer = client_for(org["clara"])

    class ClosingReader(Reader):
        def sign_in_events(self, subject, since_ms):
            if not self.calls:
                # The reviewer closes the case while this reading is in flight.
                assert (
                    post(reviewer, f"{PREFIX}/{case.pk}/close", close_input(case)).status_code
                    == 200
                )
            return super().sign_in_events(subject, since_ms)

    at = int(timezone.now().timestamp() * 1000) - 1000
    reader = ClosingReader([{"time": at, "type": "LOGIN", "clientId": "atlas-app", "error": ""}])
    before = ActivityCheck.objects.count()
    assert assurance.watch_departures(reader) == 0
    assert ActivityCheck.objects.count() == before
    assert assurance.watch_departures(reader) == 1
    case.refresh_from_db()
    assert assess(case)["watch"]["afterClosure"] == 1
    assert AuditEvent.objects.filter(action="departure.access_after_closure").exists()


def test_session_signal_ids_are_unique(org, signer):
    (first,) = ssf.emit("session-revoked", "s", "ref:" + secrets.token_hex(4))
    (second,) = ssf.emit("session-revoked", "s", "ref:" + secrets.token_hex(4))
    assert first.jti != second.jti and len(first.jti) == 32


def test_atlas_stream_gets_only_revocations_with_its_own_audience(org, settings, signer):
    settings.SSF_ATLAS_TOKEN = ATLAS_TOKEN
    ssf.emit("account-disabled", "worker", "test:disabled")
    ssf.emit("session-revoked", "worker", "test:revoked")
    ssf.emit("session-established", "worker", "test:established")
    ssf.emit("session-revoked", "worker", "test:revoked")
    rows = SecurityEvent.objects.values_list("receiver", "event_type")
    assert sorted(rows) == [
        ("atlas", "account-disabled"),
        ("atlas", "session-revoked"),
        ("soc", "account-disabled"),
        ("soc", "session-established"),
        ("soc", "session-revoked"),
    ]
    sets = poll(token=ATLAS_TOKEN).json()["sets"]
    assert len(sets) == 2
    for token in sets.values():
        claims = verify(token, audience="urn:accessops:atlas")
        assert claims["sub_id"]["sub"] == "worker"
        with pytest.raises(jwt.InvalidAudienceError):
            verify(token)


def test_each_receiver_polls_and_acknowledges_only_its_own_stream(org, settings, signer):
    settings.SSF_ATLAS_TOKEN = ATLAS_TOKEN
    ssf.emit("session-revoked", "worker", "test:revoked")
    atlas = poll(token=ATLAS_TOKEN).json()["sets"]
    soc = poll().json()["sets"]
    assert len(atlas) == len(soc) == 1 and atlas.keys() != soc.keys()
    # Acknowledging the SOC's event through Atlas's stream changes nothing.
    assert poll({"ack": list(soc)}, token=ATLAS_TOKEN).json()["sets"].keys() == atlas.keys()
    assert poll().json()["sets"].keys() == soc.keys()
    poll({"ack": list(atlas)}, token=ATLAS_TOKEN)
    assert poll(token=ATLAS_TOKEN).json()["sets"] == {}
    assert poll().json()["sets"].keys() == soc.keys()


def test_atlas_stream_is_off_until_its_token_is_set(org, settings, signer):
    settings.SSF_ATLAS_TOKEN = "too-short"
    ssf.emit("session-revoked", "worker", "test:revoked")
    assert list(SecurityEvent.objects.values_list("receiver", flat=True)) == ["soc"]
    assert poll(token="too-short").status_code == 401


def test_worker_emits_signals_when_containment_is_verified(org, client_for, signer):
    import httpx
    from core.models import OutboxJob
    from core.worker import process_one

    from integrations.keycloak import SESSIONS_ORIGIN, KeycloakConnector

    client = client_for(org["alice"])
    response = post(
        client,
        PREFIX,
        {
            "identityId": str(org["sponsor"].pk),
            "employmentType": "contractor",
            "hrEventId": "HR-SSF-" + secrets.token_hex(4),
            "hrSource": "Synthetic HR export",
            "effectiveAt": (timezone.now() - timedelta(minutes=5)).isoformat(),
            "reason": "Synthetic departure for signal emission",
            "bindings": [],
        },
    )
    assert response.status_code == 201, response.json()
    case_id = response.json()["result"]["id"]
    assert post(client, f"{PREFIX}/{case_id}/contain").status_code == 200
    case = OffboardingCase.objects.get(pk=case_id)
    job = OutboxJob.objects.get(request=case.containment_request)
    OutboxJob.objects.exclude(pk=job.pk).update(status="cancelled")
    subject = case.identity.subject

    def handle(request):
        if request.method == "POST":
            return httpx.Response(204)
        return httpx.Response(200, json=[])

    connector = KeycloakConnector(
        http=httpx.Client(transport=httpx.MockTransport(handle)),
        issuer="https://id.accessops.test/realms/accessops-workforce",
    )
    connector._call = lambda method, path, **kwargs: {"id": subject, "active": False}
    connector._token = lambda: "synthetic-placeholder"
    assert SESSIONS_ORIGIN and process_one(connector)
    job.refresh_from_db()
    assert job.status == "verified"
    assert sorted(SecurityEvent.objects.filter(case=case).values_list("event_type", flat=True)) == [
        "account-disabled",
        "session-revoked",
    ]
    before = assess(case)
    assert [item["eventType"] for item in before["signals"]] == [
        "account-disabled",
        "session-revoked",
    ]
    poll({"ack": [item["jti"] for item in before["signals"]]})
    after = assess(case)
    assert all(item["deliveredAt"] for item in after["signals"])
    assert after["packetHash"] == before["packetHash"]
