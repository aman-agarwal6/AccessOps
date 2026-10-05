"""Post-departure activity watch and signed leaver signals; synthetic data only."""

import secrets
from datetime import timedelta

import jwt
import pytest
from core import assurance, ssf
from core.models import ActivityCheck, OffboardingCase, SecurityEvent
from core.offboarding import assess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.utils import timezone
from rest_framework.test import APIClient
from tests.test_offboarding_cases import PREFIX, complete_case, post

from integrations.errors import ConnectorError

pytestmark = pytest.mark.django_db
TOKEN = "synthetic-receiver-token-" + "x" * 24
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
RISC = "https://schemas.openid.net/secevent/risc/event-type/"


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


def verify(token):
    key = jwt.PyJWK.from_dict(APIClient().get("/api/v1/ssf/jwks").json()["keys"][0])
    assert jwt.get_unverified_header(token)["typ"] == "secevent+jwt"
    return jwt.decode(token, key.key, algorithms=["ES256"], audience="urn:accessops:soc-receiver")


def poll(body=None, token=TOKEN):
    return APIClient().post(
        "/api/v1/ssf/poll", body or {}, format="json", HTTP_AUTHORIZATION="Bearer " + token
    )


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
    case = complete_case(org, client_for(org["alice"]))
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
    case = complete_case(org, client_for(org["alice"]))
    assurance.watch_departures(Reader(fail=True))
    assert ActivityCheck.objects.get(case=case).status == "unavailable"
    assert "Since the departure" not in keycloak_task(case)["evidenceSummary"]


def test_watch_reads_only_contained_open_cases_within_the_event_window(org, client_for):
    case = complete_case(org, client_for(org["alice"]))
    OffboardingCase.objects.filter(pk=case.pk).update(
        effective_at=timezone.now() - timedelta(hours=25)
    )
    reader = Reader()
    assert assurance.watch_departures(reader) == 0 and reader.calls == []


def test_watch_is_off_without_an_events_client_secret(org, client_for, settings):
    settings.EVENTS_CLIENT_SECRET = ""
    complete_case(org, client_for(org["alice"]))
    assert assurance.watch_departures() == 0
    assert not ActivityCheck.objects.exists()


def test_session_signal_ids_are_unique(org, signer):
    first = ssf.emit("session-revoked", "s", "ref:" + secrets.token_hex(4))
    second = ssf.emit("session-revoked", "s", "ref:" + secrets.token_hex(4))
    assert first.jti != second.jti and len(first.jti) == 32


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
