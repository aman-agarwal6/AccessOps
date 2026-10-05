"""Per-user session logout and session-count boundaries; all responses are synthetic."""

import httpx
import pytest

from integrations.errors import ConnectorError
from integrations.keycloak import (
    EVENTS_URL,
    SESSIONS_ORIGIN,
    SIGN_IN_REFUSED,
    SIGN_IN_SUCCESS,
    KeycloakConnector,
)

UID = "22222222-2222-4222-8222-222222222222"
BASE = SESSIONS_ORIGIN + "/admin/realms/accessops-workforce/users/" + UID
ISSUER = "https://id.accessops.test:8443/realms/accessops-workforce"


def make_connector(handle, user=None):
    calls = []

    def record(request):
        calls.append(request.method + " " + str(request.url))
        return handle(request)

    connector = KeycloakConnector(
        issuer=ISSUER, http=httpx.Client(transport=httpx.MockTransport(record))
    )
    connector._token = lambda: "synthetic-placeholder"
    state = {"active": True} if user is None else user

    def call(method, path, **kwargs):
        assert path == "/Users/" + UID
        calls.append("SCIM " + method)
        if method == "PATCH":
            state["active"] = kwargs["body"]["Operations"][0]["value"]
        return {"id": UID, "active": state["active"]}

    connector._call = call
    return connector, calls


def sessions(count, **extra):
    return [{"id": f"session-{i}", "userId": UID, **extra} for i in range(count)]


def test_session_count_reads_only_the_private_user_route():
    connector, calls = make_connector(lambda request: httpx.Response(200, json=sessions(2)))
    assert connector.count_sessions(UID) == 2
    assert calls == ["GET " + BASE + "/sessions"]


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(403, json=[]),
        httpx.Response(200, json={"sessions": []}),
        httpx.Response(200, json=sessions(501)),
        httpx.Response(200, json=[{"userId": UID}]),
        httpx.Response(200, json=sessions(1) * 2),
        httpx.Response(200, json=[{"id": "session-0", "userId": "someone-else"}]),
        httpx.Response(200, json=[{"id": "session-0"}]),
        httpx.Response(200, content=b"not json"),
    ],
)
def test_incomplete_or_foreign_session_reads_stay_unknown(response):
    connector, _ = make_connector(lambda request: response)
    with pytest.raises(ConnectorError):
        connector.count_sessions(UID)


def test_redirected_session_read_is_rejected():
    def handle(request):
        if request.url.path.endswith("/sessions"):
            return httpx.Response(302, headers={"location": "https://elsewhere.test/x"})
        return httpx.Response(200, json=[])

    connector, _ = make_connector(handle)
    with pytest.raises(ConnectorError):
        connector.count_sessions(UID)


@pytest.mark.parametrize(
    "subject", ["not-a-uuid", "../users", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", None]
)
def test_session_calls_require_an_exact_user_uuid(subject):
    connector, calls = make_connector(lambda request: httpx.Response(204))
    with pytest.raises(ConnectorError):
        connector.end_sessions(subject)
    with pytest.raises(ConnectorError):
        connector.count_sessions(subject)
    assert calls == []


@pytest.mark.parametrize("status", [200, 403, 404, 500])
def test_logout_must_return_no_content(status):
    connector, _ = make_connector(lambda request: httpx.Response(status))
    with pytest.raises(ConnectorError):
        connector.end_sessions(UID)


@pytest.mark.parametrize("left", [0, 1])
def test_offboard_disables_then_ends_sessions_and_verifies_none_remain(left):
    state = {"sessions": 3}

    def handle(request):
        if request.method == "POST":
            state["sessions"] = left
            return httpx.Response(204)
        return httpx.Response(200, json=sessions(state["sessions"]))

    connector, calls = make_connector(handle)
    result = connector.apply({"kind": "offboard"}, {"providerSubject": UID})
    assert calls == [
        "SCIM PATCH",
        "POST " + BASE + "/logout",
        "SCIM GET",
        "GET " + BASE + "/sessions",
    ]
    assert result["observed"] == {"active": False, "sessions": left}
    assert result["verified"] is (left == 0)


@pytest.mark.parametrize(
    ("status", "active", "count", "drift"),
    [
        ("offboarded", False, 0, False),
        ("offboarded", False, 1, True),
        ("offboarded", True, 0, True),
        ("active", True, 2, False),
    ],
)
def test_reconcile_counts_sessions_and_contained_accounts_must_have_none(
    status, active, count, drift
):
    connector, _ = make_connector(
        lambda request: httpx.Response(200, json=sessions(count)), user={"active": active}
    )
    result = connector.reconcile({"providerSubject": UID, "status": status})
    assert result == {"drift": drift, "observed": {"active": active, "sessions": count}}


def events_connector(records, status=200):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(status, json=records)

    connector = KeycloakConnector(
        issuer=ISSUER, http=httpx.Client(transport=httpx.MockTransport(handle))
    )
    connector._token = lambda: "synthetic-placeholder"
    return connector, seen


def record(**changes):
    value = {
        "time": 2_000,
        "type": "LOGIN",
        "userId": UID,
        "clientId": "atlas-app",
        "ipAddress": "10.0.0.9",
    }
    value.update(changes)
    return value


def test_sign_in_events_use_the_private_route_and_drop_addresses():
    connector, seen = events_connector(
        [record(), record(time=500), record(type="LOGIN_ERROR", error="user_disabled")]
    )
    events = connector.sign_in_events(UID, 1_000)
    assert str(seen[0].url).split("?", 1)[0] == EVENTS_URL
    assert seen[0].url.params["user"] == UID and seen[0].url.params["dateFrom"] == "1000"
    assert set(seen[0].url.params.get_list("type")) == set(SIGN_IN_SUCCESS + SIGN_IN_REFUSED)
    assert events == [
        {"time": 2_000, "type": "LOGIN", "clientId": "atlas-app", "error": ""},
        {"time": 2_000, "type": "LOGIN_ERROR", "clientId": "atlas-app", "error": "user_disabled"},
    ]
    assert "ipAddress" not in str(events)


@pytest.mark.parametrize(
    "records",
    [
        [record(userId="someone-else")],
        [record(type="UPDATE_PASSWORD")],
        [record(time="2000")],
        [record()] * 201,
        {"events": []},
    ],
)
def test_incomplete_or_foreign_event_reads_stay_unknown(records):
    connector, _ = events_connector(records)
    with pytest.raises(ConnectorError):
        connector.sign_in_events(UID, 0)


@pytest.mark.parametrize("args", [("not-a-uuid", 0), (UID, -1), (UID, "0")])
def test_event_reads_need_an_exact_account_and_window(args):
    connector, seen = events_connector([])
    with pytest.raises(ConnectorError):
        connector.sign_in_events(*args)
    assert seen == []


def test_event_read_refusal_stays_unknown():
    connector, _ = events_connector([], status=403)
    with pytest.raises(ConnectorError):
        connector.sign_in_events(UID, 0)
