"""Entra connector against a simulated Microsoft Graph; synthetic IDs only."""

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from integrations import entra
from integrations.errors import ConnectorError

TENANT = "11111111-1111-4111-8111-111111111111"
CLIENT = "22222222-2222-4222-8222-222222222222"
USER = "33333333-3333-4333-8333-333333333333"
OTHER_USER = "44444444-4444-4444-8444-444444444444"
GROUP = "55555555-5555-4555-8555-555555555555"
ADMIN = "66666666-6666-4666-8666-666666666666"
ROLE = "77777777-7777-4777-8777-777777777777"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
BINDING = {"tenantId": TENANT, "userId": USER, "groupIds": [GROUP]}


def config(**changes):
    value = {
        "tenantId": TENANT,
        "clientId": CLIENT,
        "x5t": "c3ludGhldGljLXRodW1icHJpbnQ",
        "keyFile": None,
        "protected": {ADMIN},
        "users": {USER, OTHER_USER},
        "groups": {GROUP},
    }
    value.update(changes)
    return value


class Graph:
    """Just enough of Graph and the token endpoint, recording every request."""

    def __init__(self, *, enabled=True, member=True, roles=(), stale_reads=0, tenant=TENANT):
        self.enabled, self.member, self.roles = enabled, member, list(roles)
        self.revoked_at, self.stale_reads, self.tenant = None, stale_reads, tenant
        self.requests, self.assertions = [], []

    def __call__(self, request):
        path = request.url.path
        self.requests.append((request.method, path))
        if request.url.host == "login.microsoftonline.com":
            self.assertions.append(parse_qs(request.content.decode())["client_assertion"][0])
            return httpx.Response(
                200, json={"access_token": "synthetic-graph-token", "expires_in": 3600}
            )
        assert request.headers["Authorization"] == "Bearer synthetic-graph-token"
        if path == "/v1.0/organization":
            return httpx.Response(200, json={"value": [{"id": self.tenant}]})
        if path == f"/v1.0/users/{USER}" and request.method == "GET":
            enabled = self.enabled
            if self.stale_reads:
                self.stale_reads -= 1
                enabled = True
            return httpx.Response(
                200,
                json={
                    "id": USER,
                    "accountEnabled": enabled,
                    "signInSessionsValidFromDateTime": self.revoked_at,
                },
            )
        if path == f"/v1.0/users/{USER}" and request.method == "PATCH":
            assert json.loads(request.content) == {"accountEnabled": False}
            self.enabled = False
            return httpx.Response(204)
        if path == f"/v1.0/users/{USER}/memberOf":
            values = [{"@odata.type": "#microsoft.graph.group", "id": GROUP}] if self.member else []
            values += [
                {"@odata.type": "#microsoft.graph.directoryRole", "id": r} for r in self.roles
            ]
            return httpx.Response(200, json={"value": values})
        if path == f"/v1.0/groups/{GROUP}/members/{USER}/$ref" and request.method == "DELETE":
            was, self.member = self.member, False
            return httpx.Response(204 if was else 404)
        if path == f"/v1.0/users/{USER}/revokeSignInSessions":
            self.revoked_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.1234567Z")
            return httpx.Response(200, json={"value": True})
        return httpx.Response(404)


def connector(graph, **changes):
    return entra.EntraConnector(
        http=httpx.Client(transport=httpx.MockTransport(graph)),
        config=config(**changes),
        private_key=KEY,
        sleep=lambda seconds: None,
    )


def writes(graph):
    return [
        r for r in graph.requests if r[0] in ("PATCH", "DELETE", "POST") and "oauth2" not in r[1]
    ]


def since():
    return datetime.now(UTC) - timedelta(minutes=1)


def test_offboard_disables_removes_revokes_and_reads_back():
    graph = Graph()
    result = connector(graph).offboard(BINDING, since())
    assert result["verified"] is True
    assert result["observed"] == {
        "provider": "entra",
        "tenantId": TENANT,
        "userId": USER,
        "active": False,
        "privileged": False,
        "groups": [{"groupId": GROUP, "member": False}],
        "sessionsValidFrom": graph.revoked_at,
    }
    assert writes(graph) == [
        ("PATCH", f"/v1.0/users/{USER}"),
        ("DELETE", f"/v1.0/groups/{GROUP}/members/{USER}/$ref"),
        ("POST", f"/v1.0/users/{USER}/revokeSignInSessions"),
    ]


def test_an_already_disabled_account_is_never_re_enabled_or_re_added():
    graph = Graph(enabled=False, member=False)
    result = connector(graph).offboard(BINDING, since())
    assert result["verified"] is True
    assert writes(graph) == [("POST", f"/v1.0/users/{USER}/revokeSignInSessions")]


@pytest.mark.parametrize(
    "binding, changes",
    [
        ({**BINDING, "userId": ADMIN}, {"users": {USER, ADMIN}}),
        ({**BINDING, "userId": "88888888-8888-4888-8888-888888888888"}, {}),
        ({**BINDING, "groupIds": ["99999999-9999-4999-8999-999999999999"]}, {}),
        ({**BINDING, "tenantId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, {}),
    ],
    ids=["protected", "unlisted-user", "unlisted-group", "other-tenant"],
)
def test_objects_outside_scope_are_refused_before_any_request(binding, changes):
    graph = Graph()
    with pytest.raises(ConnectorError):
        connector(graph, **changes).offboard(binding, since())
    assert graph.requests == []


def test_a_user_holding_a_directory_role_is_never_changed():
    graph = Graph(roles=[ROLE])
    with pytest.raises(ConnectorError, match="directory role"):
        connector(graph).offboard(BINDING, since())
    assert writes(graph) == []


def test_a_different_tenant_answering_stops_before_any_write():
    graph = Graph(tenant="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    with pytest.raises(ConnectorError, match="tenant"):
        connector(graph).offboard(BINDING, since())
    assert writes(graph) == []


def test_eventual_consistency_is_read_again_and_a_stale_read_never_verifies():
    graph = Graph(stale_reads=2)
    assert connector(graph).offboard(BINDING, since())["verified"] is True
    graph = Graph(stale_reads=10)
    assert connector(graph).offboard(BINDING, since())["verified"] is False


def test_sessions_revoked_before_the_departure_do_not_count():
    graph = Graph()
    result = connector(graph).offboard(BINDING, datetime.now(UTC) + timedelta(minutes=5))
    assert result["verified"] is False


def test_the_client_assertion_is_a_short_certificate_signed_jwt():
    graph = Graph()
    client = connector(graph)
    client.validate_binding(BINDING)
    client.validate_binding(BINDING)
    (assertion,) = graph.assertions  # The token is reused, not fetched per call.
    header = jwt.get_unverified_header(assertion)
    claims = jwt.decode(
        assertion,
        KEY.public_key(),
        algorithms=["RS256"],
        audience=f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    )
    assert header["alg"] == "RS256" and header["x5t"] == "c3ludGhldGljLXRodW1icHJpbnQ"
    assert claims["iss"] == claims["sub"] == CLIENT and claims["exp"] - claims["iat"] <= 300


def test_malformed_or_incomplete_readings_raise_instead_of_verifying():
    observed = {
        "provider": "entra",
        "tenantId": TENANT,
        "userId": USER,
        "active": False,
        "privileged": False,
        "groups": [{"groupId": GROUP, "member": "false"}],
        "sessionsValidFrom": "2026-10-05T17:00:00Z",
    }
    with pytest.raises(ConnectorError):
        entra.verified_result(BINDING, observed, since())
    with pytest.raises(ConnectorError):
        entra.verified_result(BINDING, {**observed, "groups": []}, since())


def test_configuration_cannot_list_a_protected_object_as_managed(tmp_path):
    lab = {
        "schema_version": 1,
        "tenant_id": TENANT,
        "client_id": CLIENT,
        "certificate_sha1_thumbprint": "ab" * 20,
        "private_key_file": ".local/entra/connector-key.pem",
        "protected_object_ids": [ADMIN],
        "test_users": [{"label": "leaver-1", "object_id": USER}],
        "test_group": {"label": "readers", "object_id": GROUP},
        "admin_consent_granted_at": None,
    }
    path = tmp_path / "lab.json"
    path.write_text(json.dumps(lab))
    with pytest.raises(ValueError, match="consent"):
        entra.load_config(path)
    lab["admin_consent_granted_at"] = "2026-10-05T18:00:00Z"
    path.write_text(json.dumps(lab))
    loaded = entra.load_config(path)
    assert loaded["users"] == {USER} and loaded["keyFile"] == tmp_path / "connector-key.pem"
    lab["test_users"].append({"label": "admin", "object_id": ADMIN.upper()})
    path.write_text(json.dumps(lab))
    with pytest.raises(ValueError, match="protected"):
        entra.load_config(path)
