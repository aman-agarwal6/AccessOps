import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from integrations import security
from integrations.authzen_server import decide, normalize
from integrations.errors import ConnectorError, TokenValidationError
from integrations.keycloak import KeycloakConnector
from integrations.policy import PolicyClient

ISSUER = "https://id.accessops.test:8443/realms/accessops-workforce"
OPERATOR = "https://id.accessops.test:8443/realms/accessops-operators"


@pytest.fixture
def signing(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="test-key", use="sig", alg="RS256")
    security._keys.clear()
    security._refresh_attempt.clear()
    monkeypatch.setenv("WORKFORCE_ISSUER", ISSUER)
    monkeypatch.setenv("OIDC_ISSUER", OPERATOR)
    monkeypatch.setenv("OIDC_CLIENT_ID", "accessops-console")
    security._keys[ISSUER] = (time.monotonic() + 300, [jwk])
    security._keys[OPERATOR] = (time.monotonic() + 300, [jwk])
    return key, jwk


def token(key, **changes):
    claims = {
        "iss": ISSUER,
        "aud": "accessops-api",
        "sub": "agent-1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 120,
        "azp": "accessops-executor",
        "typ": "Bearer",
        "scope": "accessops:tools",
    }
    claims.update(changes)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})


def test_executor_accepts_only_workforce_bound_client(signing):
    assert security.verify_executor_token(token(signing[0]))["sub"] == "agent-1"


@pytest.mark.parametrize(
    "change",
    [
        {"iss": OPERATOR},
        {"aud": "other"},
        {"azp": "other"},
        {"scope": "openid"},
        {"exp": int(time.time()) - 120},
        {"act": {"sub": "sponsor"}},
        {"cnf": {}},
        {"typ": "ID"},
    ],
)
def test_executor_rejects_confused_or_expired_tokens(signing, change):
    with pytest.raises(TokenValidationError):
        security.verify_executor_token(token(signing[0], **change))


def test_dpop_profile_not_falsely_accepted(signing):
    with pytest.raises(TokenValidationError):
        security.verify_executor_token(token(signing[0]), "unsupported-proof")


def logout(key, **changes):
    claims = {
        "iss": OPERATOR,
        "aud": "accessops-console",
        "iat": int(time.time()),
        "jti": "logout-unique",
        "sid": "session-only",
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    }
    claims.update(changes)
    return jwt.encode(
        claims, key, algorithm="RS256", headers={"kid": "test-key", "typ": "logout+jwt"}
    )


def test_logout_supports_sid_without_exp_or_sub(signing):
    assert security.verify_logout_token(logout(signing[0]))["sid"] == "session-only"


@pytest.mark.parametrize(
    "change",
    [
        {"nonce": "forbidden"},
        {"events": {}},
        {"sid": None},
        {"iat": int(time.time()) - 300},
        {"iat": int(time.time()) + 60},
        {"exp": int(time.time()) - 60},
        {"iss": ISSUER},
        {"aud": "accessops-api"},
    ],
)
def test_logout_invalid_events_denied(signing, change):
    with pytest.raises(TokenValidationError):
        security.verify_logout_token(logout(signing[0], **change))


def test_unknown_kid_refresh_bounded(signing):
    security._keys.clear()
    calls = []

    def handle(request):
        calls.append(request.url)
        return httpx.Response(200, json={"keys": [signing[1]]})

    connection = httpx.Client(transport=httpx.MockTransport(handle))
    for kid in ("unknown-one", "unknown-two"):
        raw = jwt.encode({"iss": ISSUER}, signing[0], algorithm="RS256", headers={"kid": kid})
        with pytest.raises(TokenValidationError):
            security._decode(raw, ISSUER, "accessops-api", http=connection)
    assert len(calls) == 1


def test_key_rotation_after_refresh_interval(signing, monkeypatch):
    security._keys.clear()
    security._refresh_attempt[ISSUER] = time.monotonic() - 31
    connection = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"keys": [signing[1]]}))
    )
    assert (
        security._decode(token(signing[0]), ISSUER, "accessops-api", http=connection)["sub"]
        == "agent-1"
    )


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"decision": 1},
        {"decision": "true"},
        {"decision": True},
        {"decision": False, "context": []},
    ],
)
def test_authzen_missing_or_malformed_decision_fails_closed(body):
    connection = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=body))
    )
    result = PolicyClient(token="x" * 40, http=connection).evaluate({"subject": {"id": "a"}})
    assert result["allow"] is False


def evaluation():
    return {
        "subject": {
            "type": "identity",
            "id": "operator-a",
            "properties": {
                "kind": "human",
                "status": "active",
                "roles": ["operator"],
                "project_ids": ["Atlas"],
            },
        },
        "action": {"name": "execute"},
        "resource": {
            "type": "accessops-resource",
            "id": "resource-a",
            "properties": {"project": "Atlas"},
        },
        "context": {
            "policy_version": "accessops-v1",
            "approval_valid": True,
            "request": {"action": "grant", "policy_version": "accessops-v1"},
        },
    }


def test_undefined_opa_response_fails_closed():
    connection = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(RuntimeError):
        decide(evaluation(), connection)


def test_authzen_boolean_not_string():
    body = evaluation()
    body["context"]["approval_valid"] = "true"
    with pytest.raises(ValueError):
        normalize(body)


def test_scim_cannot_target_operator_realm():
    with pytest.raises(ConnectorError):
        KeycloakConnector(issuer=OPERATOR)


def test_scim_membership_patch_and_confirmation():
    requests = []

    def handle(request):
        requests.append(request)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "opaque-test-only", "expires_in": 120})
        if request.method == "PATCH":
            body = json.loads(request.content)
            assert body["Operations"][0] == {"op": "remove", "path": 'members[value eq "user-1"]'}
            return httpx.Response(
                200, json={"id": "group-1", "displayName": "accessops-test", "members": []}
            )
        return httpx.Response(
            200,
            json={
                "id": "group-1",
                "displayName": "accessops-test",
                "members": [{"value": "user-1"}],
            },
        )

    connector = KeycloakConnector(
        issuer=ISSUER,
        client_secret="x" * 40,
        http=httpx.Client(transport=httpx.MockTransport(handle)),
    )
    connector.set_membership("group-1", "user-1", False)
    assert len(requests) == 3


def test_scim_namespace_and_credentials_fail_closed():
    connector = KeycloakConnector(
        issuer=ISSUER,
        client_secret="x" * 40,
        http=httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(403, json={"error": "denied"}))
        ),
    )
    with pytest.raises(ConnectorError):
        connector.get_user("anything")
    with pytest.raises(ConnectorError):
        connector.create_group("operators")
    with pytest.raises(ConnectorError):
        connector.patch_user("user-1", [{"op": "replace", "path": "roles", "value": ["admin"]}])
