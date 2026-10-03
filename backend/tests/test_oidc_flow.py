"""Exercise Authlib's real state, nonce, PKCE and signature validation locally."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db


@pytest.fixture
def provider(org, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "synthetic-signing-key", "alg": "RS256", "use": "sig"})
    state = {"nonce": None, "challenge": None, "claims_change": {}, "token_calls": 0}

    def transport(self, method, url, **kwargs):
        issuer = settings.OIDC_ISSUER
        response = requests.Response()
        response.status_code = 200
        response.url = url
        if url == issuer + "/.well-known/openid-configuration":
            data = {
                "issuer": issuer,
                "authorization_endpoint": issuer + "/authorize",
                "token_endpoint": issuer + "/token",
                "jwks_uri": issuer + "/certs",
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            }
        elif url == issuer + "/certs":
            data = {"keys": [jwk]}
        elif url == issuer + "/token":
            state["token_calls"] += 1
            body = kwargs["data"]
            if isinstance(body, str):
                body = {k: v[0] for k, v in parse_qs(body).items()}
            verifier = body["code_verifier"]
            assert (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .rstrip(b"=")
                .decode()
                == state["challenge"]
            )
            assert body["grant_type"] == "authorization_code"
            claims = {
                "iss": issuer,
                "sub": org["alice"].subject,
                "aud": settings.OIDC_CLIENT_ID,
                "iat": int(time.time()),
                "exp": int(time.time()) + 60,
                "nonce": state["nonce"],
                "accessops_roles": ["operator"],
                "accessops_projects": ["Atlas"],
                "sid": "synthetic-oidc-session",
                **state["claims_change"],
            }
            encoded = jwt.encode(claims, key, algorithm="RS256", headers={"kid": jwk["kid"]})
            data = {
                "access_token": "synthetic-access-token",
                "token_type": "Bearer",
                "expires_in": 60,
                "id_token": encoded,
            }
        else:
            raise AssertionError("Unexpected outbound destination")
        response._content = json.dumps(data).encode()
        response.headers["Content-Type"] = "application/json"
        return response

    monkeypatch.setattr(requests.sessions.Session, "request", transport)
    return state


def begin(provider):
    client = APIClient()
    response = client.get("/auth/login")
    assert response.status_code == 302
    query = parse_qs(urlparse(response["Location"]).query)
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == [settings.OIDC_REDIRECT_URI]
    provider["nonce"] = query["nonce"][0]
    provider["challenge"] = query["code_challenge"][0]
    return client, query["state"][0]


def test_real_authlib_code_pkce_nonce_signature_flow(org, provider):
    client, state = begin(provider)
    response = client.get(
        "/auth/callback", {"code": "synthetic-authorization-code", "state": state}
    )
    assert response.status_code == 302
    assert client.get("/api/v1/session").json()["authenticated"] is True
    assert provider["token_calls"] == 1
    assert not any(k in client.session for k in ("access_token", "refresh_token", "id_token"))


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://wrong.invalid"},
        {"aud": "wrong-client"},
        {"nonce": "wrong-nonce"},
        {"exp": 1},
        {"nonce_supported": False},
    ],
)
def test_signed_but_invalid_oidc_claims_cannot_create_session(org, provider, change):
    client, state = begin(provider)
    provider["claims_change"] = change
    assert (
        client.get("/auth/callback", {"code": "synthetic-code", "state": state}).status_code == 401
    )
    assert client.get("/api/v1/session").json()["authenticated"] is False


def test_wrong_state_and_code_replay_rejected_before_token_exchange(org, provider):
    client, state = begin(provider)
    assert (
        client.get(
            "/auth/callback", {"code": "synthetic-code", "state": "incorrect-state"}
        ).status_code
        == 401
    )
    assert provider["token_calls"] == 0
    client, state = begin(provider)
    assert (
        client.get("/auth/callback", {"code": "synthetic-code", "state": state}).status_code == 302
    )
    assert (
        client.get("/auth/callback", {"code": "synthetic-code", "state": state}).status_code == 401
    )
    assert provider["token_calls"] == 1
