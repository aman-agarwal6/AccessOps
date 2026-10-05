"""OIDC verification and confidential machine-client authentication."""

import os
import secrets
import threading
import time
from pathlib import Path

import httpx
import jwt

from .errors import IntegrationError, TokenValidationError
from .transport import checked_url, client, json_response

_keys = {}
_refresh_attempt = {}
_lock = threading.Lock()
# How long fetched signing keys are trusted before Keycloak's key set is read
# again. A key removed from the realm (say, after it leaked) stops being trusted
# within this time; a planned rotation publishes the new key at least this long
# before it signs anything.
KEY_CACHE_SECONDS = 60


def _issuer(name):
    value = os.getenv(name, "")
    return checked_url(value)


def _decode(token, issuer, audience, *, http=None, logout=False):
    if not isinstance(token, str) or not 1 <= len(token) <= 16384:
        raise TokenValidationError("Invalid token")
    try:
        header = jwt.get_unverified_header(token)
        allowed_types = ("JWT", "logout+jwt") if logout else ("JWT", "at+jwt")
        if (
            header.get("alg") != "RS256"
            or not isinstance(header.get("kid"), str)
            or not 1 <= len(header["kid"]) <= 128
            or header.get("typ", "JWT") not in allowed_types
            or any(k in header for k in ("jku", "x5u", "crit", "jwk", "x5c"))
        ):
            raise ValueError("Unsupported key metadata")
        with _lock:
            cached = _keys.get(issuer)
            needs_refresh = (
                not cached
                or cached[0] < time.monotonic()
                or not any(k.get("kid") == header["kid"] for k in cached[1])
            )
            if needs_refresh:
                # Unknown kids cannot amplify requests. Refreshes are serialized,
                # including failures, and limited to one per issuer per 30 seconds.
                now = time.monotonic()
                if now - _refresh_attempt.get(issuer, -1e9) < 30:
                    raise ValueError("Signing key refresh is rate limited")
                _refresh_attempt[issuer] = now
                connection = http or client()
                try:
                    response = connection.get(issuer + "/protocol/openid-connect/certs")
                    if response.status_code != 200:
                        raise ValueError("JWKS unavailable")
                    jwks = json_response(response, limit=131072)
                    if (
                        not isinstance(jwks, dict)
                        or not isinstance(jwks.get("keys"), list)
                        or not 1 <= len(jwks["keys"]) <= 20
                        or any(not isinstance(k, dict) for k in jwks["keys"])
                    ):
                        raise ValueError("Invalid JWKS")
                    cached = (time.monotonic() + KEY_CACHE_SECONDS, jwks["keys"])
                    _keys[issuer] = cached
                finally:
                    if http is None:
                        connection.close()
        matching = [
            k
            for k in cached[1]
            if k.get("kid") == header["kid"]
            and k.get("kty") == "RSA"
            and k.get("use", "sig") == "sig"
            and k.get("alg", "RS256") == "RS256"
            and "verify" in k.get("key_ops", ["verify"])
        ]
        if len(matching) != 1:
            raise ValueError("Unknown signing key")
        key = jwt.PyJWK.from_dict(matching[0], algorithm="RS256").key
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            leeway=5,
            options={
                "require": ["iat", "iss", "aud", "jti"]
                if logout
                else ["exp", "iat", "iss", "aud", "sub"]
            },
        )
    except (
        jwt.PyJWTError,
        httpx.HTTPError,
        IntegrationError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        raise TokenValidationError("Token verification failed") from exc


def verify_executor_token(token, dpop_proof=None, method=None, url=None):
    if dpop_proof:
        raise TokenValidationError("DPoP is not enabled in the stable profile")
    try:
        claims = _decode(
            token, _issuer("WORKFORCE_ISSUER"), os.getenv("EXECUTOR_AUDIENCE", "accessops-api")
        )
        if claims.get("azp") != os.getenv("EXECUTOR_CLIENT_ID", "accessops-executor"):
            raise ValueError("Wrong client")
        if not isinstance(claims.get("sub"), str) or not 1 <= len(claims["sub"]) <= 255:
            raise ValueError("Invalid subject")
        if (
            claims.get("typ") != "Bearer"
            or "act" in claims
            or "may_act" in claims
            or "cnf" in claims
        ):
            raise ValueError("Unsupported delegation")
        if (
            not isinstance(claims.get("scope"), str)
            or "accessops:tools" not in claims["scope"].split()
        ):
            raise ValueError("Missing tool scope")
        return claims
    except (IntegrationError, ValueError, TypeError) as exc:
        raise TokenValidationError("Executor token rejected") from exc


def verify_logout_token(token):
    # Backend must atomically deduplicate jti and invalidate matching local sessions.
    try:
        claims = _decode(
            token,
            _issuer("OIDC_ISSUER"),
            os.getenv("OIDC_CLIENT_ID", "accessops-console"),
            logout=True,
        )
        event = "http://schemas.openid.net/event/backchannel-logout"
        if (
            not isinstance(claims.get("events", {}).get(event), dict)
            or "nonce" in claims
            or not claims.get("jti")
        ):
            raise ValueError("Invalid logout event")
        if time.time() - claims["iat"] > 120 or not (claims.get("sid") or claims.get("sub")):
            raise ValueError("Expired logout event")
        return claims
    except (IntegrationError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise TokenValidationError("Logout token rejected") from exc


class ExecutorClient:
    def __init__(self, *, http=None):
        self.issuer = _issuer("WORKFORCE_ISSUER")
        self.client_id = os.getenv("EXECUTOR_CLIENT_ID", "accessops-executor")
        self.private_key_file = os.getenv("EXECUTOR_PRIVATE_KEY_FILE", "")
        self.key_id = os.getenv("EXECUTOR_KEY_ID", "accessops-executor-1")
        self.http = http or client()

    def _assertion(self, audience):
        if not self.private_key_file:
            raise TokenValidationError("Executor signing key is not configured")
        now = int(time.time())
        try:
            key = Path(self.private_key_file).read_bytes()
            return jwt.encode(
                {
                    "iss": self.client_id,
                    "sub": self.client_id,
                    "aud": audience,
                    "iat": now,
                    "exp": now + 60,
                    "jti": secrets.token_urlsafe(24),
                },
                key,
                algorithm="RS256",
                headers={"kid": self.key_id},
            )
        except (OSError, ValueError, jwt.PyJWTError) as exc:
            raise TokenValidationError("Executor signing key unavailable") from exc

    def token(self):
        endpoint = self.issuer + "/protocol/openid-connect/token"
        try:
            response = self.http.post(
                endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "scope": os.getenv("EXECUTOR_SCOPE", "accessops:tools"),
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": self._assertion(endpoint),
                },
            )
            if response.status_code != 200:
                raise TokenValidationError("Executor authentication rejected")
            data = json_response(response, limit=32768)
            if data.get("token_type", "").lower() != "bearer" or not isinstance(
                data.get("access_token"), str
            ):
                raise TokenValidationError("Invalid token response")
            return data["access_token"]
        except (httpx.HTTPError, IntegrationError) as exc:
            raise TokenValidationError("Executor token unavailable") from exc

    def introspect(self, token):
        endpoint = self.issuer + "/protocol/openid-connect/token/introspect"
        api_client = os.getenv("INTROSPECTION_CLIENT_ID", "accessops-api")
        api_secret = os.getenv("INTROSPECTION_CLIENT_SECRET", "")
        if len(api_secret) < 32:
            raise TokenValidationError("API introspection credentials are not configured")
        try:
            # The resource server is the token audience. Its role-free confidential
            # client authenticates introspection; it cannot mint executor tokens.
            response = self.http.post(
                endpoint,
                data={"token": token, "client_id": api_client, "client_secret": api_secret},
            )
            if response.status_code != 200:
                raise TokenValidationError("Introspection unavailable")
            result = json_response(response, limit=32768)
            if type(result.get("active")) is not bool:
                raise TokenValidationError("Invalid introspection result")
            return result
        except (httpx.HTTPError, IntegrationError) as exc:
            raise TokenValidationError("Introspection unavailable") from exc
