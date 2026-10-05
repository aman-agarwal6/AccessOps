"""Atlas workspace: a lab-only web app that workforce users sign in to.

It exists so offboarding has real application sessions and tokens to end. It is
an OpenID Connect relying party in the workforce realm (authorization code with
PKCE, confidential client) that keeps sessions in memory and accepts
OpenID Connect Back-Channel Logout 1.0. Its API also accepts bearer tokens from
the Atlas command-line client, checked one of two ways so the difference is
measurable: by asking Keycloak (introspection) or locally, by verifying the
signature and expiry.

Local checking alone would accept a revoked token until it expires, so Atlas
also follows AccessOps' Shared Signals stream: it polls for CAEP session-revoked
and RISC account-disabled events once a second and refuses any token issued
before a revocation of its subject. When the stream has not been read in the
last ten seconds, or a token predates this process (revocations seen by an
earlier process are lost), Atlas asks Keycloak instead of trusting the token.

It is not part of AccessOps. Its only AccessOps credential is its own signal
stream's poll token. It never stores tokens: only the verified subject and
Keycloak session ID of each signed-in browser, and revocation times by subject.
"""

import base64
import hashlib
import json
import os
import secrets
import signal
import sys
import threading
import time
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt

from integrations.errors import IntegrationError, TokenValidationError
from integrations.security import _decode
from integrations.transport import checked_url, client, json_response

ISSUER = checked_url(os.environ.get("WORKFORCE_ISSUER", ""))
ORIGIN = checked_url(os.environ.get("ATLAS_ORIGIN", "https://atlas.accessops.internal:8186"))
CLIENT_ID = "atlas-app"
SECRET = os.environ.get("ATLAS_CLIENT_SECRET", "")
EVENT = "http://schemas.openid.net/event/backchannel-logout"
LIMIT = 1000
SIGNALS = checked_url(os.environ.get("ATLAS_SIGNAL_ISSUER", "https://accessops.test:8443"))
SIGNAL_TOKEN = os.environ.get("ATLAS_SIGNAL_TOKEN", "")
SIGNAL_AUDIENCE = "urn:accessops:atlas"
REVOCATIONS = {
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
}
FRESH = 10  # seconds a stream reading stays current
KEEP = 3600  # seconds a revocation is kept; access tokens live for two minutes
STARTED = int(time.time())

lock = threading.Lock()
pending = {}  # login cookie -> state, nonce, PKCE verifier, created
sessions = {}  # session cookie -> verified subject and Keycloak session ID
ended = {}  # session cookie -> why it ended (bounded tombstones)
seen_logout = {}  # logout token jti -> iat, for replay refusal
revoked = {}  # subject -> latest revocation time from the signal stream
feed = {"readAt": None, "keysAt": -1e9, "keys": {}}  # stream reading and signal keys


def bounded_put(store, key, value):
    store[key] = value
    while len(store) > LIMIT:
        store.pop(next(iter(store)))


def cookie_value(header, name):
    try:
        morsel = SimpleCookie(header or "").get(name)
    except CookieError:
        return None
    value = morsel.value if morsel else None
    return value if value and 20 <= len(value) <= 64 else None


def set_cookie(name, value, max_age):
    return f"{name}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax"


def end_sessions(claims):
    """End local sessions named by a verified logout token: its sid, else every
    session of its subject."""
    with lock:
        doomed = [
            key
            for key, item in sessions.items()
            if (item["sid"] == claims["sid"] if claims.get("sid") else item["sub"] == claims["sub"])
        ]
        for key in doomed:
            sessions.pop(key)
            bounded_put(ended, key, "backchannel_logout")
    return len(doomed)


def logout_claims(content_type, body):
    """Verify an OpenID Connect Back-Channel Logout request and record its jti.
    Raises on anything that is not exactly one fresh, signed, unreplayed token."""
    if not content_type.startswith("application/x-www-form-urlencoded"):
        raise ValueError("Unexpected logout request")
    token = parse_qs(body.decode("ascii"), max_num_fields=4).get("logout_token", [])
    if len(token) != 1 or not token[0]:
        raise ValueError("Exactly one logout token is required")
    claims = _decode(token[0], ISSUER, CLIENT_ID, logout=True)
    if (
        not isinstance(claims.get("events", {}).get(EVENT), dict)
        or "nonce" in claims
        or not isinstance(claims.get("jti"), str)
        or abs(time.time() - claims["iat"]) > 120
        or not (claims.get("sid") or claims.get("sub"))
    ):
        raise ValueError("Invalid logout event")
    with lock:
        if claims["jti"] in seen_logout:
            raise ValueError("Replayed logout token")
        bounded_put(seen_logout, claims["jti"], claims["iat"])
    return claims


def signal_key(kid):
    """AccessOps' ES256 signal key by kid; refetched at most once a minute."""
    if kid not in feed["keys"] and time.monotonic() - feed["keysAt"] >= 60:
        feed["keysAt"] = time.monotonic()
        with client(timeout=5) as http:
            response = http.get(SIGNALS + "/api/v1/ssf/jwks")
            keys = json_response(response, limit=65536).get("keys", [])
        try:
            if response.status_code != 200 or not isinstance(keys, list) or len(keys) > 10:
                raise ValueError("Signal keys unavailable")
            feed["keys"] = {
                item["kid"]: jwt.PyJWK.from_dict(item, algorithm="ES256").key
                for item in keys
                if isinstance(item, dict) and item.get("kty") == "EC" and item.get("crv") == "P-256"
            }
        except (jwt.PyJWTError, ValueError, KeyError) as error:
            # Never final: the events stay queued until the keys can be read.
            raise LookupError("Signal keys unavailable") from error
    if kid not in feed["keys"]:
        raise LookupError("Unknown signal key")
    return feed["keys"][kid]


def signal_claims(token):
    """Verify one Security Event Token from AccessOps' Atlas stream."""
    header = jwt.get_unverified_header(token)
    if header.get("typ") != "secevent+jwt" or header.get("alg") != "ES256":
        raise ValueError("Unexpected signal header")
    claims = jwt.decode(
        token,
        signal_key(str(header.get("kid", ""))),
        algorithms=["ES256"],
        audience=SIGNAL_AUDIENCE,
        issuer=SIGNALS,
        options={"require": ["iss", "aud", "iat", "jti"]},
    )
    subject = claims.get("sub_id")
    if (
        not isinstance(subject, dict)
        or subject.get("format") != "iss_sub"
        or subject.get("iss") != ISSUER
        or not isinstance(subject.get("sub"), str)
        or not isinstance(claims.get("events"), dict)
    ):
        raise ValueError("Unexpected signal subject")
    return claims


def record_revocation(claims):
    for uri, event in claims["events"].items():
        stamp = event.get("event_timestamp") if isinstance(event, dict) else None
        if uri in REVOCATIONS and isinstance(stamp, int):
            subject = claims["sub_id"]["sub"]
            with lock:
                for old in [key for key, value in revoked.items() if value < time.time() - KEEP]:
                    revoked.pop(old)
                revoked[subject] = max(revoked.get(subject, 0), stamp)


def follow_signals():
    """Poll AccessOps once a second; acknowledge each event only once stored.
    An event whose key cannot be fetched yet is left to be offered again."""
    ack, errors = [], {}
    while True:
        try:
            with client(timeout=5) as http:
                while True:
                    response = http.post(
                        SIGNALS + "/api/v1/ssf/poll",
                        json={"maxEvents": 50, "ack": ack, "setErrs": errors},
                        headers={"Authorization": "Bearer " + SIGNAL_TOKEN},
                    )
                    if response.status_code != 200:
                        raise ValueError("Signal poll refused")
                    sets = json_response(response, limit=262144).get("sets", {})
                    ack, errors = [], {}
                    for jti, token in sets.items():
                        try:
                            record_revocation(signal_claims(token))
                            ack.append(jti)
                        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
                            errors[jti] = {"err": "invalid_request"}
                        except (LookupError, httpx.HTTPError, IntegrationError):
                            pass
                    with lock:
                        feed["readAt"] = time.monotonic()
                    time.sleep(0 if ack or errors else 1)
        except (httpx.HTTPError, IntegrationError, ValueError, AttributeError):
            time.sleep(2)


def local_verdict(claims):
    """'accept', 'revoked', or 'ask' when only Keycloak can still decide."""
    if len(SIGNAL_TOKEN) < 32:
        return "accept"  # No signal stream: a plain locally validating app.
    with lock:
        current = feed["readAt"] is not None and time.monotonic() - feed["readAt"] <= FRESH
        revoked_at = revoked.get(claims["sub"])
    if not current or claims["iat"] < STARTED:
        return "ask"
    return "revoked" if revoked_at is not None and claims["iat"] <= revoked_at else "accept"


def signal_state():
    if len(SIGNAL_TOKEN) < 32:
        return "off"
    with lock:
        read = feed["readAt"]
    return "current" if read is not None and time.monotonic() - read <= FRESH else "stale"


class Atlas(BaseHTTPRequestHandler):
    server_version = "AtlasLab"
    sys_version = ""

    def log_message(self, format, *args):
        # Never log query strings: they carry authorization codes and state.
        print(f"{self.command} {urlsplit(self.path).path} {args[1] if len(args) > 1 else ''}")

    def reply(self, status, body=None, headers=()):
        data = json.dumps(body or {}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, headers=()):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/health":
            return self.reply(
                200 if len(SECRET) >= 32 else 503, {"status": "ok", "signals": signal_state()}
            )
        if url.path == "/login":
            return self.login()
        if url.path == "/callback":
            return self.callback(parse_qs(url.query))
        if url.path == "/api/me":
            return self.api_me(parse_qs(url.query).get("validation", [""]))
        if url.path == "/me":
            key = cookie_value(self.headers.get("Cookie"), "atlas_session")
            with lock:
                item = sessions.get(key) if key else None
                reason = ended.get(key) if key else None
            if item:
                return self.reply(200, {"signedIn": True, "subject": item["sub"]})
            return self.reply(401, {"signedIn": False, "reason": reason or "no_session"})
        return self.reply(404, {"error": "not_found"})

    def do_POST(self):
        if urlsplit(self.path).path != "/backchannel-logout":
            return self.reply(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384:
                raise ValueError("Unexpected logout request size")
            claims = logout_claims(self.headers.get("Content-Type", ""), self.rfile.read(length))
        except (TokenValidationError, ValueError, TypeError, KeyError, UnicodeDecodeError):
            return self.reply(400, {"error": "invalid_request"})
        end_sessions(claims)
        return self.reply(200, {})

    def api_me(self, mode):
        """Bearer-token API. Introspection asks Keycloak on every call; local
        validation checks the signature and expiry, then the signal stream."""
        header = self.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        if mode not in (["introspection"], ["local"]) or not 1 <= len(token) <= 16384:
            return self.reply(400, {"error": "invalid_request"})
        try:
            if mode == ["local"]:
                claims = _decode(token, ISSUER, CLIENT_ID)
                verdict = local_verdict(claims)
                if verdict == "accept":
                    return self.reply(
                        200,
                        {
                            "active": True,
                            "subject": claims["sub"],
                            "expiresIn": int(claims["exp"] - time.time()),
                            "checkedBy": "local",
                        },
                    )
                if verdict == "revoked":
                    return self.reply(
                        401,
                        {"active": False, "reason": "revoked_by_signal"},
                        [("WWW-Authenticate", 'Bearer error="invalid_token"')],
                    )
            with client(timeout=10) as http:
                response = http.post(
                    ISSUER + "/protocol/openid-connect/token/introspect",
                    data={"token": token},
                    auth=(CLIENT_ID, SECRET),
                )
                result = json_response(response, limit=32768) if response.status_code == 200 else {}
            if result.get("active") is True and isinstance(result.get("sub"), str):
                return self.reply(
                    200, {"active": True, "subject": result["sub"], "checkedBy": "introspection"}
                )
        except (httpx.HTTPError, IntegrationError, TokenValidationError, AttributeError):
            pass
        return self.reply(
            401, {"active": False}, [("WWW-Authenticate", 'Bearer error="invalid_token"')]
        )

    def login(self):
        key, state, nonce = (secrets.token_urlsafe(32) for _ in range(3))
        verifier = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        with lock:
            bounded_put(pending, key, (state, nonce, verifier, time.monotonic()))
        query = urlencode(
            {
                "client_id": CLIENT_ID,
                "response_type": "code",
                "scope": "openid",
                "redirect_uri": ORIGIN + "/callback",
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        self.redirect(
            ISSUER + "/protocol/openid-connect/auth?" + query,
            [("Set-Cookie", set_cookie("atlas_login", key, 300))],
        )

    def callback(self, params):
        key = cookie_value(self.headers.get("Cookie"), "atlas_login")
        with lock:
            started = pending.pop(key, None) if key else None
        code, state = params.get("code", [""]), params.get("state", [""])
        if (
            not started
            or time.monotonic() - started[3] > 300
            or len(code) != 1
            or len(state) != 1
            or not secrets.compare_digest(state[0], started[0])
        ):
            return self.reply(400, {"error": "invalid_login_state"})
        try:
            with client(timeout=10) as http:
                response = http.post(
                    ISSUER + "/protocol/openid-connect/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": code[0],
                        "redirect_uri": ORIGIN + "/callback",
                        "code_verifier": started[2],
                    },
                    auth=(CLIENT_ID, SECRET),
                )
                if response.status_code != 200:
                    raise ValueError("Code exchange rejected")
                claims = _decode(
                    json_response(response, limit=65536).get("id_token"), ISSUER, CLIENT_ID
                )
            if not secrets.compare_digest(str(claims.get("nonce", "")), started[1]) or not (
                isinstance(claims.get("sid"), str) and claims["sid"]
            ):
                raise ValueError("ID token does not match this login")
        except (
            httpx.HTTPError,
            IntegrationError,
            TokenValidationError,
            ValueError,
            AttributeError,
        ):
            return self.reply(401, {"error": "login_failed"})
        session = secrets.token_urlsafe(32)
        with lock:
            bounded_put(sessions, session, {"sub": claims["sub"], "sid": claims["sid"]})
        self.redirect(
            ORIGIN + "/me",
            [
                ("Set-Cookie", set_cookie("atlas_session", session, 3600)),
                ("Set-Cookie", set_cookie("atlas_login", "", 0)),
            ],
        )


if __name__ == "__main__":
    if len(SECRET) < 32:
        raise SystemExit("ATLAS_CLIENT_SECRET is not configured; run scripts/Upgrade-Lab.ps1.")
    # As a container's PID 1 the process ignores SIGTERM unless it handles it,
    # so "docker compose stop" would otherwise wait and kill it.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    if len(SIGNAL_TOKEN) >= 32:
        threading.Thread(target=follow_signals, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8090), Atlas).serve_forever()
