"""Workforce session revocation, measured before and after containment.

A unique synthetic worker signs in to the Atlas lab app and its command-line
client through the real workforce realm. The suite measures what still works
before containment, after only disabling the account (what earlier versions
did), and after AccessOps containment ends the worker's sessions and signals
the revocation to Atlas, which checks tokens locally.

Mount .local/operator-logins.json read-only at /run/test-logins.json into a
one-shot test container only. The worker's one-time password is random, held in
memory and never reported.
"""

import base64
import hashlib
import json
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
import jwt
from check_report import CheckReport, report_arguments
from live_offboarding import offboard, wait_binding
from live_oidc import (
    BACKEND_FILES,
    IDENTITY,
    LoginForm,
    close_sessions,
    login,
    post,
    snapshot,
    wait_observed,
)

from integrations.keycloak import KeycloakConnector
from integrations.transport import client

ATLAS = "https://atlas.accessops.internal:8186"
WORKFORCE = IDENTITY + "/realms/accessops-workforce"
CLI = "atlas-cli"
CLI_REDIRECT = "http://127.0.0.1:8765/callback"
# Fixture setup only: Keycloak's admin API on the private identity network. The
# SCIM service account already holds manage-users; AccessOps has no route for this.
ADMIN = "http://keycloak:8080/admin/realms/accessops-workforce"


def checked(location, base):
    url = urljoin(base, location)
    parsed = urlsplit(url)
    if parsed.scheme + "://" + parsed.netloc not in (ATLAS, IDENTITY) or parsed.username:
        raise RuntimeError("Sign-in attempted an unexpected destination")
    return url


def follow(http, response):
    for _ in range(10):
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        response = http.get(checked(response.headers["location"], str(response.url)))
    raise RuntimeError("Too many sign-in redirects")


def sign_in_atlas(http, username, password):
    """Browser-style sign-in to Atlas. Returns the final response."""
    page = follow(http, http.get(ATLAS + "/login"))
    form = LoginForm()
    form.feed(page.text)
    if page.status_code != 200 or not form.action:
        raise RuntimeError("Workforce login form unavailable")
    action = checked(form.action, str(page.url))
    if not action.startswith(WORKFORCE + "/"):
        raise RuntimeError("Login form targeted an unexpected realm")
    return follow(
        http, http.post(action, data={**form.fields, "username": username, "password": password})
    )


def atlas_me(http):
    response = http.get(ATLAS + "/me")
    return response.status_code, response.json()


def cli_tokens(http, scope):
    """Authorization code with PKCE for the public command-line client, reusing
    the worker's single sign-on session. The loopback redirect is never fetched."""
    verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(16)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    response = http.get(
        WORKFORCE + "/protocol/openid-connect/auth",
        params={
            "client_id": CLI,
            "response_type": "code",
            "scope": scope,
            "redirect_uri": CLI_REDIRECT,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    location = response.headers.get("location", "")
    if response.status_code != 302 or not location.startswith(CLI_REDIRECT + "?"):
        raise RuntimeError("Command-line authorization did not complete")
    params = parse_qs(urlsplit(location).query)
    if params.get("state") != [state] or len(params.get("code", [])) != 1:
        raise RuntimeError("Command-line authorization response invalid")
    tokens = http.post(
        WORKFORCE + "/protocol/openid-connect/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLI,
            "code": params["code"][0],
            "redirect_uri": CLI_REDIRECT,
            "code_verifier": verifier,
        },
    )
    if tokens.status_code != 200:
        raise RuntimeError("Command-line code exchange failed")
    return tokens.json()


def refresh(http, token):
    response = http.post(
        WORKFORCE + "/protocol/openid-connect/token",
        data={"grant_type": "refresh_token", "client_id": CLI, "refresh_token": token},
    )
    return response.status_code, response.json()


def atlas_api(http, token, validation):
    """Call the Atlas API with a bearer token, checked by introspection or locally."""
    response = http.get(
        ATLAS + "/api/me",
        params={"validation": validation},
        headers={"Authorization": "Bearer " + token},
    )
    return response.status_code, response.json()


def atlas_signals(http):
    """Atlas's view of its signal stream: current, stale or off."""
    response = http.get(ATLAS + "/health")
    return response.json().get("signals") if response.status_code == 200 else None


def unexpired(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["exp"] - time.time()


def main():
    args = report_arguments(__doc__).parse_args()
    report = CheckReport(
        "workforce-session-revocation",
        driver="real workforce OIDC sign-in, Atlas back-channel logout, AccessOps case containment and Keycloak 26.8",
        limitations=[
            "Only a uniquely registered synthetic worker is contained. Its one-time password is random, held in memory and never reported.",
            "The harness sets that password over the private identity network with the SCIM service account's existing manage-users role; AccessOps has no route for it.",
            "Atlas is a lab app registered for back-channel logout. A real application's sessions end only if it implements and registers back-channel logout or checks tokens with Keycloak.",
            "Atlas closes the local-validation window by polling AccessOps' signal stream once a second. An app that checks tokens locally without following such a stream still accepts an issued token until it expires (two minutes in the lab), as the disable-only control shows.",
            "Keycloak 26.8 lab behavior only. MFA, federation, external identity providers and Microsoft Entra sessions are not measured.",
            "The terminal fixture identity, case and audit history are retained.",
        ],
        source_files=[
            "scripts/live_sessions.py",
            "scripts/atlas_app.py",
            "scripts/live_oidc.py",
            "backend/core/ssf.py",
            "scripts/check_report.py",
            "integrations/keycloak.py",
            "integrations/security.py",
            "integrations/transport.py",
            "infra/Caddyfile",
            "backend/core/offboarding.py",
        ]
        + BACKEND_FILES,
    )
    sessions, connector, human_id, contained = {}, None, None, False
    worker = client(timeout=10)
    try:
        with report.case("operator session established over verified TLS"):
            password = json.loads(Path("/run/test-logins.json").read_text())["passwords"]["alice"]
            sessions["alice"] = login("alice", password)
        alice, acsrf = sessions["alice"]
        connector = KeycloakConnector()
        suffix = uuid.uuid4().hex[:12]
        with report.case("unique synthetic worker enrolled and bound to a workforce account"):
            human = post(
                alice,
                acsrf,
                "/api/v1/identities",
                {
                    "name": "Session Worker " + suffix,
                    "kind": "human",
                    "email": "session-" + suffix + "@fixture.test",
                    "department": "Engineering",
                    "projectIds": ["Atlas"],
                },
                expected=201,
            )["result"]
            human_id = human["id"]
            subject = wait_binding(alice, human_id, connector, active=True)
            username = connector.get_user(subject)["userName"]
        with report.case("worker signs in to the Atlas app through the workforce realm"):
            secret = secrets.token_urlsafe(24)
            with httpx.Client(timeout=10, trust_env=False) as admin:
                response = admin.put(
                    ADMIN + "/users/" + subject + "/reset-password",
                    headers={"Authorization": "Bearer " + connector._token()},
                    json={"type": "password", "value": secret, "temporary": False},
                )
            if response.status_code != 204:
                raise AssertionError("Fixture password could not be set")
            final = sign_in_atlas(worker, username, secret)
            status, me = atlas_me(worker)
            if not str(final.url).startswith(ATLAS) or status != 200 or me["subject"] != subject:
                raise AssertionError("Worker is not signed in to Atlas")
        with report.case("worker's command-line client holds a refresh token and an offline token"):
            online = cli_tokens(worker, "openid")
            offline = cli_tokens(worker, "openid offline_access")
            if (
                not online.get("refresh_token")
                or jwt.decode(offline["refresh_token"], options={"verify_signature": False}).get(
                    "typ"
                )
                != "Offline"
            ):
                raise AssertionError("Expected refresh and offline tokens")
        tokens = {"online": online, "offline": offline}

        def renew(kind):
            status, body = refresh(worker, tokens[kind]["refresh_token"])
            if status == 200:
                tokens[kind] = body  # Refresh tokens rotate; keep the newest.
            return status, body

        with report.case("Atlas is reading its leaver signal stream"):
            if atlas_signals(worker) != "current":
                raise AssertionError("Atlas is not reading its signal stream")
        with report.case("before: Keycloak lists the worker's session"):
            if connector.count_sessions(subject) < 1:
                raise AssertionError("No session before containment")
        with report.case("before: the refresh token and the offline token both renew"):
            if renew("online")[0] != 200 or renew("offline")[0] != 200:
                raise AssertionError("Token renewal failed before containment")
        with report.case(
            "before: the Atlas API accepts the access token, by introspection and locally"
        ):
            access = tokens["online"]["access_token"]
            if atlas_api(worker, access, "introspection")[0] != 200 or (
                atlas_api(worker, access, "local")[0] != 200
            ):
                raise AssertionError("Atlas API rejected the access token before containment")

        # Control: what disabling the account alone leaves behind.
        connector.patch_user(subject, [{"op": "replace", "path": "active", "value": False}])
        with report.case("control: disabling the account alone leaves the Atlas session signed in"):
            if atlas_me(worker)[0] != 200:
                raise AssertionError("Atlas session ended without session revocation")
        with report.case("control: disabling the account alone leaves the Keycloak session listed"):
            if connector.count_sessions(subject) < 1:
                raise AssertionError("Keycloak session ended without session revocation")
        with report.case(
            "control: disabling alone already blocks token renewal and introspection, not local validation"
        ):
            access = tokens["online"]["access_token"]
            if (
                renew("online")[0] != 400
                or renew("offline")[0] != 400
                or atlas_api(worker, access, "introspection")[0] != 401
                or atlas_api(worker, access, "local")[0] != 200
            ):
                raise AssertionError(
                    "Disable-only token behavior differs from the measured baseline"
                )

        with report.case("AccessOps departure case opened for the worker"):
            case = post(
                alice,
                acsrf,
                "/api/v1/offboarding-cases",
                {
                    "identityId": human_id,
                    "employmentType": "employee",
                    "hrEventId": "session-" + suffix,
                    "hrSource": "synthetic-fixture-hr",
                    "effectiveAt": (datetime.now(UTC) - timedelta(seconds=3))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "reason": "Unique synthetic session revocation verification",
                    "bindings": [],
                },
                expected=201,
            )["result"]
            path = "/api/v1/offboarding-cases/" + case["id"]
        # Timed: from the containment request to the moment Atlas's local check,
        # which never asks Keycloak, refuses the worker's unexpired access token.
        with report.case("containment: Atlas's local check refuses the existing token within 30 s"):
            access = tokens["online"]["access_token"]
            case = post(alice, acsrf, path + "/contain", {})["result"]
            deadline = time.monotonic() + 30
            while atlas_api(worker, access, "local")[0] != 401:
                if time.monotonic() > deadline:
                    raise AssertionError("Atlas still accepts the token locally")
                time.sleep(0.25)
        with report.case("AccessOps containment ends the worker's sessions and observes none left"):
            wait_observed(alice, case["containmentRequestId"])
            contained = True
            item = next(c for c in snapshot(alice)["offboardingCases"] if c["id"] == case["id"])
            task = next(t for t in item["tasks"] if t["id"] == "keycloak-directory")
            if task["status"] != "observed" or "no active sessions" not in task["evidenceSummary"]:
                raise AssertionError("Case lacks the session observation")
        with report.case("after: Keycloak lists no session for the worker"):
            if connector.count_sessions(subject) != 0:
                raise AssertionError("A session survived containment")
        with report.case("after: the Atlas session ended through a verified back-channel logout"):
            status, me = atlas_me(worker)
            if status != 401 or me.get("reason") != "backchannel_logout":
                raise AssertionError("Atlas session was not ended by back-channel logout")
        with report.case("after: the refresh token is rejected"):
            if renew("online")[0] != 400:
                raise AssertionError("Refresh token still renews")
        with report.case("after: the offline token is rejected"):
            if renew("offline")[0] != 400:
                raise AssertionError("Offline token still renews")
        with report.case(
            "after: the Atlas API rejects the earlier access token when it asks Keycloak"
        ):
            if atlas_api(worker, tokens["online"]["access_token"], "introspection")[0] != 401:
                raise AssertionError("Access token still accepted by introspection")
        with report.case("after: a new sign-in to Atlas is refused"):
            with client(timeout=10) as fresh:
                final = sign_in_atlas(fresh, username, secret)
                if str(final.url).startswith(ATLAS) or atlas_me(fresh)[0] != 401:
                    raise AssertionError("A disabled worker signed in again")
        with report.case(
            "after: Atlas's local check refuses the unexpired access token from the revocation signal"
        ):
            access = tokens["online"]["access_token"]
            status, body = atlas_api(worker, access, "local")
            left = unexpired(access)
            if status != 401 or body.get("reason") != "revoked_by_signal" or left <= 0:
                raise AssertionError("Atlas refused the token for another reason")
            print(f"refused with {left:.0f} s of the token's lifetime left")
    except Exception as error:
        report.record_error(error)
    finally:
        if human_id and not contained and "alice" in sessions:
            try:
                with report.case("interrupted fixture worker contained through the API"):
                    alice, acsrf = sessions["alice"]
                    wait_observed(alice, offboard(alice, acsrf, human_id))
            except Exception as error:
                report.record_error(error, name="fixture containment cleanup")
        close_sessions(report, sessions)
        worker.close()
        if connector:
            connector.http.close()
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
