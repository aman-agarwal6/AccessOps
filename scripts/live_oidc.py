"""Real OIDC code+PKCE and API lifecycle over verified TLS, without browser UI.

Mount .local/operator-logins.json read-only at /run/test-logins.json into a
one-shot test container only. It never becomes an application runtime mount.
The test uses synthetic Clara/Atlas and returns it to a revoked state; audit
events and measured requests are intentionally preserved.
"""

import json
import time
import uuid
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

from check_report import CheckReport, report_arguments

from integrations.transport import client

APP = "https://accessops.test:8443"
IDENTITY = "https://id.accessops.test:8443"
BACKEND_FILES = [
    "backend/accessops/settings.py",
    "backend/accessops/urls.py",
    "backend/core/auth.py",
    "backend/core/audit.py",
    "backend/core/enrollment.py",
    "backend/core/errors.py",
    "backend/core/middleware.py",
    "backend/core/models.py",
    "backend/core/presentation.py",
    "backend/core/rate_limit.py",
    "backend/core/serializers.py",
    "backend/core/services.py",
    "backend/core/views.py",
    "backend/core/worker.py",
]


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.fields = {}
        self.inside = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action, self.inside = attrs.get("action"), True
        if self.inside and tag == "input" and attrs.get("type") == "hidden" and attrs.get("name"):
            self.fields[attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.inside = False


def safe_url(location, base):
    url = urljoin(base, location)
    parsed = urlsplit(url)
    if parsed.scheme + "://" + parsed.netloc not in (APP, IDENTITY) or parsed.username:
        raise RuntimeError("OIDC attempted an unexpected destination")
    return url


def follow(http, response):
    for _ in range(8):
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        url = safe_url(response.headers["location"], str(response.url))
        response = http.get(url)
    raise RuntimeError("Too many OIDC redirects")


def login(person, password):
    http = client(timeout=10)
    try:
        return _login(http, person, password)
    except Exception:
        http.close()
        raise


def _login(http, person, password):
    start = http.get(APP + "/auth/login")
    if start.status_code != 302:
        raise RuntimeError("OIDC authorization initiation failed")
    url = safe_url(start.headers["location"], APP)
    params = parse_qs(urlsplit(url).query)
    if (
        params.get("code_challenge_method") != ["S256"]
        or not params.get("state")
        or not params.get("nonce")
    ):
        raise RuntimeError("OIDC state, nonce, or S256 challenge absent")
    page = follow(http, http.get(url))
    form = LoginForm()
    form.feed(page.text)
    if page.status_code != 200 or not form.action:
        raise RuntimeError("Expected identity login form unavailable")
    action = safe_url(form.action, str(page.url))
    if not action.startswith(IDENTITY + "/realms/accessops-operators/"):
        raise RuntimeError("Login form targeted unexpected realm")
    response = follow(
        http, http.post(action, data={**form.fields, "username": person, "password": password})
    )
    if response.status_code != 200 or not str(response.url).startswith(APP):
        raise RuntimeError("OIDC callback did not establish an application session")
    session = http.get(APP + "/api/v1/session").json()
    if session.get("authenticated") is not True:
        raise RuntimeError("Application session not authenticated")
    return http, session["csrfToken"]


def post(http, csrf, path, body, expected=200, key=None):
    response = http.post(
        APP + path,
        json=body,
        headers={"X-CSRFToken": csrf, "Origin": APP, "Idempotency-Key": key or str(uuid.uuid4())},
    )
    if response.status_code != expected:
        code = response.json().get("error", {}).get("code", "unknown")
        raise RuntimeError(
            f"API check failed: {path.split('/')[-1]} HTTP {response.status_code} {code}"
        )
    return response.json()


def wait_observed(http, request_id):
    for _ in range(30):
        response = http.get(APP + "/api/v1/snapshot")
        if response.status_code != 200:
            raise RuntimeError("Snapshot unavailable while observing connector")
        item = next((v for v in response.json()["requests"] if v["id"] == request_id), None)
        if item and item["status"] == "verified":
            return
        if item and item["status"] == "failed":
            raise RuntimeError("Provider observation failed")
        time.sleep(1)
    raise RuntimeError("Provider observation timed out")


def snapshot(http):
    response = http.get(APP + "/api/v1/snapshot")
    if response.status_code != 200:
        raise RuntimeError("Snapshot unavailable")
    return response.json()


def close_sessions(report, sessions):
    # Each logout is independent so a failed provider/API call cannot prevent the
    # remaining synthetic sessions from being invalidated and clients closed.
    for name, (http, csrf) in sessions.items():
        try:
            with report.case("synthetic " + name + " application session logged out"):
                post(http, csrf, "/auth/logout", {})
                if http.get(APP + "/api/v1/session").json().get("authenticated") is not False:
                    raise RuntimeError("Local logout did not invalidate session")
        except Exception as error:
            report.record_error(error, name="application session cleanup")
        finally:
            http.close()


def main():
    args = report_arguments(__doc__).parse_args()
    report = CheckReport(
        "oidc-business",
        driver="real HTTP OIDC code+PKCE and authenticated API; no browser UI",
        limitations=[
            "Uses synthetic Clara/Atlas only and requires no active Clara/Atlas grant at the start.",
            "Leaves synthetic request/audit history and returns Clara/Atlas to a revoked grant state.",
            "Local application logout is measured; IdP-triggered backchannel logout and signing-key rotation are not.",
        ],
        source_files=[
            "scripts/live_oidc.py",
            "scripts/check_report.py",
            "integrations/transport.py",
        ]
        + BACKEND_FILES,
    )
    sessions = {}
    containment_required = False
    try:
        with report.case("three real operator OIDC code+PKCE sessions over verified TLS"):
            logins = json.loads(Path("/run/test-logins.json").read_text())["passwords"]
            for name in ("alice", "bob", "clara"):
                sessions[name] = login(name, logins[name])
        alice, acsrf = sessions["alice"]
        bob, bcsrf = sessions["bob"]
        clara, ccsrf = sessions["clara"]

        def uid(slug):
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, "accessops:" + slug))

        resource = uid("atlas-workspace")
        target = uid("clara-ellis")
        with report.case("synthetic lifecycle precondition and request recorded"):
            if any(
                g["identityId"] == target
                and g["resourceId"] == resource
                and g["status"] == "active"
                for g in snapshot(alice)["grants"]
            ):
                raise RuntimeError(
                    "Clara already has an active Atlas grant; do not replace existing scenario work"
                )
            created = post(
                alice,
                acsrf,
                "/api/v1/requests",
                {
                    "identityId": target,
                    "resourceId": resource,
                    "action": "grant",
                    "permission": "read",
                    "reason": "Synthetic live integration validation",
                },
                expected=201,
            )
            request_id = created["result"]["id"]
            path = "/api/v1/requests/" + request_id
        with report.case("self approval denied by real policy"):
            post(alice, acsrf, path + "/approve", {}, expected=403)
        with report.case("execution without independent approval denied"):
            post(alice, acsrf, path + "/execute", {}, expected=403)
        with report.case("independent approval and SCIM grant observed"):
            post(bob, bcsrf, path + "/approve", {})
            containment_required = True
            post(alice, acsrf, path + "/execute", {})
            wait_observed(alice, request_id)
        key = str(uuid.uuid4())
        with report.case("protected synthetic resource allows active entitlement"):
            post(clara, ccsrf, "/api/v1/resources/" + resource + "/read", {}, key=key)
        with report.case("revocation denies previous successful resource replay immediately"):
            revoked = post(
                alice,
                acsrf,
                "/api/v1/requests",
                {
                    "identityId": target,
                    "resourceId": resource,
                    "action": "revoke",
                    "permission": "read",
                    "reason": "Complete synthetic containment validation",
                },
                expected=201,
            )
            revoke_id = revoked["result"]["id"]
            post(alice, acsrf, "/api/v1/requests/" + revoke_id + "/execute", {})
            post(clara, ccsrf, "/api/v1/resources/" + resource + "/read", {}, expected=403, key=key)
        with report.case("SCIM group revoke observed independently"):
            wait_observed(alice, revoke_id)
            containment_required = False
    except Exception as error:
        report.record_error(error)
    finally:
        if containment_required and "alice" in sessions:
            try:
                with report.case("interrupted grant validation contained"):
                    alice, acsrf = sessions["alice"]
                    revoked = post(
                        alice,
                        acsrf,
                        "/api/v1/requests",
                        {
                            "identityId": target,
                            "resourceId": resource,
                            "action": "revoke",
                            "permission": "read",
                            "reason": "Contain interrupted synthetic validation",
                        },
                        expected=201,
                    )
                    revoke_id = revoked["result"]["id"]
                    post(alice, acsrf, "/api/v1/requests/" + revoke_id + "/execute", {})
                    wait_observed(alice, revoke_id)
            except Exception as error:
                report.record_error(error, name="interrupted grant cleanup")
        close_sessions(report, sessions)
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
