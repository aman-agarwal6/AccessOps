"""Leaver assurance and signed SOC signals, measured on the live lab.

A unique synthetic worker signs in to Atlas and leaves through the signed HR
feed. The suite acts as the SOC receiver: it polls AccessOps (RFC 8936),
verifies each Security Event Token against the published key and acknowledges
it. It then checks the post-departure watch twice: a refused sign-in is only
counted, and a sign-in that succeeds after the account is re-enabled outside
AccessOps is detected, signalled and blocks the case until investigated.

As the lab's only receiver, this suite acknowledges every event it is offered.
Mount .local/operator-logins.json read-only at /run/test-logins.json into a
one-shot test container only. Secrets and passwords are never reported.
"""

import json
import os
import re
import secrets
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import jwt
from check_report import CheckReport, report_arguments
from live_hr_intake import EVENTS as HR_EVENTS
from live_hr_intake import departure, signed
from live_offboarding import offboard, wait_binding
from live_oidc import APP, BACKEND_FILES, close_sessions, login, post, snapshot, wait_observed
from live_sessions import ADMIN, atlas_me, sign_in_atlas

from integrations.keycloak import KeycloakConnector
from integrations.transport import client

WORKFORCE = "https://id.accessops.test:8443/realms/accessops-workforce"
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
RISC = "https://schemas.openid.net/secevent/risc/event-type/"


def until(read, label, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = read()
        if value:
            return value
        time.sleep(1)
    raise RuntimeError("Timed out waiting for " + label)


class Receiver:
    """A minimal RFC 8936 receiver: verify, keep, acknowledge."""

    def __init__(self, http, token):
        self.http, self.token, self.received, self.drained = http, token, [], 0
        keys = http.get(APP + "/api/v1/ssf/jwks").json()["keys"]
        self.keys = {key["kid"]: jwt.PyJWK.from_dict(key) for key in keys}

    def verify(self, token):
        header = jwt.get_unverified_header(token)
        if header.get("typ") != "secevent+jwt" or header.get("alg") != "ES256":
            raise AssertionError("Unexpected token type or algorithm")
        return jwt.decode(
            token,
            self.keys[header["kid"]].key,
            algorithms=["ES256"],
            audience="urn:accessops:soc-receiver",
            issuer="https://accessops.test:8443",
        )

    def poll(self, subject=None):
        ack = []
        while True:
            response = self.http.post(
                APP + "/api/v1/ssf/poll",
                json={"maxEvents": 50, "ack": ack},
                headers={"Authorization": "Bearer " + self.token},
            )
            if response.status_code != 200:
                raise AssertionError("Poll refused")
            body = response.json()
            ack = list(body["sets"])
            for token in body["sets"].values():
                claims = self.verify(token)
                if subject and claims["sub_id"]["sub"] == subject:
                    self.received.append(claims)
                else:
                    self.drained += 1
            if not ack:
                return self.received

    def kinds(self, subject):
        self.poll(subject)
        return {kind for claims in self.received for kind in claims["events"]}


def main():
    args = report_arguments(__doc__).parse_args()
    report = CheckReport(
        "leaver-assurance",
        driver="real Keycloak 26.8 events, signed HR intake, Atlas lab app and an RFC 8936 receiver",
        limitations=[
            "This suite is the lab's SOC receiver; SignalBridge's receiver is built separately against contracts/leaver-signals.md.",
            "Keycloak keeps sign-in, code-exchange and refused sign-in events here, not refresh-token events; reuse of an old refresh token is not watched.",
            "The watch reads events every 30 seconds for 24 hours after departure, so detection time includes that interval.",
            "The account is re-enabled through SCIM as a synthetic administrator mistake and contained again before the suite ends.",
            "Unique synthetic workers, cases, signals and audit history are retained.",
        ],
        source_files=[
            "scripts/live_leaver_assurance.py",
            "scripts/live_hr_intake.py",
            "scripts/live_sessions.py",
            "scripts/check_report.py",
            "backend/core/assurance.py",
            "backend/core/ssf.py",
            "backend/core/intake.py",
            "integrations/keycloak.py",
        ]
        + BACKEND_FILES,
    )
    sessions, connector, http, browser = {}, None, None, None
    worker_id = subject = None
    exposed = contained = False
    hr_secret = os.environ.get("HR_WEBHOOK_SECRET", "")
    receiver_token = os.environ.get("SSF_RECEIVER_TOKEN", "")
    try:
        with report.case("operator session, HR secret and receiver token present"):
            password = json.loads(Path("/run/test-logins.json").read_text())["passwords"]["alice"]
            sessions["alice"] = login("alice", password)
            if len(hr_secret) < 40 or len(receiver_token) < 32:
                raise AssertionError("HR or receiver secret is not configured")
        alice, acsrf = sessions["alice"]
        connector = KeycloakConnector()
        http = client(timeout=15)
        receiver = Receiver(http, receiver_token)
        receiver.poll()  # Acknowledge earlier lab events so this run starts clean.

        suffix = uuid.uuid4().hex[:12]
        with report.case("unique synthetic worker enrolled and signed in to Atlas"):
            human = post(
                alice,
                acsrf,
                "/api/v1/identities",
                {
                    "name": "Assurance Worker " + suffix,
                    "kind": "human",
                    "email": "assurance-" + suffix + "@fixture.test",
                    "department": "Engineering",
                    "projectIds": ["Atlas"],
                },
                expected=201,
            )["result"]
            worker_id = human["id"]
            subject = wait_binding(alice, worker_id, connector, active=True)
            username = connector.get_user(subject)["userName"]
            secret = secrets.token_urlsafe(24)
            with httpx.Client(timeout=10, trust_env=False) as admin:
                response = admin.put(
                    ADMIN + "/users/" + subject + "/reset-password",
                    headers={"Authorization": "Bearer " + connector._token()},
                    json={"type": "password", "value": secret, "temporary": False},
                )
            if response.status_code != 204:
                raise AssertionError("Fixture password could not be set")
            browser = client(timeout=10)
            sign_in_atlas(browser, username, secret)
            if atlas_me(browser)[0] != 200:
                raise AssertionError("Worker is not signed in to Atlas")

        def case():
            return next(
                (c for c in snapshot(alice)["offboardingCases"] if c["identityId"] == worker_id),
                None,
            )

        def task(item, key):
            return next((t for t in item["tasks"] if t["id"] == key), None)

        with report.case("containment sends signed account-disabled and session-revoked events"):
            # Effective after the Atlas sign-in: access between the effective time
            # and containment would rightly count as access after departure.
            time.sleep(2)
            body, headers = signed(
                departure(worker_id, datetime.now(UTC), suffix), secret=hr_secret
            )
            if http.post(HR_EVENTS, content=body, headers=headers).status_code != 201:
                raise AssertionError("HR event was not accepted")
            contained = True
            until(
                lambda: (
                    {RISC + "account-disabled", CAEP + "session-revoked"} <= receiver.kinds(subject)
                ),
                "containment signals",
                60,
            )
            for claims in receiver.received:
                if claims["sub_id"] != {"format": "iss_sub", "iss": WORKFORCE, "sub": subject}:
                    raise AssertionError("Signal subject is not the leaver's account")
            signals = until(lambda: case().get("signals"), "case signal record", 10)
            if not all(item["deliveredAt"] for item in signals):
                raise AssertionError("Acknowledged signals are not shown as delivered")

        with report.case("a refused sign-in after departure is counted, with no successful one"):
            with client(timeout=10) as stranger:
                sign_in_atlas(stranger, username, secret)
                if atlas_me(stranger)[0] == 200:
                    raise AssertionError("A disabled account signed in")

            def refused():
                summary = (task(case(), "keycloak-directory") or {}).get("evidenceSummary", "")
                found = re.search(r"refused (\d+) attempt", summary)
                return found and int(found.group(1)) >= 1

            until(refused, "refused attempt in the case evidence", 75)
            if task(case(), "post-departure-access") is not None:
                raise AssertionError("A refused attempt was treated as access")

        connector.patch_user(subject, [{"op": "replace", "path": "active", "value": True}])
        exposed = True
        with report.case(
            "sign-in after an outside re-enable: blocking task and signed session-established within 60 s"
        ):
            with client(timeout=10) as returning:
                sign_in_atlas(returning, username, secret)
                started = time.monotonic()
                if atlas_me(returning)[0] != 200:
                    raise AssertionError("Re-enabled account could not sign in")
            until(
                lambda: (
                    CAEP + "session-established" in receiver.kinds(subject)
                    and task(case(), "post-departure-access") is not None
                ),
                "post-departure detection",
                60,
            )
            print(
                f"sign-in after departure detected and signalled after {time.monotonic() - started:.1f} s"
            )
            item = case()
            if task(item, "post-departure-access")["status"] != "pending" or not any(
                "after departure" in line for line in item["blockers"]
            ):
                raise AssertionError("The case does not block on access after departure")

        with report.case(
            "containing again ends the new sign-in, and the investigation unblocks the case"
        ):
            wait_observed(alice, offboard(alice, acsrf, worker_id))
            exposed = False
            if connector.get_user(subject).get("active") is not False or (
                connector.count_sessions(subject) != 0
            ):
                raise AssertionError("The account was not contained again")
            item = case()
            post(
                alice,
                acsrf,
                f"/api/v1/offboarding-cases/{item['id']}/tasks/post-departure-access/attest",
                {
                    "reference": "INC-SYN-" + suffix,
                    "summary": "Synthetic investigation: an administrator re-enabled the account by mistake; contained again, no data accessed.",
                },
            )
            item = case()
            if task(item, "post-departure-access")["status"] != "attested" or any(
                "after departure" in line for line in item["blockers"]
            ):
                raise AssertionError("The investigation statement did not unblock the case")
    except Exception as error:
        report.record_error(error)
    finally:
        if worker_id and (exposed or not contained) and "alice" in sessions:
            try:
                with report.case("fixture worker contained through the API after an interruption"):
                    alice, acsrf = sessions["alice"]
                    wait_observed(alice, offboard(alice, acsrf, worker_id))
            except Exception as error:
                report.record_error(error, name="fixture containment cleanup")
        close_sessions(report, sessions)
        for item in (http, browser):
            if item:
                item.close()
        if connector:
            connector.http.close()
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
