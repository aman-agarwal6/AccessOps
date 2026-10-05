"""Automated leaver intake through the signed HR webhook, measured end to end.

Plays the HR system: signs Standard Webhooks events with the lab secret and
sends them to the real front door. Unique synthetic workers sign in to the
Atlas lab app first, so each timed check runs from the HR event to the moment
Keycloak lists no session, the case shows provider evidence and Atlas has
signed the person out. A check's duration is that measured time.

Mount .local/operator-logins.json read-only at /run/test-logins.json into a
one-shot test container only. Secrets and passwords are never reported.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from check_report import CheckReport, report_arguments
from live_offboarding import offboard, wait_binding
from live_oidc import APP, BACKEND_FILES, close_sessions, login, post, snapshot, wait_observed
from live_sessions import ADMIN, atlas_me, sign_in_atlas

from integrations.keycloak import KeycloakConnector
from integrations.transport import client

EVENTS = APP + "/api/v1/hr-events"


def signed(payload, *, secret, message_id=None, stamp=None):
    body = json.dumps(payload).encode()
    message_id = message_id or "msg_" + uuid.uuid4().hex
    stamp = str(int(time.time()) if stamp is None else stamp)
    key = base64.b64decode(secret.removeprefix("whsec_"))
    digest = hmac.new(key, f"{message_id}.{stamp}.".encode() + body, hashlib.sha256).digest()
    return body, {
        "Content-Type": "application/json",
        "webhook-id": message_id,
        "webhook-timestamp": stamp,
        "webhook-signature": "v1," + base64.b64encode(digest).decode(),
    }


def departure(worker_id, effective, suffix):
    return {
        "type": "worker.departed",
        "eventId": "HR-LIVE-" + suffix,
        "workerId": worker_id,
        "employmentType": "employee",
        "effectiveAt": effective.isoformat().replace("+00:00", "Z"),
        "reason": "Synthetic resignation sent by the lab HR feed",
    }


def until(read, label, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = read()
        if value:
            return value
        time.sleep(0.5)
    raise RuntimeError("Timed out waiting for " + label)


def main():
    args = report_arguments(__doc__).parse_args()
    report = CheckReport(
        "hr-leaver-intake",
        driver="real signed HR webhook, AccessOps worker, Keycloak 26.8 and the Atlas lab app",
        limitations=[
            "The HR system is simulated by this harness with the lab's shared secret; no real HR product is integrated.",
            "Workers are matched by their AccessOps identity ID, which the HR system is assumed to hold; names and emails are never matched.",
            "Timed checks include harness polling every half second, so measured times are upper bounds.",
            "Only worker.departed events are handled. Rehires, corrections and cancellations need a person.",
            "Unique synthetic workers, their cases and audit history are retained.",
        ],
        source_files=[
            "scripts/live_hr_intake.py",
            "scripts/live_sessions.py",
            "scripts/live_oidc.py",
            "scripts/check_report.py",
            "backend/core/intake.py",
            "backend/core/offboarding.py",
            "integrations/keycloak.py",
            "policies/accessops.rego",
        ]
        + BACKEND_FILES,
    )
    sessions, connector, workers, contained, hr = {}, None, {}, set(), None
    browsers = {}
    secret = os.environ.get("HR_WEBHOOK_SECRET", "")
    try:
        with report.case("operator session established and HR signing secret present"):
            password = json.loads(Path("/run/test-logins.json").read_text())["passwords"]["alice"]
            sessions["alice"] = login("alice", password)
            if len(secret) < 40:
                raise AssertionError("HR webhook secret is not configured")
        alice, acsrf = sessions["alice"]
        connector = KeycloakConnector()
        hr = client(timeout=15)

        def send(payload, **options):
            body, headers = signed(payload, secret=options.pop("key", secret), **options)
            return hr.post(EVENTS, content=body, headers=headers)

        def enroll(label):
            suffix = uuid.uuid4().hex[:12]
            human = post(
                alice,
                acsrf,
                "/api/v1/identities",
                {
                    "name": f"HR {label} Worker {suffix}",
                    "kind": "human",
                    "email": f"hr-{label}-{suffix}@fixture.test",
                    "department": "Engineering",
                    "projectIds": ["Atlas"],
                },
                expected=201,
            )["result"]
            subject = wait_binding(alice, human["id"], connector, active=True)
            workers[label] = (human["id"], subject, suffix)
            password = secrets.token_urlsafe(24)
            with httpx.Client(timeout=10, trust_env=False) as admin:
                response = admin.put(
                    ADMIN + "/users/" + subject + "/reset-password",
                    headers={"Authorization": "Bearer " + connector._token()},
                    json={"type": "password", "value": password, "temporary": False},
                )
            if response.status_code != 204:
                raise AssertionError("Fixture password could not be set")
            browsers[label] = client(timeout=10)
            sign_in_atlas(browsers[label], connector.get_user(subject)["userName"], password)
            if atlas_me(browsers[label])[0] != 200:
                raise AssertionError("Worker is not signed in to Atlas")

        def case_for(worker_id):
            return next(
                (c for c in snapshot(alice)["offboardingCases"] if c["identityId"] == worker_id),
                None,
            )

        def fully_contained(label):
            worker_id, subject, _ = workers[label]
            item = case_for(worker_id)
            tasks = {t["id"]: t for t in (item or {}).get("tasks", [])}
            return bool(
                item
                and all(
                    tasks.get(key, {}).get("status") == "observed"
                    for key in ("local-containment", "keycloak-directory")
                )
                and connector.count_sessions(subject) == 0
                and atlas_me(browsers[label])
                == (
                    401,
                    {"signedIn": False, "reason": "backchannel_logout"},
                )
            )

        with report.case("unique synthetic workers enrolled and signed in to Atlas"):
            enroll("now")
            enroll("later")
        now_id, _, now_suffix = workers["now"]
        # Effective now, after the worker's Atlas sign-in: a backdated time would make
        # that sign-in count as access after departure and alert the SOC receiver.
        event = departure(now_id, datetime.now(UTC), now_suffix)

        with report.case("unsigned, wrongly signed, stale or altered events are refused"):
            body, headers = signed(event, secret=secret)
            wrong = "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode()
            refused = [
                hr.post(EVENTS, content=body, headers={"Content-Type": "application/json"}),
                send(event, key=wrong),
                send(event, stamp=int(time.time()) - 600),
                hr.post(EVENTS, content=body.replace(b"Synthetic", b"Altered!!"), headers=headers),
            ]
            if any(response.status_code != 401 for response in refused):
                raise AssertionError("A forged or stale event was not refused")
            if case_for(now_id) is not None:
                raise AssertionError("A refused event opened a case")

        with report.case(
            "effective HR event: case, containment, zero sessions and Atlas sign-out within 60 s"
        ):
            body, headers = signed(event, secret=secret, message_id="msg_" + now_suffix)
            started = time.monotonic()
            response = hr.post(EVENTS, content=body, headers=headers)
            answered = time.monotonic() - started
            result = response.json().get("result", {})
            if response.status_code != 201 or result.get("state") != "contained":
                code = response.json().get("error", {}).get("code", "none")
                print(f"HR event refused: HTTP {response.status_code}, code {code}")
                raise AssertionError("The HR event was not accepted and contained")
            until(lambda: fully_contained("now"), "provider-verified containment", 60)
            contained.add("now")
            print(
                f"HR event answered (local containment committed) in {answered:.2f} s; "
                f"provider-verified with Atlas sign-out after {time.monotonic() - started:.1f} s"
            )
        with report.case("the case is owned by a person and attributed to the HR feed"):
            item = case_for(now_id)
            state = snapshot(alice)
            feed = {s["id"]: s["name"] for s in state["services"]}
            request = next(r for r in state["requests"] if r["id"] == item["containmentRequestId"])
            alice_id = alice.get(APP + "/api/v1/session").json()["principal"]["id"]
            if (
                item["ownerId"] != alice_id
                or item.get("intakeSourceId") not in feed
                or request["requesterId"] != item["intakeSourceId"]
                or item["status"] == "closed"
            ):
                raise AssertionError("Ownership or attribution is wrong")
        with report.case("redelivery returns the original result and opens no second case"):
            again = hr.post(EVENTS, content=body, headers=headers)
            other = send(event)
            cases = [c for c in snapshot(alice)["offboardingCases"] if c["identityId"] == now_id]
            if (
                again.status_code != 201
                or again.json() != response.json()
                or other.status_code != 200
                or other.json()["result"]["caseId"] != result["caseId"]
                or len(cases) != 1
            ):
                raise AssertionError("Redelivery was not idempotent")
        with report.case("a reused HR event ID with a different departure is refused"):
            earlier = (datetime.now(UTC) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
            conflict = send({**event, "effectiveAt": earlier})
            if conflict.status_code != 409 or conflict.json()["error"]["code"] != "event_conflict":
                raise AssertionError("Conflicting event was not refused")

        later_id, _, later_suffix = workers["later"]
        effective = datetime.now(UTC) + timedelta(seconds=20)
        with report.case("future-dated HR event opens a scheduled case and changes no access yet"):
            response = send(departure(later_id, effective, later_suffix))
            if response.status_code != 201 or response.json()["result"]["state"] != "scheduled":
                raise AssertionError("Future-dated event was not scheduled")
            person = next(i for i in snapshot(alice)["identities"] if i["id"] == later_id)
            if (
                person["status"] != "active"
                or case_for(later_id).get("containmentRequestId")
                or atlas_me(browsers["later"])[0] != 200
            ):
                raise AssertionError("Access changed before the departure took effect")
        until(lambda: datetime.now(UTC) >= effective, "effective time", 40)
        with report.case(
            "at the effective time the feed contains it: zero sessions and Atlas sign-out within 30 s"
        ):
            until(lambda: fully_contained("later"), "scheduled containment", 30)
            contained.add("later")
            print(
                "scheduled departure provider-verified "
                f"{(datetime.now(UTC) - effective).total_seconds():.1f} s after it took effect"
            )
    except Exception as error:
        report.record_error(error)
    finally:
        for label, (worker_id, _, _) in workers.items():
            if label in contained or "alice" not in sessions:
                continue
            try:
                with report.case(f"interrupted {label} fixture worker contained through the API"):
                    alice, acsrf = sessions["alice"]
                    wait_observed(alice, offboard(alice, acsrf, worker_id))
            except Exception as error:
                report.record_error(error, name="fixture containment cleanup")
        close_sessions(report, sessions)
        if hr:
            hr.close()
        for browser in browsers.values():
            browser.close()
        if connector:
            connector.http.close()
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
