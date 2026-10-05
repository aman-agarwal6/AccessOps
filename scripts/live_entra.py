"""Live Microsoft Entra departure, measured before and after through Microsoft Graph.

Runs in a one-shot backend container with the Entra overlay
(infra/compose.entra.yml): the lab's own test tenant, the connector's
certificate key and configuration read-only, and outbound HTTPS to Microsoft. A
unique synthetic AccessOps worker is enrolled server-locally, as an operator
would, to one of the tenant's test users. The suite reads that user through
Graph, contains the departure through the case API, waits for the worker's
provider evidence, then reads Graph again with a separate connector.

Afterwards the harness, not AccessOps, re-enables the test user and returns it
to the lab group so the next run has an active leaver. AccessOps' connector can
never enable an account or add a membership. The test users have no stored
password, so their sign-ins are not exercised.

Mount .local/operator-logins.json read-only at /run/test-logins.json.
"""

import json
import os
import subprocess
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from check_report import CheckReport, report_arguments
from live_offboarding import wait_binding
from live_oidc import APP, BACKEND_FILES, LOGINS, close_sessions, login, post, snapshot

from integrations.entra import EntraConnector, graph_time
from integrations.keycloak import KeycloakConnector

GRAPH_OBJECTS = "https://graph.microsoft.com/v1.0/directoryObjects/"


def enroll(identity_id, user_id, group_id):
    """The server-local enrollment command; returns True when it recorded a binding."""
    command = [
        "python",
        "/app/backend/manage.py",
        "enroll_entra",
        "--identity-id",
        identity_id,
        "--user-id",
        user_id,
        "--group-id",
        group_id,
    ]
    return subprocess.run(command, capture_output=True, timeout=120).returncode == 0


def binding_for(config, user_id, group_id):
    return {"tenantId": config["tenantId"], "userId": user_id, "groupIds": [group_id]}


def restore(binding):
    """Harness-only fixture reset: enable the test user and return it to the group.
    Uses the connector's Graph client directly; AccessOps never calls this."""
    graph = EntraConnector()
    try:
        before = graph.validate_binding(binding)
        if not before["active"]:
            graph._call(
                "PATCH", f"/users/{binding['userId']}", body={"accountEnabled": True}, expect=(204,)
            )
        for group in before["groups"]:
            if not group["member"]:
                graph._call(
                    "POST",
                    f"/groups/{group['groupId']}/members/$ref",
                    body={"@odata.id": GRAPH_OBJECTS + binding["userId"]},
                    expect=(204,),
                )
    finally:
        graph.close()
    for _ in range(10):
        graph = EntraConnector()
        try:
            after = graph.validate_binding(binding)
        finally:
            graph.close()
        if after["active"] and all(group["member"] for group in after["groups"]):
            return
        time.sleep(3)
    raise AssertionError("The test user was not restored")


def main():
    args = report_arguments(__doc__).parse_args()
    report = CheckReport(
        "entra-departure",
        driver="Microsoft Graph v1.0 against the lab's own Entra ID Free tenant, the AccessOps case API and worker",
        limitations=[
            "One test tenant with synthetic test users; no employee or production tenant.",
            "Sign-ins are not exercised: the test users have no stored password. Revocation is read from signInSessionsValidFromDateTime.",
            "An access token already issued to an app stays valid until it expires unless the app uses continuous access evaluation; app-owned sessions are separate.",
            "Graph application permissions are tenant-wide on Entra ID Free; the connector's own list of test objects and its directory-role refusal are the scope boundary.",
            "The harness re-enables the test user afterwards; the synthetic AccessOps worker, case and audit history are retained.",
        ],
        source_files=[
            "scripts/live_entra.py",
            "scripts/live_oidc.py",
            "scripts/check_report.py",
            "integrations/entra.py",
            "backend/core/offboarding.py",
            "backend/core/management/commands/enroll_entra.py",
        ]
        + BACKEND_FILES,
    )
    sessions, binding = {}, None
    raw = json.loads(Path(os.environ["ACCESSOPS_ENTRA_CONFIG_FILE"]).read_text(encoding="utf-8"))
    group = raw["test_group"]["object_id"].lower()
    users = [item["object_id"].lower() for item in raw["test_users"]]
    protected = raw["protected_object_ids"][0].lower()
    try:
        with report.case("the connector signs in with its certificate and reads the lab tenant"):
            graph = EntraConnector()
            try:
                readings = {
                    user: graph.validate_binding(binding_for(graph.config, user, group))
                    for user in users
                }
                config = graph.config
            finally:
                graph.close()
        ready = [
            user
            for user, observed in readings.items()
            if observed["active"] and all(g["member"] for g in observed["groups"])
        ]
        binding = binding_for(config, ready[0] if ready else users[0], group)
        if not ready:
            restore(binding)  # A previous run left both test users contained.
        with report.case("before: the test user is enabled and in the lab group"):
            graph = EntraConnector()
            try:
                before = graph.validate_binding(binding)
            finally:
                graph.close()
            if not before["active"] or not all(g["member"] for g in before["groups"]):
                raise AssertionError("The test user is not an active leaver")

        password = json.loads(LOGINS.read_text())["passwords"]["alice"]
        sessions["alice"] = login("alice", password)
        alice, acsrf = sessions["alice"]
        suffix = uuid.uuid4().hex[:12]
        with report.case("a unique synthetic worker is created and bound to a workforce account"):
            human = post(
                alice,
                acsrf,
                "/api/v1/identities",
                {
                    "name": "Entra Leaver " + suffix,
                    "kind": "human",
                    "email": f"entra-{suffix}@fixture.test",
                    "department": "Engineering",
                    "projectIds": ["Atlas"],
                },
                expected=201,
            )["result"]
            keycloak = KeycloakConnector()
            try:
                wait_binding(alice, human["id"], keycloak, active=True)
            finally:
                keycloak.http.close()
        with report.case("denied: enrolling the tenant's protected admin account changes nothing"):
            if enroll(human["id"], protected, group):
                raise AssertionError("The protected account was enrolled")
        with report.case("denied: enrolling a user outside the connector's list changes nothing"):
            if enroll(human["id"], str(uuid.uuid4()), group):
                raise AssertionError("An unlisted user was enrolled")
        with report.case("the worker is enrolled to the test user by the server-local command"):
            if not enroll(human["id"], binding["userId"], group):
                raise AssertionError("Enrollment failed")
            item = next(i for i in snapshot(alice)["identities"] if i["id"] == human["id"])
            if item.get("entraBinding") != binding:
                raise AssertionError("The enrollment is not the exact binding")

        effective = datetime.now(UTC) - timedelta(seconds=2)
        case = post(
            alice,
            acsrf,
            "/api/v1/offboarding-cases",
            {
                "identityId": human["id"],
                "employmentType": "employee",
                "hrEventId": "ENTRA-LIVE-" + suffix,
                "hrSource": "synthetic-fixture-hr",
                "effectiveAt": effective.isoformat().replace("+00:00", "Z"),
                "reason": "Unique synthetic Entra departure verification",
                "bindings": [],
            },
            expected=201,
        )["result"]
        path = "/api/v1/offboarding-cases/" + case["id"]

        def entra_task():
            item = next(c for c in snapshot(alice)["offboardingCases"] if c["id"] == case["id"])
            return next(t for t in item["tasks"] if t["id"] == "entra-directory")

        # Timed: from the containment request to Graph-backed provider evidence.
        with report.case(
            "containment: the case shows Graph evidence of disable, group removal and session revocation within 120 s"
        ):
            post(alice, acsrf, path + "/contain", {})
            deadline = time.monotonic() + 120
            while entra_task()["evidenceKind"] != "provider_observation":
                if time.monotonic() > deadline:
                    raise AssertionError("No Graph-backed evidence on the case")
                time.sleep(2)
        with report.case(
            "after: a separate Graph read shows the account disabled, out of the group and sessions revoked after the departure"
        ):
            graph = EntraConnector()
            try:
                after = graph.validate_binding(binding)
            finally:
                graph.close()
            revoked = graph_time(after["sessionsValidFrom"])
            if (
                after["active"]
                or any(g["member"] for g in after["groups"])
                or revoked is None
                or revoked < effective.replace(microsecond=0)
            ):
                raise AssertionError("Graph does not show the account contained")
        with report.case("after: an owner statement cannot replace the Graph evidence"):
            response = alice.post(
                APP + path + "/tasks/entra-directory/attest",
                json={
                    "reference": "ENTRA-" + suffix,
                    "summary": "Owner statement over Graph evidence.",
                },
                headers={"X-CSRFToken": acsrf, "Origin": APP, "Idempotency-Key": str(uuid.uuid4())},
            )
            if response.status_code != 409:
                raise AssertionError("An owner statement replaced the Graph evidence")
    except Exception as error:
        report.record_error(error)
    finally:
        if binding:
            try:
                with report.case("the harness restores the test user for the next run"):
                    restore(binding)
            except Exception as error:
                report.record_error(error, name="test user restoration")
        close_sessions(report, sessions)
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
