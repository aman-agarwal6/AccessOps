"""Real API offboarding for unique synthetic inventory; never changes seeded users.

Requires the same one-shot read-only login mount as live_oidc.py. All authority
changes pass through the authenticated API. No operator-realm administration or
fixture session injection is used. Retains terminal inventory and audit history.
"""

import json
import time
import uuid
from pathlib import Path

from check_report import CheckReport, report_arguments
from live_oidc import APP, BACKEND_FILES, close_sessions, login, post, snapshot, wait_observed

from integrations.keycloak import KeycloakConnector


def wait_binding(http, identity_id, connector, *, active):
    for _ in range(45):
        item = next(
            (item for item in snapshot(http)["identities"] if item["id"] == identity_id), None
        )
        if item and not item["providerSubject"].startswith("pending:"):
            observed = connector.get_user(item["providerSubject"])
            if observed.get("id") == item["providerSubject"] and observed.get("active") is active:
                return item["providerSubject"]
        time.sleep(1)
    raise RuntimeError("Synthetic enrollment observation timed out")


def offboard(http, csrf, identity_id):
    created = post(
        http,
        csrf,
        "/api/v1/requests",
        {
            "identityId": identity_id,
            "action": "offboard",
            "reason": "Contain unique synthetic departure validation fixture",
        },
        expected=201,
    )
    request_id = created["result"]["id"]
    post(http, csrf, "/api/v1/requests/" + request_id + "/execute", {})
    return request_id


def wait_reconciliation(http, run_id):
    for _ in range(180):
        response = http.get(APP + "/api/v1/evidence/" + run_id)
        if response.status_code != 200:
            raise RuntimeError("Reconciliation evidence unavailable")
        run = response.json()
        if run["status"] in ("passed", "failed"):
            if "observations" not in run.get("manifest", {}):
                raise RuntimeError("Reconciliation did not observe provider state")
            return run
        time.sleep(1)
    raise RuntimeError("Reconciliation observation timed out")


def main():
    parser = report_arguments(__doc__)
    parser.add_argument("--snapshot", help="Write the synthetic public console DTO fixture")
    parser.add_argument(
        "--principal", help="Write only the synthetic public operator principal DTO"
    )
    args = parser.parse_args()
    report = CheckReport(
        "connected-offboarding",
        driver="authenticated API and native SCIM over verified TLS",
        limitations=[
            "Uses unique synthetic inventory enrolled through the existing operator API.",
            "Offboarded human, suspended agent, revoked grants, requests and audit history are retained.",
            "The inventory agent starts suspended and has no machine credential; this does not measure running-agent token revocation.",
            "No live operator session is linked to this fixture; denial of an old offboarded operator session is not measured.",
            "IdP-triggered back-channel logout and signing-key rotation are measured by their own suites, not here.",
        ],
        source_files=[
            "scripts/live_offboarding.py",
            "scripts/live_oidc.py",
            "scripts/check_report.py",
            "integrations/keycloak.py",
            "integrations/transport.py",
        ]
        + BACKEND_FILES,
    )
    sessions = {}
    connector = None
    human_id = agent_id = human_subject = None
    group_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, "accessops:group:atlas-reader"))
    contained = False
    try:
        with report.case("real operator and independent reviewer OIDC sessions established"):
            logins = json.loads(Path("/run/test-logins.json").read_text())["passwords"]
            for name in ("alice", "bob"):
                sessions[name] = login(name, logins[name])
        alice, acsrf = sessions["alice"]
        bob, bcsrf = sessions["bob"]
        connector = KeycloakConnector()
        suffix = uuid.uuid4().hex[:12]
        with report.case(
            "unique human registered through authenticated API and native SCIM active observed"
        ):
            human = post(
                alice,
                acsrf,
                "/api/v1/identities",
                {
                    "name": "Departure Validation " + suffix,
                    "kind": "human",
                    "email": "departure-" + suffix + "@fixture.test",
                    "department": "Engineering",
                    "projectIds": ["Atlas"],
                },
                expected=201,
            )["result"]
            human_id = human["id"]
            human_subject = wait_binding(alice, human_id, connector, active=True)
        with report.case(
            "sponsored inventory agent registered suspended and native SCIM inactive observed"
        ):
            agent = post(
                alice,
                acsrf,
                "/api/v1/identities",
                {
                    "name": "Sponsored Validation " + suffix,
                    "kind": "agent",
                    "department": "Engineering",
                    "projectIds": ["Atlas"],
                    "sponsorId": human_id,
                },
                expected=201,
            )["result"]
            agent_id = agent["id"]
            if agent["status"] != "suspended" or agent["sponsorId"] != human_id:
                raise AssertionError("New agent was not safely suspended")
            agent_subject = wait_binding(alice, agent_id, connector, active=False)
        resource = str(uuid.uuid5(uuid.NAMESPACE_DNS, "accessops:atlas-workspace"))
        with report.case(
            "direct provider membership is observed as drift without adopting a local grant"
        ):
            connector.set_membership(group_id, human_subject, True)
            drift = post(alice, acsrf, "/api/v1/reconcile", {}, expected=202)["result"]
            run = wait_reconciliation(alice, drift["id"])
            observations = run["manifest"]["observations"]
            found = [
                v
                for v in observations
                if v.get("identityId") == human_id and v.get("resourceId") == resource
            ]
            if (
                run["status"] != "failed"
                or run["manifest"].get("adoptedChanges") != 0
                or not any(
                    v.get("drift") is True and v.get("observed", {}).get("member") is True
                    for v in found
                )
            ):
                raise AssertionError("Unbacked directory membership was not detected")
            if any(
                g["identityId"] == human_id
                and g["resourceId"] == resource
                and g["status"] == "active"
                for g in snapshot(alice)["grants"]
            ):
                raise AssertionError("Reconciliation adopted unbacked provider access")
            connector.set_membership(group_id, human_subject, False)
        with report.case(
            "independently approved fixture grant applied and native SCIM membership observed"
        ):
            created = post(
                alice,
                acsrf,
                "/api/v1/requests",
                {
                    "identityId": human_id,
                    "resourceId": resource,
                    "action": "grant",
                    "permission": "read",
                    "reason": "Unique synthetic departure validation",
                },
                expected=201,
            )
            request_id = created["result"]["id"]
            post(bob, bcsrf, "/api/v1/requests/" + request_id + "/approve", {})
            post(alice, acsrf, "/api/v1/requests/" + request_id + "/execute", {})
            wait_observed(alice, request_id)
            grants = [
                g
                for g in snapshot(alice)["grants"]
                if g["identityId"] == human_id and g["resourceId"] == resource
            ]
            if not any(g["status"] == "active" for g in grants):
                raise AssertionError("Fixture grant was not active")
        with report.case(
            "offboarding commits local human containment, grant revocation and sponsored suspension"
        ):
            offboard_id = offboard(alice, acsrf, human_id)
            state = snapshot(alice)
            human = next(v for v in state["identities"] if v["id"] == human_id)
            agent = next(v for v in state["identities"] if v["id"] == agent_id)
            if human["status"] != "offboarded" or agent["status"] != "suspended":
                raise AssertionError("Departure lifecycle containment failed")
            if any(
                g["status"] == "active"
                for g in state["grants"]
                if g["identityId"] in (human_id, agent_id)
            ):
                raise AssertionError("Departure left an active local grant")
        with report.case("offboarding independently observes native SCIM human active=false"):
            wait_observed(alice, offboard_id)
            if connector.get_user(human_subject).get("active") is not False:
                raise AssertionError("Provider human remained active")
        with report.case(
            "sponsored inventory agent remains suspended with native SCIM active=false"
        ):
            state = snapshot(alice)
            agent = next(v for v in state["identities"] if v["id"] == agent_id)
            if (
                agent["status"] != "suspended"
                or connector.get_user(agent_subject).get("active") is not False
            ):
                raise AssertionError("Sponsored inventory agent was not contained")
            contained = True
        if args.snapshot:
            # /snapshot is the synthetic public console DTO and carries no
            # cookies, OAuth tokens, CSRF values, passwords, or runtime settings.
            Path(args.snapshot).write_text(
                json.dumps(snapshot(alice), indent=2) + "\n", encoding="utf-8"
            )
        if args.principal:
            response = alice.get(APP + "/api/v1/session")
            if response.status_code != 200:
                raise RuntimeError("Operator session fixture unavailable")
            principal = response.json()["principal"]
            public_principal = {field: principal[field] for field in ("id", "name", "roles")}
            Path(args.principal).write_text(
                json.dumps(public_principal, indent=2) + "\n", encoding="utf-8"
            )
    except Exception as error:
        report.record_error(error)
    finally:
        if human_id and not contained and "alice" in sessions:
            try:
                with report.case(
                    "interrupted fixture validation contained through authenticated API"
                ):
                    alice, acsrf = sessions["alice"]
                    offboard_id = offboard(alice, acsrf, human_id)
                    wait_observed(alice, offboard_id)
            except Exception as error:
                report.record_error(error, name="synthetic fixture cleanup")
        if connector and human_subject:
            try:
                with report.case("unique fixture provider membership removed"):
                    connector.set_membership(group_id, human_subject, False)
                    members = connector.get_group(group_id).get("members", [])
                    if any(member.get("value") == human_subject for member in members):
                        raise AssertionError("Fixture provider membership remained")
            except Exception as error:
                report.record_error(error, name="synthetic fixture membership cleanup")
        close_sessions(report, sessions)
        if connector:
            connector.http.close()
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
