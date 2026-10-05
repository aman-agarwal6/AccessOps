"""Real authenticated departure cases; external tenant observations are synthetic.

Use a one-shot read-only /run/test-logins.json mount. Only uniquely registered
synthetic inventory is contained. Keep its terminal case, request and audit
history. Entra/GitHub owner statements exercise administrative workflow and
explicit scope exclusions, not external revocation or session termination.
"""

import hashlib
import json
import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from check_report import CheckReport, report_arguments
from live_offboarding import offboard, wait_binding
from live_oidc import APP, BACKEND_FILES, close_sessions, login, post, snapshot, wait_observed

from integrations.enterprise import parse_entra_user, parse_github_members, utc_now
from integrations.enterprise import snapshot as enterprise_snapshot
from integrations.keycloak import MEMBERSHIP_ORIGIN, KeycloakConnector

FIXTURE_NAMES = [
    f"integrations/fixtures/enterprise-{provider}-{phase}.json"
    for provider in ("entra", "github")
    for phase in ("before", "after")
]


def fixture_report(provider, phase):
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads(
        (root / f"integrations/fixtures/enterprise-{provider}-{phase}.json").read_text()
    )
    tenant_id, subject_id, at = fixture["tenantId"], fixture["subjectId"], utc_now()
    if provider == "entra":
        observations = [
            parse_entra_user(
                fixture["responses"]["user"],
                tenant_id=tenant_id,
                subject_id=subject_id,
                observed_at=at,
            )
        ]
    else:
        observations = [
            parse_github_members(
                fixture["responses"][endpoint],
                tenant_id=tenant_id,
                subject_id=subject_id,
                capability=capability,
                scope=f"organization:{tenant_id}",
                observed_at=at,
            )
            for capability, endpoint in (
                ("organization_membership", "members"),
                ("outside_collaborator", "outside_collaborators"),
            )
        ]
        observations.append(
            parse_github_members(
                fixture["responses"]["collaborators"],
                tenant_id=tenant_id,
                subject_id=subject_id,
                capability="repository_collaborator",
                scope="repository:434343",
                observed_at=at,
            )
        )
    return enterprise_snapshot(
        provider,
        tenant_id,
        subject_id,
        observations,
        method="synthetic_fixture",
        collected_at=at,
        limitations=[
            "Synthetic external vendor fixture; no Entra or GitHub tenant contacted.",
            "External owner statements are scope exclusions in a fictional administrative case, not revocation proof.",
        ],
    )


def current_case(http, case_id):
    return next(item for item in snapshot(http)["offboardingCases"] if item["id"] == case_id)


def read_packet(http, path):
    response = http.get(APP + path + "/packet")
    if response.status_code != 200:
        raise RuntimeError("Case packet unavailable")
    return response.json()


def packet_digest(packet):
    return hashlib.sha256(
        json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def closure_input(case):
    return {"expectedRevision": case["revision"], "packetHash": case["packetHash"]}


def main():
    parser = report_arguments(__doc__)
    parser.add_argument("--snapshot", help="Export only the actual synthetic public SnapshotDTO")
    parser.add_argument(
        "--ad-fixture",
        help="Private unique AD fixture reference for the opt-in real directory case",
    )
    args = parser.parse_args()
    report = CheckReport(
        "connected-departure-cases",
        driver="real HTTP OIDC, case API, independent reviewer and native Keycloak SCIM; synthetic cloud imports"
        + ("; actual scoped Samba AD LDAPS" if args.ad_fixture else ""),
        limitations=[
            "Only a uniquely registered synthetic human and suspended sponsored inventory agent are contained.",
            "Entra/GitHub observations are offline synthetic fixtures; no cloud tenant API or revocation write is measured.",
            "External owner attestations explicitly document fictional scope exclusions, not completed real tenant operations.",
            "Administrative closure and immutable packet persistence are measured; universal access termination is not claimed.",
            "Existing operator/agent token revocation and Microsoft AD are not measured here; workforce sessions, operator MFA and signing-key rotation have their own suites.",
            "Terminal fixture inventory, case, statements, requests and audit history are retained.",
            "Native membership observation is a bounded read-only Keycloak 26.8 profile, not general SCIM conformance or federation coverage.",
        ],
        source_files=[
            "scripts/live_cases.py",
            "scripts/live_oidc.py",
            "scripts/live_offboarding.py",
            "scripts/check_report.py",
            "integrations/enterprise.py",
            "integrations/ad.py",
            "scripts/ad_checks.py",
            "integrations/keycloak.py",
            "integrations/transport.py",
            "backend/core/offboarding.py",
        ]
        + BACKEND_FILES
        + FIXTURE_NAMES,
    )
    sessions = {}
    connector = None
    human_id = agent_id = None
    contained = False
    ad_fixture = None
    try:
        with report.case(
            "real owner and independent reviewer OIDC sessions established over verified TLS"
        ):
            logins = json.loads(Path("/run/test-logins.json").read_text())["passwords"]
            for person in ("alice", "bob"):
                sessions[person] = login(person, logins[person])
        alice, acsrf = sessions["alice"]
        bob, bcsrf = sessions["bob"]
        connector = KeycloakConnector()
        suffix = uuid.uuid4().hex[:12]
        with report.case(
            "unique synthetic worker and sponsored inventory agent enrolled and SCIM bindings observed"
        ):
            human = post(
                alice,
                acsrf,
                "/api/v1/identities",
                {
                    "name": "Case Worker " + suffix,
                    "kind": "human",
                    "email": "case-" + suffix + "@fixture.test",
                    "department": "Engineering",
                    "projectIds": ["Atlas"],
                },
                expected=201,
            )["result"]
            human_id = human["id"]
            human_subject = wait_binding(alice, human_id, connector, active=True)
            agent = post(
                alice,
                acsrf,
                "/api/v1/identities",
                {
                    "name": "Case Inventory Agent " + suffix,
                    "kind": "agent",
                    "department": "Engineering",
                    "projectIds": ["Atlas"],
                    "sponsorId": human_id,
                },
                expected=201,
            )["result"]
            agent_id = agent["id"]
            if agent["status"] != "suspended":
                raise AssertionError("Inventory agent was not safely suspended")
            agent_subject = wait_binding(alice, agent_id, connector, active=False)
        if args.ad_fixture:
            with report.case(
                "server-local enrollment derives the exact directory mapping for the unique workforce human"
            ):
                import django
                from django.core.management import call_command

                os.environ.setdefault("DJANGO_SETTINGS_MODULE", "accessops.settings")
                django.setup()
                ad_fixture = json.loads(Path(args.ad_fixture).read_text(encoding="utf-8"))
                binding = ad_fixture["binding"]
                call_command(
                    "enroll_ad",
                    identity_id=uuid.UUID(human_id),
                    domain_guid=binding["domainGuid"],
                    user_guid=binding["userGuid"],
                    group_guid=binding["groupGuids"],
                    verbosity=0,
                )
            from ad_checks import before_checks

            before_checks(report, ad_fixture)
        resource = str(uuid.uuid5(uuid.NAMESPACE_DNS, "accessops:atlas-workspace"))
        group = str(uuid.uuid5(uuid.NAMESPACE_DNS, "accessops:group:atlas-reader"))
        with report.case(
            "independently approved fixture resource grant applied and SCIM membership observed"
        ):
            grant = post(
                alice,
                acsrf,
                "/api/v1/requests",
                {
                    "identityId": human_id,
                    "resourceId": resource,
                    "action": "grant",
                    "permission": "read",
                    "reason": "Unique case worker entitlement for departure validation",
                },
                expected=201,
            )["result"]
            grant_path = "/api/v1/requests/" + grant["id"]
            post(bob, bcsrf, grant_path + "/approve", {})
            post(alice, acsrf, grant_path + "/execute", {})
            wait_observed(alice, grant["id"])
            if not any(
                member.get("value") == human_subject
                for member in connector.get_group(group).get("members", [])
            ):
                raise AssertionError("Approved fixture membership was not observed")
        with report.case(
            "private verified TLS native membership GET succeeds while other methods, realms, paths and public admin are denied"
        ):
            if connector._admin_member(group, human_subject) is not True:
                raise AssertionError("Native membership positive reading unavailable")
            private_path = "/admin/realms/accessops-workforce/groups/" + group + "/members"
            headers = {"Authorization": "Bearer " + connector._token()}
            for method, url in (
                ("POST", MEMBERSHIP_ORIGIN + private_path),
                (
                    "GET",
                    MEMBERSHIP_ORIGIN
                    + private_path.replace("accessops-workforce", "accessops-operators"),
                ),
                ("GET", MEMBERSHIP_ORIGIN + "/admin/realms/accessops-workforce/users"),
                ("GET", connector.issuer.split("/realms/", 1)[0] + private_path),
            ):
                response = connector.http.request(
                    method, url, headers=headers, follow_redirects=False
                )
                if response.status_code != 404:
                    raise AssertionError("Private observation route boundary failed")
        with report.case(
            "authenticated contractor departure case records exact synthetic platform bindings"
        ):
            bindings = [
                {
                    "provider": provider,
                    "tenantId": fixture_report(provider, "before")["observations"][0]["tenantId"],
                    "subjectId": fixture_report(provider, "before")["observations"][0]["subjectId"],
                }
                for provider in ("entra", "github")
            ]
            case = post(
                alice,
                acsrf,
                "/api/v1/offboarding-cases",
                {
                    "identityId": human_id,
                    "employmentType": "contractor",
                    "hrEventId": "fixture-" + suffix,
                    "hrSource": "synthetic-fixture-hr",
                    "effectiveAt": (datetime.now(UTC) - timedelta(seconds=3))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "reason": "Unique synthetic contractor case workflow verification",
                    "bindings": bindings,
                },
                expected=201,
            )["result"]
            case_id = case["id"]
            path = "/api/v1/offboarding-cases/" + case_id
            if case["bindings"] != bindings or not case["blockers"]:
                raise AssertionError("Case account scope or initial blockers missing")
        with report.case("case import without CSRF is denied on the authenticated HTTP boundary"):
            response = alice.post(
                APP + path + "/import",
                json={"report": fixture_report("entra", "before")},
                headers={"Origin": APP, "Idempotency-Key": str(uuid.uuid4())},
            )
            if response.status_code != 403:
                raise AssertionError("Unprotected case mutation accepted")
        with report.case(
            "synthetic before imports reveal residual access and preserve collection method"
        ):
            for provider in ("entra", "github"):
                case = post(
                    alice, acsrf, path + "/import", {"report": fixture_report(provider, "before")}
                )["result"]
            if len(case["imports"]) != 2 or any(
                item["collectionMethod"] != "synthetic_fixture" for item in case["imports"]
            ):
                raise AssertionError("Synthetic collection provenance was lost")
            if not all(
                any(f"Residual {provider} access" in blocker for blocker in case["blockers"])
                for provider in ("entra", "github")
            ):
                raise AssertionError("Imported residual access was not assessed")
            stale = closure_input(case)
        with report.case("mismatched account import and unexpected report fields are denied"):
            wrong = fixture_report("entra", "before")
            for item in wrong["observations"]:
                item["subjectId"] = "33333333-3333-4333-8333-333333333333"
            denied = post(alice, acsrf, path + "/import", {"report": wrong}, expected=409)
            if denied.get("error", {}).get("code") != "account_binding_mismatch":
                raise AssertionError("Wrong denial for account binding")
            invalid = {**fixture_report("entra", "before"), "rawRecords": []}
            post(alice, acsrf, path + "/import", {"report": invalid}, expected=400)
        with report.case(
            "unresolved case cannot close and native containment cannot be replaced by attestation"
        ):
            denied = post(
                bob,
                bcsrf,
                path + "/close",
                closure_input(current_case(alice, case_id)),
                expected=409,
            )
            if denied.get("error", {}).get("code") != "closure_blocked":
                raise AssertionError("Unresolved closure was not blocked")
            post(
                alice,
                acsrf,
                path + "/tasks/keycloak-directory/attest",
                {
                    "reference": "fixture-" + suffix,
                    "summary": "Synthetic owner statement cannot replace actual Keycloak observation.",
                },
                expected=409,
            )
        with report.case(
            "case containment revokes local grant and durable SCIM observes disabled worker"
        ):
            case = post(alice, acsrf, path + "/contain", {})["result"]
            wait_observed(alice, case["containmentRequestId"])
            state = snapshot(alice)
            human = next(item for item in state["identities"] if item["id"] == human_id)
            agent = next(item for item in state["identities"] if item["id"] == agent_id)
            if (
                human["status"] != "offboarded"
                or agent["status"] != "suspended"
                or any(
                    item["status"] == "active"
                    for item in state["grants"]
                    if item["identityId"] in (human_id, agent_id)
                )
            ):
                raise AssertionError("Case containment left local access")
            if (
                connector.get_user(human_subject).get("active") is not False
                or connector.get_user(agent_subject).get("active") is not False
            ):
                raise AssertionError("Native disabled account state was not observed")
            membership_deadline = time.monotonic() + 180
            while time.monotonic() < membership_deadline:
                if not any(
                    member.get("value") == human_subject
                    for member in connector.get_group(group).get("members", [])
                ):
                    break
                time.sleep(0.5)
            else:
                raise AssertionError("Fixture provider membership survived bounded containment")
            if connector._admin_member(group, human_subject) is not False:
                raise AssertionError("Independent native membership negative reading unavailable")
            case = current_case(alice, case_id)
            for key in ("local-containment", "keycloak-directory"):
                task = next(item for item in case["tasks"] if item["id"] == key)
                if task["status"] != "observed" or task["evidenceKind"] != "provider_observation":
                    raise AssertionError("Case lost actual local/provider evidence basis")
            contained = True
        if ad_fixture:
            with report.case(
                "case-triggered durable AD job publishes a fresh actual directory observation"
            ):
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline:
                    case = current_case(alice, case_id)
                    task = next(item for item in case["tasks"] if item["id"] == "ad-directory")
                    if (
                        task["status"] == "observed"
                        and task["evidenceKind"] == "provider_observation"
                    ):
                        break
                    time.sleep(0.5)
                else:
                    raise AssertionError("Directory case observation unavailable")
            from ad_checks import after_checks

            after_checks(report, ad_fixture)
            with report.case(
                "bound directory task rejects an owner statement and refreshes through read-only observation"
            ):
                post(
                    alice,
                    acsrf,
                    path + "/tasks/ad-directory/attest",
                    {
                        "reference": "fixture-" + suffix,
                        "summary": "A synthetic statement cannot replace the actual directory reading.",
                    },
                    expected=409,
                )
                post(alice, acsrf, path + "/observe-directory", {})
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline:
                    task = next(
                        item
                        for item in current_case(alice, case_id)["tasks"]
                        if item["id"] == "ad-directory"
                    )
                    if (
                        task["status"] == "observed"
                        and task["evidenceKind"] == "provider_observation"
                    ):
                        break
                    time.sleep(0.5)
                else:
                    raise AssertionError("Read-only directory refresh incomplete")
        with report.case(
            "synthetic after import observes Entra disabled and leaves GitHub and session gaps unresolved"
        ):
            for provider in ("entra", "github"):
                case = post(
                    alice, acsrf, path + "/import", {"report": fixture_report(provider, "after")}
                )["result"]
            task = next(item for item in case["tasks"] if item["id"] == "entra-directory")
            if task["status"] != "observed" or task["evidenceKind"] != "imported_snapshot":
                raise AssertionError("Matched external fixture was incorrectly classified")
            for key in ("entra-sessions", "github-org", "github-repositories", "credentials"):
                if next(item for item in case["tasks"] if item["id"] == key)["status"] != "pending":
                    raise AssertionError("Unknown platform state cleared a required action")
        with report.case("stale closure input and non-owner external attestations are denied"):
            denied = post(bob, bcsrf, path + "/close", stale, expected=409)
            if denied.get("error", {}).get("code") != "stale_case":
                raise AssertionError("Stale evidence closure was not denied")
            denied = post(
                bob,
                bcsrf,
                path + "/tasks/entra-sessions/attest",
                {
                    "reference": "fixture-" + suffix,
                    "summary": "Synthetic non-owner statement must not become accountable owner evidence.",
                },
                expected=403,
            )
            if denied.get("error", {}).get("code") != "owner_required":
                raise AssertionError("External evidence owner boundary was not applied")
        with report.case(
            "owner records explicit synthetic scope exclusions with owner-attestation evidence kind"
        ):
            for task in list(case["tasks"]):
                if task["status"] == "pending":
                    case = post(
                        alice,
                        acsrf,
                        path + "/tasks/" + task["id"] + "/attest",
                        {
                            "reference": "fixture-" + suffix + ":" + task["id"],
                            "summary": "Offline fixture scope excludes this external platform. No tenant operation or session/credential revocation was measured; this is a synthetic owner statement for administrative review only.",
                        },
                    )["result"]
            if case["blockers"] or not all(
                item["evidenceKind"] == "owner_attestation"
                for item in case["tasks"]
                if item["status"] == "attested"
            ):
                raise AssertionError("Owner statement labeling or blocker assessment failed")
        with report.case(
            "owner self-closure is denied and the current draft packet records evidence boundaries"
        ):
            denied = post(alice, acsrf, path + "/close", closure_input(case), expected=403)
            # Layered denial: a non-approver owner stops at the server role gate; an
            # approver who owns the case stops at policy or the domain check.
            owner_roles = alice.get(APP + "/api/v1/session").json()["principal"]["roles"]
            expected_codes = (
                {"policy_denied", "independent_reviewer_required"}
                if "approver" in owner_roles
                else {"role_denied"}
            )
            if denied.get("error", {}).get("code") not in expected_codes:
                raise AssertionError("Owner self-closure was not denied by the expected layer")
            if current_case(alice, case_id)["status"] == "closed":
                raise AssertionError("Owner self-closure changed the case")
            draft = read_packet(alice, path)
            if (
                draft["origin"] != "connected_case_draft"
                or draft["case"]["blockers"]
                or not draft["limitations"]
            ):
                raise AssertionError("Draft packet evidence limits missing")
        with report.case(
            "independent reviewer closes exact current evidence into a persisted administrative packet"
        ):
            case = post(bob, bcsrf, path + "/close", closure_input(draft["case"]))["result"]
            reviewer = bob.get(APP + "/api/v1/session").json()["principal"]["id"]
            if (
                case["status"] != "closed"
                or case["closedById"] != reviewer
                or case["closureBasis"] != "reviewed_evidence"
            ):
                raise AssertionError("Independent administrative closure did not persist")
            packet = read_packet(alice, path)
            if (
                packet["origin"] != "connected_case"
                or packet["case"]["status"] != "closed"
                or not packet["limitations"]
            ):
                raise AssertionError("Closed case packet unavailable")
            frozen_digest = packet_digest(packet)
        with report.case(
            "closed case rejects later import and attestation while its packet remains immutable"
        ):
            for endpoint, body in (
                ("/import", {"report": fixture_report("entra", "after")}),
                (
                    "/tasks/entra-sessions/attest",
                    {
                        "reference": "fixture-" + suffix,
                        "summary": "A later synthetic statement must not overwrite the closed evidence packet.",
                    },
                ),
            ):
                denied = post(alice, acsrf, path + endpoint, body, expected=409)
                if denied.get("error", {}).get("code") != "case_closed":
                    raise AssertionError("Closed case mutation was not rejected")
            if packet_digest(read_packet(bob, path)) != frozen_digest:
                raise AssertionError("Closed administrative packet changed")
        if args.snapshot:
            Path(args.snapshot).write_text(
                json.dumps(snapshot(alice), indent=2) + "\n", encoding="utf-8"
            )
    except Exception as error:
        report.record_error(error)
    finally:
        if human_id and not contained and "alice" in sessions:
            try:
                with report.case(
                    "interrupted unique worker fixture contained through authenticated API"
                ):
                    alice, acsrf = sessions["alice"]
                    wait_observed(alice, offboard(alice, acsrf, human_id))
            except Exception as error:
                report.record_error(error, name="unique worker containment cleanup")
        close_sessions(report, sessions)
        if connector:
            connector.http.close()
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
