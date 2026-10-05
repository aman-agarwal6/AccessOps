"""Run from the backend container; exercise real synthetic provider resources.

Creates and deletes only a unique accessops-test-* identity/group pair. Output
contains check names and statuses, never credentials, raw tokens, or headers.
"""

import os
import uuid

from check_report import CheckReport, report_arguments

from integrations.errors import ConnectorError
from integrations.keycloak import KeycloakConnector
from integrations.policy import PolicyClient
from integrations.security import ExecutorClient, verify_executor_token
from integrations.transport import client


def main():
    args = report_arguments(__doc__).parse_args()
    report = CheckReport(
        "native-protocols",
        driver="live service HTTP over verified TLS",
        limitations=[
            "A bounded interoperability check, not SCIM or AuthZEN conformance certification.",
            "Provider login-session revocation and signing-key rotation are measured by their own suites, not here.",
        ],
        source_files=[
            "scripts/live_integrations.py",
            "scripts/check_report.py",
            "integrations/keycloak.py",
            "integrations/policy.py",
            "integrations/security.py",
            "integrations/transport.py",
        ],
    )
    check = report.require
    connector = None
    user_id = group_id = None
    executor = policy = None
    try:
        connector = KeycloakConnector()
        check(
            "native SCIM discovery",
            set(connector.discover()) == {"ServiceProviderConfig", "Schemas", "ResourceTypes"},
        )
        suffix = uuid.uuid4().hex[:12]
        user = connector.create_user(
            "accessops-test-" + suffix,
            external_id="test-" + suffix,
            given_name="Synthetic",
            family_name="Validation",
        )
        user_id = user["id"]
        check("SCIM create and read", connector.get_user(user_id).get("active") is True)
        found = connector.list_resources(
            "Users", filter_expression='userName eq "accessops-test-' + suffix + '"', count=1
        )
        check(
            "SCIM filter and pagination",
            len(found.get("Resources", [])) == 1 and found["Resources"][0]["id"] == user_id,
        )
        group = connector.create_group("accessops-test-" + suffix)
        group_id = group["id"]
        identity, resource = {"providerSubject": user_id}, {"providerGroup": group_id}
        check(
            "SCIM group grant observed",
            connector.apply({"kind": "grant"}, identity, resource)["verified"],
        )
        check(
            "SCIM group revoke observed",
            connector.apply({"kind": "revoke"}, identity, resource)["verified"],
        )
        check(
            "SCIM active=false observed",
            connector.apply({"kind": "offboard"}, identity)["verified"],
        )
        denied = False
        try:
            KeycloakConnector(issuer=os.environ["OIDC_ISSUER"])
        except ConnectorError:
            denied = True
        check("connector operators realm denied", denied)
        executor = ExecutorClient()
        access_token = executor.token()
        claims = verify_executor_token(access_token)
        check(
            "private_key_jwt and signed token verified",
            claims.get("sub") == str(uuid.uuid5(uuid.NAMESPACE_DNS, "accessops:review-assistant")),
        )
        check("live introspection active", executor.introspect(access_token).get("active") is True)
        with client() as http:
            response = http.get(
                os.environ["WORKFORCE_ISSUER"] + "/scim/v2/Users",
                headers={"Authorization": "Bearer " + access_token},
            )
            check("executor denied SCIM administration", response.status_code in (401, 403))
            response = http.get(
                os.environ["OIDC_ISSUER"] + "/scim/v2/Users",
                headers={"Authorization": "Bearer " + connector._token()},
            )
            check(
                "workforce SCIM token denied operator realm",
                response.status_code in (401, 403, 404),
            )
        policy = PolicyClient()
        data = {
            "action": "execute",
            "subject": {
                "id": "synthetic-operator",
                "kind": "human",
                "status": "active",
                "roles": ["operator"],
                "project_ids": ["Atlas"],
            },
            "resource": {"id": "synthetic-resource", "project": "Atlas"},
            "request": {"action": "grant", "policy_version": "accessops-v1"},
            "context": {"policy_version": "accessops-v1", "approval_valid": True},
        }
        decision = policy.evaluate(data)
        check(
            "real AuthZEN allow with exact bundle digest",
            decision["allow"] is True
            and len(decision["bundle_sha256"]) == 64
            and decision["bundle_sha256"] == os.environ.get("ACCESSOPS_POLICY_SHA256"),
        )
        data["context"]["approval_valid"] = False
        check("real OPA grant without approval denied", policy.evaluate(data)["allow"] is False)
        data["request"]["action"] = "revoke"
        check("real OPA immediate containment allowed", policy.evaluate(data)["allow"] is True)
        data["resource"]["project"] = "Pulse"
        check("real OPA cross-project containment denied", policy.evaluate(data)["allow"] is False)
        # A short token is rejected locally by PolicyClient. Only an actual HTTP
        # request provides evidence about the adapter's authentication boundary.
        with client() as http:
            response = http.post(
                policy.base_url + "/access/v1/evaluation",
                json={},
                headers={"Authorization": "Bearer " + "invalid-" * 6},
            )
            check("real AuthZEN unauthorized evaluation denied", response.status_code == 401)
    except Exception as error:
        report.record_error(error)
    finally:
        # A failed group deletion must not prevent the user cleanup attempt.
        if connector:
            for name, identifier, remove in (
                ("temporary SCIM group removed", group_id, connector.delete_group),
                ("temporary SCIM user removed", user_id, connector.delete_user),
            ):
                if identifier:
                    try:
                        with report.case(name):
                            remove(identifier)
                    except Exception as error:
                        report.record_error(error, name=name)
            connector.http.close()
        for service in (executor, policy):
            if service:
                service.http.close()
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
