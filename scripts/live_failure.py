"""Probe a deliberately stopped dependency; never changes application records."""

from check_report import CheckReport, report_arguments

from integrations.errors import TokenValidationError
from integrations.policy import PolicyClient
from integrations.security import ExecutorClient


def main():
    parser = report_arguments(__doc__)
    parser.add_argument("dependency", choices=("policy", "identity"))
    args = parser.parse_args()
    report = CheckReport(
        args.dependency + "-outage",
        driver="live service dependency outage",
        limitations=[
            "The policy probe measures authorization denial; the identity probe measures new token issuance failure.",
            "Existing-token introspection during an outage is not measured by this suite.",
        ],
        source_files=[
            "scripts/live_failure.py",
            "scripts/check_report.py",
            "integrations/policy.py",
            "integrations/security.py",
            "integrations/transport.py",
        ],
    )
    service = None
    try:
        with report.case(args.dependency + " outage fails closed"):
            if args.dependency == "policy":
                data = {
                    "action": "snapshot",
                    "subject": {
                        "id": "outage-probe",
                        "kind": "human",
                        "status": "active",
                        "roles": ["operator"],
                        "project_ids": ["Atlas"],
                    },
                }
                service = PolicyClient()
                decision = service.evaluate(data)
                if decision["allow"] is not False or decision["reason"] != "policy_unavailable":
                    raise AssertionError("Policy did not fail closed")
            else:
                service = ExecutorClient()
                try:
                    service.token()
                except TokenValidationError:
                    pass
                else:
                    raise AssertionError("Stopped identity provider issued a token")
    except Exception as error:
        report.record_error(error)
    finally:
        if service:
            service.http.close()
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
