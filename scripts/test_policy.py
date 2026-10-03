"""Run the immutable OPA image against local policy source without network access."""

import json
import subprocess
from pathlib import Path

from check_report import CheckReport, report_arguments


def main():
    args = report_arguments(__doc__).parse_args()
    root = Path(__file__).resolve().parents[1]
    report = CheckReport(
        "opa-policy",
        driver="digest-pinned OPA container; network disabled",
        origin="local",
        limitations=["Tests local policy source, not live policy adapter interoperability."],
        source_files=[
            "scripts/test_policy.py",
            "scripts/check_report.py",
            "policies/accessops.rego",
            "policies/accessops_test.rego",
            "infra/images.lock.json",
        ],
    )
    try:
        image = json.loads((root / "infra/images.lock.json").read_text())["opa"]
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--mount",
                "type=bind,src=" + str(root / "policies") + ",dst=/policies,readonly",
                image,
                "test",
                "/policies",
                "--format=json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        tests = json.loads(result.stdout)
        if not isinstance(tests, list) or not tests:
            raise RuntimeError("OPA did not return test cases")
        for test in tests:
            # Only names from the local static test definitions enter the report.
            if not isinstance(test.get("name"), str) or not test["name"].startswith("test_"):
                raise RuntimeError("Invalid OPA test name")
            try:
                report.require(test["name"], not test.get("fail", False) and not test.get("error"))
            except AssertionError as error:
                report.record_error(error)
        if result.returncode:
            raise RuntimeError("OPA returned failure")
    except Exception as error:
        report.record_error(error)
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
