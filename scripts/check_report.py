"""Allowlisted local check reports; never serialize exception messages or records."""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


class CheckReport:
    def __init__(self, suite, *, driver, origin="connected", limitations=(), source_files=()):
        self.suite = suite
        self.driver = driver
        self.origin = origin
        self.limitations = list(limitations)
        self.started_at = utc_now()
        self.started = time.monotonic()
        self.checks = []
        self.error_type = None
        self.source_files = {}
        root = Path(__file__).resolve().parents[1]
        for name in source_files:
            path = root / name
            if path.is_file():
                self.source_files[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    @contextmanager
    def case(self, name):
        started_at, started = utc_now(), time.monotonic()
        try:
            yield
        except Exception:
            self.checks.append(
                {
                    "name": name,
                    "status": "failed",
                    "started_at": started_at,
                    "duration_seconds": round(time.monotonic() - started, 6),
                }
            )
            raise
        else:
            self.checks.append(
                {
                    "name": name,
                    "status": "passed",
                    "started_at": started_at,
                    "duration_seconds": round(time.monotonic() - started, 6),
                }
            )

    def require(self, name, condition):
        with self.case(name):
            if not condition:
                raise AssertionError("Check failed")

    def record_error(self, error, *, name="check execution"):
        # Error messages, tracebacks, HTTP URLs, and provider responses can contain
        # credentials or records. Publish only the exception class and static name.
        self.error_type = type(error).__name__
        if not self.checks or self.checks[-1]["status"] != "failed":
            self.checks.append(
                {"name": name, "status": "failed", "started_at": utc_now(), "duration_seconds": 0}
            )

    def finish(self, args):
        revision = os.getenv("ACCESSOPS_SOURCE_COMMIT", "")
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            revision = "unrecorded"
        policy = os.getenv("ACCESSOPS_POLICY_SHA256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", policy):
            policy = "unrecorded"
        counts = {
            status: sum(check["status"] == status for check in self.checks)
            for status in ("passed", "failed", "skipped")
        }
        report = {
            "schema_version": 1,
            "origin": self.origin,
            "suite": self.suite,
            "driver": self.driver,
            "started_at": self.started_at,
            "completed_at": utc_now(),
            "duration_seconds": round(time.monotonic() - self.started, 6),
            "status": "failed" if self.error_type or counts["failed"] else "passed",
            "counts": counts,
            "checks": self.checks,
            "source": {
                "revision": revision,
                "revision_origin": "runtime setting; not an attestation",
                "expected_policy_bundle_sha256": policy,
                "files_sha256": self.source_files,
            },
            "limitations": self.limitations,
        }
        if self.error_type:
            report["error_type"] = self.error_type
        raw = json.dumps(report, indent=2) + "\n"
        if args.report:
            Path(args.report).write_text(raw, encoding="utf-8")
        if args.junit:
            suite = ET.Element(
                "testsuite",
                name=self.suite,
                tests=str(len(self.checks)),
                failures=str(counts["failed"]),
                skipped=str(counts["skipped"]),
                timestamp=self.started_at,
                time=str(report["duration_seconds"]),
            )
            properties = ET.SubElement(suite, "properties")
            for name, value in (
                ("origin", self.origin),
                ("driver", self.driver),
                ("source_revision", revision),
                ("completed_at", report["completed_at"]),
            ):
                ET.SubElement(properties, "property", name=name, value=value)
            for check in self.checks:
                case = ET.SubElement(
                    suite,
                    "testcase",
                    classname=self.suite,
                    name=check["name"],
                    time=str(check["duration_seconds"]),
                )
                if check["status"] == "failed":
                    ET.SubElement(
                        case,
                        "failure",
                        type=self.error_type or "CheckFailed",
                        message="Check failed; private diagnostics were omitted",
                    )
            ET.ElementTree(suite).write(args.junit, encoding="utf-8", xml_declaration=True)
        print(raw, end="")
        return 1 if report["status"] == "failed" else 0


def report_arguments(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--report", help="Write the sanitized JSON report to this file")
    parser.add_argument("--junit", help="Write the sanitized JUnit report to this file")
    return parser
