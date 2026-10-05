"""Build a read-only public index from fixed, sanitized local verification files.

This does not run checks, create provenance, or turn simulations into evidence.
Original failed attempts retain their results and source metadata.
"""

import datetime as dt
import hashlib
import json
import math
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONNECTED = {
    "policy": "OPA authorization rules",
    "protocols": "Identity and authorization protocols",
    "oidc-business": "OIDC login and protected access lifecycle",
    "offboarding": "Connected offboarding and unbacked access",
    "cases": "Authenticated enterprise departure cases — mixed evidence",
    "cases-attempt-1": "Initial case adapter check — failed attempt retained",
    "cases-attempt-2": "Initial membership-removal check — failed attempt retained",
    "cases-attempt-3": "Owner self-closure assertion — failed attempt retained",
    "ad-offboarding": "Actual scoped Samba AD directory departure",
    "host-health": "Verified host HTTPS boundary",
    "policy-outage": "Actual OPA outage denial",
    "identity-outage": "Actual identity-provider outage denial",
    "offboarding-attempt-1-failed": "Initial drift check — failed attempt retained",
    "host-health-attempt-1-failed": "Initial TLS negative probe — failed attempt retained",
    "sessions": "Workforce session revocation before and after containment",
    "sessions-attempt-1": "Initial session revocation run — failed attempt retained",
    "hr-intake": "Signed HR leaver intake, timed to app sign-out",
    "hr-intake-attempt-1": "Initial HR intake run — failed attempt retained",
    "hr-intake-attempt-2": "Second HR intake run — failed attempt retained",
    "leaver-assurance": "Leaver assurance and signed SOC signals",
    "leaver-assurance-attempt-1": "Initial leaver assurance run — failed attempt retained",
}
JUNIT = {
    "postgresql-tests.xml": (
        "PostgreSQL lifecycle and security tests",
        "Disposable PostgreSQL 17 / Python 3.13; isolated provider boundaries, not live protocol measurements.",
    ),
    "backend-host-tests.xml": (
        "Backend lifecycle and security tests (host SQLite)",
        "Actual host run with SQLite test settings; the PostgreSQL-only concurrency test is skipped here and covered by the PostgreSQL runner.",
    ),
    "frontend-unit.xml": (
        "Console domain and contract tests",
        "Actual Vitest execution of browser-domain and data-contract tests; simulated state, no provider effects.",
    ),
    "browser-tests.xml": (
        "Console browser and accessibility checks",
        "Actual local browser automation; automated checks are not full accessibility conformance or provider authentication evidence.",
    ),
    "enterprise-integration-tests.xml": (
        "Enterprise collector and integration boundary checks",
        "Actual isolated synthetic parsing, scoped transport and denial checks; no Entra or GitHub tenant measurement.",
    ),
    "case-tests.xml": (
        "Departure case evidence and closure regressions",
        "Isolated case API/database tests, including simulated persisted provider observations; no live directory measurement.",
    ),
    "case-tests-attempt-1.xml": (
        "Initial departure case test attempt — failures retained",
        "Historical isolated test attempt; later corrections did not rewrite this result.",
    ),
    "case-tests-attempt-2.xml": (
        "Initial directory freshness test attempt — failure retained",
        "Historical isolated test fixture failure; later corrections did not rewrite this result.",
    ),
    "case-tests-attempt-3.xml": (
        "Initial directory worker fixture attempt — failures retained",
        "Historical isolated test fixture failures; later corrections did not rewrite this result.",
    ),
    "connected-renderer-tests.xml": (
        "Connected console rendering of a recorded lab snapshot",
        "Actual browser rendering of a sanitized snapshot recorded from the lab, served through intercepted read endpoints. Checks DTO compatibility, labels, layout and accessibility; it is not authentication or provider evidence.",
    ),
    "enterprise-ad-integration-tests.xml": (
        "Enterprise collectors and scoped directory adapter checks",
        "Actual isolated normalization, cryptography and transport denial checks; mocked boundaries do not prove a live tenant or directory effect.",
    ),
}


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Report timestamp is missing or invalid")
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    # The container and JS test reporters emit UTC; some JUnit formats omit Z.
    if result.tzinfo is None:
        result = result.replace(tzinfo=dt.timezone.utc)
    return result.astimezone(dt.timezone.utc)


def read_report(path):
    path.resolve().relative_to((ROOT / "output").resolve())
    if path.is_symlink() or path.stat().st_size > 8_000_000:
        raise ValueError("Report is not a bounded regular local file")
    raw = path.read_bytes()
    return raw, hashlib.sha256(raw).hexdigest()


def record(name, scenario, started, ended, checks, manifest, digest):
    if not checks or ended < started:
        raise ValueError("Empty or chronologically invalid verification")
    counts = {
        status: sum(c["status"] == status for c in checks)
        for status in ("passed", "failed", "skipped")
    }
    return {
        "id": scenario + "-" + digest[:16],
        "name": name,
        "scenario": scenario,
        "status": "failed" if counts["failed"] else "passed",
        "origin": "recorded",
        "startedAt": started.isoformat(),
        "finishedAt": ended.isoformat(),
        "summary": f"{counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped. Actual local verification; see scope and limitations.",
        "checks": checks,
        "manifest": {"reportSha256": digest, "counts": counts, **manifest},
    }


def connected_record(stem, name):
    path = ROOT / "output" / "connected" / (stem + ".json")
    raw, digest = read_report(path)
    data = json.loads(raw)
    if data.get("origin") not in ("local", "connected") or data.get("schema_version") != 1:
        raise ValueError("Only actual allowlisted check reports can be recorded")
    checks = []
    for item in data["checks"]:
        if item["status"] not in ("passed", "failed", "skipped"):
            raise ValueError("Unknown check result")
        checks.append(
            {
                "name": item["name"],
                "status": item["status"],
                "detail": "Actual check using " + data["driver"] + ".",
            }
        )
    limits = data["limitations"] + [
        "Local workstation measurement; not signed CI provenance or protocol certification."
    ]
    if "attempt" in stem:
        limits.append(
            "Historical failed attempt retained alongside the later retry; its result was not rewritten."
        )
    return record(
        name,
        stem,
        timestamp(data["started_at"]),
        timestamp(data["completed_at"]),
        checks,
        {
            "measurementOrigin": data["origin"],
            "driver": data["driver"],
            "source": data["source"],
            "limitations": limits,
        },
        digest,
    )


def junit_record(filename, name, scope):
    raw, digest = read_report(ROOT / "output" / filename)
    root = ET.fromstring(raw)
    suites = list(root.iter("testsuite"))
    started = min(timestamp(s.get("timestamp")) for s in suites)
    seconds = sum(float(s.get("time", "0")) for s in suites)
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError("Invalid JUnit duration")
    # Suite duration records elapsed verification scope; no provider latency claim.
    ended = started + dt.timedelta(seconds=seconds)
    checks = [
        {
            "name": case.get("name", "unnamed"),
            "status": "failed"
            if case.find("failure") is not None or case.find("error") is not None
            else "skipped"
            if case.find("skipped") is not None
            else "passed",
            "detail": scope,
        }
        for case in root.iter("testcase")
    ]
    return record(
        name,
        filename.removesuffix(".xml"),
        started,
        ended,
        checks,
        {
            "measurementOrigin": "local",
            "sourceRevision": "unrecorded",
            "limitations": [
                scope,
                "No signed provenance. JUnit identifies actual test outcomes; it does not establish a source revision.",
            ],
        },
        digest,
    )


def directory_auth_record(stem):
    raw, digest = read_report(ROOT / "output" / "connected" / (stem + ".json"))
    data = json.loads(raw)
    if (
        data.get("schemaVersion") != 1
        or data.get("origin") != "connected_samba_ad"
        or data.get("phase") not in ("before", "after")
    ):
        raise ValueError("Only the exact synthetic directory authentication report is supported")
    checks = []
    for item in data["checks"]:
        if item["status"] not in ("passed", "failed", "skipped"):
            raise ValueError("Unknown authentication check result")
        checks.append(
            {
                "name": item["name"],
                "status": item["status"],
                "detail": "Actual one-shot verified LDAPS and Kerberos fixture authentication.",
            }
        )
    return record(
        f"Scoped directory new authentication — {data['phase']} · fixture {stem[-12:]}",
        stem,
        timestamp(data["startedAt"]),
        timestamp(data["finishedAt"]),
        checks,
        {
            "measurementOrigin": data["origin"],
            "sourceRevision": "unrecorded",
            "limitations": [
                *data["limitations"],
                "Local one-shot measurement, not signed provenance or universal session revocation.",
            ],
        },
        digest,
    )


def main():
    runs = []
    for stem, name in CONNECTED.items():
        if (ROOT / "output" / "connected" / (stem + ".json")).is_file():
            runs.append(connected_record(stem, name))
    for filename, (name, scope) in JUNIT.items():
        if (ROOT / "output" / filename).is_file():
            runs.append(junit_record(filename, name, scope))
    # Only these reviewed report shapes and exact synthetic suffixes are eligible.
    directory_reports = [
        p
        for p in (ROOT / "output" / "connected").glob("*.json")
        if re.fullmatch(r"(?:cases-ad|ad-auth-before|ad-auth-after)-[a-f0-9]{12}", p.stem)
    ]
    if len(directory_reports) > 30:
        raise ValueError("Directory report publication limit reached; review exact selections")
    for path in directory_reports:
        runs.append(
            connected_record(
                path.stem,
                f"Actual scoped Samba directory departure case · fixture {path.stem[-12:]}",
            )
            if path.stem.startswith("cases-ad-")
            else directory_auth_record(path.stem)
        )
    if not runs:
        raise ValueError("No actual reports available; no evidence was published")
    target = ROOT / "frontend" / "public" / "evidence" / "index.json"
    target.write_text(
        json.dumps({"runs": sorted(runs, key=lambda r: r["startedAt"], reverse=True)}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(
        f"Published {len(runs)} actual local records, including retained failures. No signatures claimed."
    )


if __name__ == "__main__":
    main()
