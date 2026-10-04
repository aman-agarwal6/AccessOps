"""One-shot unique-user authentication probe; no connector/admin credentials."""

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import ldap

sys.path.insert(0, "/lab")
from health import connection


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    started = dt.datetime.now(dt.timezone.utc)
    checks = []
    try:
        fixture = json.loads(Path("/run/ad-fixture.json").read_text())
        username = fixture["fixtureUser"]
        if not re.fullmatch("departure_[a-f0-9]{12}", username):
            raise ValueError
        password = fixture["fixturePassword"]
        expect_active = args.phase == "before"
        client = connection()
        try:
            client.simple_bind_s(username + "@ADLAB.TEST", password)
            accepted = True
        except ldap.INVALID_CREDENTIALS:
            accepted = False
        finally:
            client.unbind_s()
        checks.append(
            {
                "name": "new verified LDAPS password authentication "
                + ("succeeds" if expect_active else "is denied"),
                "status": "passed" if accepted is expect_active else "failed",
            }
        )
        config = Path("/tmp/krb5.conf")
        config.write_text(
            "[libdefaults]\n default_realm = ADLAB.TEST\n dns_lookup_kdc = false\n rdns = false\n[realms]\n ADLAB.TEST = {\n kdc = dc.adlab.test\n }\n"
        )
        os.environ["KRB5_CONFIG"] = str(config)
        os.environ["KRB5CCNAME"] = "FILE:/tmp/fixture-ticket"
        outcome = subprocess.run(
            ["kinit", username + "@ADLAB.TEST"],
            input=password + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
        checks.append(
            {
                "name": "new Kerberos ticket issuance "
                + ("succeeds" if expect_active else "is denied"),
                "status": "passed" if (outcome.returncode == 0) is expect_active else "failed",
            }
        )
    except Exception:
        checks.append({"name": "bounded fixture authentication probe", "status": "failed"})
    result = {
        "schemaVersion": 1,
        "origin": "connected_samba_ad",
        "startedAt": started.isoformat(),
        "finishedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "phase": args.phase,
        "checks": checks,
        "counts": {
            "passed": sum(c["status"] == "passed" for c in checks),
            "failed": sum(c["status"] == "failed" for c in checks),
            "skipped": 0,
        },
        "limitations": [
            "Only this unique synthetic user is tested; no existing session or ticket revocation is measured.",
            "Samba AD-compatible lab behavior, not Microsoft AD interoperability.",
        ],
    }
    Path(args.report).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["counts"]))
    return int(result["counts"]["failed"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
