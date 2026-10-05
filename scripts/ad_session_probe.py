"""Existing directory sessions and Kerberos tickets, held across offboarding.

Runs in one container on the directory network for the whole departure case.
While the unique synthetic fixture user is still active, it opens what a person
already signed in would hold: an LDAPS connection authenticated with the
password, a Kerberos ticket-granting ticket, an LDAP service ticket, and an LDAP
connection authenticated with that ticket. It then waits for the case to
offboard the user and checks what each one still does.

Measured on Samba 4.19: the domain controller refuses new service tickets for
the disabled account, but connections opened before, and service tickets issued
before, keep working with the removed group still in their security token until
they close or expire. Kerberos has no per-user revocation. The "residual" checks
assert that behavior, so a change in it shows up as a failure to review. Uses
only the fixture user's own credentials; never prints them.
"""

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import ldap

sys.path.insert(0, "/lab")
from health import connection

BASE = "DC=adlab,DC=test"
SERVICE = "ldap/dc.adlab.test"


def kerberos():
    config = Path("/tmp/krb5.conf")
    config.write_text(
        "[libdefaults]\n default_realm = ADLAB.TEST\n dns_lookup_kdc = false\n rdns = false\n"
        "[realms]\n ADLAB.TEST = {\n kdc = dc.adlab.test\n }\n"
    )
    os.environ["KRB5_CONFIG"] = str(config)
    os.environ["KRB5CCNAME"] = "FILE:/tmp/held-tickets"


def run(*command, stdin=None):
    return subprocess.run(command, input=stdin, text=True, capture_output=True, timeout=15)


def ticket_expiry(principal_prefix):
    """End time of the first cached ticket for a principal, from klist."""
    listing = run("klist").stdout
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[4].startswith(principal_prefix):
            for layout in ("%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
                try:
                    return dt.datetime.strptime(parts[2] + " " + parts[3], layout)
                except ValueError:
                    continue
    return None


def kerberos_ldap():
    """An LDAP connection authenticated with the cached Kerberos ticket (GSSAPI,
    signed and sealed), through Samba's own client."""
    from samba import Ldb
    from samba.credentials import MUST_USE_KERBEROS, SPECIFIED, Credentials
    from samba.param import LoadParm

    lp = LoadParm()
    lp.set("realm", "ADLAB.TEST")
    lp.set("workgroup", "ADLAB")
    creds = Credentials()
    creds.guess(lp)
    creds.set_kerberos_state(MUST_USE_KERBEROS)
    creds.set_named_ccache("FILE:/tmp/held-tickets", SPECIFIED, lp)
    return Ldb(url="ldap://dc.adlab.test", credentials=creds, lp=lp)


def token_sids_simple(client):
    rows = client.search_s("", ldap.SCOPE_BASE, "(objectClass=*)", ["tokenGroups"])
    return {bytes(value) for value in rows[0][1].get("tokenGroups", [])}


def token_sids_kerberos(db):
    import ldb

    rows = db.search(base="", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
    return {bytes(value) for value in rows[0].get("tokenGroups", [])}


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--report", required=True)
    parser.add_argument("--ready", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--wait", type=int, default=900)
    args = parser.parse_args()
    started = dt.datetime.now(dt.timezone.utc)
    checks, observed = [], {}

    def check(name, passed):
        checks.append({"name": name, "status": "passed" if passed else "failed"})

    try:
        fixture = json.loads(Path("/run/ad-fixture.json").read_text())
        username, suffix = fixture["fixtureUser"], fixture["suffix"]
        if not re.fullmatch("departure_[a-f0-9]{12}", username) or not re.fullmatch(
            "[a-f0-9]{12}", suffix
        ):
            raise ValueError("Unexpected fixture")
        password = fixture["fixturePassword"]
        kerberos()

        # Before offboarding: everything a signed-in person would already hold.
        simple = connection()
        simple.simple_bind_s(username + "@ADLAB.TEST", password)
        identity = simple.whoami_s()
        group = simple.search_s(
            BASE, ldap.SCOPE_SUBTREE, f"(cn=Departure-Readers-{suffix})", ["objectSid"]
        )[0][1]["objectSid"][0]
        group_held = group in token_sids_simple(simple)
        tgt = run("kinit", username + "@ADLAB.TEST", stdin=password + "\n").returncode == 0
        service = run("kvno", SERVICE).returncode == 0
        sealed = kerberos_ldap()
        sealed_group = group in token_sids_kerberos(sealed)
        observed["ticketLifetimeHours"] = None
        expiry = ticket_expiry("krbtgt/")
        if expiry:
            issued = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
            observed["ticketLifetimeHours"] = round((expiry - issued).total_seconds() / 3600, 1)
        check(
            "before: the active user holds an LDAPS session, a Kerberos session and both tickets,"
            " each with the departure group in its token",
            bool(identity) and group_held and tgt and service and sealed_group,
        )
        Path(args.ready).write_text("ready\n")

        deadline = time.monotonic() + args.wait
        while not Path(args.go).exists():
            if time.monotonic() > deadline:
                raise TimeoutError("The case did not finish in time")
            time.sleep(1)

        # After offboarding: the account is disabled and its group membership removed.
        def outcome(action):
            try:
                return action()
            except Exception as error:
                return type(error).__name__

        observed["passwordSession"] = outcome(lambda: bool(simple.whoami_s()))
        observed["passwordSessionKeepsGroup"] = outcome(lambda: group in token_sids_simple(simple))
        observed["kerberosSession"] = outcome(lambda: group in token_sids_kerberos(sealed))
        observed["newConnectionWithHeldServiceTicket"] = outcome(
            lambda: group in token_sids_kerberos(kerberos_ldap())
        )
        renewed = run("kvno", "cifs/dc.adlab.test")
        observed["newServiceTicketFromHeldTicketGrantingTicket"] = (
            "issued"
            if renewed.returncode == 0
            else "refused: credentials revoked"
            if "revoked" in renewed.stderr.lower()
            else "refused"
        )
        check(
            "denied: the ticket-granting ticket issued before offboarding gets no new service ticket",
            observed["newServiceTicketFromHeldTicketGrantingTicket"] != "issued",
        )
        check(
            "residual: an LDAPS connection opened before offboarding still answers,"
            " with the removed group in its token",
            observed["passwordSession"] is True and observed["passwordSessionKeepsGroup"] is True,
        )
        check(
            "residual: an LDAP connection opened with Kerberos before offboarding keeps the removed group",
            observed["kerberosSession"] is True,
        )
        check(
            "residual: a service ticket issued before offboarding opens a new connection,"
            " with the removed group",
            observed["newConnectionWithHeldServiceTicket"] is True,
        )
        lifetime = observed["ticketLifetimeHours"]
        check(
            "bound: tickets issued before offboarding expire within 10 hours of issue",
            lifetime is not None and lifetime <= 10.05,
        )
    except Exception as error:
        line = error.__traceback__.tb_lineno  # the step in main() that failed
        checks.append(
            {
                "name": f"held-session probe: {type(error).__name__} near line {line}",
                "status": "failed",
            }
        )
    result = {
        "schemaVersion": 1,
        "origin": "connected_samba_ad",
        "suite": "directory-held-sessions",
        "startedAt": started.isoformat(),
        "finishedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "checks": checks,
        "observed": observed,
        "counts": {
            "passed": sum(c["status"] == "passed" for c in checks),
            "failed": sum(c["status"] == "failed" for c in checks),
            "skipped": 0,
        },
        "limitations": [
            "Only this unique synthetic user is tested, over LDAP and Kerberos; SMB sessions are not measured.",
            "Samba AD-compatible lab behavior, not Microsoft AD interoperability.",
        ],
    }
    Path(args.report).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"counts": result["counts"], "observed": observed}))
    return int(result["counts"]["failed"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
