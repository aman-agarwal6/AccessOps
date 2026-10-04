"""Reviewed local Samba management: unique fixtures and per-object ACEs only.

Run inside the authorized DC with its local database. No Administrator password
is read, exported, or passed to AccessOps. Sensitive input arrives on stdin.
"""

import contextlib
import io
import json
import re
import sys
import uuid

import ldb
from samba.auth import system_session
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.sd_utils import SDUtils

BASE = "DC=adlab,DC=test"
SCOPE = "OU=AccessOps-Fixtures," + BASE
CANARIES = "OU=AccessOps-Canaries," + BASE
UAC_ATTRIBUTE = "bf967a68-0de6-11d0-a285-00aa003049e2"
MEMBER_ATTRIBUTE = "bf9679c0-0de6-11d0-a285-00aa003049e2"


def guid(db, dn):
    result = db.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
    if len(result) != 1:
        raise ValueError
    return str(uuid.UUID(bytes_le=bytes(result[0]["objectGUID"][0])))


def ou(db, dn):
    if not db.search(
        base=BASE,
        scope=ldb.SCOPE_SUBTREE,
        expression="(distinguishedName=" + ldb.binary_encode(dn) + ")",
        attrs=["dn"],
    ):
        message = ldb.Message()
        message.dn = ldb.Dn(db, dn)
        message["objectClass"] = ldb.MessageElement(
            [b"top", b"organizationalUnit"], ldb.FLAG_MOD_ADD, "objectClass"
        )
        db.add(message)


def prepare(data):
    if not isinstance(data, dict) or set(data) != {
        "suffix",
        "connectorPassword",
        "fixturePassword",
        "connectorExists",
    }:
        raise ValueError
    suffix = data["suffix"]
    if (
        not isinstance(suffix, str)
        or not re.fullmatch("[a-f0-9]{12}", suffix)
        or type(data["connectorExists"]) is not bool
    ):
        raise ValueError
    for name in ("connectorPassword", "fixturePassword"):
        if not isinstance(data[name], str) or not 32 <= len(data[name]) <= 128:
            raise ValueError
    lp = LoadParm()
    lp.load("/var/lib/adlab/etc/smb.conf")
    db = SamDB(url="/var/lib/adlab/private/sam.ldb", session_info=system_session(), lp=lp)
    if str(db.domain_dn()).casefold() != BASE.casefold():
        raise ValueError
    ou(db, SCOPE)
    ou(db, CANARIES)
    connector_dn = "CN=AccessOps-Connector," + SCOPE
    exists = bool(
        db.search(
            base=BASE,
            scope=ldb.SCOPE_SUBTREE,
            expression="(sAMAccountName=AccessOps-Connector)",
            attrs=["dn"],
        )
    )
    if exists and not data["connectorExists"]:
        raise ValueError  # Never reset an existing credential from a fresh file.
    if not exists:
        db.newuser(
            "AccessOps-Connector",
            data["connectorPassword"],
            userou="OU=AccessOps-Fixtures",
            useusernameascn=True,
        )
    connector = db.search(
        base=connector_dn, scope=ldb.SCOPE_BASE, attrs=["objectSid", "adminCount", "memberOf"]
    )[0]
    if (
        "adminCount" in connector
        and bytes(connector["adminCount"][0]) == b"1"
        or "memberOf" in connector
    ):
        raise ValueError
    sid = str(ndr_unpack(security.dom_sid, bytes(connector["objectSid"][0])))
    user = "departure_" + suffix
    group = "Departure-Readers-" + suffix
    canary = "canary_" + suffix
    canary_group = "Canary-Readers-" + suffix
    for username, ou_name in ((user, "OU=AccessOps-Fixtures"), (canary, "OU=AccessOps-Canaries")):
        db.newuser(username, data["fixturePassword"], userou=ou_name, useusernameascn=True)
    for group_name, ou_name, member in (
        (group, "OU=AccessOps-Fixtures", user),
        (canary_group, "OU=AccessOps-Canaries", canary),
    ):
        db.newgroup(group_name, groupou=ou_name)
        db.add_remove_group_members(group_name, [member], add_members_operation=True)
    user_dn = "CN=" + user + "," + SCOPE
    group_dn = "CN=" + group + "," + SCOPE
    # No inheritance flag: exactly these new objects, exactly these properties.
    sd = SDUtils(db)
    sd.dacl_add_ace(user_dn, f"(OA;;WP;{UAC_ATTRIBUTE};;{sid})")
    sd.dacl_add_ace(group_dn, f"(OA;;WP;{MEMBER_ATTRIBUTE};;{sid})")
    return {
        "binding": {
            "domainGuid": guid(db, BASE),
            "userGuid": guid(db, user_dn),
            "groupGuids": [guid(db, group_dn)],
        },
        "canary": {
            "userGuid": guid(db, "CN=" + canary + "," + CANARIES),
            "groupGuid": guid(db, "CN=" + canary_group + "," + CANARIES),
        },
        "fixtureUser": user,
        "fixtureDn": user_dn,
        "canaryDn": "CN=" + canary + "," + CANARIES,
        "canaryGroupDn": "CN=" + canary_group + "," + CANARIES,
    }


def contain_interrupted(suffix):
    """Only deterministic new fixture names; retain records, never touch seeds."""
    if not isinstance(suffix, str) or not re.fullmatch("[a-f0-9]{12}", suffix):
        return
    lp = LoadParm()
    lp.load("/var/lib/adlab/etc/smb.conf")
    db = SamDB(url="/var/lib/adlab/private/sam.ldb", session_info=system_session(), lp=lp)
    for username, ou_dn in (("departure_" + suffix, SCOPE), ("canary_" + suffix, CANARIES)):
        dn = "CN=" + username + "," + ou_dn
        rows = db.search(
            base=BASE,
            scope=ldb.SCOPE_SUBTREE,
            expression="(distinguishedName=" + ldb.binary_encode(dn) + ")",
            attrs=["userAccountControl"],
        )
        if rows:
            message = ldb.Message()
            message.dn = ldb.Dn(db, dn)
            message["userAccountControl"] = ldb.MessageElement(
                str(int(rows[0]["userAccountControl"][0]) | 2),
                ldb.FLAG_MOD_REPLACE,
                "userAccountControl",
            )
            db.modify(message)


def main():
    data = None
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--contain-interrupted":
            contain_interrupted(sys.argv[2])
            print("Exact newly created fixture accounts disabled; records retained.")
            return 0
        raw = sys.stdin.read(4097)
        if len(raw) > 4096:
            raise ValueError
        # Samba helpers may log user creation; keep all incidental output private.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            data = json.loads(raw)
            result = prepare(data)
        print(json.dumps(result))  # Synthetic GUIDs/names only, no credentials.
        return 0
    except Exception:
        try:
            if isinstance(data, dict):
                contain_interrupted(data.get("suffix"))
        except Exception:
            print("Exact interrupted fixture containment needs local review.", file=sys.stderr)
        print("Scoped directory preparation failed; preserve state for review.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
