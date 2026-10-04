"""Opt-in Samba AD connector: exact scoped GUIDs, disable and remove only."""

import json
import os
import ssl
import time
import uuid
from pathlib import Path

from ldap3 import (
    BASE,
    MODIFY_ADD,
    MODIFY_DELETE,
    NONE,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.utils.conv import escape_filter_chars

from .errors import ConnectorError

HOST = "dc.adlab.test"
BASE_DN = "DC=adlab,DC=test"
SCOPE_DN = "OU=AccessOps-Fixtures," + BASE_DN
MAX_GROUPS = 5


def canonical_guid(value):
    if not isinstance(value, str) or len(value) != 36:
        raise ConnectorError("Directory binding invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise ConnectorError("Directory binding invalid") from None
    if parsed.int == 0 or str(parsed) != value:
        raise ConnectorError("Directory binding invalid")
    return value


def normalize_binding(binding):
    if not isinstance(binding, dict) or set(binding) != {"domainGuid", "userGuid", "groupGuids"}:
        raise ConnectorError("Directory binding invalid")
    groups = binding["groupGuids"]
    if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_GROUPS:
        raise ConnectorError("Directory binding invalid")
    groups = [canonical_guid(group) for group in groups]
    if len(set(groups)) != len(groups):
        raise ConnectorError("Directory binding invalid")
    return {
        "domainGuid": canonical_guid(binding["domainGuid"]),
        "userGuid": canonical_guid(binding["userGuid"]),
        "groupGuids": groups,
    }


def verified_result(binding, observed):
    """Strict complete readings; malformed observations never become false values."""
    binding = normalize_binding(binding)
    if (
        not isinstance(observed, dict)
        or set(observed) != {"provider", "domainGuid", "userGuid", "active", "groups"}
        or observed["provider"] != "samba_ad"
        or observed["domainGuid"] != binding["domainGuid"]
        or observed["userGuid"] != binding["userGuid"]
        or type(observed["active"]) is not bool
        or not isinstance(observed["groups"], list)
        or len(observed["groups"]) != len(binding["groupGuids"])
    ):
        raise ConnectorError("Directory observation incomplete")
    groups = {}
    for group in observed["groups"]:
        if (
            not isinstance(group, dict)
            or set(group) != {"groupGuid", "member"}
            or type(group["member"]) is not bool
            or group["groupGuid"] in groups
        ):
            raise ConnectorError("Directory observation incomplete")
        groups[group["groupGuid"]] = group["member"]
    if set(groups) != set(binding["groupGuids"]):
        raise ConnectorError("Directory observation incomplete")
    return observed["active"] is False and all(member is False for member in groups.values())


def guid_filter(value):
    return "(objectGUID=" + "".join(f"\\{byte:02x}" for byte in uuid.UUID(value).bytes_le) + ")"


class ADDirectoryConnector:
    def __init__(self, *, connection=None, config=None, clock=time.monotonic):
        self.clock = clock
        self.deadline = clock() + 45
        self.calls = 0
        self.connection = connection
        try:
            if config is None:
                path = Path(
                    os.environ.get("ACCESSOPS_AD_CONFIG_FILE", "/run/accessops-ad/config.json")
                )
                if path.stat().st_size > 4096:
                    raise ValueError
                config = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(config, dict) or set(config) != {"domainGuid", "bindDn"}:
                raise ValueError
            self.domain_guid = canonical_guid(config["domainGuid"])
            bind_dn = config["bindDn"]
            if (
                not isinstance(bind_dn, str)
                or len(bind_dn) > 240
                or not bind_dn.startswith("CN=AccessOps-Connector,")
                or bind_dn != "CN=AccessOps-Connector," + SCOPE_DN
            ):
                raise ValueError
            if self.connection is None:
                password_path = Path("/run/accessops-ad/connector-password.txt")
                if not 32 <= password_path.stat().st_size <= 256:
                    raise ValueError
                password = password_path.read_text(encoding="utf-8")
                tls = Tls(
                    validate=ssl.CERT_REQUIRED,
                    ca_certs_file="/run/accessops-ad-ca/ca.crt",
                    version=None,  # Python's verified default context, TLS >= 1.2.
                    sni=HOST,
                )
                server = Server(
                    HOST, port=636, use_ssl=True, tls=tls, get_info=NONE, connect_timeout=5
                )
                self.connection = Connection(
                    server,
                    user=bind_dn,
                    password=password,
                    authentication=SIMPLE,
                    auto_referrals=False,
                    auto_range=False,
                    receive_timeout=5,
                    raise_exceptions=True,
                    check_names=False,
                )
                self._budget()
                if not self.connection.bind():
                    raise ValueError
        except Exception:
            self.close()
            raise ConnectorError("Directory connector unavailable") from None

    def _budget(self):
        self.calls += 1
        if self.calls > 40 or self.clock() >= self.deadline:
            raise ConnectorError("Directory operation budget exceeded")

    def _search(self, base, expression, attributes, *, scope=BASE):
        self._budget()
        try:
            self.connection.search(
                base,
                expression,
                search_scope=scope,
                attributes=attributes,
                size_limit=2,
                time_limit=5,
            )
            if self.connection.result.get("result") != 0:
                raise ValueError
            responses = self.connection.response
            if any(record.get("type") != "searchResEntry" for record in responses):
                raise ValueError
            return responses
        except Exception:
            raise ConnectorError("Directory read unavailable") from None

    @staticmethod
    def _raw(record, key, *, optional=False):
        values = record.get("raw_attributes", {}).get(key, [])
        if not isinstance(values, list) or (not optional and not values):
            raise ConnectorError("Directory object incomplete")
        if any(not isinstance(value, bytes) for value in values):
            raise ConnectorError("Directory object incomplete")
        return values

    def _object(self, guid, object_class):
        rows = self._search(
            SCOPE_DN,
            guid_filter(guid),
            ["objectGUID", "objectClass", "userAccountControl", "adminCount", "objectSid"],
            scope=SUBTREE,
        )
        if len(rows) != 1:
            raise ConnectorError("Directory object outside scope")
        row = rows[0]
        values = self._raw(row, "objectGUID")
        classes = self._raw(row, "objectClass")
        dn = row.get("dn")
        if (
            len(values) != 1
            or values[0] != uuid.UUID(guid).bytes_le
            or object_class.encode() not in classes
            or b"computer" in classes
            or not isinstance(dn, str)
            or not dn.casefold().endswith("," + SCOPE_DN.casefold())
            or self._raw(row, "adminCount", optional=True) not in ([], [b"0"])
        ):
            raise ConnectorError("Directory object protected or invalid")
        if object_class == "user":
            flags = self._raw(row, "userAccountControl")
            sid = self._raw(row, "objectSid")
            if len(flags) != 1 or len(sid) != 1 or len(sid[0]) < 12:
                raise ConnectorError("Directory user incomplete")
            try:
                flags = int(flags[0])
            except ValueError:
                raise ConnectorError("Directory user incomplete") from None
            if (
                not flags & 0x200
                or flags & (0x800 | 0x1000 | 0x2000)
                or int.from_bytes(sid[0][-4:], "little") < 1000
            ):
                raise ConnectorError("Directory user protected or invalid")
            row["flags"] = flags
        return row

    def _collect(self, binding):
        binding = normalize_binding(binding)
        if binding["domainGuid"] != self.domain_guid:
            raise ConnectorError("Directory domain binding mismatch")
        domain = self._search(BASE_DN, "(objectClass=domainDNS)", ["objectGUID"])
        if len(domain) != 1 or self._raw(domain[0], "objectGUID") != [
            uuid.UUID(self.domain_guid).bytes_le
        ]:
            raise ConnectorError("Directory domain binding mismatch")
        user = self._object(binding["userGuid"], "user")
        groups = []
        for guid in binding["groupGuids"]:
            group = self._object(guid, "group")
            match = self._search(
                "<GUID=" + guid + ">",
                "(member=" + escape_filter_chars("<GUID=" + binding["userGuid"] + ">") + ")",
                ["objectGUID"],
            )
            if (
                len(match) > 1
                or match
                and self._raw(match[0], "objectGUID") != [uuid.UUID(guid).bytes_le]
            ):
                raise ConnectorError("Directory membership incomplete")
            groups.append((group, bool(match)))
        observed = {
            "provider": "samba_ad",
            "domainGuid": binding["domainGuid"],
            "userGuid": binding["userGuid"],
            "active": not bool(user["flags"] & 2),
            "groups": [
                {"groupGuid": guid, "member": member}
                for guid, (_, member) in zip(binding["groupGuids"], groups, strict=True)
            ],
        }
        return observed, user, groups

    def validate_binding(self, binding):
        return self._collect(binding)[0]

    def _modify(self, dn, change):
        self._budget()
        try:
            if not self.connection.modify(dn, change) or self.connection.result.get("result") != 0:
                raise ValueError
        except Exception:
            raise ConnectorError("Directory mutation outcome unavailable") from None

    def offboard(self, binding):
        binding = normalize_binding(binding)
        before, user, groups = self._collect(binding)
        if before["active"]:
            self._modify(
                "<GUID=" + binding["userGuid"] + ">",
                {
                    "userAccountControl": [
                        (MODIFY_DELETE, [user["flags"]]),
                        (MODIFY_ADD, [user["flags"] | 2]),
                    ]
                },
            )
        for guid, (_, member) in zip(binding["groupGuids"], groups, strict=True):
            if member:
                self._modify(
                    "<GUID=" + guid + ">",
                    {"member": [(MODIFY_DELETE, ["<GUID=" + binding["userGuid"] + ">"])]},
                )
        observed, current, _ = self._collect(binding)
        if current["flags"] != user["flags"] | 2:
            raise ConnectorError("Directory account flags changed unexpectedly")
        return {"verified": verified_result(binding, observed), "observed": observed}

    def close(self):
        if self.connection is not None:
            try:
                self.connection.unbind()
            except Exception:
                pass
