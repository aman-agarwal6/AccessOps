"""Scoped directory boundary tests using offline synthetic LDAP responses."""

import copy
import uuid

import pytest
from ldap3 import MODIFY_ADD, MODIFY_DELETE

from integrations.ad import (
    BASE_DN,
    SCOPE_DN,
    ADDirectoryConnector,
    guid_filter,
    normalize_binding,
    verified_result,
)
from integrations.errors import ConnectorError

DOMAIN = "11111111-1111-4111-8111-111111111111"
USER = "22222222-2222-4222-8222-222222222222"
GROUP = "33333333-3333-4333-8333-333333333333"
BINDING = {"domainGuid": DOMAIN, "userGuid": USER, "groupGuids": [GROUP]}
CONFIG = {"domainGuid": DOMAIN, "bindDn": "CN=AccessOps-Connector," + SCOPE_DN}


def record(dn, guid, classes):
    return {
        "type": "searchResEntry",
        "dn": dn,
        "raw_attributes": {
            "objectGUID": [uuid.UUID(guid).bytes_le],
            "objectClass": [v.encode() for v in classes],
        },
    }


class Directory:
    def __init__(self):
        self.domain = record(BASE_DN, DOMAIN, ["domainDNS"])
        self.user = record("CN=fixture," + SCOPE_DN, USER, ["top", "person", "user"])
        self.user["raw_attributes"].update(
            userAccountControl=[b"66048"],
            objectSid=[
                b"\x01\x03" + b"\0" * 6 + (21).to_bytes(4, "little") + (1001).to_bytes(4, "little")
            ],
        )
        self.group = record("CN=fixture-group," + SCOPE_DN, GROUP, ["top", "group"])
        self.member = True
        self.changes = []
        self.result = {"result": 0}
        self.error = False
        self.concurrent_flags = None
        self.rename_before_modify = False

    def search(self, base, expression, **kwargs):
        if self.error:
            raise RuntimeError("synthetic-private-directory-data")
        assert kwargs["size_limit"] == 2 and kwargs["time_limit"] == 5
        if base == BASE_DN:
            rows = [self.domain]
        elif expression == guid_filter(USER):
            rows = [self.user]
        elif expression == guid_filter(GROUP):
            rows = [self.group]
        elif base == "<GUID=" + GROUP + ">":
            rows = [self.group] if self.member else []
        else:
            rows = []
        self.response = copy.deepcopy(rows)
        return bool(rows)

    def modify(self, dn, change):
        self.changes.append((dn, change))
        if dn == "<GUID=" + USER + ">":
            if self.rename_before_modify:
                self.user["dn"] = "CN=renamed-fixture," + SCOPE_DN
            if self.concurrent_flags is not None:
                self.user["raw_attributes"]["userAccountControl"] = [
                    str(self.concurrent_flags).encode()
                ]
            old, new = change["userAccountControl"]
            if old != (
                MODIFY_DELETE,
                [int(self.user["raw_attributes"]["userAccountControl"][0])],
            ):
                self.result = {"result": 16}
                return False
            op, values = new
            assert op == MODIFY_ADD
            self.user["raw_attributes"]["userAccountControl"] = [str(values[0]).encode()]
        else:
            assert dn == "<GUID=" + GROUP + ">"
            assert change == {"member": [(MODIFY_DELETE, ["<GUID=" + USER + ">"])]}
            self.member = False
        return True

    def unbind(self):
        return True


def connector(directory=None, **kwargs):
    return ADDirectoryConnector(connection=directory or Directory(), config=CONFIG, **kwargs)


def test_disable_preserves_flags_and_removes_only_exact_member():
    directory = Directory()
    result = connector(directory).offboard(BINDING)
    assert result["verified"] is True
    assert directory.user["raw_attributes"]["userAccountControl"] == [b"66050"]
    assert result["observed"] == {
        "provider": "samba_ad",
        "domainGuid": DOMAIN,
        "userGuid": USER,
        "active": False,
        "groups": [{"groupGuid": GROUP, "member": False}],
    }
    assert len(directory.changes) == 2


def test_replayed_offboard_is_read_first_and_does_not_repeat_writes():
    directory = Directory()
    client = connector(directory)
    assert client.offboard(BINDING)["verified"]
    count = len(directory.changes)
    assert connector(directory).offboard(BINDING)["verified"]
    assert len(directory.changes) == count


def test_concurrent_account_flag_change_is_not_overwritten_or_followed_by_group_mutation():
    directory = Directory()
    directory.concurrent_flags = 66048 | 0x100000
    with pytest.raises(ConnectorError):
        connector(directory).offboard(BINDING)
    assert (
        int(directory.user["raw_attributes"]["userAccountControl"][0]) == directory.concurrent_flags
    )
    assert directory.member is True
    assert len(directory.changes) == 1


def test_rename_before_modify_keeps_exact_guid_target_and_member_reference():
    directory = Directory()
    directory.rename_before_modify = True
    assert connector(directory).offboard(BINDING)["verified"] is True
    assert directory.user["dn"] == "CN=renamed-fixture," + SCOPE_DN
    assert directory.changes[0][0] == "<GUID=" + USER + ">"
    assert directory.changes[1][1] == {"member": [(MODIFY_DELETE, ["<GUID=" + USER + ">"])]}


def test_read_only_observation_never_mutates():
    directory = Directory()
    observed = connector(directory).validate_binding(BINDING)
    assert not verified_result(BINDING, observed)
    assert directory.changes == []


@pytest.mark.parametrize(
    "patch",
    [
        {"domainGuid": USER},
        {"userGuid": "bad"},
        {"groupGuids": []},
        {"groupGuids": [GROUP, GROUP]},
        {"groupGuids": "bad"},
        {"extra": "ignored"},
    ],
)
def test_invalid_binding_rejected_before_mutation(patch):
    directory = Directory()
    with pytest.raises(ConnectorError):
        connector(directory).offboard(BINDING | patch)
    assert directory.changes == []


@pytest.mark.parametrize(
    "mutation",
    [
        "outside",
        "computer",
        "protected",
        "system",
        "mismatch",
        "referral",
        "missingflags",
        "domain",
    ],
)
def test_protected_and_incomplete_objects_fail_closed(mutation):
    directory = Directory()
    if mutation == "outside":
        directory.user["dn"] = "CN=fixture,CN=Users," + BASE_DN
    elif mutation == "computer":
        directory.user["raw_attributes"]["objectClass"].append(b"computer")
    elif mutation == "protected":
        directory.user["raw_attributes"]["adminCount"] = [b"1"]
    elif mutation == "system":
        directory.user["raw_attributes"]["objectSid"][0] = b"\0" * 8 + (500).to_bytes(4, "little")
    elif mutation == "mismatch":
        directory.user["raw_attributes"]["objectGUID"] = [uuid.UUID(GROUP).bytes_le]
    elif mutation == "referral":
        directory.group["type"] = "searchResRef"
    elif mutation == "missingflags":
        del directory.user["raw_attributes"]["userAccountControl"]
    else:
        directory.domain["raw_attributes"]["objectGUID"] = [uuid.UUID(USER).bytes_le]
    with pytest.raises(ConnectorError):
        connector(directory).offboard(BINDING)
    assert directory.changes == []


def test_exception_does_not_disclose_remote_or_private_data():
    directory = Directory()
    directory.error = True
    with pytest.raises(ConnectorError, match="^Directory read unavailable$"):
        connector(directory).validate_binding(BINDING)


def test_total_operation_and_deadline_budget_are_enforced():
    client = connector(clock=lambda: 0)
    client.calls = 40
    with pytest.raises(ConnectorError):
        client.validate_binding(BINDING)
    client = connector(clock=lambda: 0)
    client.clock = lambda: 46
    with pytest.raises(ConnectorError):
        client.validate_binding(BINDING)


@pytest.mark.parametrize(
    "patch",
    [
        {"active": 0},
        {"provider": "microsoft_ad"},
        {"userGuid": GROUP},
        {"groups": []},
        {"groups": [{"groupGuid": GROUP, "member": None}]},
        {"groups": [{"groupGuid": USER, "member": False}]},
    ],
)
def test_partial_or_wrong_result_cannot_verify(patch):
    observed = connector().validate_binding(BINDING)
    with pytest.raises(ConnectorError):
        verified_result(BINDING, observed | patch)


def test_binary_filter_never_interpolates_user_dn_or_text():
    assert guid_filter(USER).startswith("(objectGUID=\\22\\22\\22\\22")
    assert normalize_binding(BINDING) == BINDING
