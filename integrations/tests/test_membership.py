"""Membership-only SCIM/native reader boundaries; all responses are synthetic."""

import uuid

import httpx
import pytest

from integrations.errors import ConnectorError
from integrations.keycloak import GROUP, MEMBERSHIP_ORIGIN, KeycloakConnector

GID = "33333333-3333-4333-8333-333333333333"
UID = "22222222-2222-4222-8222-222222222222"
IDENTITY = {"providerSubject": UID}
RESOURCE = {"providerGroup": GID}
ISSUER = "https://id.accessops.test:8443/realms/accessops-workforce"


def make_reader(records, *, group=None, status=200, target_url=None):
    calls = []

    def handle(request):
        calls.append(request)
        assert request.method == "GET"
        assert (
            str(request.url).split("?", 1)[0]
            == MEMBERSHIP_ORIGIN + "/admin/realms/accessops-workforce/groups/" + GID + "/members"
        )
        assert request.url.params["first"] == "0" and request.url.params["max"] == "501"
        assert request.url.params["briefRepresentation"] == "true"
        return httpx.Response(
            status,
            json=records,
            request=httpx.Request("GET", target_url) if target_url else request,
        )

    connector = KeycloakConnector(
        issuer=ISSUER,
        http=httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=True),
    )
    connector._token = lambda: "synthetic-placeholder"
    fixture = (
        {"schemas": [GROUP], "id": GID, "displayName": "accessops-fixture"}
        if group is None
        else group
    )
    connector._call = lambda *args, **kwargs: fixture
    return connector, calls


def test_explicit_scim_membership_never_calls_user_or_native_fallback():
    connector, calls = make_reader(
        None,
        group={
            "schemas": [GROUP],
            "id": GID,
            "displayName": "accessops-fixture",
            "members": [{"value": UID}],
        },
    )
    assert connector.observe_membership(IDENTITY, RESOURCE)["observed"] == {
        "member": True,
        "groupId": GID,
    }
    assert calls == []


def test_explicit_empty_scim_list_is_observed_without_fallback():
    connector, calls = make_reader(
        None,
        group={"schemas": [GROUP], "id": GID, "displayName": "accessops-fixture", "members": []},
    )
    assert connector.observe_membership(IDENTITY, RESOURCE)["observed"]["member"] is False
    assert calls == []


def test_omitted_scim_members_need_independent_native_empty_response():
    connector, calls = make_reader([])
    assert connector.observe_membership(IDENTITY, RESOURCE)["observed"]["member"] is False
    assert len(calls) == 1


def test_native_reader_retains_only_the_exact_membership_boolean():
    connector, calls = make_reader(
        [
            {
                "id": UID,
                "email": "synthetic@fixture.test",
                "username": "synthetic-fixture",
                "attributes": {"private": "not-retained"},
            }
        ]
    )
    result = connector.observe_membership(IDENTITY, RESOURCE)
    assert result == {"observed": {"member": True, "groupId": GID}}
    assert len(calls) == 1


@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 429, 500])
def test_native_error_or_redirect_is_unknown_without_following(status):
    connector, calls = make_reader([], status=status)
    with pytest.raises(ConnectorError):
        connector.observe_membership(IDENTITY, RESOURCE)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "records",
    [
        {},
        None,
        [None],
        [{"id": None}],
        [{"id": True}],
        [{"id": "bad"}],
        [{"id": UID}, {"id": UID}],
        [{"username": "email-must-not-match"}],
    ],
)
def test_malformed_or_partial_native_records_are_unknown(records):
    connector, _ = make_reader(records)
    with pytest.raises(ConnectorError):
        connector.observe_membership(IDENTITY, RESOURCE)


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/members",
        MEMBERSHIP_ORIGIN + "/admin/realms/accessops-operators/groups/" + GID + "/members",
        MEMBERSHIP_ORIGIN + "/admin/realms/accessops-workforce/groups/" + UID + "/members",
    ],
)
def test_wrong_response_origin_realm_or_group_is_rejected(target):
    connector, _ = make_reader([])
    # httpx assigns its outbound request to MockTransport responses. Inject a
    # returned response directly to exercise the independent response guard.
    connector.http.get = lambda *args, **kwargs: httpx.Response(
        200, json=[], request=httpx.Request("GET", target)
    )
    with pytest.raises(ConnectorError):
        connector.observe_membership(IDENTITY, RESOURCE)


@pytest.mark.parametrize(
    "patch",
    [
        {"id": UID},
        {"schemas": []},
        {"displayName": "operators"},
        {"members": None},
        {"members": [True]},
        {"members": [{"value": True}]},
    ],
)
def test_invalid_scim_group_never_reaches_fallback(patch):
    connector, calls = make_reader(
        [], group={"schemas": [GROUP], "id": GID, "displayName": "accessops-fixture"} | patch
    )
    with pytest.raises(ConnectorError):
        connector.observe_membership(IDENTITY, RESOURCE)
    assert calls == []


def test_oversized_native_response_cannot_prove_absence_or_positive():
    records = [{"id": str(uuid.UUID(int=i + 1))} for i in range(501)]
    connector, calls = make_reader(records)
    with pytest.raises(ConnectorError):
        connector.observe_membership(IDENTITY, RESOURCE)
    assert len(calls) == 1


def test_concurrent_page_shift_cannot_hide_member_because_no_second_offset_read_exists():
    # In the old first100/next100 scan a removal before this index could move
    # the target from index100 to99, hiding it from the second page.
    records = [{"id": str(uuid.UUID(int=i + 1))} for i in range(100)] + [{"id": UID}]
    connector, calls = make_reader(records)
    assert connector.observe_membership(IDENTITY, RESOURCE)["observed"]["member"] is True
    assert len(calls) == 1 and calls[0].url.params["max"] == "501"
