"""Offline synthetic API-shape and denial tests; no vendor tenant is contacted."""

import json
from pathlib import Path

import httpx
import pytest

from integrations.enterprise import (
    GITHUB_API_VERSION,
    EnterpriseReader,
    observation,
    parse_entra_user,
    parse_github_members,
    snapshot,
)
from integrations.errors import ConnectorError
from tools import collect_enterprise_snapshot as collector

TENANT = "11111111-1111-4111-8111-111111111111"
SUBJECT = "22222222-2222-4222-8222-222222222222"
AT = "2026-10-03T05:00:00Z"
ORG = "424242"
USER = "1001"
PLACEHOLDER = "synthetic-bearer-placeholder"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def fixture(provider, phase="before"):
    return json.loads(
        (FIXTURES / f"enterprise-{provider}-{phase}.json").read_text(encoding="utf-8")
    )


def connection(handler, **bounds):
    calls = []

    def dispatch(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.scheme == "https"
        return handler(request)

    http = httpx.Client(transport=httpx.MockTransport(dispatch), follow_redirects=True)
    return EnterpriseReader(token=PLACEHOLDER, http=http, **bounds), calls, http


def entra_handler(request):
    payload = fixture("entra")["responses"]
    return httpx.Response(
        200, json=payload["organization" if request.url.path.endswith("organization") else "user"]
    )


def github_handler(request):
    payload = fixture("github")["responses"]
    endpoint = request.url.path.rsplit("/", 1)[1]
    if request.url.path == "/orgs/synthetic-org":
        endpoint = "organization"
    elif request.url.path == "/repos/synthetic-org/synthetic-project":
        endpoint = "repository"
    return httpx.Response(200, json=payload[endpoint])


def observed(report, capability):
    return next(item for item in report["observations"] if item["capability"] == capability)


def test_entra_exact_minimal_fields_and_no_response_pii():
    def handler(request):
        if request.url.path.endswith("organization"):
            return entra_handler(request)
        return httpx.Response(
            200,
            json={
                "id": SUBJECT,
                "accountEnabled": False,
                "displayName": "Synthetic person",
                "mail": "fictional@example.invalid",
                "access_token": PLACEHOLDER,
            },
        )

    reader, calls, http = connection(handler)
    try:
        report = reader.entra(tenant_id=TENANT, subject_id=SUBJECT)
    finally:
        http.close()
    assert observed(report, "account_enabled")["value"] is False
    assert calls[0].url.params["$select"] == "id"
    assert calls[1].url.params["$select"] == "id,accountEnabled"
    assert "Synthetic person" not in json.dumps(report)
    assert "example.invalid" not in json.dumps(report)
    assert PLACEHOLDER not in json.dumps(report)
    assert report["collectionMethod"] == "read_only_api"
    assert observed(report, "session_revocation")["status"] == "unknown"
    assert observed(report, "credential_revocation")["value"] is None


@pytest.mark.parametrize("state", [None, 0, 1, "true", [], {}])
def test_entra_malformed_state_does_not_become_disabled(state):
    with pytest.raises(ConnectorError):
        parse_entra_user(
            {"id": SUBJECT, "accountEnabled": state},
            tenant_id=TENANT,
            subject_id=SUBJECT,
            observed_at=AT,
        )


def test_entra_wrong_tenant_never_reads_user():
    reader, calls, http = connection(
        lambda request: httpx.Response(200, json={"value": [{"id": SUBJECT}]})
    )
    try:
        result = reader.entra(tenant_id=TENANT, subject_id=SUBJECT)
    finally:
        http.close()
    assert len(calls) == 1
    assert observed(result, "account_enabled")["reasonCode"] == "tenant_mismatch"
    assert observed(result, "account_enabled")["value"] is None


@pytest.mark.parametrize(
    "status,reason",
    [
        (401, "access_denied"),
        (403, "access_denied"),
        (404, "not_found"),
        (429, "rate_limited"),
        (500, "provider_unavailable"),
    ],
)
def test_http_denials_are_sanitized_unknown(status, reason):
    reader, _, http = connection(
        lambda request: httpx.Response(status, json={"error": PLACEHOLDER})
    )
    try:
        result = reader.entra(tenant_id=TENANT, subject_id=SUBJECT)
    finally:
        http.close()
    assert observed(result, "account_enabled")["reasonCode"] == reason
    assert observed(result, "account_enabled")["status"] == "unknown"
    assert PLACEHOLDER not in json.dumps(result)


def test_redirect_is_not_followed_even_with_injected_client():
    reader, calls, http = connection(
        lambda request: httpx.Response(302, headers={"Location": "https://example.invalid/secret"})
    )
    try:
        result = reader.entra(tenant_id=TENANT, subject_id=SUBJECT)
    finally:
        http.close()
    assert len(calls) == 1
    assert observed(result, "account_enabled")["reasonCode"] == "redirect_denied"


@pytest.mark.parametrize("payload", [b"not-json", b"\xff\xfe"])
def test_invalid_json_is_unknown(payload):
    reader, _, http = connection(lambda request: httpx.Response(200, content=payload))
    try:
        result = reader.entra(tenant_id=TENANT, subject_id=SUBJECT)
    finally:
        http.close()
    assert observed(result, "account_enabled")["reasonCode"] == "malformed_response"


def test_streamed_response_size_is_bounded():
    reader, _, http = connection(
        lambda request: httpx.Response(200, content=b"x" * 300), max_bytes=100
    )
    try:
        result = reader.entra(tenant_id=TENANT, subject_id=SUBJECT)
    finally:
        http.close()
    assert observed(result, "account_enabled")["reasonCode"] == "response_limit"


def test_github_exact_stable_ids_and_selected_repo_only():
    reader, calls, http = connection(github_handler)
    try:
        result = reader.github(
            tenant_id=ORG,
            subject_id=USER,
            organization="synthetic-org",
            repositories=["synthetic-project"],
        )
    finally:
        http.close()
    assert observed(result, "organization_membership")["value"] is True
    assert observed(result, "outside_collaborator")["value"] is None
    assert observed(result, "repository_collaborator")["scope"] == "repository:434343"
    assert observed(result, "repository_collaborator")["value"] is True
    assert all(request.headers["X-GitHub-Api-Version"] == GITHUB_API_VERSION for request in calls)
    assert len(calls) == 5
    assert "synthetic-org" not in json.dumps(result)
    assert "synthetic-project" not in json.dumps(result)


def test_github_empty_complete_pages_do_not_prove_absence():
    item = parse_github_members(
        [],
        tenant_id=ORG,
        subject_id=USER,
        capability="organization_membership",
        scope=f"organization:{ORG}",
        observed_at=AT,
    )
    assert item["value"] is None
    assert item["reasonCode"] == "absence_not_proven"


def test_github_wrong_org_stops_before_membership_collection():
    reader, calls, http = connection(lambda request: httpx.Response(200, json={"id": 999}))
    try:
        result = reader.github(tenant_id=ORG, subject_id=USER, organization="synthetic-org")
    finally:
        http.close()
    assert len(calls) == 1
    assert all(item["value"] is None for item in result["observations"])
    assert observed(result, "organization_membership")["reasonCode"] == "tenant_mismatch"


def test_github_wrong_repository_owner_never_collects_collaborators():
    def handler(request):
        if request.url.path == "/repos/synthetic-org/synthetic-project":
            return httpx.Response(
                200, json={"id": 434343, "owner": {"id": 999, "type": "Organization"}}
            )
        return github_handler(request)

    reader, calls, http = connection(handler)
    try:
        result = reader.github(
            tenant_id=ORG,
            subject_id=USER,
            organization="synthetic-org",
            repositories=["synthetic-project"],
        )
    finally:
        http.close()
    assert not any(request.url.path.endswith("/collaborators") for request in calls)
    assert observed(result, "repository_collaborator")["reasonCode"] == "repository_scope_mismatch"


def test_multiple_unavailable_repositories_have_unique_importable_scopes():
    def handler(request):
        if request.url.path.startswith("/repos/"):
            return httpx.Response(404)
        return github_handler(request)

    reader, _, http = connection(handler)
    try:
        result = reader.github(
            tenant_id=ORG,
            subject_id=USER,
            organization="synthetic-org",
            repositories=["first-project", "second-project"],
        )
    finally:
        http.close()
    items = [
        item for item in result["observations"] if item["capability"] == "repository_collaborator"
    ]
    assert len(items) == 2 and len({item["scope"] for item in items}) == 2
    assert all(item["value"] is None for item in items)


def test_same_stable_repository_through_alias_is_unknown():
    def handler(request):
        if request.url.path.startswith("/repos/"):
            if request.url.path.endswith("/collaborators"):
                return httpx.Response(200, json=[{"id": 1001}])
            return httpx.Response(
                200, json={"id": 434343, "owner": {"id": 424242, "type": "Organization"}}
            )
        return github_handler(request)

    reader, _, http = connection(handler)
    try:
        result = reader.github(
            tenant_id=ORG,
            subject_id=USER,
            organization="synthetic-org",
            repositories=["first-alias", "second-alias"],
        )
    finally:
        http.close()
    items = [
        item for item in result["observations"] if item["capability"] == "repository_collaborator"
    ]
    assert [item["value"] for item in items] == [True, None]
    assert items[1]["reasonCode"] == "duplicate_repository_scope"


@pytest.mark.parametrize(
    "link",
    [
        '<https://example.invalid/orgs/synthetic-org/members?per_page=100&page=2>; rel="next"',
        '<http://api.github.com/orgs/synthetic-org/members?per_page=100&page=2>; rel="next"',
        '<https://api.github.com/orgs/other-org/members?per_page=100&page=2>; rel="next"',
        '<https://api.github.com/orgs/synthetic-org/members?per_page=100&page=2&access_token=bad>; rel="next"',
        '<https://api.github.com/orgs/synthetic-org/members?per_page=100&page=2&page=3>; rel="next"',
        '<https://api.github.com/orgs/synthetic-org/members?per_page=100&page=2#fragment>; rel="next"',
        '<https://name:password@api.github.com/orgs/synthetic-org/members?per_page=100&page=2>; rel="next"',
        '<https://api.github.com/orgs/synthetic-org/members?per_page=30&page=2>; rel="next"',
        "not-a-link",
    ],
)
def test_github_untrusted_nextlink_never_receives_bearer(link):
    def handler(request):
        if request.url.path.endswith("/members"):
            return httpx.Response(200, json=[{"id": 1001}], headers={"Link": link})
        return github_handler(request)

    reader, calls, http = connection(handler)
    try:
        result = reader.github(tenant_id=ORG, subject_id=USER, organization="synthetic-org")
    finally:
        http.close()
    assert len(calls) == 3
    assert observed(result, "organization_membership")["value"] is None
    assert observed(result, "organization_membership")["reasonCode"] == "unsafe_pagination"


def test_github_valid_pagination_collects_mapped_id_on_second_page():
    def handler(request):
        if request.url.path.endswith("/members"):
            if request.url.params.get("page") == "2":
                return httpx.Response(200, json=[{"id": 1001}])
            return httpx.Response(
                200,
                json=[{"id": 1002}],
                headers={
                    "Link": '<https://api.github.com/orgs/synthetic-org/members?per_page=100&page=2>; rel="next"',
                },
            )
        return github_handler(request)

    reader, calls, http = connection(handler)
    try:
        result = reader.github(tenant_id=ORG, subject_id=USER, organization="synthetic-org")
    finally:
        http.close()
    assert observed(result, "organization_membership")["value"] is True
    assert len(calls) == 4


def test_github_pagination_cycle_is_unknown_and_bounded():
    def handler(request):
        if request.url.path.endswith("/members"):
            return httpx.Response(
                200,
                json=[{"id": 1001}],
                headers={
                    "Link": '<https://api.github.com/orgs/synthetic-org/members?per_page=100&page=2>; rel="next"',
                },
            )
        return github_handler(request)

    reader, calls, http = connection(handler)
    try:
        result = reader.github(tenant_id=ORG, subject_id=USER, organization="synthetic-org")
    finally:
        http.close()
    assert len(calls) == 4
    assert observed(result, "organization_membership")["reasonCode"] == "pagination_cycle"
    assert observed(result, "organization_membership")["value"] is None


def test_network_timeout_does_not_leak_request_or_token():
    def handler(request):
        raise httpx.ReadTimeout(PLACEHOLDER, request=request)

    reader, calls, http = connection(handler)
    try:
        result = reader.entra(tenant_id=TENANT, subject_id=SUBJECT)
    finally:
        http.close()
    assert len(calls) == 1
    assert observed(result, "account_enabled")["reasonCode"] == "network_unavailable"
    assert PLACEHOLDER not in json.dumps(result)


def test_other_entra_subject_is_unknown_without_email_matching():
    def handler(request):
        if request.url.path.endswith("organization"):
            return entra_handler(request)
        return httpx.Response(
            200, json={"id": TENANT, "accountEnabled": False, "mail": "fictional@example.invalid"}
        )

    reader, _, http = connection(handler)
    try:
        result = reader.entra(tenant_id=TENANT, subject_id=SUBJECT)
    finally:
        http.close()
    assert observed(result, "account_enabled")["value"] is None
    assert observed(result, "account_enabled")["reasonCode"] == "malformed_response"


@pytest.mark.parametrize(
    "bounds,reason",
    [
        ({"max_pages": 1}, "page_limit"),
        ({"max_records": 1}, "record_limit"),
        ({"max_requests": 1}, "collection_limit"),
    ],
)
def test_collection_limits_never_produce_false_absence(bounds, reason):
    def handler(request):
        if request.url.path.endswith("/members"):
            return httpx.Response(
                200,
                json=[{"id": 1001}, {"id": 1002}],
                headers={
                    "Link": '<https://api.github.com/orgs/synthetic-org/members?per_page=100&page=2>; rel="next"',
                },
            )
        return github_handler(request)

    reader, _, http = connection(handler, **bounds)
    try:
        result = reader.github(tenant_id=ORG, subject_id=USER, organization="synthetic-org")
    finally:
        http.close()
    assert observed(result, "organization_membership")["value"] is None
    assert observed(result, "organization_membership")["reasonCode"] == reason


@pytest.mark.parametrize(
    "records", [[{"id": True}], [{"id": "1001"}], [{"id": 1001}, {"id": 1001}], [{}]]
)
def test_github_malformed_members_cannot_become_observed(records):
    with pytest.raises(ConnectorError):
        parse_github_members(
            records,
            tenant_id=ORG,
            subject_id=USER,
            capability="organization_membership",
            scope=f"organization:{ORG}",
            observed_at=AT,
        )


@pytest.mark.parametrize(
    "org,repos",
    [
        ("../other", []),
        ("synthetic-org", ["../other"]),
        ("synthetic-org", [".."]),
        ("synthetic-org", ["project?secret=1"]),
        ("synthetic-org", ["project", "PROJECT"]),
        ("synthetic-org", [[]]),
    ],
)
def test_invalid_scope_paths_make_no_requests(org, repos):
    reader, calls, http = connection(github_handler)
    try:
        with pytest.raises(ConnectorError):
            reader.github(tenant_id=ORG, subject_id=USER, organization=org, repositories=repos)
    finally:
        http.close()
    assert not calls


def test_snapshot_rejects_raw_extra_fields_and_status_confusion():
    item = observation(
        "entra",
        TENANT,
        SUBJECT,
        "account_enabled",
        False,
        scope=f"tenant:{TENANT}",
        reason="account_state_read",
        observed_at=AT,
    )
    for changed in ({**item, "mail": "fictional@example.invalid"}, {**item, "status": "unknown"}):
        with pytest.raises(ConnectorError):
            snapshot("entra", TENANT, SUBJECT, [changed], method="manual_export", collected_at=AT)


def test_snapshot_rejects_duplicate_readings_and_false_session_measurement():
    item = observation(
        "entra",
        TENANT,
        SUBJECT,
        "account_enabled",
        False,
        scope=f"tenant:{TENANT}",
        reason="account_state_read",
        observed_at=AT,
    )
    with pytest.raises(ConnectorError):
        snapshot("entra", TENANT, SUBJECT, [item, item], method="manual_export", collected_at=AT)
    session = observation(
        "entra",
        TENANT,
        SUBJECT,
        "session_revocation",
        True,
        scope="account",
        reason="not_measured",
        observed_at=AT,
    )
    with pytest.raises(ConnectorError):
        snapshot("entra", TENANT, SUBJECT, [session], method="manual_export", collected_at=AT)


def test_fixture_before_after_are_explicitly_offline():
    before = collector.fixture_snapshot("entra", "before")
    after = collector.fixture_snapshot("entra", "after")
    assert before["collectionMethod"] == after["collectionMethod"] == "synthetic_fixture"
    assert observed(before, "account_enabled")["value"] is True
    assert observed(after, "account_enabled")["value"] is False
    github_after = collector.fixture_snapshot("github", "after")
    assert all(item["status"] == "unknown" for item in github_after["observations"])


def test_fixture_does_not_read_any_token_environment(monkeypatch):
    def deny_environment(*args, **kwargs):
        pytest.fail("Offline fixtures must not read credential environments")

    monkeypatch.setattr(collector.os, "getenv", deny_environment)
    assert collector.fixture_snapshot("github", "before")["collectionMethod"] == "synthetic_fixture"


def test_cli_live_mode_requires_explicit_authorization_without_network(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(collector, "ROOT", tmp_path)
    monkeypatch.setenv("ACCESSOPS_GRAPH_READ_TOKEN", PLACEHOLDER)
    called = []
    monkeypatch.setattr(collector, "EnterpriseReader", lambda **kwargs: called.append(True))
    result = collector.main(
        [
            "--provider",
            "entra",
            "--tenant-id",
            TENANT,
            "--subject-id",
            SUBJECT,
            "--output",
            str(tmp_path / ".local" / "enterprise" / "probe.json"),
        ]
    )
    assert result == 1 and not called
    assert PLACEHOLDER not in capsys.readouterr().err


def test_cli_public_output_and_overwrite_are_denied(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "ROOT", tmp_path)
    with pytest.raises(ConnectorError):
        collector.private_output(str(tmp_path / "published.json"), fixture=False)
    target = tmp_path / ".local" / "enterprise" / "existing.json"
    target.parent.mkdir(parents=True)
    target.write_text("preserved", encoding="utf-8")
    with pytest.raises(ConnectorError):
        collector.private_output(str(target), fixture=False)
    assert target.read_text() == "preserved"
