"""Read-only enterprise observations. These are snapshots, never revocation proof."""

import json
import re
import ssl
import time
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlsplit
from uuid import UUID

import httpx

from .errors import ConnectorError

GRAPH_ORIGIN = "https://graph.microsoft.com"
GITHUB_ORIGIN = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
PROVIDERS = {"entra", "github"}
CAPABILITIES = {
    "account_enabled",
    "organization_membership",
    "outside_collaborator",
    "repository_collaborator",
    "session_revocation",
    "credential_revocation",
}
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}")


class _Unavailable(Exception):
    """Only an allowlisted reason code crosses the collector boundary."""


def utc_now():
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _uuid(value):
    if not isinstance(value, str):
        raise ConnectorError("A stable UUID is required")
    try:
        result = str(UUID(value))
    except ValueError:
        raise ConnectorError("A stable UUID is required") from None
    if value.lower() != result:
        raise ConnectorError("A stable UUID is required")
    return result


def _numeric_id(value):
    if type(value) is int:
        value = str(value)
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value):
        raise ConnectorError("A positive stable numeric ID is required")
    return value


def _timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value
    ):
        raise ConnectorError("A UTC observation time is required")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ConnectorError("A UTC observation time is required") from None
    return value


def observation(provider, tenant_id, subject_id, capability, value, *, scope, reason, observed_at):
    """Construct the canonical, minimal observation without copying vendor records."""
    if provider not in PROVIDERS or capability not in CAPABILITIES:
        raise ConnectorError("Unsupported observation capability")
    if (
        provider == "github"
        and capability == "account_enabled"
        or provider == "entra"
        and capability
        in {"organization_membership", "outside_collaborator", "repository_collaborator"}
    ):
        raise ConnectorError("Capability does not belong to the platform")
    identity = _uuid if provider == "entra" else _numeric_id
    if value is not None and type(value) is not bool:
        raise ConnectorError("Observation values must be Boolean or unknown")
    if (
        not isinstance(scope, str)
        or len(scope) > 120
        or not re.fullmatch(r"[a-z0-9:_-]+", scope)
        or not isinstance(reason, str)
        or len(reason) > 80
        or not re.fullmatch(r"[a-z][a-z0-9_]*", reason)
    ):
        raise ConnectorError("Invalid observation scope or reason")
    return {
        "provider": provider,
        "tenantId": identity(tenant_id),
        "subjectId": identity(subject_id),
        "observedAt": _timestamp(observed_at),
        "capability": capability,
        "status": "unknown" if value is None else "observed",
        "value": value,
        "scope": scope,
        "reasonCode": reason,
    }


def parse_entra_user(record, *, tenant_id, subject_id, observed_at):
    """Parse only an exact object ID and a strictly Boolean accountEnabled field."""
    subject_id = _uuid(subject_id)
    if not isinstance(record, dict):
        raise ConnectorError("Malformed user observation")
    if _uuid(record.get("id")) != subject_id:
        raise ConnectorError("User observation does not match the mapped subject")
    value = record.get("accountEnabled")
    if type(value) is not bool:
        raise ConnectorError("Account enabled state is unavailable")
    return observation(
        "entra",
        tenant_id,
        subject_id,
        "account_enabled",
        value,
        scope=f"tenant:{_uuid(tenant_id)}",
        reason="account_state_read",
        observed_at=observed_at,
    )


def parse_github_members(records, *, tenant_id, subject_id, capability, scope, observed_at):
    """Presence is observable; absence from a caller-visible list remains unknown."""
    if capability not in {
        "organization_membership",
        "outside_collaborator",
        "repository_collaborator",
    }:
        raise ConnectorError("Unsupported GitHub membership capability")
    subject_id = _numeric_id(subject_id)
    if not isinstance(records, list):
        raise ConnectorError("Malformed membership observation")
    seen = set()
    for record in records:
        if not isinstance(record, dict) or type(record.get("id")) is not int:
            raise ConnectorError("Malformed membership observation")
        stable_id = _numeric_id(record["id"])
        if stable_id in seen:
            raise ConnectorError("Duplicate membership observation")
        seen.add(stable_id)
    present = subject_id in seen
    return observation(
        "github",
        tenant_id,
        subject_id,
        capability,
        True if present else None,
        scope=scope,
        reason="membership_present" if present else "absence_not_proven",
        observed_at=observed_at,
    )


def snapshot(
    provider, tenant_id, subject_id, observations, *, method, collected_at, limitations=()
):
    if method not in {"synthetic_fixture", "read_only_api", "manual_export"}:
        raise ConnectorError("Invalid collection method")
    _timestamp(collected_at)
    result = []
    seen = set()
    for item in observations:
        if not isinstance(item, dict) or set(item) != {
            "provider",
            "tenantId",
            "subjectId",
            "observedAt",
            "capability",
            "status",
            "value",
            "scope",
            "reasonCode",
        }:
            raise ConnectorError("Invalid snapshot observation")
        normalized = observation(
            item["provider"],
            item["tenantId"],
            item["subjectId"],
            item["capability"],
            item["value"],
            scope=item["scope"],
            reason=item["reasonCode"],
            observed_at=item["observedAt"],
        )
        if normalized != item or (item["provider"], item["tenantId"], item["subjectId"]) != (
            provider,
            tenant_id,
            subject_id,
        ):
            raise ConnectorError("Snapshot identity or status mismatch")
        key = (item["capability"], item["scope"])
        if key in seen or item["capability"] in {"session_revocation", "credential_revocation"}:
            raise ConnectorError("Duplicate or unsupported measured capability")
        seen.add(key)
        result.append(normalized)
    for capability in ("session_revocation", "credential_revocation"):
        result.append(
            observation(
                provider,
                tenant_id,
                subject_id,
                capability,
                None,
                scope="account",
                reason="not_measured",
                observed_at=collected_at,
            )
        )
    gaps = [
        "Read-only imported snapshots do not revoke access or prove offboarding closure.",
        "Sessions, refresh tokens, personal credentials, and application-owned sessions are not measured.",
        *limitations,
    ]
    if (
        not 1 <= len(result) <= 100
        or len(gaps) > 20
        or any(not isinstance(x, str) or len(x) > 240 for x in gaps)
    ):
        raise ConnectorError("Snapshot exceeds the canonical bounds")
    return {
        "schemaVersion": 1,
        "collectionMethod": method,
        "collectedAt": collected_at,
        "observations": result,
        "limitations": gaps,
    }


class EnterpriseReader:
    """Fixed-origin, GET-only, TLS-verified collector with bounded response streaming."""

    def __init__(
        self,
        *,
        token,
        http=None,
        max_pages=10,
        max_records=1000,
        max_requests=32,
        max_bytes=262_144,
        deadline_seconds=60,
    ):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/-]{16,8192}=*", token):
            raise ConnectorError("A server-injected read token is required")
        for value, upper in (
            (max_pages, 20),
            (max_records, 2000),
            (max_requests, 64),
            (max_bytes, 1_048_576),
            (deadline_seconds, 120),
        ):
            if type(value) is not int or not 1 <= value <= upper:
                raise ConnectorError("Invalid collection bound")
        self._token = token
        self._owned = http is None
        self.http = http or httpx.Client(
            verify=ssl.create_default_context(),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(5, connect=3),
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=1),
        )
        self.max_pages, self.max_records = max_pages, max_records
        self.max_requests, self.max_bytes = max_requests, max_bytes
        self.deadline_seconds = deadline_seconds
        self._requests = 0
        self._deadline = 0

    def close(self):
        if self._owned:
            self.http.close()

    def _begin(self):
        self._requests = 0
        self._deadline = time.monotonic() + self.deadline_seconds

    def _read(self, url):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc not in {
            "graph.microsoft.com",
            "api.github.com",
        }:
            raise _Unavailable("unsafe_endpoint")
        if parsed.username or parsed.password or parsed.fragment:
            raise _Unavailable("unsafe_endpoint")
        if self._requests >= self.max_requests or time.monotonic() >= self._deadline:
            raise _Unavailable("collection_limit")
        self._requests += 1
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        if parsed.netloc == "api.github.com":
            headers.update(
                {
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": GITHUB_API_VERSION,
                }
            )
        try:
            with self.http.stream("GET", url, headers=headers, follow_redirects=False) as response:
                if response.status_code != 200:
                    reason = {
                        401: "access_denied",
                        403: "access_denied",
                        404: "not_found",
                        429: "rate_limited",
                    }.get(response.status_code, "provider_unavailable")
                    if 300 <= response.status_code < 400:
                        reason = "redirect_denied"
                    raise _Unavailable(reason)
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=4096):
                    if len(body) + len(chunk) > self.max_bytes:
                        raise _Unavailable("response_limit")
                    if time.monotonic() >= self._deadline:
                        raise _Unavailable("collection_limit")
                    body.extend(chunk)
                try:
                    data = json.loads(body)
                except (ValueError, UnicodeError):
                    raise _Unavailable("malformed_response") from None
                return data, response.headers
        except httpx.HTTPError:
            raise _Unavailable("network_unavailable") from None

    def _pages(self, path, params):
        initial = f"{GITHUB_ORIGIN}{path}?{urlencode(params)}"
        url, records, visited = initial, [], set()
        for _ in range(self.max_pages):
            if url in visited:
                raise _Unavailable("pagination_cycle")
            visited.add(url)
            data, headers = self._read(url)
            page = data
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise _Unavailable("malformed_response")
            records.extend(page)
            if len(records) > self.max_records:
                raise _Unavailable("record_limit")
            next_url = self._github_next(headers.get("link", ""))
            if not next_url:
                return records
            self._validate_next(next_url, path, params)
            url = next_url
        raise _Unavailable("page_limit")

    @staticmethod
    def _github_next(link):
        if not link:
            return None
        if len(link) > 8192:
            raise _Unavailable("unsafe_pagination")
        next_urls = []
        for part in link.split(","):
            match = re.fullmatch(r'\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*', part)
            if not match:
                raise _Unavailable("unsafe_pagination")
            if match[2] == "next":
                next_urls.append(match[1])
        if len(next_urls) > 1:
            raise _Unavailable("unsafe_pagination")
        return next_urls[0] if next_urls else None

    @staticmethod
    def _validate_next(url, path, params):
        if not isinstance(url, str) or len(url) > 8192:
            raise _Unavailable("unsafe_pagination")
        parsed = urlsplit(url)
        if (
            f"{parsed.scheme}://{parsed.netloc}" != GITHUB_ORIGIN
            or parsed.path != path
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise _Unavailable("unsafe_pagination")
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=12)
        query = dict(pairs)
        if len(query) != len(pairs):
            raise _Unavailable("unsafe_pagination")
        allowed = set(params) | {"page"}
        if set(query) - allowed or any(
            query.get(key) != str(value) for key, value in params.items()
        ):
            raise _Unavailable("unsafe_pagination")
        if not re.fullmatch(r"[1-9][0-9]{0,4}", query.get("page", "")):
            raise _Unavailable("unsafe_pagination")

    def entra(self, *, tenant_id, subject_id):
        tenant_id, subject_id = _uuid(tenant_id), _uuid(subject_id)
        self._begin()
        reason = None
        try:
            tenant, _ = self._read(f"{GRAPH_ORIGIN}/v1.0/organization?$select=id")
            if (
                not isinstance(tenant, dict)
                or not isinstance(tenant.get("value"), list)
                or len(tenant["value"]) != 1
                or not isinstance(tenant["value"][0], dict)
                or _uuid(tenant["value"][0].get("id")) != tenant_id
            ):
                raise _Unavailable("tenant_mismatch")
            record, _ = self._read(
                f"{GRAPH_ORIGIN}/v1.0/users/{subject_id}?$select=id,accountEnabled"
            )
            at = utc_now()
            observed = parse_entra_user(
                record, tenant_id=tenant_id, subject_id=subject_id, observed_at=at
            )
        except _Unavailable as exc:
            reason = str(exc)
        except ConnectorError:
            reason = "malformed_response"
        if reason:
            observed = observation(
                "entra",
                tenant_id,
                subject_id,
                "account_enabled",
                None,
                scope=f"tenant:{tenant_id}",
                reason=reason,
                observed_at=utc_now(),
            )
        return snapshot(
            "entra",
            tenant_id,
            subject_id,
            [observed],
            method="read_only_api",
            collected_at=utc_now(),
            limitations=[
                "Groups, directory roles, PIM eligibility, guest relationships, and application grants are not collected.",
                "accountEnabled=false alone does not prove that sessions or downstream access were revoked.",
            ],
        )

    def github(self, *, tenant_id, subject_id, organization, repositories=()):
        tenant_id, subject_id = _numeric_id(tenant_id), _numeric_id(subject_id)
        if not isinstance(organization, str) or not SLUG.fullmatch(organization):
            raise ConnectorError("Invalid organization path")
        if (
            not isinstance(repositories, (tuple, list))
            or len(repositories) > 10
            or any(
                not isinstance(repo, str) or not REPO.fullmatch(repo) or repo in {".", ".."}
                for repo in repositories
            )
        ):
            raise ConnectorError("Invalid repository paths")
        if len({repo.casefold() for repo in repositories}) != len(repositories):
            raise ConnectorError("Duplicate repository paths")
        self._begin()
        result = []
        try:
            organization_record, _ = self._read(f"{GITHUB_ORIGIN}/orgs/{organization}")
            if (
                not isinstance(organization_record, dict)
                or type(organization_record.get("id")) is not int
                or _numeric_id(organization_record["id"]) != tenant_id
            ):
                raise _Unavailable("tenant_mismatch")
        except (_Unavailable, ConnectorError) as exc:
            reason = str(exc) if isinstance(exc, _Unavailable) else "malformed_response"
            for capability in ("organization_membership", "outside_collaborator"):
                result.append(
                    observation(
                        "github",
                        tenant_id,
                        subject_id,
                        capability,
                        None,
                        scope=f"organization:{tenant_id}",
                        reason=reason,
                        observed_at=utc_now(),
                    )
                )
            if repositories:
                result.append(
                    observation(
                        "github",
                        tenant_id,
                        subject_id,
                        "repository_collaborator",
                        None,
                        scope="selected_repositories",
                        reason=reason,
                        observed_at=utc_now(),
                    )
                )
        else:
            for capability, endpoint in (
                ("organization_membership", "members"),
                ("outside_collaborator", "outside_collaborators"),
            ):
                result.append(
                    self._membership(
                        tenant_id,
                        subject_id,
                        capability,
                        f"organization:{tenant_id}",
                        f"/orgs/{organization}/{endpoint}",
                        {"per_page": 100},
                    )
                )
            seen_repositories = set()
            for index, repo in enumerate(repositories, start=1):
                scope = f"selected_repository_{index}"
                try:
                    record, _ = self._read(f"{GITHUB_ORIGIN}/repos/{organization}/{repo}")
                    if (
                        not isinstance(record, dict)
                        or not isinstance(record.get("owner"), dict)
                        or record["owner"].get("type") != "Organization"
                        or _numeric_id(record["owner"].get("id")) != tenant_id
                        or type(record.get("id")) is not int
                    ):
                        raise _Unavailable("repository_scope_mismatch")
                    repo_id = _numeric_id(record["id"])
                    if repo_id in seen_repositories:
                        raise _Unavailable("duplicate_repository_scope")
                    seen_repositories.add(repo_id)
                    scope = f"repository:{repo_id}"
                    result.append(
                        self._membership(
                            tenant_id,
                            subject_id,
                            "repository_collaborator",
                            scope,
                            f"/repos/{organization}/{repo}/collaborators",
                            {"affiliation": "all", "per_page": 100},
                        )
                    )
                except (_Unavailable, ConnectorError) as exc:
                    reason = str(exc) if isinstance(exc, _Unavailable) else "malformed_response"
                    result.append(
                        observation(
                            "github",
                            tenant_id,
                            subject_id,
                            "repository_collaborator",
                            None,
                            scope=scope,
                            reason=reason,
                            observed_at=utc_now(),
                        )
                    )
        return snapshot(
            "github",
            tenant_id,
            subject_id,
            result,
            method="read_only_api",
            collected_at=utc_now(),
            limitations=[
                "Membership absence remains unknown because caller visibility and concealed access are not proven complete.",
                "Only selected repositories are inspected; collaborator lists merge repo, team, org, and enterprise grant sources.",
                "Invitations, additional organizations, teams, deploy keys, tokens, local clones, and downstream copies are not collected.",
            ],
        )

    def _membership(self, tenant_id, subject_id, capability, scope, path, params):
        try:
            records = self._pages(path, params)
            return parse_github_members(
                records,
                tenant_id=tenant_id,
                subject_id=subject_id,
                capability=capability,
                scope=scope,
                observed_at=utc_now(),
            )
        except (_Unavailable, ConnectorError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, _Unavailable) else "malformed_response"
            return observation(
                "github",
                tenant_id,
                subject_id,
                capability,
                None,
                scope=scope,
                reason=reason,
                observed_at=utc_now(),
            )
