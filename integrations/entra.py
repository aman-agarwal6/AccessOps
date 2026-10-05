"""Opt-in Microsoft Entra ID connector through Microsoft Graph: exact object IDs;
disable, remove group membership and revoke sign-in sessions only.

It signs in as a single-tenant app registration with a certificate (client
credentials with a signed JWT assertion, RFC 7523); the private key never leaves
this process. On Entra ID Free, Graph application permissions apply to the whole
tenant, so the connector itself is the scope boundary: it acts only on the users
and groups listed in its configuration, never on a protected object ID, and never
on a user who holds a directory role. It never enables an account or adds a
membership, and every change is read back before it counts.
"""

import base64
import json
import os
import ssl
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .errors import ConnectorError

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
MAX_GROUPS = 5
MAX_BYTES = 262_144
ROLE = "#microsoft.graph.directoryRole"
GROUP = "#microsoft.graph.group"
OBSERVED_KEYS = {
    "provider",
    "tenantId",
    "userId",
    "active",
    "privileged",
    "groups",
    "sessionsValidFrom",
}


def canonical_id(value):
    if not isinstance(value, str) or len(value) != 36:
        raise ConnectorError("Entra binding invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise ConnectorError("Entra binding invalid") from None
    if parsed.int == 0 or str(parsed) != value:
        raise ConnectorError("Entra binding invalid")
    return value


def normalize_binding(binding):
    if not isinstance(binding, dict) or set(binding) != {"tenantId", "userId", "groupIds"}:
        raise ConnectorError("Entra binding invalid")
    groups = binding["groupIds"]
    if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_GROUPS:
        raise ConnectorError("Entra binding invalid")
    groups = [canonical_id(group) for group in groups]
    if len(set(groups)) != len(groups):
        raise ConnectorError("Entra binding invalid")
    return {
        "tenantId": canonical_id(binding["tenantId"]),
        "userId": canonical_id(binding["userId"]),
        "groupIds": groups,
    }


def graph_time(value):
    """A Graph UTC timestamp, or None when Entra has never revoked sessions."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 40:
        raise ConnectorError("Entra observation incomplete")
    stamp, _, fraction = value[:-1].partition(".")
    try:
        # Graph may send seven fractional digits; Python reads at most six.
        return datetime.fromisoformat(stamp + ("." + fraction[:6] if fraction else "")).replace(
            tzinfo=UTC
        )
    except ValueError:
        raise ConnectorError("Entra observation incomplete") from None


def verified_result(binding, observed, not_before):
    """Disabled, out of every bound group, not privileged, and sessions revoked at
    or after not_before. Malformed readings raise instead of becoming false."""
    binding = normalize_binding(binding)
    if (
        not isinstance(observed, dict)
        or set(observed) != OBSERVED_KEYS
        or observed["provider"] != "entra"
        or observed["tenantId"] != binding["tenantId"]
        or observed["userId"] != binding["userId"]
        or type(observed["active"]) is not bool
        or type(observed["privileged"]) is not bool
        or not isinstance(observed["groups"], list)
        or len(observed["groups"]) != len(binding["groupIds"])
    ):
        raise ConnectorError("Entra observation incomplete")
    groups = {}
    for group in observed["groups"]:
        if (
            not isinstance(group, dict)
            or set(group) != {"groupId", "member"}
            or type(group["member"]) is not bool
            or group["groupId"] in groups
        ):
            raise ConnectorError("Entra observation incomplete")
        groups[group["groupId"]] = group["member"]
    if set(groups) != set(binding["groupIds"]):
        raise ConnectorError("Entra observation incomplete")
    revoked_from = graph_time(observed["sessionsValidFrom"])
    return (
        observed["active"] is False
        and observed["privileged"] is False
        and all(member is False for member in groups.values())
        and revoked_from is not None
        and revoked_from >= not_before
    )


def load_config(path):
    """The lab's non-secret IDs and scope; the private key sits beside it."""
    if path.stat().st_size > 16384:
        raise ValueError("Configuration too large")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or config.get("schema_version") != 1:
        raise ValueError("Unsupported configuration")
    users = config.get("test_users")
    group = config.get("test_group")
    protected = config.get("protected_object_ids")
    if (
        not isinstance(users, list)
        or not 1 <= len(users) <= 20
        or not isinstance(group, dict)
        or not isinstance(protected, list)
        or not 1 <= len(protected) <= 20
    ):
        raise ValueError("Incomplete configuration")
    if not config.get("admin_consent_granted_at"):
        # The tenant administrator has not recorded consent to the Graph permissions.
        raise ValueError("Admin consent not recorded")
    thumbprint = config.get("certificate_sha1_thumbprint")
    if not isinstance(thumbprint, str) or len(thumbprint) != 40:
        raise ValueError("Certificate thumbprint required")
    key_name = Path(str(config.get("private_key_file", ""))).name
    if not key_name.endswith(".pem"):
        raise ValueError("Private key file required")
    protected = {canonical_id(item.lower()) for item in protected}
    managed_users = {canonical_id(str(item.get("object_id", "")).lower()) for item in users}
    managed_groups = {canonical_id(str(group.get("object_id", "")).lower())}
    if (managed_users | managed_groups) & protected:
        raise ValueError("A protected object is listed as managed")
    return {
        "tenantId": canonical_id(str(config.get("tenant_id", "")).lower()),
        "clientId": canonical_id(str(config.get("client_id", "")).lower()),
        "x5t": base64.urlsafe_b64encode(bytes.fromhex(thumbprint)).rstrip(b"=").decode(),
        "keyFile": path.parent / key_name,
        "protected": protected,
        "users": managed_users,
        "groups": managed_groups,
    }


class EntraConnector:
    def __init__(
        self, *, http=None, config=None, private_key=None, clock=time.monotonic, sleep=time.sleep
    ):
        self.clock, self.sleep = clock, sleep
        self.deadline = clock() + 60
        self.calls = 0
        self.token, self.token_expires = None, 0.0
        self.owned = http is None
        try:
            if config is None:
                config = load_config(
                    Path(
                        os.environ.get(
                            "ACCESSOPS_ENTRA_CONFIG_FILE", "/run/accessops-entra/lab.json"
                        )
                    )
                )
            self.config = config
            if private_key is None:
                key_file = config["keyFile"]
                if not 1024 <= key_file.stat().st_size <= 8192:
                    raise ValueError("Private key size unexpected")
                private_key = serialization.load_pem_private_key(
                    key_file.read_bytes(), password=None
                )
            if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
                raise ValueError("RSA key of at least 2048 bits required")
            self.private_key = private_key
            self.http = http or httpx.Client(
                verify=ssl.create_default_context(),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(10, connect=5),
            )
        except ConnectorError:
            raise
        except Exception:
            raise ConnectorError("Entra connector unavailable") from None

    def close(self):
        if self.owned and getattr(self, "http", None) is not None:
            self.http.close()

    def _budget(self):
        self.calls += 1
        if self.calls > 40 or self.clock() >= self.deadline:
            raise ConnectorError("Entra operation budget exceeded")

    def _token(self):
        if self.token and self.clock() < self.token_expires - 60:
            return self.token
        endpoint = f"{LOGIN}/{self.config['tenantId']}/oauth2/v2.0/token"
        now = int(time.time())
        assertion = jwt.encode(
            {
                "aud": endpoint,
                "iss": self.config["clientId"],
                "sub": self.config["clientId"],
                "jti": uuid.uuid4().hex,
                "nbf": now,
                "iat": now,
                "exp": now + 300,
            },
            self.private_key,
            algorithm="RS256",
            headers={"x5t": self.config["x5t"], "typ": "JWT"},
        )
        self._budget()
        try:
            response = self.http.post(
                endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config["clientId"],
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": assertion,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            body = response.json() if len(response.content) <= MAX_BYTES else {}
        except (httpx.HTTPError, ValueError):
            raise ConnectorError("Entra sign-in unavailable") from None
        token, lifetime = body.get("access_token"), body.get("expires_in")
        if response.status_code != 200 or not isinstance(token, str) or type(lifetime) is not int:
            raise ConnectorError("Entra sign-in refused")
        self.token, self.token_expires = token, self.clock() + lifetime
        return token

    def _call(self, method, path, *, body=None, expect=(200,)):
        url = path if path.startswith(GRAPH + "/") else GRAPH + path
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com" or parsed.fragment:
            raise ConnectorError("Unexpected Graph destination")
        token = self._token()
        self._budget()
        try:
            response = self.http.request(
                method,
                url,
                json=body,
                headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
            )
            if response.status_code not in expect or len(response.content) > MAX_BYTES:
                raise ValueError
            return response.status_code, (response.json() if response.content else None)
        except (httpx.HTTPError, ValueError):
            raise ConnectorError("Graph request failed") from None

    def _scope(self, binding):
        binding = normalize_binding(binding)
        objects = {binding["userId"], *binding["groupIds"]}
        if (
            binding["tenantId"] != self.config["tenantId"]
            or binding["userId"] not in self.config["users"]
            or not set(binding["groupIds"]) <= self.config["groups"]
            or objects & self.config["protected"]
        ):
            raise ConnectorError("Entra object outside the connector's scope")
        return binding

    def _member_of(self, user_id):
        """Every group and directory role the user directly belongs to (bounded)."""
        url, found = f"/users/{user_id}/memberOf?$select=id", set()
        for _ in range(5):
            _, page = self._call("GET", url)
            values = page.get("value") if isinstance(page, dict) else None
            if not isinstance(values, list):
                raise ConnectorError("Entra observation incomplete")
            for item in values:
                if not isinstance(item, dict) or not isinstance(item.get("@odata.type"), str):
                    raise ConnectorError("Entra observation incomplete")
                found.add((item["@odata.type"], str(item.get("id", "")).lower()))
            url = page.get("@odata.nextLink")
            if not url:
                return found
            if not isinstance(url, str) or not url.startswith(f"{GRAPH}/users/{user_id}/memberOf"):
                raise ConnectorError("Unexpected Graph pagination")
        raise ConnectorError("Entra membership exceeds the read bound")

    def _collect(self, binding):
        binding = self._scope(binding)
        _, org = self._call("GET", "/organization?$select=id")
        tenants = org.get("value") if isinstance(org, dict) else None
        if (
            not isinstance(tenants, list)
            or len(tenants) != 1
            or str(tenants[0].get("id", "")).lower() != binding["tenantId"]
        ):
            raise ConnectorError("Entra tenant binding mismatch")
        _, user = self._call(
            "GET",
            f"/users/{binding['userId']}?$select=id,accountEnabled,signInSessionsValidFromDateTime",
        )
        if (
            not isinstance(user, dict)
            or str(user.get("id", "")).lower() != binding["userId"]
            or type(user.get("accountEnabled")) is not bool
        ):
            raise ConnectorError("Entra user incomplete")
        sessions_from = user.get("signInSessionsValidFromDateTime")
        graph_time(sessions_from)
        member_of = self._member_of(binding["userId"])
        return {
            "provider": "entra",
            "tenantId": binding["tenantId"],
            "userId": binding["userId"],
            "active": user["accountEnabled"],
            "privileged": any(kind == ROLE for kind, _ in member_of),
            "groups": [
                {"groupId": group, "member": (GROUP, group) in member_of}
                for group in binding["groupIds"]
            ],
            "sessionsValidFrom": sessions_from,
        }

    def validate_binding(self, binding):
        observed = self._collect(binding)
        if observed["privileged"]:
            raise ConnectorError("Entra user holds a directory role; it is never changed here")
        return observed

    def offboard(self, binding, not_before):
        binding = normalize_binding(binding)
        before = self.validate_binding(binding)
        user = binding["userId"]
        if before["active"]:
            self._call("PATCH", f"/users/{user}", body={"accountEnabled": False}, expect=(204,))
        for group in before["groups"]:
            if group["member"]:
                # 404: already absent. The read-back decides either way.
                self._call(
                    "DELETE",
                    f"/groups/{group['groupId']}/members/{user}/$ref",
                    expect=(204, 404),
                )
        _, revoked = self._call("POST", f"/users/{user}/revokeSignInSessions")
        if not isinstance(revoked, dict) or revoked.get("value") is not True:
            raise ConnectorError("Entra session revocation unconfirmed")
        # Graph is eventually consistent: read back a few times before giving up.
        for attempt in range(4):
            observed = self._collect(binding)
            if verified_result(binding, observed, not_before) or attempt == 3:
                break
            self.sleep(2)
        return {"verified": verified_result(binding, observed, not_before), "observed": observed}
