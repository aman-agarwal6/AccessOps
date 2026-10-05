"""SCIM 2 client for Keycloak 26.8's native workforce-realm endpoint.

This connector never administers the operators realm, clients, or policy. Its
manage-users credential is workforce-wide, not a claim of per-project FGAP.
AccessOps performs project authorization before calling it. Native admin calls go
only through two private edge routes: group membership reads, and per-user
session logout and listing.
"""

import json
import os
import re
import time
import uuid
from urllib.parse import quote

import httpx

from .errors import ConnectorError, IntegrationError
from .transport import checked_url, client, json_response

USER = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
MEMBERSHIP_ORIGIN = "https://keycloak-observe.accessops.internal:8184"
# Private route allowing only per-user logout (POST) and session listing (GET).
SESSIONS_ORIGIN = "https://keycloak-sessions.accessops.internal:8185"
EVENTS_URL = MEMBERSHIP_ORIGIN + "/admin/realms/accessops-workforce/events"
# Sign-in and token events a departed account must not have; errors are refusals.
SIGN_IN_SUCCESS = ("LOGIN", "CODE_TO_TOKEN", "REFRESH_TOKEN", "TOKEN_EXCHANGE")
SIGN_IN_REFUSED = (
    "LOGIN_ERROR",
    "CODE_TO_TOKEN_ERROR",
    "REFRESH_TOKEN_ERROR",
    "TOKEN_EXCHANGE_ERROR",
)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", value):
        raise ConnectorError("Invalid provider identifier")
    return quote(value, safe="")


def user_uuid(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ConnectorError("Native user binding invalid") from None
    return value


class KeycloakConnector:
    def __init__(self, *, http=None, issuer=None, client_id=None, client_secret=None):
        self.issuer = checked_url(issuer or os.getenv("WORKFORCE_ISSUER", ""))
        if not self.issuer.endswith("/realms/accessops-workforce"):
            raise ConnectorError("Connector may only target the workforce realm")
        self.base = self.issuer + "/scim/v2"
        self.client_id = client_id or os.getenv("SCIM_CLIENT_ID", "accessops-scim")
        self.secret = client_secret or os.getenv("SCIM_CLIENT_SECRET", "")
        self.http = http or client()
        self._access_token, self._expires = "", 0

    @classmethod
    def events_reader(cls, **options):
        """A connector authenticated as the read-only events client (view-events)."""
        return cls(
            client_id=os.getenv("EVENTS_CLIENT_ID", "accessops-events"),
            client_secret=os.getenv("EVENTS_CLIENT_SECRET", ""),
            **options,
        )

    def sign_in_events(self, user_id, since_ms, limit=200):
        """Sign-in and token events for one account at or after since_ms, oldest
        first. Only time, type, client and error are kept; a reading that may be
        incomplete stays unknown."""
        user_uuid(user_id)
        if type(since_ms) is not int or since_ms < 0:
            raise ConnectorError("Invalid event window")
        params = [
            ("user", user_id),
            ("dateFrom", str(since_ms)),
            ("direction", "asc"),
            ("first", "0"),
            ("max", str(limit + 1)),
        ] + [("type", kind) for kind in SIGN_IN_SUCCESS + SIGN_IN_REFUSED]
        try:
            response = self.http.get(
                EVENTS_URL,
                params=params,
                headers={"Authorization": "Bearer " + self._token(), "Accept": "application/json"},
                follow_redirects=False,
            )
            if response.status_code != 200 or str(response.url).split("?", 1)[0] != EVENTS_URL:
                raise ConnectorError("Event observation unavailable")
            records = json_response(response, limit=262144)
            if not isinstance(records, list) or len(records) > limit:
                raise ConnectorError("Event observation incomplete")
            events = []
            for record in records:
                if (
                    not isinstance(record, dict)
                    or record.get("userId") != user_id
                    or record.get("type") not in SIGN_IN_SUCCESS + SIGN_IN_REFUSED
                    or type(record.get("time")) is not int
                    or not isinstance(record.get("clientId") or "", str)
                    or not isinstance(record.get("error") or "", str)
                ):
                    raise ConnectorError("Event observation incomplete")
                if record["time"] >= since_ms:
                    events.append(
                        {
                            "time": record["time"],
                            "type": record["type"],
                            "clientId": (record.get("clientId") or "")[:128],
                            "error": (record.get("error") or "")[:64],
                        }
                    )
            return events
        except (httpx.HTTPError, IntegrationError):
            raise ConnectorError("Event observation unavailable") from None

    def _token(self):
        if self._expires > time.monotonic():
            return self._access_token
        if len(self.secret) < 32:
            raise ConnectorError("SCIM credentials are not configured")
        try:
            response = self.http.post(
                self.issuer + "/protocol/openid-connect/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.secret,
                },
                follow_redirects=False,
            )
            if response.status_code != 200:
                raise ConnectorError("SCIM authentication rejected")
            data = json_response(response, limit=32768)
            if not isinstance(data.get("access_token"), str) or not isinstance(
                data.get("expires_in"), (int, float)
            ):
                raise ConnectorError("Invalid SCIM token response")
            self._access_token = data["access_token"]
            self._expires = time.monotonic() + max(0, min(data["expires_in"] - 10, 120))
            return self._access_token
        except (httpx.HTTPError, IntegrationError) as exc:
            raise ConnectorError("SCIM authentication unavailable") from exc

    def _call(self, method, path, *, body=None, params=None, expected=(200,)):
        try:
            response = self.http.request(
                method,
                self.base + path,
                json=body,
                params=params,
                headers={
                    "Authorization": "Bearer " + self._token(),
                    "Accept": "application/scim+json",
                    "Content-Type": "application/scim+json",
                },
                follow_redirects=False,
            )
            if response.status_code not in expected:
                raise ConnectorError(f"SCIM operation failed (HTTP {response.status_code})")
            return None if response.status_code == 204 else json_response(response)
        except (httpx.HTTPError, IntegrationError) as exc:
            raise ConnectorError("SCIM operation unavailable") from exc

    def discover(self):
        return {
            name: self._call("GET", "/" + name)
            for name in ("ServiceProviderConfig", "ResourceTypes", "Schemas")
        }

    def list_resources(self, resource_type, *, filter_expression=None, start_index=1, count=100):
        if (
            resource_type not in ("Users", "Groups")
            or type(start_index) is not int
            or start_index < 1
            or type(count) is not int
            or not 1 <= count <= 100
        ):
            raise ConnectorError("Invalid SCIM pagination")
        if filter_expression is not None and (
            not isinstance(filter_expression, str) or len(filter_expression) > 2048
        ):
            raise ConnectorError("Invalid SCIM filter")
        params = {"startIndex": start_index, "count": count}
        if filter_expression is not None:
            params["filter"] = filter_expression
        data = self._call("GET", "/" + resource_type, params=params)
        if (
            not isinstance(data, dict)
            or LIST not in data.get("schemas", [])
            or not isinstance(data.get("Resources", []), list)
        ):
            raise ConnectorError("Invalid SCIM list response")
        return data

    def create_user(self, username, *, external_id, given_name="", family_name="", email=None):
        if not isinstance(username, str) or not 1 <= len(username) <= 100:
            raise ConnectorError("Invalid username")
        body = {
            "schemas": [USER],
            "userName": username,
            "externalId": identifier(external_id),
            "active": True,
            "name": {"givenName": given_name[:100], "familyName": family_name[:100]},
        }
        if email:
            body["emails"] = [{"value": email, "primary": True, "type": "work"}]
        return self._call("POST", "/Users", body=body, expected=(201,))

    def get_user(self, user_id):
        return self._call("GET", "/Users/" + identifier(user_id))

    def patch_user(self, user_id, operations):
        if not isinstance(operations, list) or not 1 <= len(operations) <= 10:
            raise ConnectorError("Invalid patch")
        for operation in operations:
            if operation.get("op", "").lower() not in ("add", "replace", "remove") or operation.get(
                "path"
            ) not in ("active", "name.givenName", "name.familyName", "displayName"):
                raise ConnectorError("User patch is outside connector scope")
            if operation.get("path") == "active" and type(operation.get("value")) is not bool:
                raise ConnectorError("Active must be boolean")
        return self._call(
            "PATCH",
            "/Users/" + identifier(user_id),
            body={"schemas": [PATCH], "Operations": operations},
        )

    def delete_user(self, user_id):
        return self._call("DELETE", "/Users/" + identifier(user_id), expected=(204,))

    def create_group(self, display_name):
        if (
            not isinstance(display_name, str)
            or not display_name.startswith("accessops-")
            or len(display_name) > 100
        ):
            raise ConnectorError("Group must use accessops- namespace")
        return self._call(
            "POST",
            "/Groups",
            body={"schemas": [GROUP], "displayName": display_name},
            expected=(201,),
        )

    def delete_group(self, group_id):
        self.get_group(group_id)  # Namespace guard applies to deletion as well.
        return self._call("DELETE", "/Groups/" + identifier(group_id), expected=(204,))

    def get_group(self, group_id):
        # Keycloak SCIM marks members as returned=request; omission is not absence.
        data = self._call(
            "GET",
            "/Groups/" + identifier(group_id),
            params={"attributes": "id,displayName,members"},
        )
        if (
            not isinstance(data, dict)
            or data.get("id") != group_id
            or not isinstance(data.get("schemas"), list)
            or GROUP not in data["schemas"]
            or not isinstance(data.get("displayName"), str)
            or not data["displayName"].startswith("accessops-")
            or len(data["displayName"]) > 100
        ):
            raise ConnectorError("Group binding or schema is invalid")
        if "members" in data:
            self._member_ids(data["members"])
        return data

    @staticmethod
    def _member_ids(members):
        if not isinstance(members, list) or len(members) > 500:
            raise ConnectorError("Group membership incomplete")
        ids = []
        for member in members:
            if not isinstance(member, dict):
                raise ConnectorError("Group membership incomplete")
            value = member.get("value")
            identifier(value)
            ids.append(value)
        if len(set(ids)) != len(ids):
            raise ConnectorError("Group membership incomplete")
        return ids

    def _admin_member(self, group_id, user_id):
        """Read-only fixed workforce endpoint; omitted SCIM attributes are unknown."""
        try:
            if str(uuid.UUID(group_id)) != group_id or str(uuid.UUID(user_id)) != user_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ConnectorError("Native membership binding invalid") from None
        url = (
            MEMBERSHIP_ORIGIN + "/admin/realms/accessops-workforce/groups/" + group_id + "/members"
        )
        seen = set()
        try:
            # One native response avoids missing a target shifted between
            # offset pages. The supported max parameter supplies cap+1; groups
            # exceeding the documented local inventory cap remain unknown.
            response = self.http.get(
                url,
                params={"first": 0, "max": 501, "briefRepresentation": "true"},
                headers={"Authorization": "Bearer " + self._token(), "Accept": "application/json"},
                follow_redirects=False,
            )
            if response.status_code != 200 or str(response.url).split("?", 1)[0] != url:
                raise ConnectorError("Membership observation unavailable")
            records = json_response(response, limit=131072)
            if not isinstance(records, list) or len(records) > 500:
                raise ConnectorError("Membership observation incomplete")
            for record in records:
                value = record.get("id") if isinstance(record, dict) else None
                if not isinstance(value, str) or str(uuid.UUID(value)) != value or value in seen:
                    raise ConnectorError("Membership observation incomplete")
                seen.add(value)
            return user_id in seen
        except (httpx.HTTPError, IntegrationError, ValueError):
            raise ConnectorError("Membership observation unavailable") from None

    def _sessions_url(self, user_id, operation):
        return (
            SESSIONS_ORIGIN
            + "/admin/realms/accessops-workforce/users/"
            + user_uuid(user_id)
            + "/"
            + operation
        )

    def count_sessions(self, user_id):
        """Read the account's active Keycloak sessions; any doubt stays unknown."""
        url = self._sessions_url(user_id, "sessions")
        try:
            response = self.http.get(
                url,
                headers={"Authorization": "Bearer " + self._token(), "Accept": "application/json"},
                follow_redirects=False,
            )
            if response.status_code != 200 or str(response.url) != url:
                raise ConnectorError("Session observation unavailable")
            records = json_response(response, limit=131072)
            if not isinstance(records, list) or len(records) > 500:
                raise ConnectorError("Session observation incomplete")
            ids = set()
            for record in records:
                value = record.get("id") if isinstance(record, dict) else None
                if (
                    not isinstance(value, str)
                    or not 1 <= len(value) <= 128
                    or value in ids
                    or record.get("userId") != user_id
                ):
                    raise ConnectorError("Session observation incomplete")
                ids.add(value)
            return len(ids)
        except (httpx.HTTPError, IntegrationError):
            raise ConnectorError("Session observation unavailable") from None

    def end_sessions(self, user_id):
        """Keycloak's per-user logout: ends every session, rejects tokens issued
        before now (not-before) and sends back-channel logout to registered apps."""
        url = self._sessions_url(user_id, "logout")
        try:
            response = self.http.post(
                url,
                headers={"Authorization": "Bearer " + self._token()},
                follow_redirects=False,
            )
            if response.status_code != 204:
                raise ConnectorError(f"Session logout failed (HTTP {response.status_code})")
        except httpx.HTTPError:
            raise ConnectorError("Session logout unavailable") from None

    def observe_membership(self, identity, resource):
        user_id = identity.get("providerSubject")
        identifier(user_id)
        group_id = self._group(resource)
        group = self.get_group(group_id)
        member = (
            user_id in self._member_ids(group["members"])
            if "members" in group
            else self._admin_member(group_id, user_id)
        )
        return {"observed": {"member": member, "groupId": group_id}}

    def set_membership(self, group_id, user_id, present):
        identifier(user_id)
        if type(present) is not bool:
            raise ConnectorError("Membership intent invalid")
        exists = self.observe_membership({"providerSubject": user_id}, {"providerGroup": group_id})[
            "observed"
        ]["member"]
        if exists == present:
            return {"verified": True}
        operation = (
            {"op": "add", "path": "members", "value": [{"value": user_id}]}
            if present
            else {"op": "remove", "path": "members[value eq " + json.dumps(user_id) + "]"}
        )
        return self._call(
            "PATCH",
            "/Groups/" + identifier(group_id),
            body={"schemas": [PATCH], "Operations": [operation]},
        )

    def _group(self, resource):
        group = (resource or {}).get("providerGroup")
        if not group:
            raise ConnectorError("Resource has no managed provider group")
        return identifier(group)

    def apply(self, operation, identity, resource=None):
        user_id = identity.get("providerSubject")
        if not user_id:
            raise ConnectorError("Identity has no provider binding")
        kind = operation.get("kind", operation.get("action"))
        if kind in ("grant", "revoke"):
            group_id = self._group(resource)
            expected = kind == "grant"
            self.set_membership(group_id, user_id, expected)
            actual = self.observe_membership(identity, resource)["observed"]["member"]
            return {
                "desired": {"member": expected},
                "observed": {"member": actual, "groupId": group_id},
                "verified": actual == expected,
            }
        if kind == "offboard":
            # Disable first so no new session can start, then end existing ones.
            # Both steps are idempotent, so every delivery repeats them.
            self.patch_user(user_id, [{"op": "replace", "path": "active", "value": False}])
            self.end_sessions(user_id)
            actual = self.get_user(user_id)
            sessions = self.count_sessions(user_id)
            return {
                "desired": {"active": False, "sessions": 0},
                "observed": {"active": actual.get("active"), "sessions": sessions},
                "verified": actual.get("active") is False and sessions == 0,
            }
        if kind == "transfer":
            # Sponsor is exclusively an AccessOps server record, not an OIDC act claim.
            return {
                "desired": {"sponsor": operation.get("new_sponsor_id")},
                "observed": {"providerChangeRequired": False},
                "verified": True,
            }
        raise ConnectorError("Unsupported connector operation")

    def reconcile(self, identity, resource=None):
        observed = self.get_user(identity.get("providerSubject"))
        desired_active = identity.get("status") == "active"
        sessions = self.count_sessions(identity.get("providerSubject"))
        result = {"active": observed.get("active"), "sessions": sessions}
        # A contained account must be disabled and hold no live session.
        drift = observed.get("active") is not desired_active or (
            not desired_active and sessions != 0
        )
        if resource and resource.get("providerGroup"):
            result["member"] = self.observe_membership(identity, resource)["observed"]["member"]
            if "desiredMember" in resource:
                drift = drift or result["member"] != resource["desiredMember"]
        return {"drift": drift, "observed": result}
