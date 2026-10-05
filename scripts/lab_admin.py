"""A temporary Keycloak admin for one-shot lab maintenance. Never prints secrets.

The lab has no standing Keycloak administrator. Upgrade-Lab.ps1 and
Test-KeyRotation.ps1 create a temporary bootstrap admin service account while
Keycloak is stopped and pass its ID and secret to one container by variable name.
temporary_admin() gives that container an admin API client, then always deletes
the account and records whether its credential is refused afterwards.
"""

import os
import time
from contextlib import contextmanager

import httpx

from integrations.transport import client

TOKEN_URL = "https://id.accessops.test:8443/realms/master/protocol/openid-connect/token"
# Keycloak's admin API is never published. Only the one-shot container reaches
# it, over the private identity network.
ADMIN_URL = "http://keycloak:8080/admin/realms"


def require(response, *statuses):
    if response.status_code not in statuses:
        raise RuntimeError(f"Admin API returned HTTP {response.status_code}")
    return response


class AdminAuth(httpx.Auth):
    """Client-credentials bearer token, fetched again before it expires (master
    realm tokens last a minute) or once after a refusal."""

    def __init__(self, public, credentials):
        self.public, self.credentials = public, credentials
        self.token, self.expires = None, 0.0

    def fetch(self):
        response = self.public.post(TOKEN_URL, data=self.credentials)
        if response.status_code != 200:
            raise RuntimeError("Temporary admin token was refused")
        body = response.json()
        self.token, self.expires = body["access_token"], time.monotonic() + body["expires_in"]

    def auth_flow(self, request):
        if self.token is None or time.monotonic() > self.expires - 10:
            self.fetch()
        request.headers["Authorization"] = "Bearer " + self.token
        response = yield request
        if response.status_code == 401:
            self.fetch()
            request.headers["Authorization"] = "Bearer " + self.token
            yield request


@contextmanager
def temporary_admin(result):
    admin_id = os.environ["UPGRADE_CLIENT_ID"]
    credentials = {
        "grant_type": "client_credentials",
        "client_id": admin_id,
        "client_secret": os.environ["UPGRADE_CLIENT_SECRET"],
    }
    result["temporaryAdminRemoved"] = False
    with client(timeout=15) as public:
        auth = AdminAuth(public, credentials)
        try:
            auth.fetch()
        except RuntimeError:
            raise SystemExit("Temporary admin token was refused; nothing was changed.") from None
        admin = httpx.Client(
            base_url=ADMIN_URL, auth=auth, timeout=15, trust_env=False, follow_redirects=False
        )
        try:
            yield admin
        finally:
            # Always remove the temporary admin, even after a failed step. The
            # refused-token check below is what decides success.
            try:
                for item in require(
                    admin.get("/master/clients", params={"clientId": admin_id}), 200
                ).json():
                    require(admin.delete(f"/master/clients/{item['id']}"), 204)
            except (httpx.HTTPError, RuntimeError, ValueError, KeyError):
                pass
            finally:
                admin.close()
            refused = public.post(TOKEN_URL, data=credentials).status_code in (400, 401)
            result["temporaryAdminRemoved"] = refused
            if not refused:
                result["temporaryAdminClientId"] = admin_id
