"""Live signing-key rotation drill in both lab realms. Never prints secrets.

Run by scripts/Test-KeyRotation.ps1, which creates a temporary Keycloak admin
for this one container; lab_admin.temporary_admin() deletes it at the end and
proves its credential is refused.

Planned rotation, publish first: a new RS256 key is published in each realm as
passive (verification only) and the drill waits one key-cache lifetime, so every
app that checks tokens locally has fetched it before it signs anything. Then it
becomes the signing key. The drill checks that Atlas (which checks tokens
locally) accepts the first new token at once, that AccessOps' operator sign-in
and Keycloak's back-channel logout keep working, and that the previous key's
tokens stay valid while it is passive. Every previous RS256 key is removed at
the end.

Emergency: the drill publishes a key it generated itself, as if an attacker had
copied a signing key, and forges an Atlas access token with it. It then removes
the key and measures how long Keycloak and Atlas keep trusting the forged token.

Mount .local/operator-logins.json read-only at /run/test-logins.json and the
report folder at /test-output. The drill user's password is random, held in
memory and never reported; the user is deleted at the end.
"""

import json
import secrets
import time
import uuid

import jwt
from check_report import CheckReport, report_arguments
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lab_admin import require, temporary_admin
from live_oidc import APP, IDENTITY, LOGINS, login
from live_sessions import atlas_api, cli_tokens, sign_in_atlas

from integrations.security import KEY_CACHE_SECONDS
from integrations.transport import client

WORKFORCE = "accessops-workforce"
OPERATORS = "accessops-operators"
KEYS = "org.keycloak.keys.KeyProvider"


def signing_keys(admin, realm):
    """RS256 signing keys by kid, each with its provider component and status."""
    data = require(admin.get(f"/{realm}/keys"), 200).json()
    return {
        item["kid"]: item
        for item in data["keys"]
        if item.get("algorithm") == "RS256" and item.get("use", "SIG") == "SIG"
    }


def add_key(admin, realm, name, priority, *, private_pem=None, active=True):
    """Add an RS256 key provider; returns (component id, kid)."""
    realm_id = require(admin.get(f"/{realm}"), 200).json()["id"]
    config = {
        "priority": [str(priority)],
        "enabled": ["true"],
        "active": ["true" if active else "false"],
        "algorithm": ["RS256"],
    }
    if private_pem:
        provider, config["privateKey"] = "rsa", [private_pem]
    else:
        provider, config["keySize"] = "rsa-generated", ["2048"]
    response = require(
        admin.post(
            f"/{realm}/components",
            json={
                "name": name,
                "providerId": provider,
                "providerType": KEYS,
                "parentId": realm_id,
                "config": config,
            },
        ),
        201,
    )
    component = response.headers["location"].rsplit("/", 1)[-1]
    kid = next(
        k for k, item in signing_keys(admin, realm).items() if item["providerId"] == component
    )
    return component, kid


def set_active(admin, realm, component, active):
    # Secret settings come back masked and are kept as they are on update.
    item = require(admin.get(f"/{realm}/components/{component}"), 200).json()
    item["config"]["active"] = ["true" if active else "false"]
    require(admin.put(f"/{realm}/components/{component}", json=item), 204)


def published(http, realm):
    response = http.get(f"{IDENTITY}/realms/{realm}/protocol/openid-connect/certs")
    return {item["kid"] for item in response.json()["keys"]}


def kid_of(token):
    return jwt.get_unverified_header(token)["kid"]


def until(read, seconds, interval=1.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if read():
            return True
        time.sleep(interval)
    return False


def main():
    args = report_arguments(__doc__).parse_args()
    report = CheckReport(
        "key-rotation",
        driver="Keycloak 26.8 realm signing keys rotated live by a temporary admin; Atlas and AccessOps observed",
        limitations=[
            "Lab realms only. The temporary admin exists for this drill and is deleted at the end.",
            "The 'stolen' key is one the drill generated and published itself; no real key was exposed.",
            "Atlas stands in for an app that checks tokens locally. AccessOps fetches Keycloak's keys afresh at each operator sign-in and caches them for logout tokens.",
            "The previous signing keys are removed at the end, so the lab runs on the new keys afterwards.",
        ],
        source_files=[
            "scripts/live_key_rotation.py",
            "scripts/lab_admin.py",
            "scripts/live_oidc.py",
            "scripts/live_sessions.py",
            "scripts/atlas_app.py",
            "scripts/check_report.py",
            "integrations/security.py",
            "integrations/transport.py",
            "backend/core/auth.py",
        ],
    )
    result, cleanup = {}, []
    http = client(timeout=10)
    try:
        with temporary_admin(result) as admin:
            try:
                drill(report, admin, http, cleanup)
            finally:
                for label, undo in reversed(cleanup):
                    try:
                        undo()
                    except Exception as error:
                        report.record_error(error, name="drill cleanup: " + label)
    except Exception as error:
        report.record_error(error)
    finally:
        http.close()
    with report.case("temporary drill admin deleted and its credential refused"):
        if not result.get("temporaryAdminRemoved"):
            raise AssertionError("The temporary admin may remain")
    return report.finish(args)


def drill(report, admin, http, cleanup):
    realms = (WORKFORCE, OPERATORS)
    with report.case("temporary drill admin reached Keycloak's admin API"):
        before = {realm: signing_keys(admin, realm) for realm in realms}
        current = {
            realm: require(admin.get(f"/{realm}/keys"), 200).json()["active"]["RS256"]
            for realm in realms
        }

    suffix = uuid.uuid4().hex[:10]
    username, password = "key-drill-" + suffix, secrets.token_urlsafe(24)
    with report.case("a synthetic drill user signs in, and Atlas accepts its token locally"):
        require(
            admin.post(
                f"/{WORKFORCE}/users",
                json={
                    "username": username,
                    "enabled": True,
                    "email": username + "@fixture.test",
                    "emailVerified": True,
                    "firstName": "Key",
                    "lastName": "Drill " + suffix,
                    "credentials": [{"type": "password", "value": password, "temporary": False}],
                },
            ),
            201,
        )
        user = require(
            admin.get(f"/{WORKFORCE}/users", params={"username": username, "exact": "true"}), 200
        ).json()[0]
        cleanup.append(
            ("drill user", lambda: require(admin.delete(f"/{WORKFORCE}/users/{user['id']}"), 204))
        )
        sign_in_atlas(http, username, password)
        old_token = cli_tokens(http, "openid")["access_token"]
        if kid_of(old_token) != current[WORKFORCE] or atlas_api(http, old_token, "local")[0] != 200:
            raise AssertionError("The drill user's token was not accepted on the current key")

    added = {}
    with report.case("planned rotation, step 1: new keys are published before they sign anything"):
        for realm in realms:
            top = max(int(item["providerPriority"]) for item in before[realm].values())
            added[realm] = add_key(admin, realm, "drill-" + suffix, top + 100, active=False)
            if added[realm][1] not in published(http, realm):
                raise AssertionError("The new key is not published")
        if kid_of(cli_tokens(http, "openid")["access_token"]) != current[WORKFORCE]:
            raise AssertionError("A passive key signed a token")

    # Timed: one key-cache lifetime, after which every locally checking app has
    # read the key set that includes the new keys.
    with report.case(f"waited one key-cache lifetime ({KEY_CACHE_SECONDS} s) for apps to see them"):
        time.sleep(KEY_CACHE_SECONDS + 5)

    with report.case(
        "planned rotation, step 2: the new keys sign, and Atlas accepts the first token"
    ):
        for realm in realms:
            set_active(admin, realm, added[realm][0], True)
            set_active(admin, realm, before[realm][current[realm]]["providerId"], False)
        new_token = cli_tokens(http, "openid")["access_token"]
        if kid_of(new_token) != added[WORKFORCE][1]:
            raise AssertionError("New tokens are not signed with the new key")
        if atlas_api(http, new_token, "local")[0] != 200:
            raise AssertionError("Atlas refused the first token signed by the new key")

    with report.case("the previous key's tokens stay valid while it is passive"):
        if (
            atlas_api(http, old_token, "local")[0] != 200
            or atlas_api(http, old_token, "introspection")[0] != 200
            or current[WORKFORCE] not in published(http, WORKFORCE)
        ):
            raise AssertionError("A passive key's token was refused")

    with report.case(
        "operator sign-in with a one-time code works on the operators realm's new key"
    ):
        alice, _ = login("alice", json.loads(LOGINS.read_text())["passwords"]["alice"])
        cleanup.append(("operator client", alice.close))

    # Timed: Keycloak signs the logout token with the new key; AccessOps must
    # verify it to end the session.
    with report.case(
        "Keycloak's back-channel logout, signed by the new key, ends the operator's AccessOps session"
    ):
        account = require(
            admin.get(f"/{OPERATORS}/users", params={"username": "alice", "exact": "true"}), 200
        ).json()[0]
        require(admin.post(f"/{OPERATORS}/users/{account['id']}/logout"), 204)
        if not until(
            lambda: alice.get(APP + "/api/v1/session").json().get("authenticated") is False, 35
        ):
            raise AssertionError("The operator session survived the logout")

    with report.case(
        "emergency drill: a token forged with a published key passes Atlas's local check and Keycloak introspection alike"
    ):
        stolen = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = stolen.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        component, stolen_kid = add_key(
            admin, WORKFORCE, "stolen-" + suffix, 1, private_pem=pem, active=False
        )
        cleanup.append(("stolen key", lambda: admin.delete(f"/{WORKFORCE}/components/{component}")))
        now = int(time.time())
        forged = jwt.encode(
            {
                "iss": f"{IDENTITY}/realms/{WORKFORCE}",
                "aud": ["atlas-app"],
                "azp": "atlas-cli",
                "sub": user["id"],
                "typ": "Bearer",
                "iat": now,
                "exp": now + 3600,
                "jti": uuid.uuid4().hex,
            },
            pem,
            algorithm="RS256",
            headers={"kid": stolen_kid},
        )
        # Atlas may wait out its refresh limit before reading the new key set.
        if not until(lambda: atlas_api(http, forged, "local")[0] == 200, 45):
            raise AssertionError("Atlas did not trust the published key")
        if atlas_api(http, forged, "introspection")[0] != 200:
            raise AssertionError("Introspection refused a token signed by a realm key")

    with report.case("after the key is removed, Keycloak introspection refuses the forged token"):
        require(admin.delete(f"/{WORKFORCE}/components/{component}"), 204)
        cleanup.pop()
        removed = time.monotonic()
        if (
            stolen_kid in published(http, WORKFORCE)
            or atlas_api(http, forged, "introspection")[0] != 401
        ):
            raise AssertionError("Keycloak still trusts the removed key")

    with report.case(
        f"Atlas's local check refuses it within one key-cache lifetime ({KEY_CACHE_SECONDS} s)"
    ):
        if not until(lambda: atlas_api(http, forged, "local")[0] == 401, KEY_CACHE_SECONDS + 35):
            raise AssertionError("Atlas kept trusting the removed key")
        print(f"Atlas refused the forged token {time.monotonic() - removed:.0f} s after removal")

    with report.case("planned rotation completed: every previous RS256 key is removed"):
        for realm in realms:
            for kid, item in before[realm].items():
                require(admin.delete(f"/{realm}/components/{item['providerId']}"), 204)
                if kid in published(http, realm):
                    raise AssertionError("A retired key is still published")


if __name__ == "__main__":
    raise SystemExit(main())
