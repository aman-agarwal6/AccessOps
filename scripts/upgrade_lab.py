"""One-time, non-destructive upgrades of an existing lab. Never prints secrets.

local  (host)       Create missing Atlas and events-reader client secrets and
                    write the current lab-added client definitions into the
                    stored workforce realm import.
realm  (container)  Using a temporary bootstrap admin service account, create the
                    lab-added clients in the running workforce realm, or add any
                    protocol mapper, client scope or role they lack, then delete
                    that temporary account and prove its credential fails. Only
                    the Atlas clients and the events reader are touched; other
                    clients, users and sessions are not.
hr     (host)       Create .local/hr-intake.env with an HR webhook signing secret
                    if it is missing.
ssf    (host)       Create the security event signing key and the poll tokens
                    of the SOC and Atlas signal streams if they are missing.

Start-Lab.ps1 runs hr and ssf on every start. scripts/Upgrade-Lab.ps1 runs local
and realm with a database backup first.
"""

import json
import os
import secrets
import sys
from pathlib import Path

REALM = "accessops-workforce"
TOKEN_URL = "https://id.accessops.test:8443/realms/master/protocol/openid-connect/token"
# Keycloak's admin API is never published. Only this one-shot container reaches
# it, over the private identity network.
ADMIN_URL = "http://keycloak:8080/admin/realms"


def read_env(path):
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key and value:
            values[key.strip()] = value.strip()
    return values


def ensure_secret(path, key, make):
    """Create a one-line env file if missing; return (secret, created)."""
    created = not path.exists()
    if created:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="\n") as target:
            target.write(key + "=" + make() + "\n")
    value = read_env(path).get(key, "")
    if len(value) < 32:
        raise SystemExit(path.name + " exists but has no usable secret.")
    return value, created


def lab_clients(atlas_secret, events_secret):
    from generate_local import events_client, workforce_apps

    return [*workforce_apps(atlas_secret), events_client(events_secret)]


def local():
    from generate_local import EVENTS_SCOPE_MAPPING, EVENTS_SERVICE_USER, LOCAL, uid

    def token():
        return secrets.token_urlsafe(36)

    atlas, atlas_created = ensure_secret(LOCAL / "atlas.env", "ATLAS_CLIENT_SECRET", token)
    events, events_created = ensure_secret(
        LOCAL / "keycloak-events.env", "EVENTS_CLIENT_SECRET", token
    )
    realm_file = LOCAL / "realms" / (REALM + "-realm.json")
    data = json.loads(realm_file.read_text(encoding="utf-8"))
    clients = lab_clients(atlas, events)
    names = {item["clientId"] for item in clients}
    others = [item for item in data.get("clients", []) if item.get("clientId") not in names]
    users = data.get("users", [])
    if not any(user.get("username") == EVENTS_SERVICE_USER["username"] for user in users):
        users = [*users, {"id": uid("events-service"), **EVENTS_SERVICE_USER}]
    mappings = json.loads(json.dumps(data.get("clientScopeMappings", {})))
    management = mappings.setdefault("realm-management", [])
    if EVENTS_SCOPE_MAPPING not in management:
        management.append(EVENTS_SCOPE_MAPPING)
    if (
        others + clients != data.get("clients")
        or users != data.get("users")
        or mappings != data.get("clientScopeMappings")
    ):
        data["clients"], data["users"] = others + clients, users
        data["clientScopeMappings"] = mappings
        staged = realm_file.with_suffix(".json.upgrade")
        staged.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(staged, realm_file)
    print(
        json.dumps(
            {
                "atlasEnv": "created" if atlas_created else "present",
                "eventsEnv": "created" if events_created else "present",
                "realmImportLabClients": sorted(names),
            }
        )
    )


def hr():
    from generate_local import LOCAL, hr_webhook_secret

    _, created = ensure_secret(LOCAL / "hr-intake.env", "HR_WEBHOOK_SECRET", hr_webhook_secret)
    print(json.dumps({"hrIntakeEnv": "created" if created else "present"}))


def ssf():
    from generate_local import LOCAL, ssf_signing_key

    key = LOCAL / "ssf" / "signing.pem"
    key_created = not key.exists()
    if key_created:
        key.parent.mkdir(parents=True, exist_ok=True)
        with key.open("x", encoding="utf-8", newline="\n") as target:
            target.write(ssf_signing_key())
    _, token_created = ensure_secret(
        LOCAL / "ssf-receiver.env", "SSF_RECEIVER_TOKEN", lambda: secrets.token_urlsafe(36)
    )
    _, atlas_created = ensure_secret(
        LOCAL / "atlas-signals.env", "ATLAS_SIGNAL_TOKEN", lambda: secrets.token_urlsafe(36)
    )
    print(
        json.dumps(
            {
                "ssfSigningKey": "created" if key_created else "present",
                "ssfReceiverToken": "created" if token_created else "present",
                "atlasSignalToken": "created" if atlas_created else "present",
            }
        )
    )


def realm():
    import httpx

    from integrations.transport import client

    admin_id = os.environ["UPGRADE_CLIENT_ID"]
    credentials = {
        "grant_type": "client_credentials",
        "client_id": admin_id,
        "client_secret": os.environ["UPGRADE_CLIENT_SECRET"],
    }
    clients = lab_clients(
        read_env("/run/atlas.env")["ATLAS_CLIENT_SECRET"],
        read_env("/run/keycloak-events.env")["EVENTS_CLIENT_SECRET"],
    )
    result = {"created": [], "present": [], "updated": [], "temporaryAdminRemoved": False}
    with client(timeout=15) as public:
        response = public.post(TOKEN_URL, data=credentials)
        if response.status_code != 200:
            raise SystemExit("Temporary admin token was refused; nothing was changed.")
        admin = httpx.Client(
            base_url=ADMIN_URL,
            headers={"Authorization": "Bearer " + response.json()["access_token"]},
            timeout=15,
            trust_env=False,
            follow_redirects=False,
        )

        def require(response, *statuses):
            if response.status_code not in statuses:
                raise RuntimeError(f"Admin API returned HTTP {response.status_code}")
            return response

        def ensure(app):
            path = f"/{REALM}/clients"
            found = require(admin.get(path, params={"clientId": app["clientId"]}), 200).json()
            if not found:
                require(admin.post(path, json=app), 201)
                found = require(admin.get(path, params={"clientId": app["clientId"]}), 200).json()
                if not found:
                    raise RuntimeError("Created client is not readable")
                result["created"].append(app["clientId"])
                return found[0]["id"]
            # Existing lab client: add only what its definition gained since.
            base = f"{path}/{found[0]['id']}"
            mappers = {
                item["name"]
                for item in require(admin.get(base + "/protocol-mappers/models"), 200).json()
            }
            for item in app.get("protocolMappers", []):
                if item["name"] not in mappers:
                    require(admin.post(base + "/protocol-mappers/models", json=item), 201)
                    result["updated"].append(app["clientId"] + " mapper " + item["name"])
            scopes = None
            for kind in ("default", "optional"):
                linked = {
                    item["name"]
                    for item in require(admin.get(f"{base}/{kind}-client-scopes"), 200).json()
                }
                for name in app.get(kind + "ClientScopes", []):
                    if name in linked:
                        continue
                    scopes = scopes or require(admin.get(f"/{REALM}/client-scopes"), 200).json()
                    scope = next(item for item in scopes if item["name"] == name)
                    require(admin.put(f"{base}/{kind}-client-scopes/{scope['id']}"), 204)
                    result["updated"].append(app["clientId"] + f" {kind} scope {name}")
            result["present"].append(app["clientId"])
            return found[0]["id"]

        def grant_view_events(client_id):
            # The events reader's service account holds view-events and nothing
            # else, and the client may carry only that role in its tokens.
            user = require(
                admin.get(f"/{REALM}/clients/{client_id}/service-account-user"), 200
            ).json()
            management = require(
                admin.get(f"/{REALM}/clients", params={"clientId": "realm-management"}), 200
            ).json()[0]["id"]
            role = require(
                admin.get(f"/{REALM}/clients/{management}/roles/view-events"), 200
            ).json()
            for label, path in (
                ("role", f"/{REALM}/users/{user['id']}/role-mappings/clients/{management}"),
                ("scope", f"/{REALM}/clients/{client_id}/scope-mappings/clients/{management}"),
            ):
                held = {item["name"] for item in require(admin.get(path), 200).json()}
                if "view-events" not in held:
                    require(admin.post(path, json=[role]), 204)
                    result["updated"].append(f"accessops-events {label} view-events")

        try:
            for app in clients:
                client_id = ensure(app)
                if app["clientId"] == "accessops-events":
                    grant_view_events(client_id)
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
            print(json.dumps(result))
    if not result["temporaryAdminRemoved"]:
        raise SystemExit(f"Temporary admin client {admin_id} may remain; delete it.")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    commands = {"local": local, "realm": realm, "hr": hr, "ssf": ssf}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise SystemExit("usage: upgrade_lab.py local|realm|hr|ssf")
    commands[sys.argv[1]]()
