"""One-time, non-destructive upgrade of an existing lab for session revocation.

local  (host)       Create .local/atlas.env and write the current Atlas client
                    definitions into the stored workforce realm import. Never
                    prints secrets.
realm  (container)  Using a temporary bootstrap admin service account, create the
                    Atlas clients in the running workforce realm, or add any
                    protocol mapper or client scope they lack, then delete that
                    temporary account and prove its credential fails. Only the two
                    Atlas lab clients are touched; other clients, users and
                    sessions are not.

hr     (host)       Create .local/hr-intake.env with an HR webhook signing secret
                    if it is missing. Start-Lab.ps1 runs it on every start.

scripts/Upgrade-Lab.ps1 runs local and realm with a database backup first.
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


def local():
    from generate_local import LOCAL, workforce_apps

    env = LOCAL / "atlas.env"
    created = not env.exists()
    if created:
        with env.open("x", encoding="utf-8", newline="\n") as target:
            target.write("ATLAS_CLIENT_SECRET=" + secrets.token_urlsafe(36) + "\n")
    secret = read_env(env).get("ATLAS_CLIENT_SECRET", "")
    if len(secret) < 32:
        raise SystemExit("atlas.env exists but has no usable client secret.")
    realm_file = LOCAL / "realms" / (REALM + "-realm.json")
    data = json.loads(realm_file.read_text(encoding="utf-8"))
    apps = workforce_apps(secret)
    names = {app["clientId"] for app in apps}
    others = [item for item in data.get("clients", []) if item.get("clientId") not in names]
    if others + apps != data.get("clients"):
        data["clients"] = others + apps
        staged = realm_file.with_suffix(".json.upgrade")
        staged.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(staged, realm_file)
    print(
        json.dumps(
            {
                "atlasEnv": "created" if created else "present",
                "realmImportAtlasClients": sorted(names),
            }
        )
    )


def hr():
    from generate_local import LOCAL, hr_webhook_secret

    env = LOCAL / "hr-intake.env"
    if env.exists():
        print(json.dumps({"hrIntakeEnv": "present"}))
        return
    with env.open("x", encoding="utf-8", newline="\n") as target:
        target.write("HR_WEBHOOK_SECRET=" + hr_webhook_secret() + "\n")
    print(json.dumps({"hrIntakeEnv": "created"}))


def realm():
    import httpx
    from generate_local import workforce_apps

    from integrations.transport import client

    admin_id = os.environ["UPGRADE_CLIENT_ID"]
    credentials = {
        "grant_type": "client_credentials",
        "client_id": admin_id,
        "client_secret": os.environ["UPGRADE_CLIENT_SECRET"],
    }
    atlas_secret = read_env("/run/atlas.env")["ATLAS_CLIENT_SECRET"]
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
                if not require(admin.get(path, params={"clientId": app["clientId"]}), 200).json():
                    raise RuntimeError("Created client is not readable")
                result["created"].append(app["clientId"])
                return
            # Existing Atlas client: add only what its definition gained since.
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

        try:
            for app in workforce_apps(atlas_secret):
                ensure(app)
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
    commands = {"local": local, "realm": realm, "hr": hr}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise SystemExit("usage: upgrade_lab.py local|realm|hr")
    commands[sys.argv[1]]()
