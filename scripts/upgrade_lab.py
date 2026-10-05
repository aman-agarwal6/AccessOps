"""One-time, non-destructive upgrades of an existing lab. Never prints secrets.

local  (host)       Create missing Atlas and events-reader client secrets and
                    write the current lab-added client definitions into the
                    stored workforce realm import.
mfa    (host)       Add a one-time-code secret for each lab operator to
                    .local/operator-logins.json, keeping existing ones, and write
                    operator MFA into the stored operators realm import.
realm  (container)  Using a temporary bootstrap admin service account, create the
                    lab-added clients in the running workforce realm, or add any
                    protocol mapper, client scope or role they lack; in the
                    operators realm, add the MFA sign-in flow, the console's
                    required level and each operator's authenticator. Then delete
                    that temporary account and prove its credential fails. Other
                    clients, users and sessions are not touched.
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
from urllib.parse import quote

REALM = "accessops-workforce"
OPERATORS_REALM = "accessops-operators"


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


def mfa():
    from generate_local import LOCAL, OPERATORS, add_operator_mfa, totp_secret

    logins_file = LOCAL / "operator-logins.json"
    logins = json.loads(logins_file.read_text(encoding="utf-8"))
    totp = logins.setdefault("totp", {})
    created = [name for name in OPERATORS if not totp.get(name)]
    for name in created:
        totp[name] = totp_secret()
    if created:
        staged = logins_file.with_suffix(".json.upgrade")
        staged.write_text(json.dumps(logins, indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(staged, logins_file)
    realm_file = LOCAL / "realms" / (OPERATORS_REALM + "-realm.json")
    data = json.loads(realm_file.read_text(encoding="utf-8"))
    updated = add_operator_mfa(json.loads(json.dumps(data)), totp)
    if updated != data:
        staged = realm_file.with_suffix(".json.upgrade")
        staged.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(staged, realm_file)
    print(json.dumps({"authenticatorsCreated": created, "operatorsRealmImport": "current"}))


def operator_mfa(admin, require, result):
    """Operators realm: MFA flow, required level, and each operator's authenticator."""
    from generate_local import (
        CONSOLE_ACR_ATTRIBUTES,
        OPERATOR_ACR_MAP,
        OPERATOR_FLOW,
        OPERATOR_MFA_REALM,
        OTP_LABEL,
        console_acr_mapper,
        operator_flows,
        otp_credential,
    )

    base = f"/{OPERATORS_REALM}"
    flows, configs = operator_flows()
    by_alias = {item["alias"]: item for item in flows}
    configs = {item["alias"]: item for item in configs}
    present = {
        item["alias"]: item["id"]
        for item in require(admin.get(base + "/authentication/flows"), 200).json()
    }
    bound = require(admin.get(base), 200).json().get("browserFlow")

    def build(alias):
        # Executions are appended in order; each new one is the last at level 0.
        for item in by_alias[alias]["authenticationExecutions"]:
            path = f"{base}/authentication/flows/{quote(alias)}/executions"
            if item["autheticatorFlow"]:
                child = by_alias[item["flowAlias"]]
                body = {
                    "alias": child["alias"],
                    "description": child["description"],
                    "type": "basic-flow",
                    "provider": "registration-page-form",
                }
                require(admin.post(path + "/flow", json=body), 201)
            else:
                require(
                    admin.post(path + "/execution", json={"provider": item["authenticator"]}), 201
                )
            added = [e for e in require(admin.get(path), 200).json() if e["level"] == 0][-1]
            added["requirement"] = item["requirement"]
            require(admin.put(path, json=added), 202, 204)
            if item.get("authenticatorConfig"):
                require(
                    admin.post(
                        f"{base}/authentication/executions/{added['id']}/config",
                        json=configs[item["authenticatorConfig"]],
                    ),
                    201,
                )
            if item["autheticatorFlow"]:
                build(item["flowAlias"])

    if OPERATOR_FLOW in present and bound != OPERATOR_FLOW:
        # A flow left by an interrupted upgrade is rebuilt rather than trusted.
        require(admin.delete(f"{base}/authentication/flows/{present.pop(OPERATOR_FLOW)}"), 204)
    if OPERATOR_FLOW not in present:
        top = by_alias[OPERATOR_FLOW]
        require(
            admin.post(
                base + "/authentication/flows",
                json={
                    key: top[key]
                    for key in ("alias", "description", "providerId", "topLevel", "builtIn")
                },
            ),
            201,
        )
        build(OPERATOR_FLOW)
        result["updated"].append("operators flow " + OPERATOR_FLOW)
    realm = require(admin.get(base), 200).json()
    attributes = {**realm.get("attributes", {}), "acr.loa.map": OPERATOR_ACR_MAP}
    if any(realm.get(key) != value for key, value in OPERATOR_MFA_REALM.items()) or (
        realm.get("attributes", {}).get("acr.loa.map") != OPERATOR_ACR_MAP
    ):
        require(admin.put(base, json={**OPERATOR_MFA_REALM, "attributes": attributes}), 204)
        result["updated"].append("operators realm MFA settings")

    console = require(admin.get(base + "/clients", params={"clientId": "accessops-console"}), 200)
    console = console.json()[0]
    if any(console["attributes"].get(k) != v for k, v in CONSOLE_ACR_ATTRIBUTES.items()):
        console["attributes"].update(CONSOLE_ACR_ATTRIBUTES)
        require(admin.put(f"{base}/clients/{console['id']}", json=console), 204)
        result["updated"].append("accessops-console required level")
    mappers = require(admin.get(f"{base}/clients/{console['id']}/protocol-mappers/models"), 200)
    if not any(item["name"] == "acr loa level" for item in mappers.json()):
        require(
            admin.post(
                f"{base}/clients/{console['id']}/protocol-mappers/models", json=console_acr_mapper()
            ),
            201,
        )
        result["updated"].append("accessops-console mapper acr loa level")

    totp = json.loads(Path("/run/operator-logins.json").read_text(encoding="utf-8"))["totp"]
    for name, secret in sorted(totp.items()):
        found = require(
            admin.get(base + "/users", params={"username": name, "exact": "true"}), 200
        ).json()
        if len(found) != 1:
            raise RuntimeError("Operator account not found")
        user = f"{base}/users/{found[0]['id']}"
        held = require(admin.get(user + "/credentials"), 200).json()
        if any(item["type"] == "otp" and item.get("userLabel") == OTP_LABEL for item in held):
            continue
        for item in held:
            if item["type"] == "otp":  # An authenticator this lab did not issue.
                require(admin.delete(f"{user}/credentials/{item['id']}"), 204)
        current = require(admin.get(user), 200).json()
        require(admin.put(user, json={**current, "credentials": [otp_credential(secret)]}), 204)
        held = require(admin.get(user + "/credentials"), 200).json()
        if not any(item["type"] == "otp" for item in held):
            raise RuntimeError("Operator authenticator was not stored")
        result["updated"].append("operator authenticator " + name)


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
    from lab_admin import require, temporary_admin

    clients = lab_clients(
        read_env("/run/atlas.env")["ATLAS_CLIENT_SECRET"],
        read_env("/run/keycloak-events.env")["EVENTS_CLIENT_SECRET"],
    )
    result = {"created": [], "present": [], "updated": []}

    def apply(admin):
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

        for app in clients:
            client_id = ensure(app)
            if app["clientId"] == "accessops-events":
                grant_view_events(client_id)
        operator_mfa(admin, require, result)

    try:
        with temporary_admin(result) as admin:
            apply(admin)
    finally:
        print(json.dumps(result))
    if not result["temporaryAdminRemoved"]:
        raise SystemExit("The temporary admin client may remain; delete it.")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    commands = {"local": local, "realm": realm, "mfa": mfa, "hr": hr, "ssf": ssf}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise SystemExit("usage: upgrade_lab.py local|realm|mfa|hr|ssf")
    commands[sys.argv[1]]()
