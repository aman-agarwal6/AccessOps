"""Generate first-run local credentials. Never emits secret values or overwrites.

Run with the backend virtual environment (cryptography is already a dependency).
Files remain under ignored .local; realm imports contain credentials intentionally.
"""

import base64
import datetime as dt
import hashlib
import json
import os
import secrets
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
ID_ORIGIN = "https://id.accessops.test:8443"
APP_ORIGIN = "https://accessops.test:8443"


def uid(slug):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, "accessops:" + slug))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as target:
        target.write(value)
    if os.name != "nt":
        path.chmod(0o600)


def env_file(name, values):
    write(LOCAL / name, "".join(f"{key}={value}\n" for key, value in values.items()))


def mapper(name, provider, config):
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": provider,
        "consentRequired": False,
        "config": config,
    }


def audience(value):
    return mapper(
        "accessops-audience",
        "oidc-audience-mapper",
        {
            "included.custom.audience": value,
            "access.token.claim": "true",
            "id.token.claim": "false",
        },
    )


def base_client(name):
    return {
        "clientId": name,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "fullScopeAllowed": False,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "serviceAccountsEnabled": True,
        "defaultClientScopes": [],
        "optionalClientScopes": [],
        "attributes": {"oauth2.device.authorization.grant.enabled": "false"},
    }


def realm(name):
    return {
        "realm": name,
        "enabled": True,
        "sslRequired": "all",
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "editUsernameAllowed": False,
        "loginWithEmailAllowed": False,
        "bruteForceProtected": True,
        "failureFactor": 5,
        "waitIncrementSeconds": 60,
        "accessTokenLifespan": 120,
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 3600,
        "revokeRefreshToken": True,
        "refreshTokenMaxReuse": 0,
        "defaultSignatureAlgorithm": "RS256",
        "eventsEnabled": True,
        "eventsExpiration": 86400,
        "adminEventsEnabled": True,
        "adminEventsDetailsEnabled": False,
        "attributes": {},
    }


def main():
    if (LOCAL / "backend.env").exists():
        raise SystemExit("Local configuration already exists; no credentials were changed.")
    if not (ROOT / "AGENTS.md").is_file():
        raise SystemExit("Wrong repository")
    for subdir in ("tls", "executor", "realms", "docker"):
        (LOCAL / subdir).mkdir(parents=True, exist_ok=True)

    def secret():
        return secrets.token_urlsafe(36)

    app_pass, id_pass, oidc_secret, scim_secret, authzen_token, api_secret = [
        secret() for _ in range(6)
    ]
    operator_passwords = {name: secret() for name in ("alice", "bob", "clara")}
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "accessops-executor")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(private, hashes.SHA256())
    )
    write(
        LOCAL / "executor/private.pem",
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )
    certificate = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_id = (
        base64.urlsafe_b64encode(
            hashlib.sha256(
                private.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    write(LOCAL / "executor/public.crt", certificate)
    env_file(
        "app-db.env",
        {
            "POSTGRES_USER": "app_bootstrap",
            "POSTGRES_PASSWORD": secret(),
            "APP_DB_USER": "accessops_app",
            "APP_DB_PASSWORD": app_pass,
            "APP_DB_NAME": "accessops_app",
        },
    )
    env_file(
        "identity-db.env",
        {
            "POSTGRES_USER": "identity_bootstrap",
            "POSTGRES_PASSWORD": secret(),
            "APP_DB_USER": "accessops_identity",
            "APP_DB_PASSWORD": id_pass,
            "APP_DB_NAME": "accessops_identity",
        },
    )
    env_file("keycloak.env", {"KC_DB_USERNAME": "accessops_identity", "KC_DB_PASSWORD": id_pass})
    env_file("policy.env", {"AUTHZEN_TOKEN": authzen_token})
    env_file(
        "backend.env",
        {
            "DJANGO_SECRET_KEY": secret(),
            "DJANGO_ALLOWED_HOSTS": "accessops.test,backend,127.0.0.1",
            "DATABASE_URL": f"postgresql://accessops_app:{app_pass}@app-db:5432/accessops_app",
            "CSRF_TRUSTED_ORIGINS": APP_ORIGIN,
            "OIDC_ISSUER": ID_ORIGIN + "/realms/accessops-operators",
            "OIDC_CLIENT_ID": "accessops-console",
            "OIDC_CLIENT_SECRET": oidc_secret,
            "OIDC_REDIRECT_URI": APP_ORIGIN + "/auth/callback",
            "OIDC_POST_LOGOUT_URI": APP_ORIGIN + "/",
            "WORKFORCE_ISSUER": ID_ORIGIN + "/realms/accessops-workforce",
            "EXECUTOR_CLIENT_ID": "accessops-executor",
            "EXECUTOR_PRIVATE_KEY_FILE": "/run/executor/private.pem",
            "EXECUTOR_KEY_ID": key_id,
            "EXECUTOR_SCOPE": "accessops:tools",
            "EXECUTOR_AUDIENCE": "accessops-api",
            "INTROSPECTION_CLIENT_ID": "accessops-api",
            "INTROSPECTION_CLIENT_SECRET": api_secret,
            "SCIM_CLIENT_ID": "accessops-scim",
            "SCIM_CLIENT_SECRET": scim_secret,
            "AUTHZEN_URL": "https://policy.accessops.internal:8183",
            "AUTHZEN_TOKEN": authzen_token,
            "POLICY_VERSION": "accessops-v1",
            "INTERNAL_API_URL": APP_ORIGIN,
            "ACCESSOPS_TRUST_PRIVATE_PROXY": "1",
            "REQUESTS_CA_BUNDLE": "/run/accessops-ca/root.crt",
        },
    )
    operators = realm("accessops-operators")
    console = base_client("accessops-console")
    console.update(
        {
            "secret": oidc_secret,
            "clientAuthenticatorType": "client-secret",
            "standardFlowEnabled": True,
            "serviceAccountsEnabled": False,
            "redirectUris": [APP_ORIGIN + "/auth/callback"],
            "webOrigins": [APP_ORIGIN],
            "defaultClientScopes": ["profile", "email"],
            "attributes": {
                "pkce.code.challenge.method": "S256",
                "post.logout.redirect.uris": APP_ORIGIN + "/",
                "backchannel.logout.url": APP_ORIGIN + "/auth/backchannel-logout",
                "backchannel.logout.session.required": "true",
                "backchannel.logout.revoke.offline.tokens": "true",
            },
            "protocolMappers": [
                mapper(
                    field,
                    "oidc-usermodel-attribute-mapper",
                    {
                        "user.attribute": field,
                        "claim.name": field,
                        "jsonType.label": "String",
                        "multivalued": "true",
                        "id.token.claim": "true",
                        "access.token.claim": "true",
                        "userinfo.token.claim": "true",
                    },
                )
                for field in ("accessops_roles", "accessops_projects")
            ],
        }
    )
    operators["clients"] = [console]
    operators["users"] = []
    roles = {
        "alice": ["operator"],
        "bob": ["operator", "approver"],
        "clara": ["auditor", "approver", "resource_owner"],
    }
    family = {"alice": "Morgan", "bob": "Chen", "clara": "Ellis"}
    for person in roles:
        operators["users"].append(
            {
                "id": uid("operator-" + person),
                "username": person,
                "firstName": person.title(),
                "lastName": family[person],
                "email": person + ".operator@example.invalid",
                "emailVerified": True,
                "enabled": True,
                "attributes": {
                    "accessops_roles": roles[person],
                    "accessops_projects": ["Atlas", "Pulse"],
                },
                "credentials": [
                    {"type": "password", "value": operator_passwords[person], "temporary": False}
                ],
            }
        )
    # User attributes are admin-managed: no account self-service mapper can edit authority.
    operators["components"] = {
        "org.keycloak.userprofile.UserProfileProvider": [
            {
                "providerId": "declarative-user-profile",
                "config": {
                    "kc.user.profile.config": [
                        json.dumps(
                            {
                                "unmanagedAttributePolicy": "ADMIN_EDIT",
                                "attributes": [
                                    {
                                        "name": "username",
                                        "permissions": {
                                            "view": ["admin", "user"],
                                            "edit": ["admin"],
                                        },
                                    },
                                    {
                                        "name": "email",
                                        "permissions": {
                                            "view": ["admin", "user"],
                                            "edit": ["admin"],
                                        },
                                    },
                                    {
                                        "name": "firstName",
                                        "permissions": {
                                            "view": ["admin", "user"],
                                            "edit": ["admin"],
                                        },
                                    },
                                    {
                                        "name": "lastName",
                                        "permissions": {
                                            "view": ["admin", "user"],
                                            "edit": ["admin"],
                                        },
                                    },
                                ],
                            }
                        )
                    ]
                },
            }
        ]
    }
    workforce = realm("accessops-workforce")
    workforce["scimApiEnabled"] = True
    scim = base_client("accessops-scim")
    scim.update(
        {
            "secret": scim_secret,
            "clientAuthenticatorType": "client-secret",
            "protocolMappers": [
                audience(ID_ORIGIN + "/realms/accessops-workforce/scim/v2"),
                mapper(
                    "scim-realm-management-roles",
                    "oidc-usermodel-client-role-mapper",
                    {
                        "usermodel.clientRoleMapping.clientId": "realm-management",
                        "claim.name": "resource_access.realm-management.roles",
                        "jsonType.label": "String",
                        "multivalued": "true",
                        "access.token.claim": "true",
                        "id.token.claim": "false",
                    },
                ),
            ],
        }
    )
    executor = base_client("accessops-executor")
    executor.update(
        {
            "clientAuthenticatorType": "client-jwt",
            "attributes": {
                "jwt.credential.certificate": "".join(certificate.splitlines()[1:-1]),
                "jwt.credential.kid": key_id,
                "token.endpoint.auth.signing.alg": "RS256",
                "access.token.lifespan": "120",
            },
            "defaultClientScopes": ["accessops:tools"],
            "protocolMappers": [audience("accessops-api")],
        }
    )
    workforce["clientScopes"] = [
        {
            "name": "accessops:tools",
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
        }
    ]
    api_client = base_client("accessops-api")
    api_client.update(
        {
            "secret": api_secret,
            "clientAuthenticatorType": "client-secret",
            "serviceAccountsEnabled": False,
        }
    )
    workforce["clients"] = [scim, executor, api_client]
    workforce["clientScopeMappings"] = {
        "realm-management": [{"client": "accessops-scim", "roles": ["manage-users"]}]
    }
    workforce["groups"] = [
        {"id": uid("group:" + name), "name": "accessops-" + name}
        for name in ("atlas-reader", "pulse-reader")
    ]
    workforce["users"] = [
        {
            "id": uid(person + "-" + family[person].lower()),
            "username": person + "." + family[person].lower(),
            "firstName": person.title(),
            "lastName": family[person],
            "email": person + "@example.invalid",
            "emailVerified": True,
            "enabled": True,
            "groups": ["/accessops-atlas-reader"]
            if person == "alice"
            else ["/accessops-pulse-reader"]
            if person == "bob"
            else [],
        }
        for person in family
    ]
    workforce["users"] += [
        {
            "id": uid("review-assistant"),
            "username": "service-account-accessops-executor",
            "enabled": True,
            "serviceAccountClientId": "accessops-executor",
        },
        {
            "id": uid("scim-service"),
            "username": "service-account-accessops-scim",
            "enabled": True,
            "serviceAccountClientId": "accessops-scim",
            "clientRoles": {"realm-management": ["manage-users"]},
        },
    ]
    for data in (operators, workforce):
        write(LOCAL / "realms" / (data["realm"] + "-realm.json"), json.dumps(data, indent=2) + "\n")
    write(
        LOCAL / "operator-logins.json",
        json.dumps({"origin": APP_ORIGIN, "passwords": operator_passwords}, indent=2) + "\n",
    )
    print(
        "Generated ignored local configuration and per-user credentials. No secret values were printed."
    )


if __name__ == "__main__":
    main()
