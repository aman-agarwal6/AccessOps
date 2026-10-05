# Connected local lab

The optional [directory departure case](../docs/directory-lab.md) adds the bundled
free Samba lab through an explicit private-network override. Base cases continue
to work without that directory enrollment.

SCIM group observations validate the exact group/schema and `accessops-` namespace.
Native Keycloak can omit requested `members` on empty groups. Such omission needs
a separate read-only workforce group-members observation through container-only
verified TLS `keycloak-observe.accessops.internal:8184`; it never becomes absence
by default. The proxy permits only GET for the fixed workforce UUID-group members
path, with no host port or public admin route. The existing workforce credential
keeps its whole-realm permissions; no new permission is added. One native response
requests `first=0,max=501`; a result above 500, malformed/duplicate IDs, denial,
redirect or incomplete observation stays unknown. This profile relies on the
[pinned native endpoint's max contract](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/services/resources/admin/GroupResource.java),
not unstable offset pages. Only the exact membership Boolean is retained; it
does not establish general SCIM conformance, federation completeness, or a service
account's disabled state. Native `/Users` service-account visibility remains a
separate limitation. Positive and negative readings and proxy denials are checked
in the real case script.

Run these commands from the repository root in PowerShell. This reference uses
synthetic data, Docker Engine with Compose, Python 3.13, and a loopback HTTPS
front door. The tested workstation used Windows, WSL2, and Docker Desktop with
about 16 GB or more host RAM. No model API, cloud database, or paid identity
service is required by the application.

## First start

Inspect `compose.yml`, the Dockerfiles, and the scripts before running them.
Create the local bootstrap environment using the hashed runtime lockfile:

```powershell
py -3.13 -m venv backend/.venv
& ./backend/.venv/Scripts/python.exe -m pip install --only-binary=:all: --require-hashes -r backend/requirements.lock
./scripts/Start-Lab.ps1
```

The start script creates unique credentials and an executor signing key under
ignored `.local/`, restricts its Windows permissions, builds the application
images, creates the local Caddy CA, migrates the isolated application database,
and seeds the fictional organization. Existing credentials and lifecycle state
are preserved. If generation stops partway through, inspect the ignored local
files before retrying; do not overwrite a working database's credentials.

Only `127.0.0.1:8443` is published. Application and identity databases are
different services and volumes with different credentials. Backend, worker,
policy adapter, and Keycloak administration have no host ports. The operator
realm authenticates console users; native SCIM provisioning targets only the
workforce realm. The executor has no SCIM administration role. Its independent
`private_key_jwt` client receives an `accessops-api` audience. A separate,
role-free confidential API client authenticates introspection using its own
client secret.

## Verify without changing the operating system

The checks below use the exported public CA certificate with verification
enabled. Containers resolve the lab names on their private Compose networks.
The host check routes only to loopback while preserving the configured TLS
hostname and SNI. No hosts-file or OS-trust changes are required:

```powershell
./scripts/Test-Lab.ps1
./scripts/Test-FailurePaths.ps1
& ./backend/.venv/Scripts/python.exe scripts/host_health.py --report output/connected/host-health.json --junit output/connected/host-health.xml
& ./backend/.venv/Scripts/python.exe scripts/record_runtime.py --output output/connected/runtime-source.json
```

Run the outage script only when no other lab scenario is in progress. It stops
OPA and Keycloak one at a time and restores each dependency in `finally`, even
when the probe fails. If restoration fails, the script stops with an error;
restore that named service before using the lab. The final host check confirms
the front door after the outage probes.

`Test-Lab.ps1` writes sanitized JSON and JUnit files under `output/connected/`:

| Files | Actual scope |
| --- | --- |
| `policy.*` | Local Rego tests using the pinned OPA image with no network |
| `protocols.*` | Real native SCIM discovery, user/group changes, private-key client authentication, introspection, realm boundaries, AuthZEN and OPA |
| `oidc-business.*` | Real HTTP authorization code + PKCE logins, independent grant approval, protected resource access, immediate revoke/replay denial, SCIM observation and local logout |
| `offboarding.*` | Authenticated inventory registration, unique human/agent provider bindings, live drift without adopting access, independently approved grant, local offboarding and SCIM `active=false` observation |
| `cases.*` | Real authenticated case creation/import/containment, native SCIM disabled-account observation, synthetic cloud snapshots and owner scope exclusions, independent administrative closure and immutable packet |
| `host-health.*` | Host loopback HTTPS, exact operator issuer, hidden administration route and rejection of an unconfigured TLS server name |
| `policy-outage.*`, `identity-outage.*` | Live policy denial and new token issuance failure while the respective dependency is stopped |

Reports retain failures, real UTC timestamps, explicit limitations, and hashes
of the check code actually loaded. The test scripts are mounted read-only in
one-shot containers; their reports are the only writable host output mount.
The source revision is `unrecorded` unless a real build revision was explicitly
injected. These reports are local measurements, not signed provenance or a
protocol certification. They omit passwords, tokens, login parameters, raw
responses, stack traces, and exception messages.

The case check enrolls another unique fictional worker and suspended inventory
agent, grants that worker access through independent approval, and contains it
through the departure case API. Its Entra/GitHub snapshots are explicitly
synthetic, and external owner statements record fictional scope exclusions.
Successful administrative case closure measures the persisted review workflow;
it does not claim real cloud revocation. Session and credential gaps remain
explicit in the packet. See [enterprise snapshots](../docs/platform-connectors.md)
for the credential-free fixtures and optional read-only tenant collector.

`runtime-source.json` records service states, published addresses, actual image
IDs and SHA-256 hashes read from the running backend image. It compares those
Python sources with the host checkout and fails when they differ. It does not
invent a commit for an uncommitted initial project or attest the image's origin.

The OIDC grant/revoke check uses seeded Clara/Atlas and requires it to have no
active grant at the start. It returns the grant to revoked and preserves request
and audit history. The offboarding check registers new, uniquely named synthetic
fixtures instead of offboarding seeded users. Those records are retained as an
offboarded human and suspended sponsored inventory agent with no active grants;
their provider accounts remain disabled. Inventory registration gives the agent
no machine credential, so this check does not demonstrate revocation of a
running agent token. The suite does not create another privileged operator
login, measure an old offboarded operator session, trigger provider backchannel
logout, or rotate the live realm signing key. Boundary tests cover additional
denials using isolated test inputs. The real-browser check below is separate.

Native SCIM does not expose the configured executor service account as a `Users`
resource. Reconciliation must record that observation as unavailable, retain
known drift findings for other identities, and report the incomplete inventory
as failed. It cannot label the whole directory clean or adopt unbacked access.
The connected drift check expects a failed reconciliation when its deliberate
unbacked membership is detected, then removes only that fixture membership.

## Optional browser setup

Normal browser sign-in uses `https://accessops.test:8443` and
`https://id.accessops.test:8443`. DNS and certificate trust are separate,
explicit workstation choices:

```powershell
# Run only after choosing to add the two loopback hostnames; needs elevation.
./scripts/Configure-Hosts.ps1
# Run only after reviewing the exported CA; affects CurrentUser trust only.
./scripts/Start-Lab.ps1 -SkipBuild -TrustLocalCA
```

Neither optional action runs during protocol or host health checks. Never
disable certificate verification to make the browser or tests connect. Windows
curl's Schannel behavior can differ from Python/OpenSSL for a locally generated
CA; use the verified host check for repeatable automated measurement.

The fictional usernames are `alice` (operator), `bob` (independent approver), and
`clara` (resource owner/auditor). Open `.local/operator-logins.json` locally in an
editor when a password is needed. Do not paste it into chat, commands, reports,
source control, screenshots, or a public artifact. The live tests mount that file
read-only only into their one-shot test container; application services do not
mount operator passwords.

## Real-browser check of the console

With the lab running and `npm ci --ignore-scripts` done in `frontend`, this
drives the connected console in Firefox through a whole departure case:
Keycloak sign-in as `alice`, register a new synthetic employee, wait for real
provisioning, open a case, contain, wait for the provider observations, record
owner statements, confirm the owner cannot close, then sign in as `bob` in a
separate browser profile, close and export the packet. axe runs on the live
pages.

```powershell
docker compose -f infra/compose.yml -f infra/compose.browser.yml run --rm browser-tests
```

It needs no host changes. The pinned Playwright image joins the lab's existing
internal networks, so the lab hostnames resolve inside Docker and no new network
is created. A Firefox enterprise policy adds only the lab CA
(`.local/tls/root.crt`) to the browser's trust, so chain and hostname
verification stay on. Status polls run as same-origin fetches inside the page,
so a failed poll does not echo session or CSRF headers into the report; traces
stay in the container's temporary memory and are discarded. The container runs
as a non-root user with a read-only root filesystem, no capabilities and
memory/process limits. Each run registers a new uniquely named worker; before
starting, it contains any worker an interrupted earlier run left active. The
JUnit report and two screenshots go to `output/connected/` (`console-live.xml`,
`console-live-case.png`, `console-live-closed.png`).

## Restart, update, and stop

```powershell
./scripts/Start-Lab.ps1 -SkipBuild
./scripts/Stop-Lab.ps1
```

Stopping preserves the database and local secrets. Re-run `Start-Lab.ps1` after
source or dependency changes to rebuild images. It deterministically builds
the exact policy bundle, records its SHA-256 in the runtime configuration, and
reloads the policy services. The backend fails closed if the configured bundle
digest does not match the decision response. Realm import is first-run setup;
changing an import file does not update a realm already stored in Keycloak's
database. Review and apply realm changes separately with a scoped migration.

Base image digests live in `images.lock.json` and the Dockerfiles/Compose file;
Python and JavaScript dependencies have separate lockfiles. Review upgrades
deliberately, rebuild, rerun the affected denial paths, and collect new reports.
Do not use broad automatic fixes, change sibling project services, expose debug
ports, delete volumes to troubleshoot, or reuse this synthetic setup with
production records. Database backup and secret/key rotation are separate
operator tasks; this local reference does not automate them.
