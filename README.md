# AccessOps

**Disabling a leaver's account doesn't end their access. AccessOps does, and proves it.**

When an employee or contractor leaves, their sessions, tokens, group rights and
Kerberos tickets can outlive the disabled account. AccessOps starts from a
signed HR event: it opens a departure case, ends access in Keycloak, Microsoft
Entra ID and an Active Directory-compatible directory, suspends the automated
agents the person sponsors, and reads every system back before the work counts.
What it can't reach (GitHub, shared credentials, Microsoft 365 handover and
legacy apps) stays open as owned work with a four-hour target. The case closes
only when someone other than its owner accepts the exact evidence packet.

[Live demo](https://aman-agarwal6.github.io/AccessOps/) ·
[Case study](https://aman-agarwal6.github.io/projects/accessops.html) ·
[Verification ledger](docs/verification.md) ·
[The departure problem](docs/enterprise-application.md) ·
[Releases](https://github.com/aman-agarwal6/AccessOps/releases)

![A departure case: next step, required actions grouped by phase, and the evidence source of each action](docs/assets/offboarding.png)

## What it shows

Measured with synthetic people on a local lab with real Keycloak 26.8, OPA,
PostgreSQL and a Samba directory, and in a free Microsoft Entra test tenant:

- **A signed HR event ends access in 2.6 seconds.** The case opens, the account
  is disabled, every Keycloak session ends, the person is signed out of an app,
  and that app refuses their still-unexpired access token.
- **Microsoft Entra is contained for real**: the account disabled, its group
  removed and its sign-in sessions revoked through Microsoft Graph, then read
  back before the case counts it.
- **Disabled is not done.** Live before-and-after checks found six gaps that
  disabling an account leaves open or key handling exposes. Each one is fixed
  or stated on the case (below).
- **Access after departure is caught.** A sign-in after the departure is
  detected 32 seconds after it happened, blocks closure, and reaches the SOC
  as a signed Shared Signals event that
  [SignalBridge](https://github.com/aman-agarwal6/signalbridge) turns into a case.
- **The people who can disable anyone need a second factor**, enforced by the
  identity provider and again by the backend, including against a request
  rewritten to ask for less.
- **Key rotation and a leaked signing key are rehearsed live**, in both realms.
- **The directory's limits are measured, not assumed.** Kerberos tickets issued
  before offboarding keep working for up to 10 hours, and the case says so.

## What the live runs caught

Each of these was found by a check that failed against the live services, and
each failed run stays on the demo's evidence page beside the fix.

| What survived | Measured before the fix | Now |
| --- | --- | --- |
| Group membership | Disabling the account left a managed group membership behind | Offboarding removes every known managed grant and needs a fresh negative reading for each |
| Signed-in sessions | New tokens stopped, but the person stayed signed in to the app and Keycloak kept the session | Containment ends Keycloak sessions and sends back-channel logout; it counts as done only when no session is left |
| Tokens an app checks itself | The app kept accepting the leaver's token for two more minutes | Each app gets its own stream of signed revocation events; the lab app refuses the token 3 seconds after containment |
| A leaked signing key | Keycloak's own introspection accepted a token forged with the published key; apps trusted a removed key for five minutes | Removing a leaked key is the only remedy, so apps drop removed keys within 60 seconds |
| Key rotation | Switching to a new signing key at once made the app refuse valid tokens for 30 seconds | Rotation publishes the new key first and waits one key-cache lifetime; no valid token is refused |
| Kerberos tickets | Connections and tickets from before offboarding kept the removed group's rights | Kerberos has no per-user revocation; new tickets are refused and the case states when the old ones expire |

## Try it

The demo runs entirely in your browser with synthetic data. No sign-in, live
identities or external calls.

1. Open **Mara's departure** from the overview.
2. **Apply local containment.** Grants are revoked and her sponsored agent is
   suspended.
3. **Import the after-departure report.** Entra sign-in clears as an imported
   snapshot; GitHub stays unresolved because absence from a list is not proof.
4. **Record owner statements** for the remaining external work.
5. **Act as Avery** (an independent reviewer), close the case and export the
   frozen packet.

The queue also holds an overdue contractor, a scheduled departure and a closed
historical case. Switch roles from the top bar to see each boundary explained.

## What is real and what is simulated

Every action carries one of these labels, and a label never upgrades itself.

| Evidence | Meaning |
| --- | --- |
| Signed CI evidence | Release bytes bound to the public workflow and source commit by a Sigstore attestation |
| Provider observation | Read back from the lab's real Keycloak or Samba directory after the change |
| Imported snapshot | A bounded report someone supplied; point-in-time and untrusted |
| Owner attestation | A written statement by the case owner, reviewed at closure, never treated as proof |
| Simulated | Produced by the browser demo; nothing outside the tab was contacted |

## Verified results

Local lab runs on 5 October 2026 with synthetic records, on the current backend
source. Details, every failed attempt and the limits of each check are in the
[verification ledger](docs/verification.md).

| Check | Result |
| --- | --- |
| Signed HR event → case, containment, sessions ended, app signed out, token refused | 10 / 10 passed: 2.6 s, or 2.3 s after a future-dated departure takes effect |
| Leaver's sessions and tokens before → after containment | 22 / 22 passed: back-channel logout; refresh, offline and introspection rejected; a locally checked token refused 3.0 s after containment |
| Sign-in after departure detected, blocking closure, signalled to the SOC | 7 / 7 passed: detected 32 s after the sign-in |
| Operator sign-in with a second factor | 14 / 14 passed: wrong code and password-only request refused |
| Signing-key rotation and leaked-key drill, both realms | 13 / 13 passed: no token refused during rotation; a forged token refused by Keycloak at once and by the app 60 s after the key's removal |
| Live Microsoft Entra departure (a free test tenant, synthetic users) | 11 / 11 passed: Graph showed the account disabled, out of the group and sessions revoked 19.8 s after containment; the tenant administrator and an unlisted user were refused |
| Departure case end to end through real Keycloak | 18 / 18 passed |
| Departure case with a Samba directory account | 28 / 28 passed; new LDAPS and Kerberos logins allowed → denied (2 / 2 each) |
| Directory sessions and tickets held from before offboarding | 6 / 6 passed: no new service tickets; earlier ones keep working until they expire (10 h) |
| Full lab suite (`Test-Lab.ps1`) | All passed: policy 32, protocols 18, sign-in 14, offboarding 11, cases 18, sessions 22, HR 10, assurance 7, HTTPS 5 |
| Console in real Firefox against the lab | Full departure case passed, with one-time codes |
| Signed [v0.4.0 release](https://github.com/aman-agarwal6/AccessOps/releases/tag/v0.4.0) (GitHub CI) | 401 / 401 backend and integration cases on PostgreSQL 17; provenance and SBOM attestations verified |
| Deployed demo | 17 / 17 checks passed |

## How it is built

- **Console:** React, TypeScript and Vite, with Radix dialogs. Dark and light
  themes from one token set, a 16px type scale, keyboard-first navigation.
- **Backend:** Django and PostgreSQL. Server sessions with OIDC code flow and
  PKCE; no tokens in the browser. CSRF on every mutation.
- **Identity and policy:** Keycloak keeps operator login (with a second factor)
  separate from workforce provisioning (SCIM). Every action is checked by OPA
  through an AuthZEN request, and policy failure denies.
- **Execution:** a durable outbox applies remote changes, reads before retrying
  and records actual observation times.
- **Signals:** a Shared Signals transmitter (SSF 1.0, CAEP, RISC) with a
  separate poll stream (RFC 8936) per receiver: the SOC, and apps that check
  tokens themselves.
- **Directory:** LDAPS with verified TLS, immutable GUID targets, atomic account
  flag updates and permissions limited to the exact fixture objects.
- **Microsoft Entra:** Microsoft Graph with certificate client credentials; the
  connector acts only on listed test objects and refuses administrators.
- **Standards:** OIDC with PKCE, SCIM 2.0, OIDC Back-Channel Logout, Shared
  Signals (SSF 1.0, CAEP, RISC), Standard Webhooks and the AuthZEN API. The
  [control map](docs/control-map.md) ties controls to NIST SP 800-53 (AC-2,
  AC-5, AC-6, IA-2(1), PS-4, AU-6) and to the tests that exercise them; it is
  a mapping, not a compliance claim.

## Security choices

- Independent approval, bound to the exact change and policy version, expiring
  after 15 minutes. Case owners cannot close their own case.
- Operators sign in with a password and a one-time code; the backend refuses any
  session the identity provider did not mark as multi-factor.
- Stale, unknown or partial readings keep work open; a disabled account does
  not stand in for removed group memberships or ended sessions.
- HR events must carry a valid Standard Webhooks signature. The HR feed is its
  own identity that can open and contain departures and nothing else.
- For a day after each departure, AccessOps reads the account's sign-ins. Any
  successful one blocks closure until investigated.
- Accounts are matched by immutable IDs, never by name or email.
- The review assistant can only propose. It cannot approve or apply anything.
- `main` accepts only pull requests that pass tests, CodeQL and dependency
  review; OpenSSF Scorecard rates the repository weekly. Releases are signed
  with build provenance and an SBOM.

## Limits

This is a reference system with synthetic data, not a production deployment.
Microsoft Entra was tested only in a free test tenant with synthetic users; no
GitHub organization or Microsoft 365 service was contacted, and those appear as
offline fixtures and owner statements. Samba results do not prove Microsoft AD
interoperability. An app that checks access tokens itself refuses a leaver's
token early only if it follows AccessOps' revocation signals, as the lab app
does. In the directory, connections and Kerberos tickets from before
containment keep working until they close or expire. Closure is an
administrative record, not proof that every copy or session is gone. See the
[threat model](docs/threat-model.md) and [standards matrix](docs/standards.md).

## Run it

Console only (Node.js 24):

```powershell
cd frontend
npm ci --ignore-scripts
npm run dev
```

The full local lab uses Docker Desktop and PowerShell; follow
[infra/README.md](infra/README.md). The optional
[directory lab](docs/directory-lab.md) adds a real Samba directory without a
Microsoft tenant. Secrets are generated under `.local/` and never committed.

## Documentation

[Case contract](contracts/offboarding.md) ·
[API contract](contracts/README.md) ·
[Leaver signals](contracts/leaver-signals.md) ·
[Platform connectors](docs/platform-connectors.md) ·
[Threat model](docs/threat-model.md) ·
[Control-to-test map](docs/control-map.md) ·
[Standards](docs/standards.md) ·
[Evidence verification](docs/evidence.md) ·
[Maintenance](docs/maintenance.md)

AccessOps was built with AI coding assistance under my direction and review.
Licensed under Apache-2.0. Report security issues as described in
[SECURITY.md](SECURITY.md).
