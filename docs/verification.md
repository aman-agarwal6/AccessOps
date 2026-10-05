# Verification ledger

Every row below records a check that actually ran, with its real count. Failed
attempts are kept, not rewritten. Counts describe separate suites, not unique
requirements. All runs used synthetic records on a personal workstation; no
employer or production identity provider or GitHub organization was contacted;
Microsoft Entra was used only in the lab's own free test tenant with synthetic
users. Local reports are unsigned; signed CI evidence is listed separately.

## v0.4.0: live Microsoft Entra containment (5 October 2026)

### Live Microsoft Entra departure

Local runs on 5 October 2026 (UTC) against the lab's own Entra ID Free test
tenant: two synthetic test users and one group, a single-tenant app registration
signing in with a certificate, and five Graph application permissions granted
by the tenant administrator. On containment, the worker disables the enrolled
test user, removes its group membership and revokes its sign-in sessions, then
reads all three back; the case's Entra task counts only that reading.

| Check | Actual result | Scope |
| --- | --- | --- |
| Live Entra departure (`entra-departure.json`) | 11 passed | The connector signed in with its certificate and read the tenant; the test user was enabled and in the group before; a unique synthetic worker was created and enrolled server-locally; enrolling the tenant administrator and an unlisted user were both refused with nothing changed; from the containment request, the case showed Graph evidence of disable, group removal and session revocation in 19.8 s; a separate Graph read confirmed all three, with sessions revoked after the departure; an owner statement could not replace that evidence; the harness then re-enabled the test user and returned it to the group |
| Worker job | Verified on its first attempt | Queued 18:09:25, sessions revoked 18:09:37, read back 18:09:40 UTC; no retries |
| Test users after the run | Both enabled and in the group, no directory roles | Read through Graph |
| Full `Test-Lab.ps1` on the connector branch | All passed in 5 min 1 s | Policy 32, protocols 18, OIDC 14, offboarding 11, departure cases 18, sessions 22, HR intake 10, leaver assurance 7, host HTTPS 5; migration 0008 applied |
| Signed v0.4.0 release | Passed: provenance, SBOM and published bytes verified | [Release](https://github.com/aman-agarwal6/AccessOps/releases/tag/v0.4.0), [workflow 37359252983](https://github.com/aman-agarwal6/AccessOps/actions/runs/37359252983), exact source `380e42c659ed2505d76fbc3947f9de969e1ababf`, clean tree. 401 backend and integration cases on PostgreSQL 17, none skipped; CycloneDX SBOM of 63 components. Both attestations verified with the pinned repository, signer workflow, `refs/heads/main`, commit and GitHub-hosted runner; all seven published assets match the verified files byte for byte. Three signing attempts were cancelled during GitHub's runner outage, which never assigned them a machine; the fourth signed the same frozen evidence |
| Published simulation | 17 passed | [Pages run 37359258745](https://github.com/aman-agarwal6/AccessOps/actions/runs/37359258745) reran CI before deploying; `tools/check_published.mjs` against the live site |
| Backend and integrations, host test settings | 400 passed, 1 skipped | Includes 13 connector tests against a simulated Graph (scope and administrator refusals before any request, never re-enabling, read-back retries, the certificate assertion, the consent gate) and 16 case tests |

Sign-ins of the test users were not exercised (they have no stored password),
and sign-in logs need Entra ID P1, so access after departure is still watched
in Keycloak only. An access token an app already holds stays valid until it
expires unless the app uses continuous access evaluation.

## v0.3.0: closing what disabling leaves behind (5 October 2026)

This release adds signed HR intake, session and token revocation, monitoring
for access after departure with signed SOC signals, operator MFA, a live
signing-key rotation drill and measurements of directory sessions held from
before offboarding. Each section below records its own runs and retained
failures; the latest results are:

| Suite (latest run, 5 October UTC) | Result |
| --- | --- |
| Full `Test-Lab.ps1` on the rotated keys | Policy 32, protocols 18, OIDC with MFA 14, offboarding 11, departure cases 18, sessions 22, HR intake 10, leaver assurance 7, host HTTPS 5: all passed |
| Signing-key rotation drill | 13 passed |
| Samba directory case, fixture `2a882426c8f1` | Case 28 passed; new logins 2 → 2 denied; held sessions 6 passed |
| Console in a real browser | Passed, with one-time codes |
| Backend and integrations, host test settings | 371 passed, 1 skipped |

The demo's evidence index lists 48 recorded runs: 35 passed and 13 failed
attempts kept beside their fixes.

### CI, deployment and signed release (5 October 2026)

| Check | Actual result | Scope |
| --- | --- | --- |
| GitHub CI on each pull request | All nine required checks passed | PRs #18 to #23; `main` accepts only pull requests that pass Verify (backend, frontend, policy, secrets), dependency review and CodeQL |
| Published simulation | 17 passed | [Pages run 37348348038](https://github.com/aman-agarwal6/AccessOps/actions/runs/37348348038) reran CI before deploying; `tools/check_published.mjs` against the live site; 48 recorded runs served |
| Signed v0.3.0 release | Passed: provenance, SBOM and published bytes verified | [Release](https://github.com/aman-agarwal6/AccessOps/releases/tag/v0.3.0), [workflow 37348343541](https://github.com/aman-agarwal6/AccessOps/actions/runs/37348343541), exact source `d924b4c3762224860ba865526085c50cc8826c79`, clean tree. 372 backend and integration cases on PostgreSQL 17, none skipped; CycloneDX SBOM of 63 components. Both attestations verified with the pinned repository, signer workflow, `refs/heads/main`, commit and GitHub-hosted runner; all seven published assets match the verified files byte for byte |

A secret scan of the release files before publishing flagged 50 lines; every one
was a public source file's SHA-256 digest (the same lines the repository's
scanner allowlists in the evidence index), not a credential.

### Tokens refused by apps that check them locally

Local runs on 5 October 2026 (UTC). The session table below ended with one
gap: an app that verifies tokens itself kept accepting the leaver's access token
until it expired. AccessOps now keeps a separate signal stream per receiver, and
the Atlas lab app follows its own: it polls for CAEP session-revoked and RISC
account-disabled events once a second and refuses any token issued at or before
a revocation of its subject. If it has not read the stream in ten seconds, or a
token predates the app's own start, it asks Keycloak rather than trust the
token. The SOC stream is unchanged.

| Check | Actual result | Scope |
| --- | --- | --- |
| Session revocation before → after | 22 passed | The 19 earlier checks plus Atlas reading its stream, and two new ones: from the containment request, Atlas's local check refused the worker's unexpired token in 3.0 s (114 s of its lifetime left), and the refusal came from the signal, not expiry. The disable-only control still shows local acceptance, because disabling alone sends no signal |
| HR intake | 10 passed | The timed checks now also require the token refusal: 2.6 s from the HR event to case, containment, zero sessions, Atlas sign-out and the existing token refused; 2.3 s after a future departure took effect |
| Leaver assurance | 7 passed | The SOC stream's signals and acknowledgements are unaffected by Atlas's stream |
| Backend and integrations, host test settings | 366 passed, 1 skipped | Includes per-stream audience, event types, polling and acknowledgement isolation, and Atlas's signal rules: real ES256 signatures, wrong audience, issuer or type refused, stale stream or older tokens referred to Keycloak, unreadable keys never reported as invalid events |
| Full `Test-Lab.ps1` | All passed in 3 min 54 s | Policy 32, protocols 18, OIDC 11, offboarding 11, departure cases 18, sessions 22, HR intake 10, leaver assurance 7, host HTTPS 5; the running source matched the checkout across 9 services |

Not run for this change: the Samba directory case and the real-browser journey,
neither of which touches token checks or signal streams.

### Operator sign-in with a second factor

Local runs on 5 October 2026 (UTC). The people who can disable anyone now need a
second factor. Keycloak's operator browser flow asks for a password (level
`password`) and then a time-based one-time code (level `mfa`); the console
client requires `mfa` as its default and minimum level. The backend requests
`mfa`, refuses any ID token whose `acr` is anything else, and records the level
on each session in the audit log. Existing labs get the flow, the client
settings and one authenticator per operator from `Upgrade-Lab.ps1`; new labs get
them in the generated realm import.

| Check | Actual result | Scope |
| --- | --- | --- |
| Upgrade of the running lab | Passed | Flow, required level, `acr` mapper and three authenticators added through a temporary admin, which was then deleted and its credential refused; identity database backed up first |
| OIDC suite | 14 passed | Three new: a correct password stops at the code form; a wrong code is refused with no session; a request rewritten to ask for `password` only still stops at the code form (Keycloak enforced the client's minimum level). The three operator sessions then sign in with real codes |
| Sessions recorded at `mfa` | Passed | The audit log's `session.created` events for those sign-ins carry `acr: mfa` |
| Full `Test-Lab.ps1` | All passed in 5 min 3 s | Every suite signs in with codes; a shared step file means no code is offered twice, so a few sign-ins waited for the next 30-second step |
| Console in a real browser | Passed | The PR #9 journey, with Alice and Bob entering one-time codes in Firefox |
| Fresh-lab realm import | Passed | Realms generated from scratch, with the MFA flow and authenticators, imported by Keycloak 26.8 into a throwaway in-container database; the lab's own database was not used |
| Backend, host test settings | 31 passed in the OIDC and security tests | The login request carries `acr_values=mfa`; ID tokens at `password`, `1` or with no `acr` cannot open a session; the level is audited |

Not run: phishing-resistant authenticators (WebAuthn). The authenticator is a
software TOTP secret held in the lab's protected login file.

### Live signing-key rotation

Local runs on 5 October 2026 (UTC). `Test-KeyRotation.ps1` rotates the RS256
signing key of both realms on the running lab, through a temporary Keycloak
admin that is deleted at the end (the identity database is backed up first).
It covers a planned rotation and a leaked key.

| Check | Actual result | Scope |
| --- | --- | --- |
| Rotation drill (`key-rotation.json`) | 13 passed in 2 min 39 s | New keys published as passive, then a 65 s wait (one key-cache lifetime plus margin), then made the signing keys: Atlas accepted the first token signed by the new key on the first try; the previous key's token stayed valid locally and by introspection while passive; operator sign-in with a one-time code worked; Keycloak's back-channel logout, signed with the new operators key, ended the AccessOps session within 0.3 s. Every previous RS256 key was then removed |
| Leaked-key rehearsal | Passed | A key the drill generated was published (as a stolen key would be) and an Atlas token forged with it. Both Atlas's local check and Keycloak's introspection accepted the forgery while the key was published. After removal, introspection refused it at once and Atlas's local check 60 s later |
| Full `Test-Lab.ps1` on the rotated keys | All passed | Policy 32, protocols 18, OIDC 14, offboarding 11, departure cases 18, sessions 22, HR intake 10, leaver assurance 7, host HTTPS 5 |
| Integration boundaries | 34 passed in the boundary tests | Includes a removed key ceasing to be trusted once the cache lifetime passes |

What the drill changed:

| Attempt | What it showed | Fix |
| --- | --- | --- |
| First drill (its report was overwritten by the rerun; results from the console) | Activating a new key at once made Atlas refuse tokens signed with it for 30 s: Atlas had just refreshed Keycloak's key set, and unknown-key refreshes are limited to one per 30 seconds. The leaked-key step then failed on its own expectation: Keycloak's introspection accepted the forged token, because Keycloak 26 accepts a token without a session ID when a realm key signs it | Planned rotation now publishes the new key first and waits one key-cache lifetime. The rehearsal now expects introspection to accept a forgery while the key is published: removing a leaked key is the only remedy, so its speed is what matters |
| Key cache lifetime | Keycloak's keys were cached for 300 s, so a removed key could stay trusted for five minutes | Cut to 60 s (`KEY_CACHE_SECONDS`), measured above at 60 s |

### Directory sessions and tickets held from before offboarding

Local runs on 5 October 2026 (UTC) against the Samba 4.19 lab domain, fresh
fixture `2a882426c8f1`. A new probe holds, for the whole case, what a person
already signed in would have: an LDAPS connection opened with the password, a
ticket-granting ticket, an LDAP service ticket and an LDAP connection opened
with that ticket (`ad-held-sessions-2a882426c8f1.json`, 6 passed).

| Held from before offboarding | After the account is disabled and the group removed |
| --- | --- |
| Ticket-granting ticket asking for a new service ticket | Refused by the domain controller |
| LDAPS connection opened with the password | Still answers; its security token still lists the removed group |
| LDAP connection opened with Kerberos | Still answers, with the removed group |
| A new connection using the earlier LDAP service ticket | Accepted, with the removed group (the old membership travels in the ticket) |
| Ticket lifetime | 10 hours from issue |

Kerberos has no per-user revocation, so this access ends only when a connection
closes or a ticket expires. The directory task's evidence now names that time,
10 hours after the observation at the latest (`ACCESSOPS_AD_TICKET_HOURS`), and
the case limitation says what disabling does not stop.

| Check | Actual result | Scope |
| --- | --- | --- |
| Directory case | 28 passed | Unchanged suite on the new evidence wording |
| New logins before → after | 2 passed → 2 passed | LDAPS and Kerberos |
| Held sessions | 6 passed | The table above; the "residual" checks assert today's behavior so a change shows up as a failure to review |
| Backend directory tests | 27 passed | Includes the stated latest expiry time |

| Attempt | What it showed | Fix |
| --- | --- | --- |
| `ad-held-sessions-c5f2964d7916` | The probe stopped before holding anything: Samba's Python credentials take the ticket cache arguments positionally | Corrected; the case itself passed 28 of 28 in that run |
| `ad-held-sessions-1bc29c6400b3`, exploratory | Recorded the behavior above without asserting it | The final probe asserts it |

The directory probes now run in an opt-in `directory-probe` Compose service
(the directory image with only its public CA) instead of a separate
`docker run`, and `Test-ADCase.ps1` judges each Docker step by its exit code.

### Workforce session revocation

Local runs on 5 October 2026 (UTC). Containment now disables the workforce
account, calls Keycloak's per-user logout and counts sessions back; the Keycloak
task is a provider observation only when none remain. Atlas, a lab app in the
workforce realm, gives the leaver real sessions and tokens to lose.

What a unique synthetic worker could still do, measured at each stage
(`sessions.json`, 19 checks passed in 7 s):

| | Before | Disable only (control) | After containment |
| --- | --- | --- | --- |
| Atlas web session | Signed in | Still signed in | Ended by verified back-channel logout |
| Keycloak session listed | Yes | Yes | None |
| Refresh token | Renews | Rejected | Rejected |
| Offline token | Renews | Rejected | Rejected |
| Atlas API, asking Keycloak (introspection) | Accepted | Rejected | Rejected |
| Atlas API, checking the token itself | Accepted | Accepted | Accepted until expiry (115 s left) |
| New sign-in | Allowed | Not measured | Refused |

The control row is why the change matters: disabling the account already stops
new tokens, but the app's own session and Keycloak's session record survive it.
The last row is the remaining gap: an app that never asks Keycloak keeps
accepting an access token it already holds until it expires (120-second
lifetime in the lab).

| Check | Actual result | Scope |
| --- | --- | --- |
| Session revocation before → after | 19 passed | Real workforce sign-in to Atlas (authorization code + PKCE) and its command-line client (refresh and offline tokens), containment through the AccessOps case API, Keycloak session counts through the new private route. The worker's one-time password was random and never stored. |
| Existing live suites on the new containment | Protocols 18, OIDC 11, offboarding 11, departure cases 18 passed | Rerun into a separate folder so the v0.2 reports stay unchanged |
| Host HTTPS boundary and runtime source | 5 passed; source matches | 74 Python files in the running image match the checkout; 9 services |
| Console in a real browser | Passed | The PR #9 journey rerun on the new containment |
| Backend on host test settings | 114 passed, 1 skipped | Includes containment that ends sessions even for an already-disabled account, and evidence that requires a counted zero |
| Integration boundaries | 179 passed | Includes the session route's UUID, redirect and record checks, and the Atlas app's logout-token rules |

| Attempt | What it showed | Fix |
| --- | --- | --- |
| `sessions-attempt-1` | Introspection reported the Atlas command-line token inactive even before containment. Keycloak 26 introspects only for clients in a token's audience | Atlas became the resource server for those tokens (audience mapper) and introspects with its own client |
| `sessions-attempt-2` | Passed (18 checks); the disable-only token results were printed, not asserted | Asserted as a check in the final run |
| Lab upgrade, first run | Stopped while copying the backup: Windows PowerShell 5.1 turned Docker's progress message into an error. Nothing else had changed | The upgrade judges each Docker step by its exit code |
| Lab upgrade, later pass | Stopped after adding the audience mapper: the realm has no `basic` client scope, which is how Keycloak puts the subject in access tokens | The subject is mapped directly on the client. Every run that created the temporary admin removed it and confirmed its credential was refused |
| Browser rerun with a bad report path | Git Bash rewrote the report folder, so the run stopped at its first screenshot after containment, leaving one contained synthetic case open | Rerun with the path unchanged; passed |

Not run for this change: the Samba directory case, the dependency-outage suite
and `Test-Lab.ps1` end to end (each stage ran separately), and the local
PostgreSQL runner (CI runs that suite).

### Automated leaver intake

Local runs on 5 October 2026 (UTC). A signed HR event (Standard Webhooks HMAC)
opens the departure case and contains access without a person: in the same
request when the departure is already effective, or through the worker once a
future departure takes effect. The HR feed is a service identity that can only
open and contain departures; its sponsor, an operator, owns each case.

Measured with unique synthetic workers signed in to Atlas (`hr-intake.json`, 10
checks passed; each time below is a check's own duration, polled every half
second, so it is an upper bound):

| From the HR event to | First passing run | Final run |
| --- | --- | --- |
| Local containment committed (the HTTP answer) | 0.19 s | 0.19 s |
| Keycloak account disabled with zero sessions, case evidence recorded, Atlas signed out | 3.7 s | 2.8 s |
| The same for a future-dated departure, measured from when it took effect | 2.7 s | 2.6 s |

| Check | Actual result | Scope |
| --- | --- | --- |
| HR intake, live | 10 passed | Forged, unsigned, stale and altered events refused with no case opened; redelivery returns the original answer with one case; a reused event ID for a different departure refused; case owned by the feed's operator and the containment request attributed to the feed; future event scheduled, with access unchanged when checked before it took effect |
| Existing live suites on the changed policy and gate | Protocols 18, OIDC 11, offboarding 11, departure cases 18, sessions 19 passed | Written to a separate folder |
| Host HTTPS boundary and runtime source | 5 passed; source matches | 78 Python files in the running image match the checkout; 9 services |
| Console in a real browser | Passed | The PR #9 journey |
| OPA policy | 32 passed | Includes nine HR feed cases: it may open and contain, and cannot grant, revoke, transfer, approve, close, request, read or act outside its projects |
| Backend on host test settings | 147 passed, 1 skipped | Includes 33 intake tests: signatures, rotation, replay, conflicts, unknown or non-human workers, owner rules, scheduled containment and refusals recorded once |
| Integration boundaries | 180 passed | Includes the policy adapter accepting only the new action and service kind |
| Console unit and browser tests | 45 and 33 passed | Includes the snapshot's service list and the case's HR-feed attribution |

| Attempt | What it showed | Fix |
| --- | --- | --- |
| `hr-intake-attempt-1`, `-attempt-2` | Forged events were refused, but the signed event was refused too: the policy adapter rejected the new action and subject kind and answered `policy_unavailable`, failing closed | The adapter allowlists `departure_intake` and the `service` kind; any other kind still fails |

### Leaver assurance and signed SOC signals

Local runs on 5 October 2026 (UTC). For 24 hours after a departure, the worker
reads the account's Keycloak sign-in events every 30 seconds through a new
read-only events client. A successful sign-in or code exchange after the
effective time adds a required "Investigate sign-in after departure" task that
blocks closure until the owner records an investigation. Containment and any
such sign-in also become signed Security Event Tokens (RISC account-disabled,
CAEP session-revoked and session-established) that a SOC receiver collects by
polling. SignalBridge's receiver is being built separately against
[the leaver signals contract](../contracts/leaver-signals.md); this suite acted
as the receiver.

| Check | Actual result | Scope |
| --- | --- | --- |
| Leaver assurance, live | 7 passed | Containment signals arrived signed, verified against the published key and were shown on the case as delivered once acknowledged; a refused sign-in by the disabled account was counted and recorded on the Keycloak task with no access recorded; after the account was re-enabled outside AccessOps, the leaver's sign-in was detected, signalled and blocked the case 32 s later (mostly the 30-second reading interval); containing again ended it, and the owner's investigation statement unblocked the case |
| Leaver assurance with `--external-receiver` | 7 passed | Same journey, leaving its signals queued for SignalBridge's receiver and checking them on the case; detection 33 s after the sign-in |
| Existing live suites on the new worker loop | Protocols 18, OIDC 11, offboarding 11, departure cases 18, sessions 19, HR intake 10 passed | Written to a separate folder |
| Host HTTPS boundary | 5 passed | |
| Console in a real browser | Passed | The PR #9 journey |
| Backend on host test settings | 167 passed, 1 skipped | Includes 20 tests for signing, key-less operation, receiver authentication, acknowledgement and errors, bounded polls, metadata, readings, the blocking task and its statement timing, unavailable readings and the event window |
| Integration boundaries | 190 passed | Includes the events reader: private route, account and window checks, foreign or unknown records, and IP addresses dropped |
| Console unit and browser tests | 46 and 33 passed | Includes the new task's placement with containment |

What Keycloak records in this lab: sign-ins, code exchanges and refused sign-ins
(`user_disabled`) are saved; refresh-token events are not, so reuse of an
already-issued refresh token is not watched. A sign-in between the effective
time and containment counts as access after departure.

| Attempt | What it showed | Fix |
| --- | --- | --- |
| Events client, first upgrade | Keycloak answered 403: the client held `view-events` but, as in this realm's SCIM client, a role only reaches the token through a scope mapping and a role mapper | The upgrade adds both, and only for that role |
| `leaver-assurance-attempt-1` | Signals passed, but the refused-sign-in check timed out: the test had backdated the departure by five seconds, so the worker's own Atlas sign-in just before it correctly counted as access after departure | The test sets the effective time after the sign-in; the behaviour is documented above |

### Full lab run after the restart (5 October 2026, UTC)

| Check | Actual result | Scope |
| --- | --- | --- |
| `Test-Lab.ps1` end to end | All stages passed in 4 min 23 s | OPA policy 32, protocols 18, OIDC 11, offboarding 11, departure cases 18, sessions 19, HR intake 10, leaver assurance 7, host HTTPS 5; runtime source matches the checkout (83 files, 9 services). The first run of every suite in one invocation, through the shared exit-code helper with all output captured |
| `Start-Lab.ps1` and `Stop-Lab.ps1` with output captured | Both completed | Before the fix, a stop with captured output reported an error after Docker had stopped every container |
| Container stop | Atlas and the policy adapter exit 0 in about 1 s | Before: both were killed (exit 137), because as PID 1 they ignored SIGTERM |

## v0.2: departure cases, directory lab and console redesign

Local runs on 3–4 October 2026 (UTC). The backend source was unchanged between
the PostgreSQL run on 3 October and the live lab runs on 4 October; the lab's
runtime source matched the checkout (`runtime-source.json`: no mismatches).

| Check | Actual result | Scope |
| --- | --- | --- |
| Departure cases through the live lab | 18 passed | Real OIDC sessions, CSRF denial, binding mismatch denial, containment through real Keycloak (account disabled and managed group membership removed, confirmed by an independent read-only native membership query), owner statements, owner self-closure denied, independent closure, immutable packet. Entra/GitHub inputs are synthetic fixtures. |
| Departure case with a Samba directory account | 28 passed | Fresh fixture `6bfe42dc4a25`. Strict LDAPS and wrong-name/CA denial, GUID binding, canary and delegated-permission denials, stale-flag atomic denial, case-triggered disable and group removal with complete readback, read-first replay, private membership route (GET allowed; other methods, realms, paths and public admin denied). |
| New directory logins before → after | 2 passed → 2 passed | Before: new LDAPS bind and Kerberos ticket succeed. After: both denied. Existing tickets and sessions are not measured. |
| OIDC and business lifecycle | 11 passed | Code + S256 PKCE, independent approval, SCIM grant/revoke, protected read, replay denial, logout |
| Identity and authorization protocols | 18 passed | Native SCIM, `private_key_jwt`, JWT validation, introspection, AuthZEN/OPA with exact bundle digest |
| Connected offboarding and drift | 11 passed | Local containment, remote `active:false`, direct membership drift without adoption |
| OPA policy rules | 23 passed | Pinned OPA container |
| Host HTTPS boundary | 5 passed | Loopback only, SNI, CA/hostname verification, hidden admin route |
| Backend on PostgreSQL 17 / Python 3.13 | 110 passed | Disposable database, including concurrent serialization (3 October) |
| Backend on host test settings | 109 passed, 1 skipped | SQLite; the skipped test needs PostgreSQL row locks |
| Integration boundaries | 145 passed | Collectors, directory adapter, membership observation, cryptography; isolated or mocked transport |
| Console unit tests | 43 passed | Case rules, seeded queue, next-step and role logic, report parsing, DTO validation |
| Console browser tests | 33 passed | Full departure journey to closure and export, role boundaries, queue filters, import errors, keyboard and focus, mobile layout, axe WCAG 2.2 A/AA on every route in both themes |
| Connected console rendering | 9 passed | The sanitized snapshot recorded by the directory run, rendered by the connected build through intercepted read endpoints. Checks DTO compatibility, provenance labels, layout and accessibility; not authentication evidence. |
| Evidence and lock tooling | 10 passed | Publisher allowlist, hashing, traversal and lock-consistency tests |
| Public evidence index | 28 records | 20 passed, 8 failed attempts retained |

### Failed attempts kept on record

| Attempt | What it showed | Fix |
| --- | --- | --- |
| `cases-attempt-1` (3 Oct) | The policy did not allow the new departure action | Added the reviewed AuthZEN/OPA allowance |
| `cases-attempt-2` (3 Oct) | Disabling the account left the managed Keycloak group membership behind | Offboarding now queues a removal for every known managed grant, including history |
| `ad-boundaries-attempt-1` (3 Oct, local report) | The lab CA lacked CA key usage, so strict TLS rejected it | Reissued the CA certificate with the same key and subject; verification unchanged |
| `cases-attempt-3` (4 Oct) | Owner self-closure was denied, but by the role gate rather than the domain check the test expected | Test now expects the denial layer that applies to the owner's roles and confirms the case stayed open |

The 4 October runs also exposed three Windows PowerShell 5.1 problems in the
lab scripts (native stderr treated as an error, embedded quotes stripped from
arguments, and a byte-order mark added to container stdin). Each failed closed
before any directory change. The scripts were fixed and the runs repeated.

### Console in a real browser against the live lab (5 October 2026, UTC)

| Check | Actual result | Scope |
| --- | --- | --- |
| Full departure case through the redesigned console | Passed (final run 27 s, `console-live.xml`) | Firefox in the pinned Playwright image on the lab's internal networks, verifying TLS with only the lab CA added to its trust. Real Keycloak sign-in as the operator; a new synthetic employee registered in the UI and provisioned to Keycloak; case opened, contained, and both native tasks read back as provider observations (none simulated); the other seven actions recorded and displayed as owner attestations; owner's closure button disabled; the approver, in a separate browser profile, closed the case and exported a `connected_case` packet with closure basis `reviewed_evidence`. axe WCAG 2.2 A/AA passed on the live overview, the open case and the closed case. |
| Repeatability | Passed on four consecutive runs | Attempts 3–5 and the final run each opened and closed a new case. Attempt 4 contained one worker left active by attempt 2; later runs found none. |

| Attempt | What it showed | Fix |
| --- | --- | --- |
| Attempt 1 (report overwritten, not kept) | Firefox rejected the lab certificate (`SEC_ERROR_UNKNOWN_ISSUER`): Playwright's Firefox build ignores the standard `distribution/policies.json` | Point `PLAYWRIGHT_FIREFOX_POLICIES_JSON` at the CA-only policy |
| `console-live-attempt-2` | Sign-in, axe and registration passed; the status poll from Playwright's Node HTTP client failed TLS because only Firefox trusts the lab CA. Its error log also printed that request's lab session cookie and CSRF token | Polls now run as same-origin fetches inside the page. The local report was redacted; that loopback-only lab session had a fixed 30-minute lifetime and was not reused. The run left its new worker active, so the test now contains leftovers before it starts and after a failure |
| `console-live-attempt-3` to `-attempt-5` | Passed | Earlier passing runs, kept. The final run added an explicit check that the seven non-native actions display as attestations |

### CI, deployment and signed release (4 October 2026)

| Check | Actual result | Scope |
| --- | --- | --- |
| GitHub CI on the PR | All four jobs passed | [Run 37185324787](https://github.com/aman-agarwal6/AccessOps/actions/runs/37185324787) on `94ede7d`, the PR head merged as `193d9ea`. An earlier run on `639505d` failed one phone-width browser check; the fix is commit `94ede7d`. |
| Published simulation | 17 passed | [Pages run 37185519790](https://github.com/aman-agarwal6/AccessOps/actions/runs/37185519790) reran CI before deploying. `tools/check_published.mjs` against the live site: routes, both themes, recorded evidence, walkthrough denials, the departure journey to a labeled packet, mobile fit, and no API, third-party or error traffic. |
| Signed v0.2.0 release | Passed: provenance, SBOM and published bytes verified | [Release](https://github.com/aman-agarwal6/AccessOps/releases/tag/v0.2.0), [workflow 37185521660](https://github.com/aman-agarwal6/AccessOps/actions/runs/37185521660), exact source `193d9eab4bca89c34bebdd8f5042ab8d3bfe2f5f`, clean tree. 255 backend and integration cases on PostgreSQL 17; CycloneDX SBOM of 63 components. Both attestations verified with the pinned repository, signer workflow, `refs/heads/main`, commit and GitHub-hosted runner; all seven published assets match the verified files byte for byte. |

### Not run for this version

- The local PostgreSQL runner on 4 October (Docker was reserved for another
  workload). CI ran the same backend suite on PostgreSQL 17 in the signed run.
- Revocation of existing sessions or Kerberos tickets, MFA, live key rotation and
  any Microsoft Entra, Microsoft AD or GitHub tenant measurement.
- The real-browser check in Chromium or WebKit, at phone width, or in the light
  theme against the live lab; those were covered with mocked or recorded data.
- Manual screen-reader testing. Automated axe checks do not establish full
  accessibility conformance.

## v0.1.0 release (2–3 October 2026)

Actual local checks were executed on 2–3 October 2026; UTC reports use 3 October.
Counts describe separate suites, not unique combined requirements. Tests used
synthetic records and an isolated local Docker lab. No employer or production
identity provider was contacted. Publication is separate from local verification.

| Check | Actual result | Scope |
| --- | --- | --- |
| Backend: PostgreSQL 17 / Python 3.13 | 54 passed, no skips | Disposable DB, including concurrent transaction serialization; actual report persisted in an output-only mount |
| Reconciliation regressions | 5 passed | Unavailable/malformed/empty observations cannot pass; other measured drift retained; no access adoption |
| Integration boundaries | 31 passed | Cryptography, logout, bounded key refresh, AuthZEN/SCIM; isolated or mocked transport |
| Frontend domain | 24 passed | Approval, expiry, containment, budget, inventory/transfer, structured audit and public record validation |
| Browser | 15 passed | Navigation, keyboard/dialogs, six-route/modal accessibility, mobile layout, passed/failed evidence drawers and simulation flows |
| Connected-data renderer | 14 passed, 1 skipped | Actual sanitized snapshot with intercepted transport; desktop/mobile routes, bindings and audit. Snapshot lacked accepted transfer; no live-provider claim |
| Actual provider protocols | 18 passed | Native SCIM, private-key client authentication, JWT, introspection, realms, authenticated AuthZEN/OPA and exact configured bundle digest |
| Actual OIDC/business HTTP | 11 passed | Code + S256 PKCE, independent approval, SCIM grant/revoke, protected read, replay denial and local logout; loaded backend source hashes |
| OPA | 19 passed | Actual pinned container and Rego cases |
| Host HTTPS | 5 passed | Loopback, preserved SNI, CA/hostname verification, exact issuer, hidden administration route and invalid-SNI denial |
| Actual dependency outage | 2 passed | OPA denies policy and Keycloak denies new token acquisition; both restored and strict host TLS rechecked |
| Evidence tooling | 6 passed | Failed/skipped counts, empty-report rejection, tamper/traversal checks, source coverage and runtime exclusion |
| Dependency lock consistency | 4 regression tests passed; actual locks match | Direct pins, development/runtime parity, include cycles/traversal and malformed/unhashed input |
| Build/type/format and workflow syntax | Passed | Production build, TypeScript, Prettier, Ruff, actionlint; not a GitHub workflow execution |
| Known dependency advisories | No known vulnerabilities found | npm and Python runtime locks at check time; no image-layer/model inventory claim |
| Staged source scan | Passed | Gitleaks; generated runtime credentials excluded from Git; narrowly scoped reviewed source-digest exclusions |
| CycloneDX 1.6 | Generated: 59 components | Locked Python runtime and npm inventory; OS layers separate |
| Connected offboarding/drift | 11 passed after fix; initial failure retained | SCIM bindings, direct membership drift without adoption, approved grant, local containment and remote active:false; seeded users preserved |
| Public recorded index | 12 actual records assembled | Sanitized JSON/JUnit reports, explicit limits and retained failed attempts; local hashes are not provenance |
| Source-bound frozen receipt | Passed: 54 PostgreSQL cases, content hashes verified | Clean source revision `0c81aa4b5978`; inputs captured before execution; local receipt remains unsigned |
| Repeatable lab startup | Passed | Reused local configuration, migrations, idempotent seed, protected credential files and strict service health |
| GitHub CI | All four jobs passed | [Run 37097744436](https://github.com/aman-agarwal6/AccessOps/actions/runs/37097744436), revision `0c81aa4b5978`; 85 backend/integration cases, frontend, policy and source-history scanning |
| Published simulation | 12 live-site checks passed | [Pages run 37097964717](https://github.com/aman-agarwal6/AccessOps/actions/runs/37097964717); six routes, guided containment, recorded results, source link, mobile layout, no protected/third-party calls or browser errors |
| Signed v0.1.0 release | Passed: provenance, SBOM and published bytes verified | [Release](https://github.com/aman-agarwal6/AccessOps/releases/tag/v0.1.0), [workflow 37098372200](https://github.com/aman-agarwal6/AccessOps/actions/runs/37098372200), exact source `94ad0f1f43ddace7921e15c52e621bd954637e79`; 85 passing cases and 59 components |

[Lab instructions](../infra/README.md) describe report paths and exact-fixture
containment. Browser simulation never proves remote effects. Negative tests can
pass by proving denial; a reconciliation run still fails if any principal is
unobservable. Failed attempts are retained alongside successful retries.

### Unrun and unsupported scopes (v0.1)

- IdP-triggered backchannel logout and live realm signing-key rotation. Dedicated
  verification/replay/refresh code has isolated tests.
- Old operator-session/running-executor-token revocation after real provider-backed
  offboard. Isolated backend tests cover those app gates; real revoke/replay denial
  is measured separately. New inventory agents start suspended with no credentials.
- MFA/AAL: synthetic operator login is password-only.
- Delegated token exchange/`act`, DPoP, native RAR/resource parameters, CAEP/SSF
  interoperability and full RFC 9068 profile conformance.
- A generative model, model performance/resistance, image OS inventory, load test,
  independent penetration test, multi-tenant or enterprise deployment.
- Full accessibility, ASVS, NIST, SLSA-level or other certification/conformance.

Native Keycloak SCIM Users returns HTTP 404 for the configured executor service
account in the tested configuration. Reconciliation keeps other readings and
marks that record unknown; absence cannot prove a match or grant authority.
Ordinary registered human/agent inventory records are observed separately.

See [evidence verification](evidence.md) for exact bytes and expected signer.
Local hashes/timestamps do not establish trusted provenance. This ledger is
updated from completed checks, never from planned or skipped execution.
