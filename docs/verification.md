# Verification ledger

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
| Signed release | Pending final maintenance commit | Successful signing and expected-signer verification must be recorded separately |

[Lab instructions](../infra/README.md) describe report paths and exact-fixture
containment. Browser simulation never proves remote effects. Negative tests can
pass by proving denial; a reconciliation run still fails if any principal is
unobservable. Failed attempts are retained alongside successful retries.

## Unrun and unsupported scopes

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
