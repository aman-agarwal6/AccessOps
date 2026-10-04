# AccessOps console

The console has three groups of pages: **Offboarding** (Overview, Offboarding
cases), **Access governance** (Requests, Identities, Access reviews, Policies &
resources) and **Evidence** (Runs & evidence). The default build is a login-free
browser simulation with synthetic Northstar Systems data. State lives in memory
and resets on refresh; it never calls lab APIs or creates recorded evidence.

## Run and verify

Use the exact versions in `package-lock.json` (Node.js 24):

```sh
npm ci --ignore-scripts
npm run dev            # http://127.0.0.1:4173
npm run check          # TypeScript
npm test               # Vitest unit tests
npm run build
npm run format:check
npm run test:e2e       # Playwright + axe, desktop and mobile, both themes
```

Local browser tests use the installed Chrome channel; CI installs Playwright's
Chromium. Screenshots are written to `../output/screenshots/`.

`npm run test:connected` renders a sanitized snapshot recorded from the real lab
through the connected build. Set `ACCESSOPS_CONNECTED_SNAPSHOT` to that file
first; without it the suite is skipped. Transport is intercepted and only the
session and snapshot reads are allowed, so it checks rendering and data
compatibility, not authentication or provider behavior.

## Design system

Tokens live in `src/styles/tokens.css`: a dark graphite theme (default) and a
light theme with the same roles, a 16px type scale using the bundled Geist and
Geist Mono fonts, and a 4px spacing grid. Every text token meets WCAG AA contrast
on every surface of its theme. The theme choice is stored in `localStorage` when
available and falls back to dark.

Evidence provenance has its own palette and always pairs color with an icon and
a label: signed CI evidence, provider observation, imported snapshot, owner
attestation, simulated and no evidence. `src/ui.tsx` defines these with the other
shared primitives.

## Code map

| Path                                                  | Role                                                                      |
| ----------------------------------------------------- | ------------------------------------------------------------------------- |
| `src/App.tsx`                                         | State, actions and routing; no page markup                                |
| `src/workspace.ts`                                    | Navigation and the explicit `Workspace` contract each page receives       |
| `src/caseflow.ts`                                     | Pure case logic: next step, role boundaries, SLA, queue order, provenance |
| `src/pages/`                                          | Overview, cases (queue, detail, dialogs), governance and evidence pages   |
| `src/details.tsx`, `src/forms.tsx`, `src/dialogs.tsx` | Drawers, forms, informational dialogs and the walkthrough coach           |
| `src/domain.ts`, `src/offboarding.ts`                 | Simulation model and case rules, shared with the unit tests               |
| `src/api.ts`                                          | Connected-mode client and recorded-evidence loader                        |

## Browser simulation

The queue holds four synthetic cases: Mara (due soon, the guided case), Leo
(overdue contractor), Sam (scheduled) and Priya (closed, built through the same
case functions). Each case shows one **next step**. When the current role cannot
take it, the card says why and offers to switch to a role that can. The
boundaries themselves are enforced in the case functions, not in the UI.

Public report imports accept only canonical `synthetic_fixture` JSON, at most
100 KB and 100 readings. Bindings, timestamps, duplicates and structure are
checked. Unknown, stale, pre-departure or partial readings cannot clear an
action, and each import resets owner statements for external actions. Never paste
real employee, tenant or credential data into the public demo.

The containment walkthrough on the overview follows one departure request
through containment, a simulated provider check and denied retries. Other
scenarios cover approval expiry, policy outage, provider drift, bounded access
review, registration, department transfer and successor acceptance.

## Connected local lab

Build with `VITE_ACCESSOPS_MODE=connected` and serve `dist/` through the lab's
HTTPS reverse proxy:

```powershell
$env:VITE_ACCESSOPS_MODE = 'connected'
npm run build
Remove-Item Env:VITE_ACCESSOPS_MODE
```

`src/api.ts` uses same-origin `/api/v1` and `/auth` endpoints with server
session cookies, CSRF headers, bounded timeouts and idempotency keys. No OAuth
token reaches browser storage or the bundle. Connected mode never falls back to
synthetic data. Role labels in the UI are informational; the backend enforces
authority. Server-enrolled directory accounts add a tenth action that can be
refreshed read-only but never attested, and the UI has no editable GUID fields.

Routes use URL hashes and Vite's relative base so the build works under a GitHub
Pages path. Set `VITE_SOURCE_URL` to link the source repository.

## Recorded evidence

`public/evidence/index.json` (`{"runs": []}`) is generated by
`tools/publish_recordings.py` from an allowlist of actual local reports. The
loader validates its contract, and simulation records cannot enter it. Loading,
empty and error states are explicit, and a failed load assumes no results.
Never add credentials, cookies, private certificates, personal data or raw logs.
