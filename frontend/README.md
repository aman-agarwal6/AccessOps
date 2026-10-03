# AccessOps console

Six destinations connect the access workflow: Overview, Requests, Identities,
Access reviews, Policies & resources, and Runs & evidence. The default build is
a login-free browser simulation using synthetic Northstar Systems identities.
State lives in memory and resets on refresh. It never calls lab APIs or produces
real-run evidence.

## Run and verify

Use the exact dependency versions in `package-lock.json`:

```sh
npm ci --ignore-scripts
npm run dev
npm run check
npm test
npm run build
npm run format:check
npm run test:e2e
```

The development server binds to `127.0.0.1:4173`. Local browser tests use an
installed Chrome browser through Playwright's `chrome` channel. CI uses
Playwright's Chromium installation (`npx playwright install --with-deps chromium`).
Install Chrome separately if it is unavailable locally. Tests cover the guided employee/agent containment flow,
independent approval, malicious review text, drift, registration, keyboard focus,
six-route automated accessibility checks, and mobile layout. Automated checks
do not establish full accessibility conformance.

Screenshots are generated under `../output/screenshots/`. They show synthetic
data. `npm run format` formats source and configuration with pinned Prettier.

## Browser simulation

The 90-second route starts on Overview. It establishes employee and agent reads,
applies authorized containment, checks the simulated provider, and retries both
reads. The results remain explicitly labeled simulation. Other scenarios cover
approval expiry, unavailable policy, direct provider drift, bounded access review,
onboarding, department transfer, and successor acceptance.

Containment requires an operator, without waiting for independent approval. New
read grants and transfers require independent approval bound to the exact change,
policy version, and a 15-minute expiry. Sponsor changes suspend the agent and
revoke existing grants. Registration creates inventory only; agents remain
suspended pending reviewed local credential binding. The UI cannot mint or bind
credentials. Version 1 grants support read permission only.
New agent grants expire after ten minutes and allow six successful reads; new
human grants remain until explicitly revoked. The browser model and connected
lab use these same limits. Existing synthetic baseline grants include expiring
examples and are labeled as fixtures in identity details.

The ten-minute engineering route links decisions to source areas and evidence.
`src/domain.ts` contains the immutable simulation model and enforcement checks;
`src/domain.test.ts` exercises meaningful success and denial boundaries.

## Connected local lab

Build with `VITE_ACCESSOPS_MODE=connected` and serve `dist/` through the lab's
HTTPS reverse proxy. For example, in PowerShell:

```powershell
$env:VITE_ACCESSOPS_MODE = 'connected'
npm run build
Remove-Item Env:VITE_ACCESSOPS_MODE
```

`src/api.ts` talks to same-origin `/api/v1` and `/auth` endpoints using server
session cookies, CSRF protection, bounded timeouts, and idempotency keys. No
OAuth token is placed in local storage, session storage, or the bundle. Connected
mode uses server snapshots and never falls back to synthetic data after a failed
request. Client role labels are informational; the backend enforces authority.

All routes use URL hashes and Vite's relative base so the public build works
under a GitHub Pages repository path. Set `VITE_SOURCE_URL` only after the source
repository is available; otherwise the UI reports publication pending.

## Recorded evidence

The read-only public index is `public/evidence/index.json`, shaped as
`{"runs": []}`. Publish only sanitized records from actual local execution. Each
record follows the `Run` contract in `src/domain.ts` with `origin: "recorded"`,
dated checks, outcome, limitations, and optional manifest. The loader validates
the public contract; simulation records cannot enter this collection. Empty
and unavailable evidence states are explicit.
Run details display the supplied manifest's scope and limitations separately
from its executed checks. Contract and browser tests also use clearly named
viewer fixtures that are never published as local provider evidence.

Do not include credentials, session cookies, private certificates, personal data,
or raw runtime logs. Browser checks and downloads are useful for explanation;
they are not cryptographic proof or actual connector measurements.
