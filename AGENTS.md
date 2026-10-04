# AccessOps development instructions

AccessOps is an isolated, synthetic-data access-governance reference system.
Never commit credentials, private keys, local certificates, environment files,
databases, personal records or runtime logs. Use generated local secrets.

Keep the browser simulation, the authenticated lab and recorded evidence
distinct. Never fabricate protocol conformance or passing results, and keep
failed attempts. Fail closed when identity, policy, grant state or connector
outcomes are unknown. Agent proposals never become approvals. Bind approvals to
exact changes, policy versions and a 15-minute expiry. Preserve issuer/subject
identity keys.

Bind development services to loopback. Do not bypass TLS verification. Keep
Keycloak workforce administration separate from operator authentication.
Public builds must work without credentials, external APIs or an LLM.

Verification: frontend `npm ci --ignore-scripts`, `npm run check`, `npm test`,
`npm run build`, `npm run test:e2e`; backend `python -m pytest` and
`python backend/run_postgres_tests.py`; integrations `python -m pytest
integrations/tests`; lab `scripts/Test-Lab.ps1` and `scripts/Test-ADCase.ps1`.
Read the setup files before running scripts, and record skipped checks.
