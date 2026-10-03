# AccessOps development instructions

AccessOps is an isolated, synthetic-data access-governance reference system.
Follow the workspace security baseline. Do not read or change sibling projects.
Never commit credentials, private keys, local certificates, environment files,
databases, personal records, or runtime logs. Use generated local secrets.

Keep browser simulation, authenticated connected lab, and recorded evidence
distinct. Never fabricate protocol conformance or passing test results. Fail
closed when identity, policy, grant state, or connector outcomes are unknown.
Agent proposals must never become approvals. Bind approvals to exact changes,
policy versions, and a 15-minute expiry. Preserve issuer/subject identity keys.

Bind development services to loopback. Do not bypass TLS verification. Keep
Keycloak workforce administration separate from operator authentication.
Public builds must function without credentials, external APIs, or an LLM.

Verification: frontend npm ci, npm run check, npm test, npm run build;
backend python -m pytest; policy opa test policies; Compose integration scripts.
Read the relevant setup files before executing scripts. Record skipped checks.

Ownership during initial implementation: backend/ belongs to backend agent;
frontend/ belongs to frontend agent; infra/, scripts/, integrations/, policies/
belong to integrations agent; root docs, contracts/, and .github/ to coordinator.
Coordinate before editing another agent's files. Use Apache-2.0-compatible tools.
