# Contributing to AccessOps

AccessOps is a reference system that runs on synthetic data. These rules keep it that way.

## Ground rules

- Never commit credentials, private keys, local certificates, environment files, databases, personal records or runtime logs. `scripts/generate_local.py` creates local secrets under `.local/`, which git ignores.
- Keep the browser demo, the authenticated lab and recorded evidence separate. Never fake a passing result, and keep failed runs.
- Fail closed when identity, policy, grant state or a connector's outcome is unknown.
- A review suggestion never counts as an approval. Approvals are tied to the exact change and policy version and expire after 15 minutes.
- Match accounts by issuer and subject, never by name or email.
- Bind development services to loopback and never turn off TLS verification.
- Keep Keycloak workforce administration separate from operator sign-in.
- The public demo must work without credentials, external APIs or a language model.

## Checks before a pull request

| Area | Commands |
| --- | --- |
| Frontend | `npm ci --ignore-scripts`, `npm run check`, `npm test`, `npm run build`, `npm run test:e2e` |
| Backend | `python -m pytest`, `python backend/run_postgres_tests.py` |
| Integrations | `python -m pytest integrations/tests` |
| Lab | `scripts/Test-Lab.ps1`, `scripts/Test-ADCase.ps1` |

Read the setup notes in `infra/README.md` before running the lab scripts, and say in the pull request which checks you skipped.
