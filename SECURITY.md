# Security reporting

This repository is a local synthetic-data reference system. Do not put real
employee records or production credentials in the lab or browser simulation.

Report suspected vulnerabilities through GitHub's private vulnerability
reporting feature when enabled on the published repository. If unavailable,
open an issue asking for a private reporting channel without exploit details,
credentials or private records. Do not post secrets in public issues.

Include the affected revision, trust boundary, synthetic reproduction steps,
expected denial and actual effect. Test only your local authorized lab.

The main branch receives fixes. Locked versions and image digests are reviewed
monthly and after relevant advisories. Upgrade one boundary at a time and rerun
the denial tests. The standards matrix describes selected controls, not a
security certification or a guarantee of safe production deployment.
