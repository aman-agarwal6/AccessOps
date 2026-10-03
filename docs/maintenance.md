# Keeping AccessOps available without a paid service

The recruiter demo is a static GitHub Pages build. It needs no running backend,
database, model endpoint, scheduled keep-alive or credit card. The connected lab
runs on your own computer and can be stopped when it is not being demonstrated.
Its credentials and database stay outside the public repository.

[Pages supports public repositories on GitHub Free](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).
The workflows use standard `ubuntu-latest` runners, which are
[free for public repositories](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Artifact/cache storage still has [separate limits](https://docs.github.com/en/actions/reference/limits).
Test artifacts expire after seven days and release workflow artifacts after
fourteen; small verified release files are copied to a GitHub Release for the
portfolio handoff. Do not enable larger runners, paid storage or external APIs
to maintain the demo. Provider terms can change; the static build remains portable.

## Monthly review

1. Open dependency/security alerts and the monthly Dependabot proposals. Read
   the upstream release notes and check the affected trust boundary. Do not
   merge a green dependency proposal automatically.
2. Keep Django in the supported 5.2 LTS family until a separately tested major
   migration. For a Python update, change the `.txt` input, regenerate both
   hashed locks with reviewed pip-tools, and run `python tools/check_locks.py`.
   CI rejects input/lock or runtime/test version drift.
3. For JavaScript, preserve `package-lock.json`; use `npm ci --ignore-scripts`
   and the documented frontend checks. For images/actions, verify the upstream
   source and new immutable digest. Keep upgrades focused.
4. Require all four Verify AccessOps jobs to pass. For an identity, policy or
   connector change, rerun the relevant actual lab checks, including denial and
   outage paths. Browser tests alone do not verify provider behavior.
5. Run **Publish browser simulation** from `main` after review. It verifies before
   deployment. Open the live overview, guided offboarding and recorded evidence
   drawer. Record new results without removing historical failed attempts.
   After frontend dependencies are installed, `node tools/check_published.mjs`
   repeats the bounded live-site checks against the public AccessOps URL.
6. Run **Release signed evidence** for a reviewed milestone, verify the expected
   signer/ref/commit, and attach exact frozen bytes and detached bundles to the
   release. Keep the evidence's original source revision when later docs change.

## Recoverability

An earlier source commit can be built and reviewed on a branch, then restored to
`main` with a normal revert and republished. Do not rewrite shared history or
delete audit/evidence records to hide a failure. Keep local lab configuration
under `.local/` private and back up any lab state you intend to retain before
changing database versions. Never use the disposable test runner against the
connected database.

The demo is deliberately independent of the local lab. A powered-off workstation
does not break the recruiter link. The deterministic assistant works without
an LLM; adding a model is a separate implementation and evaluation task.
