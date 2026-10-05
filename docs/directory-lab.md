# Actual local directory departure cases

The optional free lab adds real Samba AD-compatible directory behavior to the
authenticated AccessOps case workflow. It does not establish Microsoft Active
Directory interoperability. Cases without a trusted directory enrollment keep
the existing nine-task workflow; an enrolled case has a required tenth directory
task backed by actual provider observations.

Complete the ordinary [connected setup](../infra/README.md) first. Docker Desktop
and the documented local Python environment are sufficient; no cloud tenant,
Windows Server license, paid service, host DNS change, or OS trust change is needed.
From the AccessOps repository in PowerShell:

```powershell
# Fresh clone: use the credential-free bundled standalone lab source.
./scripts/Test-ADCase.ps1

# This workspace's explicitly handed-over existing running directory:
./scripts/Test-ADCase.ps1 -LabRoot ../accessops-ad-lab
```

The default standalone source is `infra/ad-lab/`. Setup inspects the existing
`accessops-adlab` Compose project origin before startup or credential generation.
If that origin differs, it refuses the default path and requires the explicit
existing `-LabRoot`; it never starts a second copy over an existing domain using
fresh secrets. The original handed-over source and running domain remain intact.
The copied source allowlist contains no `.local/`, output, database, or keys.

The test prepares only uniquely named synthetic users/groups in two dedicated
fixture/canary OUs, then connects backend/worker through the opt-in
`infra/compose.ad.yml` override. The directory remains on its private internal
network with no host ports. Only the public directory CA certificate volume and
the nonadmin connector's protected config/password are mounted in app services.
The separate fixture-user password is mounted only in one-shot test harnesses.
Private targets and their ancestors reject reparse points; Windows credentials
are restricted to the current user and SYSTEM. Never commit those directories.

The application never receives Administrator credentials. Reviewed local Samba
management grants the connector noninherited WriteProperty ACEs for exactly
`userAccountControl` on the new fixture user and `member` on its new fixture group.
It receives no broad create/delete/reset-password rights or group inheritance.
These property rights can technically alter other account flags or membership
values on those same objects; the application constrains operations to disabling
the bound user and removing that user's exact reference. Canary mutations verify
that rights do not extend to the separate out-of-scope objects.

Server-local `enroll_ad` validates the live domain GUID, exact normal-user/group
GUIDs, protected-account exclusions and dedicated OU scope, then stores an
immutable mapping for the exact local workforce identity under the policy gate.
The public case request cannot supply or retarget a directory GUID. Case creation
freezes the server enrollment; local containment must commit and the effective
departure must be reached before a durable directory job can act.

Mutations address objects and member values through server-resolved GUIDs, with
no mutable-DN fallback. Disabling uses one atomic LDAP modify deleting the exact
old account flag value and adding that value with the disabled bit set. A stale
old value fails the whole operation, preserving concurrent flags. The connector
reads first on retries, never enables an account or adds a membership, and verifies
the complete bound group set afterward. TLS chain and hostname verification are
mandatory for fixed `dc.adlab.test:636`; referrals are disabled. Each call is
bounded to five seconds, with at most forty calls and a 45-second operation
deadline checked before each call (an in-flight final call can add five seconds).

The live case test covers real OIDC/API/CSRF controls, independently approved
local access, frozen directory enrollment, actual case-triggered disable/removal,
explicit complete readback and a read-only refresh. Successful readings capture
their actual time before the completion database gate; stale/missing readings,
new pending jobs and later failed outcomes block closure. Owner statements cannot
replace the native directory proof. Before/after one-shot probes verify new
LDAPS authentication and new Kerberos ticket issuance. Entra/GitHub imports
remain visibly synthetic; external scope exclusions remain owner statements
rather than live cloud measurements.

A third probe holds what an already signed-in person would have for the whole
case: an LDAPS connection opened with the password, a Kerberos ticket-granting
ticket, an LDAP service ticket and an LDAP connection opened with it. After
offboarding, the domain controller refuses the old ticket-granting ticket any
new service ticket. Everything already held keeps working, with the removed
group still in its security token: both open connections answer, and the old
service ticket opens a new connection. Kerberos has no per-user revocation, so
that access ends only when the connection closes or the ticket expires (10
hours here, the Samba and AD default). The directory task's evidence therefore
names the latest expiry time instead of implying that all access is gone.
`ACCESSOPS_AD_TICKET_HOURS` sets the domain's lifetime if it differs; shortening
the domain's service ticket lifetime is the lever that narrows the window.

Measured on 5 October 2026 with fresh fixture `2a882426c8f1`: the case suite
passed 28 of 28 checks, new LDAPS and Kerberos authentication succeeded before
offboarding (2 of 2) and both were denied afterward (2 of 2), and the held-session
probe passed 6 of 6. See the [verification ledger](verification.md) for scope
and retained failed attempts.

The wrappers run under Windows PowerShell 5.1 and PowerShell 7. Under 5.1 they
pin UTF-8 without a byte-order mark for container stdin and read Compose labels
as JSON, because 5.1 adds a BOM and strips embedded quotes from native arguments.

Sanitized reports retain real timestamps and failed attempts under
`output/connected/cases-ad-<suffix>.json/.xml` and
`ad-auth-before|after-<suffix>.json`. The public synthetic response fixture is
`connected-cases-ad-snapshot.json`. Test cleanup disables only its exact new
fixture/canary accounts and retains case, directory and audit history. It never
offboards seeded Mara or changes Atlas-Readers/IT-Operators. Do not delete domain
volumes or reset passwords to make a failed test pass.

For individual preparation, use `Prepare-ADLab.ps1` with the same `-LabRoot`; its
private reference can be supplied as `Test-ADCase.ps1 -FixturePath <reference>`.
Do not reuse a successfully contained fixture for a fresh active-user scenario;
prepare a new one. `-SkipBuild` is only appropriate when the running image was
already rebuilt from the reviewed current source. To stop the directory, use its
standalone `Stop-Lab.ps1`; domain volumes and protected credentials are retained.
Restart connected services with both Compose files when resuming AD cases.

Review the standalone [maintenance limits](../infra/ad-lab/README.md): the Ubuntu
base digest is pinned but signed repository package resolution can change on
rebuild. Certificates expire after one year; automatic renewal is not implemented.
Back up the directory volume/private credentials and perform a deliberate renewal
with the public CA mount updated; never disable validation for expired certificates.
The handed-over CA originally omitted CA key usage, which Python 3.13 strict
verification rejected. The reviewed `scripts/ad_correct_ca.py` server-local helper
reissues only the public CA certificate with its same key/subject/SKI and critical
keyCertSign/cRLSign, preserving the prior certificate privately and the leaf
certificate/domain/credentials. The bundled fresh bootstrap includes that extension.
This repair does not weaken verification or export a private key. It is a narrow
compatibility correction, not an automatic renewal service.

For that specific legacy certificate correction, review the helper first and run
it inside the explicitly selected DC from the repository root; fresh bundled labs
already include the extension and do not need this repair. Use PowerShell 7 for
this one-off command (Windows PowerShell 5.1 would strip its inner quotes):

```powershell
Get-Content -LiteralPath ./scripts/ad_correct_ca.py -Raw |
    docker compose -f ../accessops-ad-lab/compose.yml exec -T dc /usr/bin/python3 -c 'import sys; exec(compile(sys.stdin.read(), "reviewed-ad-certificate-helper", "exec"))'
```

Select the exact authorized lab's Compose file. The helper validates unchanged
public key, subject, SKI and leaf and strict chain verification before replacing
the certificate. It preserves the old certificate inside the DC's private TLS
directory. Its JSON output contains public certificate digests and check results,
with no key or credentials. Preserve that output as a separate correction record.
See [third-party licenses and dated dependency review](third-party-notices.md).
Production directory onboarding, full enterprise permission discovery, SMB
sessions and Windows member-server authorization are separate work.

Protocol references: [LDAP atomic modify](https://www.rfc-editor.org/rfc/rfc4511#section-4.6),
[immutable AD object identity](https://learn.microsoft.com/en-us/windows/win32/ad/object-names-and-identities),
[Samba directory tools](https://www.samba.org/samba/docs/current/man-html/samba-tool.8.html),
[ldap3 TLS configuration](https://ldap3.readthedocs.io/en/latest/ssltls.html).
