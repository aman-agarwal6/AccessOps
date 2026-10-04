# AccessOps AD lab

A real Samba Active Directory-compatible domain for local IAM practice. It uses
Ubuntu packages and your existing Docker installation, with synthetic records.
There is no cloud account, paid API or time-limited Windows Server license.
Samba is a separate AD-compatible implementation, not Microsoft AD or Entra ID.

This lab lives separately from AccessOps. It does not modify the application,
join your Windows computer to a domain, change Windows DNS or install a trusted
certificate. Application integration is a separate step.

## Start, verify and stop

From PowerShell in this directory:

```powershell
./Start-Lab.ps1               # Build if needed, generate private credentials, start.
./Test-Lab.ps1                # Actual synthetic offboarding scenario.
./Stop-Lab.ps1                # Stop; preserve directory and credentials.
./Start-Lab.ps1 -SkipBuild    # Reuse the built image and existing domain.
```

Docker Desktop must be running. The DC is capped at 768 MB RAM and 1.5 CPUs;
the temporary test client at 192 MB. No service port is published to Windows
or your LAN. The dedicated Docker network is internal, and the service is not
privileged. Its filesystem is read-only except for named directory/CA volumes
and explicit temporary runtime directories.

## Directory details

| Setting | Value |
| --- | --- |
| DNS domain | `adlab.test` |
| Kerberos realm | `ADLAB.TEST` |
| Short domain | `ADLAB` |
| Domain controller | `dc.adlab.test` |
| Directory base | `DC=adlab,DC=test` |
| Verified LDAP endpoint inside the lab | `ldaps://dc.adlab.test:636` |
| Docker network | `accessops-adlab_directory` |
| Seeded employee | `mara` / Mara Patel |
| Project access group | `Atlas-Readers` |
| Additional group | `IT-Operators` |

The LDAPS address is reachable inside the lab network, not directly from a
Windows browser. Passwords are generated and stored privately in
`.local/administrator-password.txt` and `.local/mara-password.txt`. Windows
permissions restrict those files to your account and SYSTEM. Open them locally
only when needed; never paste them into chat, source, command arguments or logs.
The test client receives the public CA certificate only, not its private key.

## Inspect the directory

These local administration commands need no password in a command argument:

```powershell
docker compose exec dc samba-tool user list --configfile=/var/lib/adlab/etc/smb.conf
docker compose exec dc samba-tool group listmembers Atlas-Readers --configfile=/var/lib/adlab/etc/smb.conf
docker compose exec dc samba-tool domain level show --configfile=/var/lib/adlab/etc/smb.conf
```

Local container administration is privileged directory access. An application
connector should use a separate account with explicitly delegated permissions,
not the Administrator credential used by this bounded test harness.

## What the checks establish

Each run creates a unique synthetic account and grants it membership in
`Atlas-Readers`. It verifies directory TLS, service-discovery DNS, active LDAP
sign-in and Kerberos ticket issuance. It checks denial of an incorrect TLS
hostname and unencrypted password authentication, then removes project
membership and disables the account. New LDAP sign-in and new Kerberos ticket
issuance must be denied while the directory remains healthy.

Reports under `output/` contain actual times, synthetic fixture names and check
results, with no passwords or raw authentication responses. Historical reports
are retained; `latest-report.json` identifies the most recent run. Test accounts
remain disabled for audit rather than being deleted. The seeded Mara account
and its lifecycle state are preserved by repeatable startup.

These checks do not establish revocation of existing tickets/sessions, Microsoft
AD interoperability, Entra integration, Windows domain join, access to a member
file server or AccessOps application integration. They demonstrate real local
directory behavior rather than browser-simulated effects.

## Maintenance and recovery

The Ubuntu base image is pinned by digest. Samba packages come from the signed
Ubuntu repositories; the installed package versions are recorded inside the
image at `/usr/share/lab-package-versions.txt`. Package resolution can change
when rebuilding; this is not a fully immutable package snapshot.

Review available security updates periodically and rebuild deliberately with
`docker compose build --no-cache`, then start and repeat the checks. Review any
base-image digest change separately. The local TLS certificates last one year;
renew them before expiry without disabling validation.

Stopping preserves the domain volume. Do not run `down -v`, delete volumes,
replace credentials or automatically reprovision a partially initialized domain.
Back up the lab's directory volume and protected credentials before substantial
changes. No broad Docker cleanup is needed.

Setup references: [Ubuntu Samba AD/DC guide](https://ubuntu.com/server/docs/how-to/samba/provision-samba-ad-controller/),
[Samba overview](https://www.samba.org/samba/what_is_samba.html),
[Samba provisioning API](https://github.com/samba-team/samba/blob/master/python/samba/provision/__init__.py).
