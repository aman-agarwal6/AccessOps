# Directory integration dependencies

AccessOps source remains under its repository license. These unmodified external
components retain their own licenses; their code is not copied into AccessOps.

The optional connector uses [ldap3 2.9.1](https://pypi.org/project/ldap3/2.9.1/),
copyright Giovanni Cannata, under
[GNU LGPLv3](https://github.com/cannatag/ldap3/blob/master/LICENSE.txt).
It is installed as a separate Python library from the hash-locked official wheel.
The wheel retains upstream notices and license. Source and replacement libraries
are available through the linked upstream project; no modified library is shipped.
Its parser dependency [pyasn1](https://github.com/pyasn1/pyasn1) uses the BSD license.

The optional standalone directory image installs unmodified
[Samba](https://www.samba.org/samba/what_is_samba.html) from signed Ubuntu package
repositories. Samba is licensed under
[GNU GPLv3](https://www.samba.org/samba/docs/GPL.html), with relevant additional
component licenses preserved in the distribution packages. The Docker recipe is
included, rather than a binary Samba distribution; Ubuntu source packages and the
[Samba source repository](https://git.samba.org/samba.git/) provide upstream source.
The lab source originated in the explicitly handed-over `accessops-ad-lab` local
project and is reproduced as an allowlist under `infra/ad-lab/`; no credentials,
directory state, private certificate keys, or runtime reports were copied.

On 2026-10-03, the exact PyPI package/version OSV queries for ldap3 2.9.1 and
pyasn1 0.6.4 returned no vulnerability records. The
[ldap3 upstream advisory page](https://github.com/cannatag/ldap3/security/advisories)
showed no published advisories. This is a dated database review, not a security
guarantee. ldap3's stable release dates to 2021-07-18; newer PyPI releases were
prereleases at review time. Its compatibility and strict TLS behavior must be
verified on the pinned Python 3.13 runtime. Do not silently install a prerelease
or relax certificate checks to accommodate its age.
