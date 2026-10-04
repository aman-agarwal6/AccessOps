"""Provision only the new isolated lab; never reset existing directory state."""
import contextlib
import io
import logging
import os
from pathlib import Path
import subprocess
import sys
import traceback

from samba.auth import system_session
from samba.param import LoadParm
from samba.provision import provision
from samba.samdb import SamDB
import ldb

ROOT = Path('/var/lib/adlab')
CONFIG = ROOT / 'etc/smb.conf'
BASE = 'DC=adlab,DC=test'


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup():
    database = ROOT / 'private/sam.ldb'
    complete = ROOT / 'provision-complete'
    if not complete.exists():
        if database.exists():
            raise RuntimeError('Partial domain exists; automatic reprovisioning refused')
        administrator_password = Path('/run/secrets/administrator_password').read_text()
        if len(administrator_password) < 32:
            raise ValueError('Generated administrator credential missing')
        logger = logging.getLogger('lab-provision')
        logger.addHandler(logging.NullHandler())
        logger.propagate = False
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            provision(logger, system_session(), targetdir=str(ROOT), realm='ADLAB.TEST',
                      domain='ADLAB', hostname='dc', hostip='10.247.240.10',
                      serverrole='active directory domain controller',
                      dns_backend='SAMBA_INTERNAL', adminpass=administrator_password,
                      use_rfc2307=True, useeadb=True, skip_sysvolacl=False)
        complete.write_text('Provision completed; do not replace this domain.\n')
        print('Isolated AD domain provisioned.', flush=True)

    tls = ROOT / 'private/lab-tls'
    tls.mkdir(mode=0o700, parents=True, exist_ok=True)
    public_ca = Path('/run/lab-ca/ca.crt')
    if not (tls / 'server.crt').exists():
        command('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '365',
                '-subj', '/CN=AD Lab Local CA', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                '-keyout', str(tls / 'ca.key'), '-out', str(tls / 'ca.crt'))
        command('openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes',
                '-subj', '/CN=dc.adlab.test', '-keyout', str(tls / 'server.key'),
                '-out', str(tls / 'server.csr'))
        extensions = tls / 'extensions.conf'
        extensions.write_text('subjectAltName=DNS:dc.adlab.test\nextendedKeyUsage=serverAuth\n'
                              'keyUsage=critical,digitalSignature,keyEncipherment\n'
                              'basicConstraints=critical,CA:FALSE\n')
        command('openssl', 'x509', '-req', '-in', str(tls / 'server.csr'),
                '-CA', str(tls / 'ca.crt'), '-CAkey', str(tls / 'ca.key'), '-CAcreateserial',
                '-days', '365', '-extfile', str(extensions), '-out', str(tls / 'server.crt'))
        for private_file in tls.glob('*.key'):
            private_file.chmod(0o600)
    public_ca.write_bytes((tls / 'ca.crt').read_bytes())
    public_ca.chmod(0o644)
    lp = LoadParm()
    lp.load(str(CONFIG))
    for name, value in {
        'tls enabled': 'yes', 'tls keyfile': str(tls / 'server.key'),
        'tls certfile': str(tls / 'server.crt'), 'tls cafile': str(public_ca),
        'ldap server require strong auth': 'yes', 'server signing': 'mandatory',
        'server min protocol': 'SMB3_11', 'pid directory': '/run/samba',
        'ntp signd socket directory': '/run/samba/ntp_signd',
        'log file': '/var/log/samba/log.%m', 'log level': '0',
    }.items():
        lp.set(name, value)
    lp.dump(False, str(CONFIG))
    db = SamDB(url=str(database), session_info=system_session(), lp=lp)
    if not (ROOT / 'seed-complete').exists():
        for group in ('Atlas-Readers', 'IT-Operators'):
            if not db.search(base=BASE, scope=ldb.SCOPE_SUBTREE,
                             expression=f'(sAMAccountName={group})', attrs=['dn']):
                db.newgroup(group)
        if not db.search(base=BASE, scope=ldb.SCOPE_SUBTREE,
                         expression='(sAMAccountName=mara)', attrs=['dn']):
            db.newuser('mara', Path('/run/secrets/mara_password').read_text(),
                       givenname='Mara', surname='Patel')
            db.add_remove_group_members('Atlas-Readers', ['mara'], add_members_operation=True)
        (ROOT / 'seed-complete').write_text('Synthetic seed created once; lifecycle state preserved.\n')
    db = None
    print('Directory TLS and synthetic fixture ready. Passwords remain private.', flush=True)
    os.execv('/usr/sbin/samba', ['samba', '--foreground', '--no-process-group',
                               '--debug-stdout', '--configfile=' + str(CONFIG)])


if __name__ == '__main__':
    try:
        setup()
    except Exception as error:
        frames = traceback.extract_tb(error.__traceback__)[-3:]
        # Never print exception values, local variables, credentials or raw responses.
        print('Lab setup failed: ' + type(error).__name__, file=sys.stderr)
        for frame in frames:
            print(f'  {Path(frame.filename).name}:{frame.lineno} {frame.name}', file=sys.stderr)
        raise SystemExit(1) from None
