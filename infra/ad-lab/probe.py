"""Real bounded LDAP/Kerberos offboarding test, sanitized reports only."""
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys

import ldap
from health import connection

BASE = 'DC=adlab,DC=test'
checks = []
started = dt.datetime.now(dt.timezone.utc)
username = 'case_' + secrets.token_hex(6)
password = 'Aa1!' + secrets.token_urlsafe(32)
user_dn = f'CN={username},CN=Users,{BASE}'
group_dn = f'CN=Atlas-Readers,CN=Users,{BASE}'
admin = None
created = False
failure = False


def check(name, action):
    try:
        action()
        checks.append({'name': name, 'status': 'passed'})
    except Exception:
        checks.append({'name': name, 'status': 'failed'})
        raise RuntimeError(name) from None


def require(value):
    if not value:
        raise ValueError('Expected condition not observed')


def kerberos():
    result = subprocess.run(['kinit', username + '@ADLAB.TEST'], input=password + '\n',
                            text=True, capture_output=True, timeout=10)
    return result


try:
    krb = Path('/tmp/krb5.conf')
    krb.write_text('[libdefaults]\n default_realm = ADLAB.TEST\n dns_lookup_kdc = false\n'
                   ' rdns = false\n[realms]\n ADLAB.TEST = {\n kdc = dc.adlab.test\n }\n')
    os.environ['KRB5_CONFIG'] = str(krb)
    os.environ['KRB5CCNAME'] = 'FILE:/tmp/lab-ticket-' + username
    check('Verified TLS and correct directory naming context',
          lambda: require(connection().search_s('', ldap.SCOPE_BASE, '(objectClass=*)',
                          ['defaultNamingContext'])[0][1]['defaultNamingContext'] == [BASE.encode()]))
    def directory_dns():
        result = subprocess.run(['dig', '@dc.adlab.test', '_ldap._tcp.adlab.test', 'SRV', '+short'],
                                capture_output=True, text=True, timeout=5)
        require(result.returncode == 0 and '389 dc.adlab.test.' in result.stdout)
    check('Directory DNS advertises the actual LDAP service', directory_dns)
    admin = connection()
    admin.simple_bind_s('Administrator@ADLAB.TEST',
                        Path('/run/secrets/administrator_password').read_text())
    admin.add_s(user_dn, [
        ('objectClass', [b'top', b'person', b'organizationalPerson', b'user']),
        ('sAMAccountName', [username.encode()]), ('userPrincipalName', [(username + '@ADLAB.TEST').encode()]),
        ('userAccountControl', [b'512']), ('unicodePwd', [('"' + password + '"').encode('utf-16-le')]),
    ])
    created = True
    admin.modify_s(group_dn, [(ldap.MOD_ADD, 'member', [user_dn.encode()])])
    check('Synthetic account and group membership actually created',
          lambda: require(user_dn.encode() in admin.search_s(group_dn, ldap.SCOPE_BASE,
                          '(objectClass=*)', ['member'])[0][1]['member']))
    def login():
        user = connection()
        user.simple_bind_s(username + '@ADLAB.TEST', password)
        user.unbind_s()
    check('Active user can complete a new TLS directory sign-in', login)
    check('Active user can obtain a new Kerberos ticket', lambda: require(kerberos().returncode == 0))
    def bad_hostname():
        # Establish reachability first; a DNS/port failure is not a TLS denial.
        with socket.create_connection(('dc', 636), timeout=3):
            pass
        wrong = connection(host='dc')
        try:
            wrong.search_s('', ldap.SCOPE_BASE, '(objectClass=*)', ['defaultNamingContext'])
        except ldap.SERVER_DOWN:
            return
        finally:
            wrong.unbind_s()
        raise ValueError('Wrong TLS hostname accepted')
    check('Incorrect TLS hostname rejected', bad_hostname)
    def require_encrypted_auth():
        plaintext = connection(tls=False)
        try:
            plaintext.simple_bind_s('NONFUNCTIONAL_TEST_USER', 'NONFUNCTIONAL_TEST_PASSWORD')
        except (ldap.STRONG_AUTH_REQUIRED, ldap.CONFIDENTIALITY_REQUIRED):
            return
        finally:
            plaintext.unbind_s()
        raise ValueError('Expected encryption requirement not observed')
    check('Unencrypted password authentication rejected', require_encrypted_auth)
    admin.modify_s(group_dn, [(ldap.MOD_DELETE, 'member', [user_dn.encode()])])
    admin.modify_s(user_dn, [(ldap.MOD_REPLACE, 'userAccountControl', [b'514'])])
    check('Offboarding disabled account and removed project membership',
          lambda: require(admin.search_s(user_dn, ldap.SCOPE_BASE, '(objectClass=*)',
                          ['userAccountControl'])[0][1]['userAccountControl'] == [b'514']
                          and user_dn.encode() not in admin.search_s(group_dn, ldap.SCOPE_BASE,
                          '(objectClass=*)', ['member'])[0][1].get('member', [])))
    def denied_login():
        user = connection()
        try:
            user.simple_bind_s(username + '@ADLAB.TEST', password)
        except ldap.INVALID_CREDENTIALS:
            return
        finally:
            user.unbind_s()
        raise ValueError('Disabled account signed in')
    check('Disabled account cannot complete a new directory sign-in', denied_login)
    def denied_ticket():
        result = kerberos()
        require(result.returncode != 0 and 'credentials have been revoked' in result.stderr.lower())
    check('Disabled account cannot obtain a new Kerberos ticket', denied_ticket)
    check('Directory still healthy after containment',
          lambda: require(len(admin.search_s(BASE, ldap.SCOPE_BASE, '(objectClass=*)', ['objectGUID'])) == 1))
except Exception:
    failure = True
    if not any(item['status'] == 'failed' for item in checks):
        checks.append({'name': 'Test setup or execution', 'status': 'failed'})
finally:
    if created and admin is not None:
        try:
            admin.modify_s(user_dn, [(ldap.MOD_REPLACE, 'userAccountControl', [b'514'])])
        except Exception:
            failure = True
            checks.append({'name': 'Final synthetic fixture containment', 'status': 'failed'})
    if admin is not None:
        admin.unbind_s()
    report = {
        'origin': 'actual-local-samba-ad', 'startedAt': started.isoformat(),
        'finishedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
        'realm': 'ADLAB.TEST', 'fixture': username, 'checks': checks,
        'limitations': ['Samba AD-compatible directory, not Microsoft AD or Entra.',
                       'Existing sessions/tickets and application integration not tested.',
                       'Fixture history retained as a disabled directory account.'],
    }
    destination = Path('/reports')
    destination.mkdir(parents=True, exist_ok=True)
    data = json.dumps(report, indent=2)
    (destination / ('checks-' + started.strftime('%Y%m%dT%H%M%S') + '.json')).write_text(data)
    (destination / 'latest-report.json').write_text(data)
    print(json.dumps({'passed': sum(c['status'] == 'passed' for c in checks),
                      'failed': sum(c['status'] == 'failed' for c in checks), 'report': 'output/latest-report.json'}))
    sys.exit(1 if failure else 0)
