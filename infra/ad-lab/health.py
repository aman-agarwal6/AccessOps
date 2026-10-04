"""Require verified directory TLS and RootDSE; no authentication secret needed."""
import ldap


def connection(host='dc.adlab.test', tls=True):
    directory = ldap.initialize(('ldaps' if tls else 'ldap') + '://' + host)
    directory.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
    directory.set_option(ldap.OPT_TIMEOUT, 5)
    directory.set_option(ldap.OPT_REFERRALS, 0)
    if tls:
        directory.set_option(ldap.OPT_X_TLS_CACERTFILE, '/run/lab-ca/ca.crt')
        directory.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        directory.set_option(ldap.OPT_X_TLS_REQUIRE_SAN, ldap.OPT_X_TLS_DEMAND)
        directory.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    return directory


if __name__ == '__main__':
    try:
        directory = connection()
        rows = directory.search_s('', ldap.SCOPE_BASE, '(objectClass=*)', ['defaultNamingContext'])
        assert rows[0][1]['defaultNamingContext'] == [b'DC=adlab,DC=test']
        directory.unbind_s()
    except Exception:
        raise SystemExit(1) from None
