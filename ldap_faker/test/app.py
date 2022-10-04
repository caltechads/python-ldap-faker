import ldap


class MyLDAPClass:

    LDAP_URI = 'ldap://server'

    def __init__(self):
        pass

    def connect(self, dn: str = None, password: str = None):
        ldap_object: ldap.ldapobject.LDAPObject = ldap.initialize(self.LDAP_URI)
        ldap_object.set_option(ldap.OPT_REFERRALS, 0)
        ldap_object.set_option(ldap.OPT_NETWORK_TIMEOUT, 15.0)
        ldap_object.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ldap_object.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        ldap_object.start_tls_s()
        ldap_object.simple_bind_s(dn, password)
        return ldap_object
