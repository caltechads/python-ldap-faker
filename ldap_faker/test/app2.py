import ldap


class MyLDAPClass2:
    LDAP_URI = "ldap://server2"

    def __init__(self):
        pass

    def connect(self, dn: str | None = None, password: str | None = None):
        ldap_object: ldap.ldapobject.LDAPObject = ldap.initialize(self.LDAP_URI)  # type: ignore[attr-defined]
        ldap_object.set_option(ldap.OPT_REFERRALS, 0)  # type: ignore[attr-defined]
        ldap_object.set_option(ldap.OPT_NETWORK_TIMEOUT, 15.0)  # type: ignore[attr-defined]
        ldap_object.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)  # type: ignore[attr-defined]
        ldap_object.set_option(ldap.OPT_X_TLS_NEWCTX, 0)  # type: ignore[attr-defined]
        ldap_object.start_tls_s()  # type: ignore[attr-defined]
        ldap_object.simple_bind_s(dn, password)
        return ldap_object
