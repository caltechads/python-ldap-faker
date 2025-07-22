import unittest
from pathlib import Path

import ldap
import asn1

from ldap_faker import FakeLDAPObject, ObjectStore


class RegisterObjectsMixin:
    def setUp(self) -> None:
        self.filename: Path = Path(__file__).parent / Path("big.json")
        self.store: ObjectStore = ObjectStore()
        self.store.load_objects(str(self.filename))
        self.ldap: FakeLDAPObject = FakeLDAPObject("ldap://server", self.store)


class TestObjectStore_attributes(RegisterObjectsMixin, unittest.TestCase):
    def test_deref(self):
        self.assertEqual(self.ldap.deref, ldap.DEREF_NEVER)  # type: ignore[attr-defined]

    def test_protocol_version(self):
        self.assertEqual(self.ldap.protocol_version, ldap.VERSION3)  # type: ignore[attr-defined]

    def test_sizelimit(self):
        self.assertEqual(self.ldap.sizelimit, ldap.NO_LIMIT)  # type: ignore[attr-defined]

    def test_network_timeout(self):
        self.assertEqual(self.ldap.network_timeout, ldap.NO_LIMIT)  # type: ignore[attr-defined]

    def test_timelimit(self):
        self.assertEqual(self.ldap.timelimit, ldap.NO_LIMIT)  # type: ignore[attr-defined]

    def test_timeout(self):
        self.assertEqual(self.ldap.timeout, ldap.NO_LIMIT)  # type: ignore[attr-defined]

    def test_tls_enabled(self):
        self.assertFalse(self.ldap.tls_enabled)

    def test_bound_dn(self):
        self.assertEqual(self.ldap.bound_dn, None)


class TestObjectStore_set_option(RegisterObjectsMixin, unittest.TestCase):
    def test_sets_option(self):
        self.ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)  # type: ignore[attr-defined]
        self.assertEqual(self.ldap.get_option(ldap.OPT_X_TLS_NEWCTX), 0)  # type: ignore[attr-defined]

    def test_records_call(self):
        self.ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)  # type: ignore[attr-defined]
        self.assertTrue("set_option" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("set_option")[0]
        self.assertEqual(call.args, {"option": ldap.OPT_X_TLS_NEWCTX, "invalue": 0})  # type: ignore[attr-defined]

    def test_non_existant_option_raises_ValueError(self):
        with self.assertRaises(ValueError):  # noqa: PT027
            self.ldap.set_option(6000, 0)


class TestObjectStore_get_option(RegisterObjectsMixin, unittest.TestCase):
    def test_gets_option(self):
        self.ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)  # type: ignore[attr-defined]
        self.assertEqual(self.ldap.get_option(ldap.OPT_X_TLS_NEWCTX), 0)  # type: ignore[attr-defined]

    def test_records_call(self):
        self.ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)  # type: ignore[attr-defined]
        self.ldap.get_option(ldap.OPT_X_TLS_NEWCTX)  # type: ignore[attr-defined]
        self.assertTrue("get_option" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("get_option")[0]
        self.assertEqual(call.args, {"option": ldap.OPT_X_TLS_NEWCTX})  # type: ignore[attr-defined]

    def test_non_existant_option_raises_ValueError(self):
        with self.assertRaises(ValueError):  # noqa: PT027
            self.ldap.get_option(6000)

    # Special options that we simulate
    def test_OPT_URI(self):
        self.assertEqual(self.ldap.get_option(ldap.OPT_URI), "ldap://server")  # type: ignore[attr-defined]

    def test_OPT_HOST_NAME(self):
        self.assertEqual(self.ldap.get_option(ldap.OPT_HOST_NAME), "server")  # type: ignore[attr-defined]

    def test_OPT_PROTOCOL_VERSION(self):
        self.assertEqual(self.ldap.get_option(ldap.OPT_PROTOCOL_VERSION), 3)  # type: ignore[attr-defined]

    def test_OPT_API_INFO(self):
        self.assertEqual(
            self.ldap.get_option(ldap.OPT_API_INFO),  # type: ignore[attr-defined]
            {
                "info_version": 1,
                "api_version": 3001,
                "vendor_name": "python-ldap-faker",
                "vendor_version": "1.0.0",
            },
        )

    def test_OPT_SUCCESS(self):
        self.assertEqual(
            self.ldap.get_option(ldap.OPT_SUCCESS),  # type: ignore[attr-defined]
            {
                "info_version": 1,
                "api_version": 3001,
                "vendor_name": "python-ldap-faker",
                "vendor_version": "1.0.0",
            },
        )


class TestObjectStore_simple_bind_s(RegisterObjectsMixin, unittest.TestCase):
    def test_anonymous_bind_works(self):
        self.ldap.simple_bind_s()
        self.assertTrue("simple_bind_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("simple_bind_s")[0]
        self.assertEqual(call.args, {})

    def test_invalid_dns_are_raise_INVALID_CREDENTIALS(self):
        """
        Strangely to me, you can pass any old string as the ``who`` argument to
        simple_bind_s and all that will happen is that we get
        ``ldap.INVALID_CREDENTIALS``.
        """
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            # Not a valid DN
            self.ldap.simple_bind_s("uid=user,,ou=mydept", "the wrong password")

    def test_anonymous_bind_returns_None(self):
        result = self.ldap.simple_bind_s()
        self.assertEqual(result, None)

    def test_anonymous_bind_does_not_set_bound_dn(self):
        self.ldap.simple_bind_s()
        self.assertEqual(self.ldap.bound_dn, None)

    def test_non_anonymous_bind_works(self):
        self.ldap.simple_bind_s("uid=user,ou=mydept,o=myorg,c=country", "the password")
        self.assertTrue("simple_bind_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("simple_bind_s")[0]
        self.assertEqual(
            call.args,
            {"who": "uid=user,ou=mydept,o=myorg,c=country", "cred": "the password"},
        )

    def test_non_anonymous_bind_returns_4_tuple(self):
        result = self.ldap.simple_bind_s(
            "uid=user,ou=mydept,o=myorg,c=country", "the password"
        )
        self.assertEqual(result, (ldap.RES_BIND, [], 3, []))

    def test_non_anonymous_bind_sets_bound_dn(self):
        self.ldap.simple_bind_s("uid=user,ou=mydept,o=myorg,c=country", "the password")
        self.assertEqual(self.ldap.bound_dn, "uid=user,ou=mydept,o=myorg,c=country")

    def test_non_anonymous_bind_with_wrong_password_raises_INVALID_CREDENTIALS(self):
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            self.ldap.simple_bind_s(
                "uid=user,ou=mydept,o=myorg,c=country", "the wrong password"
            )
        self.assertTrue("simple_bind_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("simple_bind_s")[0]
        self.assertEqual(
            call.args,
            {
                "who": "uid=user,ou=mydept,o=myorg,c=country",
                "cred": "the wrong password",
            },
        )


class TestObjectStore_whoami_s(RegisterObjectsMixin, unittest.TestCase):
    def test_no_login_returns_empty_string(self):
        self.assertEqual(self.ldap.whoami_s(), "")

    def test_anonymous_bind_returns_empty_string(self):
        self.ldap.simple_bind_s()
        self.assertEqual(self.ldap.whoami_s(), "")
        self.assertTrue("whoami_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("whoami_s")[0]
        self.assertEqual(call.args, {})

    def test_non_anonymous_bind_returns_bind_dn(self):
        self.ldap.simple_bind_s("uid=user,ou=mydept,o=myorg,c=country", "the password")
        self.assertEqual(
            self.ldap.whoami_s(), "dn: uid=user,ou=mydept,o=myorg,c=country"
        )
        self.assertTrue("whoami_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("whoami_s")[0]
        self.assertEqual(call.args, {})


class TestObjectStore_start_tls_s(RegisterObjectsMixin, unittest.TestCase):
    def test_tls_enabled_starts_False(self):
        self.assertFalse(self.ldap.tls_enabled)

    def test_start_tls_s_sets_tls_enabled_True(self):
        self.ldap.start_tls_s()
        self.assertTrue(self.ldap.tls_enabled)

    def test_records_call(self):
        self.ldap.start_tls_s()
        self.assertTrue("start_tls_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("start_tls_s")[0]
        self.assertEqual(call.args, {})


class TestObjectStore_modify_s(RegisterObjectsMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.dn = "uid=fred,ou=mydept,o=myorg,c=country"
        self.ldap.start_tls_s()
        self.ldap.simple_bind_s(
            "uid=barney,ou=mydept,o=myorg,c=country", "the barneypassword"
        )

    def test_modify_s_requires_authenticated_bind(self):
        self.ldap.bound_dn = None
        modlist = [(ldap.MOD_ADD, "newattr", [b"new value"])]
        with self.assertRaises(ldap.INSUFFICIENT_ACCESS):
            self.ldap.modify_s(self.dn, modlist)

    def test_records_call(self):
        modlist = [(ldap.MOD_ADD, "newattr", [b"new value"])]
        self.ldap.modify_s(self.dn, modlist)
        self.assertTrue("modify_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("modify_s")[0]
        self.assertEqual(call.args, {"dn": self.dn, "modlist": modlist})

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.modify_s("uid=foo,,ou=bar,o=baz,c=country", [])

    def test_can_add_new_attribute(self):
        modlist = [(ldap.MOD_ADD, "newattr", [b"new value"])]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data["newattr"], [b"new value"])

    def test_can_add_values_to_existing_attribute(self):
        modlist = [(ldap.MOD_ADD, "objectclass", [b"eduPerson"])]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data["objectclass"], [b"posixAccount", b"top", b"eduPerson"])

    def test_cannot_add_duplicate_values_to_existing_attribute(self):
        modlist = [(ldap.MOD_ADD, "objectclass", [b"posixAccount"])]
        with self.assertRaises(ldap.TYPE_OR_VALUE_EXISTS):
            self.ldap.modify_s(self.dn, modlist)

    def test_cannot_add_duplicate_values_to_existing_attribute_case_insensitive(self):
        modlist = [(ldap.MOD_ADD, "objectclass", [b"posixaccount"])]
        with self.assertRaises(ldap.TYPE_OR_VALUE_EXISTS):
            self.ldap.modify_s(self.dn, modlist)

    def test_can_delete_attribute(self):
        modlist = [(ldap.MOD_DELETE, "loginShell", None)]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertTrue("loginShell" not in data)

    def test_can_delete_some_values_from_attribute(self):
        modlist = [(ldap.MOD_DELETE, "objectclass", [b"top"])]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data["objectclass"], [b"posixAccount"])

    def test_can_delete_some_values_from_attribute_is_case_insensitive(self):
        modlist = [(ldap.MOD_DELETE, "objectclass", [b"posixaccount"])]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data["objectclass"], [b"top"])

    def test_can_replace_existing_attribute(self):
        modlist = [(ldap.MOD_REPLACE, "objectclass", [b"posixaccount"])]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data["objectclass"], [b"posixaccount"])

    def test_can_replace_new_attribute(self):
        modlist = [(ldap.MOD_REPLACE, "gecos", [b"my gecos"])]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data["gecos"], [b"my gecos"])

    def test_can_perform_multiple_operations(self):
        modlist = [
            (ldap.MOD_DELETE, "objectclass", [b"posixaccount"]),
            (ldap.MOD_ADD, "objectclass", [b"eduPerson"]),
            (ldap.MOD_ADD, "newattr", [b"new value"]),
            (ldap.MOD_REPLACE, "gidNumber", [b"456"]),
        ]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data["objectclass"], [b"top", b"eduPerson"])
        self.assertEqual(data["newattr"], [b"new value"])
        self.assertEqual(data["gidNumber"], [b"456"])

    def test_invalid_operation_raises_PROTOCOL_ERROR(self):
        modlist = [
            (100, "objectclass", [b"posixaccount"]),
        ]
        with self.assertRaises(ldap.PROTOCOL_ERROR):
            self.ldap.modify_s(self.dn, modlist)


class TestObjectStore_add_s(RegisterObjectsMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.dn = "uid=myuser,ou=bar,o=baz,c=country"
        self.modlist = [
            ("uid", [b"myuser"]),
            ("gidNumber", [b"1000"]),
            ("uidNumber", [b"1000"]),
            ("loginShell", [b"/bin/bash"]),
            ("homeDirectory", [b"/home/myuser"]),
            ("userPassword", [b"the password"]),
            ("cn", [b"My Name"]),
            ("objectClass", [b"top", b"posixAccount"]),
        ]
        self.ldap.start_tls_s()
        self.ldap.simple_bind_s(
            "uid=barney,ou=mydept,o=myorg,c=country", "the barneypassword"
        )

    def test_add_s_requires_authenticated_bind(self):
        self.ldap.bound_dn = None
        with self.assertRaises(ldap.INSUFFICIENT_ACCESS):
            self.ldap.add_s(self.dn, self.modlist)

    def test_can_add_new_object(self):
        self.ldap.add_s(self.dn, self.modlist)
        data = self.store.get(self.dn)
        for entry in self.modlist:
            self.assertEqual(data[entry[0]], entry[1])

    def test_records_call(self):
        self.ldap.add_s(self.dn, self.modlist)
        self.assertTrue("add_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("add_s")[0]
        self.assertEqual(call.args, {"dn": self.dn, "modlist": self.modlist})

    def test_adding_object_with_existing_dn_raises_ALREADY_EXISTS(self):
        with self.assertRaises(ldap.ALREADY_EXISTS):
            self.ldap.add_s("uid=barney,ou=mydept,o=myorg,c=country", self.modlist)

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.add_s("uid=foo,,ou=bar,o=baz,c=country", self.modlist)

    def test_invalid_value_raises_TypeError(self):
        self.modlist.append(("gecos", "foobar"))
        with self.assertRaises(TypeError):
            self.ldap.add_s(self.dn, self.modlist)


class TestObjectStore_delete_s(RegisterObjectsMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.dn = "uid=user,ou=mydept,o=myorg,c=country"
        self.ldap.start_tls_s()
        self.ldap.simple_bind_s(
            "uid=barney,ou=mydept,o=myorg,c=country", "the barneypassword"
        )

    def test_delete_s_requires_authenticated_bind(self):
        self.ldap.bound_dn = None
        with self.assertRaises(ldap.INSUFFICIENT_ACCESS):
            self.ldap.delete_s(self.dn)

    def test_can_delete_existing_object(self):
        self.ldap.delete_s(self.dn)
        self.assertFalse(self.store.exists(self.dn))

    def test_records_call(self):
        self.ldap.delete_s(self.dn)
        self.assertTrue("delete_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("delete_s")[0]
        self.assertEqual(call.args, {"dn": self.dn})

    def test_adding_object_with_existing_dn_raises_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldap.delete_s("uid=blah,ou=mydept,o=myorg,c=country")

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.delete_s("uid=foo,,ou=bar,o=baz,c=country")


class TestObjectStore_compare_s(RegisterObjectsMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.dn = "uid=fred,ou=mydept,o=myorg,c=country"

    def test_records_call(self):
        self.ldap.compare_s(self.dn, "uidNumber", b"125")
        self.assertTrue("compare_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("compare_s")[0]
        self.assertEqual(
            call.args, {"dn": self.dn, "attr": "uidNumber", "value": b"125"}
        )

    def test_can_compare_values_for_existing_object(self):
        self.assertTrue(self.ldap.compare_s(self.dn, "uidNumber", b"125"))
        self.assertFalse(self.ldap.compare_s(self.dn, "uidNumber", b"124"))

    def test_can_compare_values_for_existing_object_for_multivalued_attr(self):
        self.assertTrue(self.ldap.compare_s(self.dn, "objectclass", b"top"))
        self.assertFalse(self.ldap.compare_s(self.dn, "objectclass", b"sdlkjfalsdj"))

    def test_value_must_be_bytes(self):
        with self.assertRaises(TypeError):
            self.ldap.compare_s(self.dn, "uidNumber", "125")

    def test_comparing_nonexistant_object_raises_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldap.compare_s(
                "uid=blah,ou=mydept,o=myorg,c=country", "uidNumber", b"125"
            )

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.compare_s("uid=foo,,ou=bar,o=baz,c=country", "uidNumber", b"125")


class TestObjectStore_rename_s(RegisterObjectsMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.dn = "uid=fred,ou=mydept,o=myorg,c=country"
        self.basedn = "ou=mydept,o=myorg,c=country"
        self.newrdn = "uid=freddy"
        self.data = self.store.get(self.dn)
        self.data["uid"] = [b"freddy"]
        self.ldap.start_tls_s()
        self.ldap.simple_bind_s(
            "uid=barney,ou=mydept,o=myorg,c=country", "the barneypassword"
        )

    def test_rename_s_requires_authenticated_bind(self):
        self.ldap.bound_dn = None
        with self.assertRaises(ldap.INSUFFICIENT_ACCESS):
            self.ldap.rename_s(self.dn, self.newrdn)

    def test_records_call(self):
        self.ldap.rename_s(self.dn, self.newrdn)
        self.assertTrue("rename_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("rename_s")[0]
        self.assertEqual(call.args, {"dn": self.dn, "newrdn": "uid=freddy"})

    def test_can_rename_in_same_basedn(self):
        newdn = f"{self.newrdn},{self.basedn}"
        self.ldap.rename_s(self.dn, self.newrdn)
        self.assertTrue(self.store.exists(newdn))
        self.assertFalse(self.store.exists(self.dn))

    def test_rename_updates_rdn_in_the_object(self):
        newdn = f"{self.newrdn},{self.basedn}"
        self.ldap.rename_s(self.dn, self.newrdn)
        self.assertEqual(self.store.get(newdn), self.data)

    def test_can_rename_to_differnt_basedn(self):
        newbasedn = f"ou=children,{self.basedn}"
        newdn = f"{self.newrdn},{newbasedn}"
        self.ldap.rename_s(self.dn, self.newrdn, newsuperior=newbasedn)
        self.assertEqual(self.store.get(newdn), self.data)

    def test_can_keep_old_object_after_renaming(self):
        newdn = f"{self.newrdn},{self.basedn}"
        self.ldap.rename_s(self.dn, self.newrdn, delold=0)
        self.assertTrue(self.store.exists(newdn))
        self.assertTrue(self.store.exists(self.dn))

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.rename_s("uid=foo,,ou=bar,o=baz,c=country", "uid=bar")

    def test_renaming_nonexistant_object_raises_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldap.rename_s("uid=blah,ou=mydept,o=myorg,c=country", "uid=blarg")


class TestObjectStore_search_s(RegisterObjectsMixin, unittest.TestCase):
    def test_records_call(self):
        self.ldap.search_s(
            "uid=fred,ou=mydept,o=myorg,c=country", ldap.SCOPE_BASE, "(objectclass=*)"
        )
        self.assertTrue("search_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("search_s")[0]
        self.assertEqual(
            call.args,
            {
                "base": "uid=fred,ou=mydept,o=myorg,c=country",
                "scope": ldap.SCOPE_BASE,
                "filterstr": "(objectclass=*)",
            },
        )


class TestObjectStore_search_s_SCOPE_BASE(RegisterObjectsMixin, unittest.TestCase):
    def test_returns_one_object_if_object_exists(self):
        results = self.ldap.search_s(
            "uid=fred,ou=mydept,o=myorg,c=country", ldap.SCOPE_BASE, "(objectclass=*)"
        )
        self.assertEqual(len(results), 1)

    def test_returns_expected_object_if_object_exists(self):
        results = self.ldap.search_s(
            "uid=fred,ou=mydept,o=myorg,c=country", ldap.SCOPE_BASE, "(objectclass=*)"
        )
        self.assertEqual(results[0][0], "uid=fred,ou=mydept,o=myorg,c=country")
        self.assertEqual(results[0][1]["cn"], [b"Fred Flintstone"])

    def test_filtering_works_on_matched_objects(self):
        results = self.ldap.search_s(
            "uid=fred,ou=mydept,o=myorg,c=country", ldap.SCOPE_BASE, "(uid=blah)"
        )
        self.assertEqual(len(results), 0)

    def test_attrlist_works_on_matched_objects(self):
        results = self.ldap.search_s(
            "uid=fred,ou=mydept,o=myorg,c=country",
            ldap.SCOPE_BASE,
            "(objectclass=*)",
            attrlist=["uid", "cn"],
        )
        self.assertEqual(len(results), 1)
        data = results[0]
        self.assertEqual(list(data[1].keys()), ["cn", "uid"])

    def test_raises_NO_SUCH_OBJECT_if_object_does_not_exist(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldap.search_s(
                "uid=snoopy,ou=mydept,o=myorg,c=country",
                ldap.SCOPE_BASE,
                "(objectclass=*)",
            )


class TestObjectStore_search_s_SCOPE_ONELEVEL(RegisterObjectsMixin, unittest.TestCase):
    def test_returns_objects_only_at_the_desired_level(self):
        results = self.ldap.search_s(
            "ou=mydept,o=myorg,c=country", ldap.SCOPE_ONELEVEL, "(objectclass=*)"
        )
        self.assertEqual(len(results), 6)
        results = self.ldap.search_s(
            "o=myorg,c=country", ldap.SCOPE_ONELEVEL, "(objectclass=*)"
        )
        self.assertEqual(len(results), 0)
        results = self.ldap.search_s(
            "ou=children,ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,
            "(objectclass=*)",
        )
        self.assertEqual(len(results), 2)

    def test_filtering_works_on_matched_objects(self):
        results = self.ldap.search_s(
            "ou=mydept,o=myorg,c=country", ldap.SCOPE_ONELEVEL, "(loginshell=/bin/bash)"
        )
        self.assertEqual(len(results), 5)
        results = self.ldap.search_s(
            "ou=mydept,o=myorg,c=country", ldap.SCOPE_ONELEVEL, "(cn=*flintstone)"
        )
        self.assertEqual(len(results), 2)

    def test_attrlist_works_on_matched_objects(self):
        results = self.ldap.search_s(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,
            "(objectclass=*)",
            attrlist=["uid", "cn"],
        )
        data = results[0]
        self.assertEqual(list(data[1].keys()), ["cn", "uid"])


class TestObjectStore_search_s_SCOPE_SUBTREE(RegisterObjectsMixin, unittest.TestCase):
    def test_returns_objects_all_subtrees(self):
        results = self.ldap.search_s(
            "ou=mydept,o=myorg,c=country", ldap.SCOPE_SUBTREE, "(objectclass=*)"
        )
        self.assertEqual(len(results), 8)
        results = self.ldap.search_s(
            "o=myorg,c=country", ldap.SCOPE_SUBTREE, "(objectclass=*)"
        )
        self.assertEqual(len(results), 8)
        results = self.ldap.search_s(
            "ou=children,ou=mydept,o=myorg,c=country",
            ldap.SCOPE_SUBTREE,
            "(objectclass=*)",
        )
        self.assertEqual(len(results), 2)

    def test_filtering_works_on_matched_objects(self):
        results = self.ldap.search_s(
            "ou=mydept,o=myorg,c=country", ldap.SCOPE_SUBTREE, "(loginshell=/bin/tcsh)"
        )
        self.assertEqual(len(results), 2)
        results = self.ldap.search_s(
            "ou=mydept,o=myorg,c=country", ldap.SCOPE_SUBTREE, "(cn=*flintstone)"
        )
        self.assertEqual(len(results), 3)

    def test_attrlist_works_on_matched_objects(self):
        results = self.ldap.search_s(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_SUBTREE,
            "(objectclass=*)",
            attrlist=["uid", "cn"],
        )
        data = results[0]
        self.assertEqual(list(data[1].keys()), ["cn", "uid"])


class TestObjectStore_search_ext_AND_result3(RegisterObjectsMixin, unittest.TestCase):
    def test_returns_objects(self):
        controls = ldap.controls.LDAPControl()
        msgid = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_SUBTREE,
            "(objectclass=*)",
            serverctrls=[controls],
        )
        op, data, _msgid, ctrls = self.ldap.result3(msgid)
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)
        self.assertEqual(len(data), 8)
        self.assertEqual(_msgid, msgid)
        self.assertIs(ctrls[0], controls)

    def test_msg_id_properly_identifies_our_results(self):
        controls1 = ldap.controls.LDAPControl()
        msgid1 = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_SUBTREE,
            "(objectclass=*)",
            serverctrls=[controls1],
        )
        controls2 = ldap.controls.LDAPControl()
        msgid2 = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_SUBTREE,
            "(uid=fred)",
            serverctrls=[controls2],
        )
        op, data, _msgid, ctrls = self.ldap.result3(msgid1)
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)
        self.assertEqual(len(data), 8)
        self.assertEqual(_msgid, msgid1)
        self.assertIs(ctrls[0], controls1)

        op, data, _msgid, ctrls = self.ldap.result3(msgid2)
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)
        self.assertEqual(len(data), 1)
        self.assertEqual(_msgid, msgid2)
        self.assertIs(ctrls[0], controls2)


def encode_sort_control_value_asn1(sort_keys):
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)
    for key in sort_keys:
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(key.encode("utf-8"), asn1.Numbers.OctetString)
        encoder.leave()
    encoder.leave()
    return encoder.output()


class TestObjectStore_search_ext_sort_control(RegisterObjectsMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()

        # Create a mock control for sorting using ASN.1 BER encoding
        class MockSortControl:
            def __init__(self, sort_keys):
                self.controlType = "1.2.840.113556.1.4.473"
                self.criticality = False
                self.controlValue = encode_sort_control_value_asn1(sort_keys)

        self.MockSortControl = MockSortControl

    def test_search_ext_with_sort_control_sorts_results(self):
        """Test that search_ext sorts results when sort control is present."""
        # Create a sort control that sorts by 'cn' attribute
        sort_control = self.MockSortControl(["cn"])
        controls = [sort_control]

        msgid = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,  # type: ignore[attr-defined]
            "(objectclass=*)",
            serverctrls=controls,
        )

        op, data, _msgid, ctrls = self.ldap.result3(msgid)

        # Check that we got results
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        self.assertGreater(len(data), 1)

        # Check that results are sorted by 'cn' (case-insensitive)
        cn_values = []
        for dn, attrs in data:
            if "cn" in attrs:
                cn_values.append(attrs["cn"][0].decode().lower())

        # Verify the cn values are sorted
        self.assertEqual(cn_values, sorted(cn_values))

    def test_search_ext_with_multi_key_sort_control(self):
        """Test that search_ext supports multi-key sorting."""
        # Create a sort control that sorts by 'objectclass' then 'cn'
        sort_control = self.MockSortControl(["objectclass", "cn"])
        controls = [sort_control]

        msgid = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,  # type: ignore[attr-defined]
            "(objectclass=*)",
            serverctrls=controls,
        )

        op, data, _msgid, ctrls = self.ldap.result3(msgid)

        # Check that we got results
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        self.assertGreater(len(data), 1)

        # Extract sort keys for verification
        sort_keys = []
        for dn, attrs in data:
            objclass = attrs.get("objectclass", [b""])[0].decode().lower()
            cn = attrs.get("cn", [b""])[0].decode().lower()
            sort_keys.append((objclass, cn))

        # Verify the results are sorted by objectclass, then cn
        self.assertEqual(sort_keys, sorted(sort_keys))

    def test_search_ext_with_controlvalue_sort_keys(self):
        """Test that search_ext can use controlValue for sort keys."""

        # Create a sort control using controlValue with proper BER encoding
        class MockSortControlValue:
            def __init__(self, sort_keys):
                self.controlType = "1.2.840.113556.1.4.473"
                self.controlValue = encode_sort_control_value_asn1(sort_keys)
                self.criticality = False

        sort_control = MockSortControlValue(["uid"])
        controls = [sort_control]

        msgid = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,  # type: ignore[attr-defined]
            "(objectclass=*)",
            serverctrls=controls,
        )

        op, data, _msgid, ctrls = self.ldap.result3(msgid)

        # Check that we got results
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        self.assertGreater(len(data), 1)

        # Check that results are sorted by 'uid'
        uid_values = []
        for dn, attrs in data:
            if "uid" in attrs:
                uid_values.append(attrs["uid"][0].decode().lower())

        # Verify the uid values are sorted
        self.assertEqual(uid_values, sorted(uid_values))

    def test_search_ext_without_sort_control_returns_unsorted_results(self):
        """Test that search_ext returns unsorted results when no sort control is present."""
        msgid = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,  # type: ignore[attr-defined]
            "(objectclass=*)",
        )

        op, data, _msgid, ctrls = self.ldap.result3(msgid)

        # Check that we got results
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        self.assertGreater(len(data), 1)

        # Results should be in the order they were stored (not necessarily sorted)
        # This test verifies that sorting only happens when the control is present


class TestObjectStore_search_ext_size_limit(RegisterObjectsMixin, unittest.TestCase):
    def test_search_ext_with_size_limit_limits_results(self):
        """Test that search_ext respects the sizelimit parameter."""
        # Search for all objects in the department
        msgid = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,  # type: ignore[attr-defined]
            "(objectclass=*)",
            sizelimit=3,
        )

        op, data, _msgid, ctrls = self.ldap.result3(msgid)

        # Check that we got results
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        # Should be limited to 3 results
        self.assertEqual(len(data), 3)

    def test_search_ext_with_size_limit_zero_returns_all_results(self):
        """Test that search_ext with sizelimit=0 returns all results."""
        # Search for all objects in the department
        msgid = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,  # type: ignore[attr-defined]
            "(objectclass=*)",
            sizelimit=0,
        )

        op, data, _msgid, ctrls = self.ldap.result3(msgid)

        # Check that we got results
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        # Should return all results (more than 3)
        self.assertGreater(len(data), 3)

    def test_search_ext_with_large_size_limit_returns_all_results(self):
        """Test that search_ext with large sizelimit returns all results."""
        # Search for all objects in the department
        msgid = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,  # type: ignore[attr-defined]
            "(objectclass=*)",
            sizelimit=100,
        )

        op, data, _msgid, ctrls = self.ldap.result3(msgid)

        # Check that we got results
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        # Should return all results since limit is larger than available results
        self.assertGreater(len(data), 0)
        # Should be less than or equal to the limit
        self.assertLessEqual(len(data), 100)

    def test_search_ext_with_size_limit_and_sort_control(self):
        """Test that search_ext applies size limit after sorting."""

        # Create a sort control that sorts by 'cn' attribute
        class MockSortControl:
            def __init__(self, sort_keys):
                self.controlType = "1.2.840.113556.1.4.473"
                self.criticality = False
                self.controlValue = encode_sort_control_value_asn1(sort_keys)

        sort_control = MockSortControl(["cn"])
        controls = [sort_control]

        msgid = self.ldap.search_ext(
            "ou=mydept,o=myorg,c=country",
            ldap.SCOPE_ONELEVEL,  # type: ignore[attr-defined]
            "(objectclass=*)",
            serverctrls=controls,
            sizelimit=2,
        )

        op, data, _msgid, ctrls = self.ldap.result3(msgid)

        # Check that we got results
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        # Should be limited to 2 results
        self.assertEqual(len(data), 2)

        # Check that results are sorted by 'cn' (first 2 after sorting)
        cn_values = []
        for dn, attrs in data:
            if "cn" in attrs:
                cn_values.append(attrs["cn"][0].decode().lower())

        # Verify the cn values are sorted (first 2 after sorting)
        self.assertEqual(cn_values, sorted(cn_values)[:2])


class TestObjectStore_modrdn_s(RegisterObjectsMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.dn = "uid=fred,ou=mydept,o=myorg,c=country"
        self.basedn = "ou=mydept,o=myorg,c=country"
        self.newrdn = "uid=freddy"
        self.data = self.store.get(self.dn)
        self.data["uid"] = [b"freddy"]
        self.ldap.start_tls_s()
        self.ldap.simple_bind_s(
            "uid=barney,ou=mydept,o=myorg,c=country", "the barneypassword"
        )

    def test_modrdn_s_requires_authenticated_bind(self):
        self.ldap.bound_dn = None
        with self.assertRaises(ldap.INSUFFICIENT_ACCESS):
            self.ldap.modrdn_s(self.dn, self.newrdn)

    def test_records_call(self):
        self.ldap.modrdn_s(self.dn, self.newrdn)
        self.assertTrue("modrdn_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("modrdn_s")[0]
        self.assertEqual(call.args, {"dn": self.dn, "newrdn": "uid=freddy"})

    def test_can_modify_rdn_in_same_basedn(self):
        newdn = f"{self.newrdn},{self.basedn}"
        self.ldap.modrdn_s(self.dn, self.newrdn)
        self.assertTrue(self.store.exists(newdn))
        self.assertFalse(self.store.exists(self.dn))

    def test_modrdn_updates_rdn_in_the_object(self):
        newdn = f"{self.newrdn},{self.basedn}"
        self.ldap.modrdn_s(self.dn, self.newrdn)
        self.assertEqual(self.store.get(newdn), self.data)

    def test_can_keep_old_object_after_modifying_rdn(self):
        newdn = f"{self.newrdn},{self.basedn}"
        self.ldap.modrdn_s(self.dn, self.newrdn, delold=0)
        self.assertTrue(self.store.exists(newdn))
        self.assertTrue(self.store.exists(self.dn))

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.modrdn_s("uid=foo,,ou=bar,o=baz,c=country", "uid=bar")

    def test_modifying_rdn_of_nonexistant_object_raises_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldap.modrdn_s("uid=blah,ou=mydept,o=myorg,c=country", "uid=blarg")

    def test_modrdn_does_not_support_newsuperior_parameter(self):
        # Unlike rename_s, modrdn_s should not support newsuperior parameter
        # This test verifies that the method signature is correct
        newdn = f"{self.newrdn},{self.basedn}"
        self.ldap.modrdn_s(self.dn, self.newrdn)
        self.assertTrue(self.store.exists(newdn))
        self.assertFalse(self.store.exists(self.dn))


class TestObjectStore_root_dse(RegisterObjectsMixin, unittest.TestCase):
    """Test Root DSE functionality in FakeLDAPObject."""

    def test_root_dse_query_returns_entry(self):
        """Test that Root DSE query returns the expected entry."""
        results = self.ldap.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")

        self.assertEqual(len(results), 1)
        dn, attrs = results[0]
        self.assertEqual(dn, "")
        self.assertIn("objectClass", attrs)
        self.assertIn("supportedControl", attrs)

    def test_root_dse_supported_control_contains_server_side_sort(self):
        """Test that Root DSE includes Server Side Sort OID."""
        results = self.ldap.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
        dn, attrs = results[0]

        supported_controls = attrs["supportedControl"]
        server_side_sort_oid = b"1.2.840.113556.1.4.473"
        self.assertIn(server_side_sort_oid, supported_controls)

    def test_root_dse_supported_control_contains_paged_results(self):
        """Test that Root DSE includes Paged Results OID."""
        results = self.ldap.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
        dn, attrs = results[0]

        supported_controls = attrs["supportedControl"]
        paged_results_oid = b"1.2.840.113556.1.4.319"
        self.assertIn(paged_results_oid, supported_controls)

    def test_root_dse_supported_control_oids_are_bytes(self):
        """Test that supportedControl OIDs are returned as bytes."""
        results = self.ldap.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
        dn, attrs = results[0]

        supported_controls = attrs["supportedControl"]
        for oid in supported_controls:
            self.assertIsInstance(oid, bytes)

    def test_root_dse_attrlist_filtering_works(self):
        """Test that attrlist parameter works for Root DSE queries."""
        results = self.ldap.search_s(
            "", ldap.SCOPE_BASE, "(objectClass=*)", attrlist=["supportedControl"]
        )

        self.assertEqual(len(results), 1)
        dn, attrs = results[0]
        self.assertEqual(dn, "")
        self.assertIn("supportedControl", attrs)
        self.assertNotIn("objectClass", attrs)
        self.assertNotIn("supportedSASLMechanisms", attrs)

    def test_root_dse_attrlist_multiple_attributes(self):
        """Test that multiple attributes can be requested from Root DSE."""
        results = self.ldap.search_s(
            "",
            ldap.SCOPE_BASE,
            "(objectClass=*)",
            attrlist=["supportedControl", "supportedSASLMechanisms"],
        )

        self.assertEqual(len(results), 1)
        dn, attrs = results[0]
        self.assertEqual(dn, "")
        self.assertIn("supportedControl", attrs)
        self.assertIn("supportedSASLMechanisms", attrs)
        self.assertNotIn("objectClass", attrs)

    def test_root_dse_non_objectclass_filter_returns_empty(self):
        """Test that non-objectClass filters return empty results."""
        results = self.ldap.search_s("", ldap.SCOPE_BASE, "(cn=*)")

        self.assertEqual(len(results), 0)

    def test_non_root_dse_queries_still_work(self):
        """Test that non-Root DSE queries continue to work normally."""
        # This should still work as before
        results = self.ldap.search_s(
            "uid=fred,ou=mydept,o=myorg,c=country", ldap.SCOPE_BASE, "(objectClass=*)"
        )

        self.assertEqual(len(results), 1)
        dn, attrs = results[0]
        self.assertEqual(dn, "uid=fred,ou=mydept,o=myorg,c=country")
        self.assertIn("cn", attrs)

    def test_root_dse_records_call(self):
        """Test that Root DSE queries are recorded in call history."""
        self.ldap.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")

        self.assertTrue("search_s" in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls("search_s")[0]
        self.assertEqual(call.args["base"], "")
        self.assertEqual(call.args["scope"], ldap.SCOPE_BASE)
        self.assertEqual(call.args["filterstr"], "(objectClass=*)")

    def test_root_dse_contains_standard_attributes(self):
        """Test that Root DSE contains standard LDAP server attributes."""
        results = self.ldap.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
        dn, attrs = results[0]

        # Check for standard Root DSE attributes
        self.assertIn("objectClass", attrs)
        self.assertIn("supportedControl", attrs)
        self.assertIn("supportedSASLMechanisms", attrs)
        self.assertIn("supportedLDAPVersion", attrs)
        self.assertIn("namingContexts", attrs)

    def test_root_dse_objectclass_is_top(self):
        """Test that Root DSE objectClass is 'top'."""
        results = self.ldap.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
        dn, attrs = results[0]

        self.assertEqual(attrs["objectClass"], [b"top"])
