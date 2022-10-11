from pathlib import Path
import unittest

import ldap
from ldap_faker import ObjectStore, FakeLDAPObject


class RegisterObjectsMixin:

    def setUp(self):
        self.filename = Path(__file__).parent / Path('big.json')
        self.store = ObjectStore()
        self.store.load_objects(self.filename)
        self.ldap = FakeLDAPObject('ldap://server', self.store)


class TestObjectStore_attributes(RegisterObjectsMixin, unittest.TestCase):

    def test_deref(self):
        self.assertEqual(self.ldap.deref, ldap.DEREF_NEVER)

    def test_protocol_version(self):
        self.assertEqual(self.ldap.protocol_version, ldap.VERSION3)

    def test_sizelimit(self):
        self.assertEqual(self.ldap.sizelimit, ldap.NO_LIMIT)

    def test_network_timeout(self):
        self.assertEqual(self.ldap.network_timeout, ldap.NO_LIMIT)

    def test_timelimit(self):
        self.assertEqual(self.ldap.timelimit, ldap.NO_LIMIT)

    def test_timeout(self):
        self.assertEqual(self.ldap.timeout, ldap.NO_LIMIT)

    def test_tls_enabled(self):
        self.assertFalse(self.ldap.tls_enabled)

    def test_bound_dn(self):
        self.assertEqual(self.ldap.bound_dn, None)


class TestObjectStore_set_option(RegisterObjectsMixin, unittest.TestCase):

    def test_sets_option(self):
        self.ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        self.assertEqual(self.ldap.get_option(ldap.OPT_X_TLS_NEWCTX), 0)

    def test_records_call(self):
        self.ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        self.assertTrue('set_option' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('set_option')[0]
        self.assertEqual(call.args, {'option': ldap.OPT_X_TLS_NEWCTX, 'invalue': 0})

    def test_non_existant_option_raises_ValueError(self):
        with self.assertRaises(ValueError):
            self.ldap.set_option(6000, 0)


class TestObjectStore_get_option(RegisterObjectsMixin, unittest.TestCase):

    def test_gets_option(self):
        self.ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        self.assertEqual(self.ldap.get_option(ldap.OPT_X_TLS_NEWCTX), 0)

    def test_records_call(self):
        self.ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        self.ldap.get_option(ldap.OPT_X_TLS_NEWCTX)
        self.assertTrue('get_option' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('get_option')[0]
        self.assertEqual(call.args, {'option': ldap.OPT_X_TLS_NEWCTX})

    def test_non_existant_option_raises_ValueError(self):
        with self.assertRaises(ValueError):
            self.ldap.get_option(6000)

    # Special options that we simulate
    def test_OPT_URI(self):
        self.assertEqual(self.ldap.get_option(ldap.OPT_URI), 'ldap://server')

    def test_OPT_HOST_NAME(self):
        self.assertEqual(self.ldap.get_option(ldap.OPT_HOST_NAME), 'server')

    def test_OPT_PROTOCOL_VERSION(self):
        self.assertEqual(self.ldap.get_option(ldap.OPT_PROTOCOL_VERSION), 3)

    def test_OPT_API_INFO(self):
        self.assertEqual(
            self.ldap.get_option(ldap.OPT_API_INFO),
            {
                'info_version': 1,
                'api_version': 3001,
                'vendor_name': 'python-ldap-faker',
                'vendor_version': '1.0.0'
            }
        )

    def test_OPT_SUCCESS(self):
        self.assertEqual(
            self.ldap.get_option(ldap.OPT_SUCCESS),
            {
                'info_version': 1,
                'api_version': 3001,
                'vendor_name': 'python-ldap-faker',
                'vendor_version': '1.0.0'
            }
        )


class TestObjectStore_simple_bind_s(RegisterObjectsMixin, unittest.TestCase):

    def test_anonymous_bind_works(self):
        self.ldap.simple_bind_s()
        self.assertTrue('simple_bind_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('simple_bind_s')[0]
        self.assertEqual(call.args, {})

    def test_invalid_dns_are_raise_INVALID_CREDENTIALS(self):
        """
        Strangely to me, you can pass any old string as the ``who`` argument to simple_bind_s
        and all that will happen is that we get ``ldap.INVALID_CREDENTIALS``.
        """
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            # Not a valid DN
            self.ldap.simple_bind_s('uid=user,,ou=mydept', 'the wrong password')

    def test_anonymous_bind_returns_None(self):
        result = self.ldap.simple_bind_s()
        self.assertEqual(result, None)

    def test_anonymous_bind_does_not_set_bound_dn(self):
        self.ldap.simple_bind_s()
        self.assertEqual(self.ldap.bound_dn, None)

    def test_non_anonymous_bind_works(self):
        self.ldap.simple_bind_s('uid=user,ou=mydept,o=myorg,c=country', 'the password')
        self.assertTrue('simple_bind_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('simple_bind_s')[0]
        self.assertEqual(call.args, {'who': 'uid=user,ou=mydept,o=myorg,c=country', 'cred': 'the password'})

    def test_non_anonymous_bind_returns_4_tuple(self):
        result = self.ldap.simple_bind_s('uid=user,ou=mydept,o=myorg,c=country', 'the password')
        self.assertEqual(result, (ldap.RES_BIND, [], 3, []))

    def test_non_anonymous_bind_sets_bound_dn(self):
        self.ldap.simple_bind_s('uid=user,ou=mydept,o=myorg,c=country', 'the password')
        self.assertEqual(self.ldap.bound_dn, 'uid=user,ou=mydept,o=myorg,c=country')

    def test_non_anonymous_bind_with_wrong_password_raises_INVALID_CREDENTIALS(self):
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            self.ldap.simple_bind_s('uid=user,ou=mydept,o=myorg,c=country', 'the wrong password')
        self.assertTrue('simple_bind_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('simple_bind_s')[0]
        self.assertEqual(call.args, {'who': 'uid=user,ou=mydept,o=myorg,c=country', 'cred': 'the wrong password'})


class TestObjectStore_whoami_s(RegisterObjectsMixin, unittest.TestCase):

    def test_no_login_returns_empty_string(self):
        self.assertEqual(self.ldap.whoami_s(), '')

    def test_anonymous_bind_returns_empty_string(self):
        self.ldap.simple_bind_s()
        self.assertEqual(self.ldap.whoami_s(), '')
        self.assertTrue('whoami_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('whoami_s')[0]
        self.assertEqual(call.args, {})

    def test_non_anonymous_bind_returns_bind_dn(self):
        self.ldap.simple_bind_s('uid=user,ou=mydept,o=myorg,c=country', 'the password')
        self.assertEqual(self.ldap.whoami_s(), 'dn: uid=user,ou=mydept,o=myorg,c=country')
        self.assertTrue('whoami_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('whoami_s')[0]
        self.assertEqual(call.args, {})


class TestObjectStore_start_tls_s(RegisterObjectsMixin, unittest.TestCase):

    def test_tls_enabled_starts_False(self):
        self.assertFalse(self.ldap.tls_enabled)

    def test_start_tls_s_sets_tls_enabled_True(self):
        self.ldap.start_tls_s()
        self.assertTrue(self.ldap.tls_enabled)

    def test_records_call(self):
        self.ldap.start_tls_s()
        self.assertTrue('start_tls_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('start_tls_s')[0]
        self.assertEqual(call.args, {})


class TestObjectStore_modify_s(RegisterObjectsMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.dn = 'uid=fred,ou=mydept,o=myorg,c=country'
        self.ldap.start_tls_s()
        self.ldap.simple_bind_s('uid=barney,ou=mydept,o=myorg,c=country', 'the barneypassword')

    def test_modify_s_requires_authenticated_bind(self):
        self.ldap.bound_dn = None
        modlist = [(ldap.MOD_ADD, 'newattr', [b'new value'])]
        with self.assertRaises(ldap.INSUFFICIENT_ACCESS):
            self.ldap.modify_s(self.dn, modlist)

    def test_records_call(self):
        modlist = [(ldap.MOD_ADD, 'newattr', [b'new value'])]
        self.ldap.modify_s(self.dn, modlist)
        self.assertTrue('modify_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('modify_s')[0]
        self.assertEqual(call.args, {'dn': self.dn, 'modlist': modlist})

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.modify_s('uid=foo,,ou=bar,o=baz,c=country', [])

    def test_can_add_new_attribute(self):
        modlist = [
            (ldap.MOD_ADD, 'newattr', [b'new value'])
        ]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data['newattr'], [b'new value'])

    def test_can_add_values_to_existing_attribute(self):
        modlist = [
            (ldap.MOD_ADD, 'objectclass', [b'eduPerson'])
        ]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data['objectclass'], [b'posixAccount', b'top', b'eduPerson'])

    def test_cannot_add_duplicate_values_to_existing_attribute(self):
        modlist = [
            (ldap.MOD_ADD, 'objectclass', [b'posixAccount'])
        ]
        with self.assertRaises(ldap.TYPE_OR_VALUE_EXISTS):
            self.ldap.modify_s(self.dn, modlist)

    def test_cannot_add_duplicate_values_to_existing_attribute_case_insensitive(self):
        modlist = [
            (ldap.MOD_ADD, 'objectclass', [b'posixaccount'])
        ]
        with self.assertRaises(ldap.TYPE_OR_VALUE_EXISTS):
            self.ldap.modify_s(self.dn, modlist)

    def test_can_delete_attribute(self):
        modlist = [
            (ldap.MOD_DELETE, 'loginShell', None)
        ]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertTrue('loginShell' not in data)

    def test_can_delete_some_values_from_attribute(self):
        modlist = [
            (ldap.MOD_DELETE, 'objectclass', [b'top'])
        ]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data['objectclass'], [b'posixAccount'])

    def test_can_delete_some_values_from_attribute_is_case_insensitive(self):
        modlist = [
            (ldap.MOD_DELETE, 'objectclass', [b'posixaccount'])
        ]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data['objectclass'], [b'top'])

    def test_can_replace_existing_attribute(self):
        modlist = [
            (ldap.MOD_REPLACE, 'objectclass', [b'posixaccount'])
        ]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data['objectclass'], [b'posixaccount'])

    def test_can_replace_new_attribute(self):
        modlist = [
            (ldap.MOD_REPLACE, 'gecos', [b'my gecos'])
        ]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data['gecos'], [b'my gecos'])

    def test_can_perform_multiple_operations(self):
        modlist = [
            (ldap.MOD_DELETE, 'objectclass', [b'posixaccount']),
            (ldap.MOD_ADD, 'objectclass', [b'eduPerson']),
            (ldap.MOD_ADD, 'newattr', [b'new value']),
            (ldap.MOD_REPLACE, 'gidNumber', [b'456'])
        ]
        self.ldap.modify_s(self.dn, modlist)
        data = self.store.get(self.dn)
        self.assertEqual(data['objectclass'], [b'top', b'eduPerson'])
        self.assertEqual(data['newattr'], [b'new value'])
        self.assertEqual(data['gidNumber'], [b'456'])

    def test_invalid_operation_raises_PROTOCOL_ERROR(self):
        modlist = [
            (100, 'objectclass', [b'posixaccount']),
        ]
        with self.assertRaises(ldap.PROTOCOL_ERROR):
            self.ldap.modify_s(self.dn, modlist)


class TestObjectStore_add_s(RegisterObjectsMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.dn = 'uid=myuser,ou=bar,o=baz,c=country'
        self.modlist = [
            ('uid', [b'myuser']),
            ('gidNumber', [b'1000']),
            ('uidNumber', [b'1000']),
            ('loginShell', [b'/bin/bash']),
            ('homeDirectory', [b'/home/myuser']),
            ('userPassword', [b'the password']),
            ('cn', [b'My Name']),
            ('objectClass', [b'top', b'posixAccount']),
        ]
        self.ldap.start_tls_s()
        self.ldap.simple_bind_s('uid=barney,ou=mydept,o=myorg,c=country', 'the barneypassword')

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
        self.assertTrue('add_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('add_s')[0]
        self.assertEqual(call.args, {'dn': self.dn, 'modlist': self.modlist})

    def test_adding_object_with_existing_dn_raises_ALREADY_EXISTS(self):
        with self.assertRaises(ldap.ALREADY_EXISTS):
            self.ldap.add_s('uid=barney,ou=mydept,o=myorg,c=country', self.modlist)

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.add_s('uid=foo,,ou=bar,o=baz,c=country', self.modlist)

    def test_invalid_value_raises_TypeError(self):
        self.modlist.append(('gecos', 'foobar'))
        with self.assertRaises(TypeError):
            self.ldap.add_s(self.dn, self.modlist)


class TestObjectStore_delete_s(RegisterObjectsMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.dn = 'uid=user,ou=mydept,o=myorg,c=country'
        self.ldap.start_tls_s()
        self.ldap.simple_bind_s('uid=barney,ou=mydept,o=myorg,c=country', 'the barneypassword')

    def test_delete_s_requires_authenticated_bind(self):
        self.ldap.bound_dn = None
        with self.assertRaises(ldap.INSUFFICIENT_ACCESS):
            self.ldap.delete_s(self.dn)

    def test_can_delete_existing_object(self):
        self.ldap.delete_s(self.dn)
        self.assertFalse(self.store.exists(self.dn))

    def test_records_call(self):
        self.ldap.delete_s(self.dn)
        self.assertTrue('delete_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('delete_s')[0]
        self.assertEqual(call.args, {'dn': self.dn})

    def test_adding_object_with_existing_dn_raises_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldap.delete_s('uid=blah,ou=mydept,o=myorg,c=country')

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.delete_s('uid=foo,,ou=bar,o=baz,c=country')


class TestObjectStore_compare_s(RegisterObjectsMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.dn = 'uid=fred,ou=mydept,o=myorg,c=country'

    def test_records_call(self):
        self.ldap.compare_s(self.dn, 'uidNumber', b'125')
        self.assertTrue('compare_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('compare_s')[0]
        self.assertEqual(call.args, {'dn': self.dn, 'attr': 'uidNumber', 'value': b'125'})

    def test_can_compare_values_for_existing_object(self):
        self.assertTrue(self.ldap.compare_s(self.dn, 'uidNumber', b'125'))
        self.assertFalse(self.ldap.compare_s(self.dn, 'uidNumber', b'124'))

    def test_can_compare_values_for_existing_object_for_multivalued_attr(self):
        self.assertTrue(self.ldap.compare_s(self.dn, 'objectclass', b'top'))
        self.assertFalse(self.ldap.compare_s(self.dn, 'objectclass', b'sdlkjfalsdj'))

    def test_value_must_be_bytes(self):
        with self.assertRaises(TypeError):
            self.ldap.compare_s(self.dn, 'uidNumber', '125')

    def test_comparing_nonexistant_object_raises_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldap.compare_s('uid=blah,ou=mydept,o=myorg,c=country', 'uidNumber', b'125')

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.compare_s('uid=foo,,ou=bar,o=baz,c=country', 'uidNumber', b'125')


class TestObjectStore_rename_s(RegisterObjectsMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.dn = 'uid=fred,ou=mydept,o=myorg,c=country'
        self.basedn = 'ou=mydept,o=myorg,c=country'
        self.newrdn = 'uid=freddy'
        self.data = self.store.get(self.dn)
        self.data['uid'] = [b'freddy']
        self.ldap.start_tls_s()
        self.ldap.simple_bind_s('uid=barney,ou=mydept,o=myorg,c=country', 'the barneypassword')

    def test_rename_s_requires_authenticated_bind(self):
        self.ldap.bound_dn = None
        with self.assertRaises(ldap.INSUFFICIENT_ACCESS):
            self.ldap.rename_s(self.dn, self.newrdn)

    def test_records_call(self):
        self.ldap.rename_s(self.dn, self.newrdn)
        self.assertTrue('rename_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('rename_s')[0]
        self.assertEqual(call.args, {'dn': self.dn, 'newrdn': 'uid=freddy'})

    def test_can_rename_in_same_basedn(self):
        newdn = f'{self.newrdn},{self.basedn}'
        self.ldap.rename_s(self.dn, self.newrdn)
        self.assertTrue(self.store.exists(newdn))
        self.assertFalse(self.store.exists(self.dn))

    def test_rename_updates_rdn_in_the_object(self):
        newdn = f'{self.newrdn},{self.basedn}'
        self.ldap.rename_s(self.dn, self.newrdn)
        self.assertEqual(self.store.get(newdn), self.data)

    def test_can_rename_to_differnt_basedn(self):
        newbasedn = f'ou=children,{self.basedn}'
        newdn = f'{self.newrdn},{newbasedn}'
        self.ldap.rename_s(self.dn, self.newrdn, newsuperior=newbasedn)
        self.assertEqual(self.store.get(newdn), self.data)

    def test_can_keep_old_object_after_renaming(self):
        newdn = f'{self.newrdn},{self.basedn}'
        self.ldap.rename_s(self.dn, self.newrdn, delold=0)
        self.assertTrue(self.store.exists(newdn))
        self.assertTrue(self.store.exists(self.dn))

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldap.rename_s('uid=foo,,ou=bar,o=baz,c=country', 'uid=bar')

    def test_renaming_nonexistant_object_raises_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldap.rename_s('uid=blah,ou=mydept,o=myorg,c=country', 'uid=blarg')


class TestObjectStore_search_s(RegisterObjectsMixin, unittest.TestCase):

    def test_records_call(self):
        self.ldap.search_s('uid=fred,ou=mydept,o=myorg,c=country', ldap.SCOPE_BASE, '(objectclass=*)')
        self.assertTrue('search_s' in self.ldap.calls.names)
        call = self.ldap.calls.filter_calls('search_s')[0]
        self.assertEqual(
            call.args,
            {
                'base': 'uid=fred,ou=mydept,o=myorg,c=country',
                'scope': ldap.SCOPE_BASE,
                'filterstr': '(objectclass=*)'
            }
        )


class TestObjectStore_search_s_SCOPE_BASE(RegisterObjectsMixin, unittest.TestCase):

    def test_returns_one_object_if_object_exists(self):
        results = self.ldap.search_s('uid=fred,ou=mydept,o=myorg,c=country', ldap.SCOPE_BASE, '(objectclass=*)')
        self.assertEqual(len(results), 1)

    def test_returns_expected_object_if_object_exists(self):
        results = self.ldap.search_s('uid=fred,ou=mydept,o=myorg,c=country', ldap.SCOPE_BASE, '(objectclass=*)')
        self.assertEqual(results[0][0], 'uid=fred,ou=mydept,o=myorg,c=country')
        self.assertEqual(results[0][1]['cn'], [b'Fred Flintstone'])

    def test_filtering_works_on_matched_objects(self):
        results = self.ldap.search_s('uid=fred,ou=mydept,o=myorg,c=country', ldap.SCOPE_BASE, '(uid=blah)')
        self.assertEqual(len(results), 0)

    def test_attrlist_works_on_matched_objects(self):
        results = self.ldap.search_s(
            'uid=fred,ou=mydept,o=myorg,c=country',
            ldap.SCOPE_BASE,
            '(objectclass=*)',
            attrlist=['uid', 'cn']
        )
        self.assertEqual(len(results), 1)
        data = results[0]
        self.assertEqual(list(data[1].keys()), ['cn', 'uid'])

    def test_raises_NO_SUCH_OBJECT_if_object_does_not_exist(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldap.search_s('uid=snoopy,ou=mydept,o=myorg,c=country', ldap.SCOPE_BASE, '(objectclass=*)')


class TestObjectStore_search_s_SCOPE_ONELEVEL(RegisterObjectsMixin, unittest.TestCase):

    def test_returns_objects_only_at_the_desired_level(self):
        results = self.ldap.search_s('ou=mydept,o=myorg,c=country', ldap.SCOPE_ONELEVEL, '(objectclass=*)')
        self.assertEqual(len(results), 6)
        results = self.ldap.search_s('o=myorg,c=country', ldap.SCOPE_ONELEVEL, '(objectclass=*)')
        self.assertEqual(len(results), 0)
        results = self.ldap.search_s('ou=children,ou=mydept,o=myorg,c=country', ldap.SCOPE_ONELEVEL, '(objectclass=*)')
        self.assertEqual(len(results), 2)

    def test_filtering_works_on_matched_objects(self):
        results = self.ldap.search_s('ou=mydept,o=myorg,c=country', ldap.SCOPE_ONELEVEL, '(loginshell=/bin/bash)')
        self.assertEqual(len(results), 5)
        results = self.ldap.search_s('ou=mydept,o=myorg,c=country', ldap.SCOPE_ONELEVEL, '(cn=*flintstone)')
        self.assertEqual(len(results), 2)

    def test_attrlist_works_on_matched_objects(self):
        results = self.ldap.search_s(
            'ou=mydept,o=myorg,c=country',
            ldap.SCOPE_ONELEVEL,
            '(objectclass=*)',
            attrlist=['uid', 'cn']
        )
        data = results[0]
        self.assertEqual(list(data[1].keys()), ['cn', 'uid'])


class TestObjectStore_search_s_SCOPE_SUBTREE(RegisterObjectsMixin, unittest.TestCase):

    def test_returns_objects_all_subtrees(self):
        results = self.ldap.search_s('ou=mydept,o=myorg,c=country', ldap.SCOPE_SUBTREE, '(objectclass=*)')
        self.assertEqual(len(results), 8)
        results = self.ldap.search_s('o=myorg,c=country', ldap.SCOPE_SUBTREE, '(objectclass=*)')
        self.assertEqual(len(results), 8)
        results = self.ldap.search_s('ou=children,ou=mydept,o=myorg,c=country', ldap.SCOPE_SUBTREE, '(objectclass=*)')
        self.assertEqual(len(results), 2)

    def test_filtering_works_on_matched_objects(self):
        results = self.ldap.search_s('ou=mydept,o=myorg,c=country', ldap.SCOPE_SUBTREE, '(loginshell=/bin/tcsh)')
        self.assertEqual(len(results), 2)
        results = self.ldap.search_s('ou=mydept,o=myorg,c=country', ldap.SCOPE_SUBTREE, '(cn=*flintstone)')
        self.assertEqual(len(results), 3)

    def test_attrlist_works_on_matched_objects(self):
        results = self.ldap.search_s(
            'ou=mydept,o=myorg,c=country',
            ldap.SCOPE_SUBTREE,
            '(objectclass=*)',
            attrlist=['uid', 'cn']
        )
        data = results[0]
        self.assertEqual(list(data[1].keys()), ['cn', 'uid'])


class TestObjectStore_search_ext_AND_result3(RegisterObjectsMixin, unittest.TestCase):

    def test_returns_objects(self):
        controls = ldap.controls.LDAPControl()
        msgid = self.ldap.search_ext(
            'ou=mydept,o=myorg,c=country',
            ldap.SCOPE_SUBTREE,
            '(objectclass=*)',
            serverctrls=[controls]
        )
        op, data, _msgid, ctrls = self.ldap.result3(msgid)
        self.assertEqual(op, ldap.RES_SEARCH_RESULT)
        self.assertEqual(len(data), 8)
        self.assertEqual(_msgid, msgid)
        self.assertIs(ctrls[0], controls)

    def test_msg_id_properly_identifies_our_results(self):
        controls1 = ldap.controls.LDAPControl()
        msgid1 = self.ldap.search_ext(
            'ou=mydept,o=myorg,c=country',
            ldap.SCOPE_SUBTREE,
            '(objectclass=*)',
            serverctrls=[controls1]
        )
        controls2 = ldap.controls.LDAPControl()
        msgid2 = self.ldap.search_ext(
            'ou=mydept,o=myorg,c=country',
            ldap.SCOPE_SUBTREE,
            '(uid=fred)',
            serverctrls=[controls2]
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
