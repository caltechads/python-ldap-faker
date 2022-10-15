import copy
from pathlib import Path
import unittest

import ldap
from ldap_faker import ObjectStore


class ObjectMixin:

    def setUp(self):
        self.data = (
            'uid=user,ou=mydept,o=myorg,c=country',
            {
                'cn': [b'Firstname User1'],
                'uid': [b'user'],
                'uidNumber': [b'123'],
                'gidNumber': [b'456'],
                'homeDirectory': [b'/home/user'],
                'loginShell': [b'/bin/bash'],
                'userPassword': [b'the password'],
                'objectclass': [b'posixAccount', b'top']
            }
        )


class ObjectsMixin:

    def setUp(self):
        self.data = [
            (
                'uid=user,ou=mydept,o=myorg,c=country',
                {
                    'cn': [b'Firstname User1'],
                    'uid': [b'user'],
                    'uidNumber': [b'123'],
                    'gidNumber': [b'456'],
                    'homeDirectory': [b'/home/user'],
                    'loginShell': [b'/bin/bash'],
                    'userPassword': [b'the password'],
                    'objectclass': [b'posixAccount', b'top']
                }
            ),
            (
                'uid=user2,ou=mydept,o=myorg,c=country',
                {
                    'cn': [b'Firstname User2'],
                    'uid': [b'user2'],
                    'uidNumber': [b'124'],
                    'gidNumber': [b'457'],
                    'homeDirectory': [b'/home/user1'],
                    'loginShell': [b'/bin/bash'],
                    'userPassword': [b'the password'],
                    'objectclass': [b'posixAccount', b'top']
                }
            )
        ]


class RegisterObjectsMixin(ObjectsMixin):

    def setUp(self):
        super().setUp()
        self.store = ObjectStore()
        self.store.register_objects(self.data)


class TestObjectStore_register_object(ObjectMixin, unittest.TestCase):

    def test_register_object_works(self):
        store = ObjectStore()
        self.assertEqual(store.count, 0)
        store.register_object(self.data)
        self.assertEqual(store.count, 1)
        self.assertEqual(len(store.raw_objects), 1)
        self.assertEqual(len(store.objects), 1)

    def test_register_object_raises_INVALID_DN_SYNTAX_for_bad_dn(self):
        store = ObjectStore()
        data = ('uid=foo,,ou=bar,o=baz,c=country', self.data[1])
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            store.register_object(data)

    def test_register_object_raises_TypeError_for_bad_attribute_type(self):
        store = ObjectStore()
        for attr in [b'foo', 3]:
            data = copy.deepcopy(self.data)
            data[1][attr] = [b'foo']
            with self.assertRaises(TypeError):
                store.register_object(data)

    def test_register_object_raises_TypeError_for_bad_attribute_value_type(self):
        store = ObjectStore()
        for value in [b'foo', ['foo']]:
            data = copy.deepcopy(self.data)
            data[1]['myattr'] = value
            with self.assertRaises(TypeError):
                store.register_object(data)

    def test_raises_ALREADY_EXISTS_if_dn_exists(self):
        store = ObjectStore()
        store.register_object(self.data)
        with self.assertRaises(ldap.ALREADY_EXISTS):
            store.register_object(self.data)

    def testsearchable_object(self):
        store = ObjectStore()
        store.register_object(self.data)
        dn = self.data[0]
        cn = store.objects[dn]['cn'][0]
        self.assertTrue(isinstance(cn, str))


class TestObjectStoreCaseSensitivity(ObjectMixin, unittest.TestCase):

    def test_dns_are_always_case_insensitive(self):
        store = ObjectStore()
        store.register_object(self.data)
        dn = self.data[0]
        self.assertTrue(dn in store.objects)
        self.assertTrue(dn.upper() in store.objects)
        self.assertTrue(dn in store.raw_objects)
        self.assertTrue(dn.upper() in store.raw_objects)

    def test_attrs_are_case_insensitive_in_searchable_objects(self):
        store = ObjectStore()
        store.register_object(self.data)
        dn = self.data[0]
        self.assertIn('cn', store.objects[dn])
        self.assertIn('CN', store.objects[dn])
        self.assertIs(store.objects[dn]['cn'], store.objects[dn]['CN'])

    def test_attrs_are_case_sensitive_in_raw_objects(self):
        store = ObjectStore()
        store.register_object(self.data)
        dn = self.data[0]
        self.assertIn('cn', store.raw_objects[dn])
        self.assertNotIn('CN', store.raw_objects[dn])


class TestObjectStore_register_objects(ObjectsMixin, unittest.TestCase):

    def test_register_objects_works(self):
        store = ObjectStore()
        self.assertEqual(store.count, 0)
        store.register_objects(self.data)
        self.assertEqual(store.count, 2)
        self.assertEqual(len(store.raw_objects), 2)
        self.assertEqual(len(store.objects), 2)

    def test_throws_ldap_ALREADY_EXISTS_if_dn_exists(self):
        store = ObjectStore()
        store.register_objects(self.data)
        with self.assertRaises(ldap.ALREADY_EXISTS):
            store.register_objects(self.data)

    def test_converts_values_to_str_in_searchable_object(self):
        store = ObjectStore()
        store.register_objects(self.data)
        dn = self.data[0][0]
        cn = store.objects[dn]['cn'][0]
        self.assertTrue(isinstance(cn, str))
        dn = self.data[1][0]
        cn = store.objects[dn]['cn'][0]
        self.assertTrue(isinstance(cn, str))


class TestObjectStore_load_objects(unittest.TestCase):

    def setUp(self):
        self.filename = Path(__file__).parent / Path('server1.json')

    def test_load_objects_works(self):
        store = ObjectStore()
        self.assertEqual(store.count, 0)
        store.load_objects(self.filename)
        self.assertEqual(store.count, 2)
        self.assertEqual(len(store.raw_objects), 2)
        self.assertEqual(len(store.objects), 2)

    def test_throws_ldap_ALREADY_EXISTS_if_dn_exists(self):
        store = ObjectStore()
        store.load_objects(self.filename)
        with self.assertRaises(ldap.ALREADY_EXISTS):
            store.load_objects(self.filename)

    def test_converts_values_to_str_in_searchable_object(self):
        store = ObjectStore()
        store.load_objects(self.filename)
        for record in store.objects.values():
            self.assertTrue(isinstance(record['cn'][0], str))


class BaseTestObjectStore_exists:
    """
    We're doing this here so that we can use these test methods in server specific
    tests without running the same test suite multiple times.
    """

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.store.exists('uid=foo,,ou=bar,o=baz,c=country')

    def test_returns_True_if_dn_exists(self):
        self.assertTrue(self.store.exists(self.data[0][0]))

    def test_returns_False_if_dn_does_not_exist(self):
        self.assertFalse(self.store.exists("uid=not-here,ou=bar,o=baz,c=country"))


class TestObjectStore_exists(RegisterObjectsMixin, BaseTestObjectStore_exists, unittest.TestCase):
    pass


class BaseTestObjectStore_get:
    """
    We're doing this here so that we can use these test methods in server specific
    tests without running the same test suite multiple times.
    """

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.store.get('uid=foo,,ou=bar,o=baz,c=country')

    def test_get_of_existing_record_returns_record(self):
        data = self.store.get(self.data[0][0])
        self.assertIs(self.data[0][1], data)
        self.assertEqual(data['cn'], [b'Firstname User1'])
        self.assertEqual(data['uid'], [b'user'])

    def test_get_of_nonexisting_record_raises_ldap_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.store.get('uid=fred,ou=mydept,o=myorg,c=country')

    def test_get_returns_case_sensitive_values(self):
        data = self.store.get(self.data[0][0])
        self.assertEqual(data['cn'], [b'Firstname User1'])

    def test_get_returns_case_sensitive_attribute_names(self):
        self.assertEqual(
            self.store.get(self.data[0][0]).keys(),
            self.data[0][1].keys()
        )


class TestObjectStore_get(RegisterObjectsMixin, BaseTestObjectStore_get, unittest.TestCase):
    pass


class BaseTestObjectStore_copy:
    """
    We're doing this here so that we can use these test methods in server specific
    tests without running the same test suite multiple times.
    """

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.store.copy('uid=foo,,ou=bar,o=baz,c=country')

    def test_copy_does_deepcopy(self):
        data = self.store.copy(self.data[0][0])
        self.assertIsNot(self.data[0][1], data)
        self.assertEqual(data['cn'], [b'Firstname User1'])
        self.assertEqual(data['uid'], [b'user'])

    def test_copy_of_nonexisting_record_raises_ldap_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.store.copy('uid=fred,ou=mydept,o=myorg,c=country')


class TestObjectStore_copy(RegisterObjectsMixin, BaseTestObjectStore_copy, unittest.TestCase):
    pass


class BaseTestObjectStore_set:
    """
    We're doing this here so that we can use these test methods in server specific
    tests without running the same test suite multiple times.
    """

    def test_adds_new_record(self):
        self.assertEqual(self.store.count, 2)
        self.store.set(self.obj[0], self.obj[1])
        self.assertEqual(self.store.count, 3)
        self.assertTrue(self.obj[0] in self.store.objects)
        self.assertTrue(self.obj[0] in self.store.raw_objects)

    def test_raises_INVALID_DN_SYNTAX_for_bad_dn(self):
        store = ObjectStore()
        data = ('uid=foo,,ou=bar,o=baz,c=country', self.obj[1])
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            store.register_object(data)

    def test_raises_TypeError_for_bad_attribute_type(self):
        store = ObjectStore()
        for attr in [b'foo', 3]:
            data = copy.deepcopy(self.obj)
            data[1][attr] = [b'foo']
            with self.assertRaises(TypeError):
                store.register_object(data)

    def test_raises_TypeError_for_bad_attribute_value_type(self):
        store = ObjectStore()
        for value in [b'foo', ['foo']]:
            data = copy.deepcopy(self.obj)
            data[1]['myattr'] = value
            with self.assertRaises(TypeError):
                store.set(data[0], data[1])

    def test_updates_existing_record(self):
        dn = self.data[0][0]
        data = copy.deepcopy(self.data[0][1])
        data['cn'] = [b'My New Name']
        self.assertEqual(self.store.count, 2)
        self.store.set(dn, data)
        self.assertEqual(self.store.count, 2)
        self.assertEqual(self.store.raw_objects[dn]['cn'], [b'My New Name'])
        self.assertEqual(self.store.objects[dn]['cn'], ['My New Name'])

    def test_converts_values_to_str_in_searchable_object(self):
        self.assertEqual(self.store.count, 2)
        self.store.set(self.obj[0], self.obj[1])
        self.assertTrue(isinstance(self.store.objects[self.obj[0]]['cn'][0], str))


class TestObjectStore_set(RegisterObjectsMixin, BaseTestObjectStore_set, unittest.TestCase):

    def setUp(self):
        self.obj = (
            'uid=user3,ou=mydept,o=myorg,c=country',
            {
                'cn': [b'Firstname User3'],
                'uid': [b'user3'],
                'uidNumber': [b'126'],
                'gidNumber': [b'458'],
                'homeDirectory': [b'/home/user3'],
                'loginShell': [b'/bin/bash'],
                'userPassword': [b'the user3 password'],
                'objectclass': [b'posixAccount', b'top']
            }
        )
        super().setUp()


class BaseTestObjectStore_update:

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.store.update('uid=foo,,ou=bar,o=baz,c=country', [])

    def test_can_add_new_attribute(self):
        modlist = [
            (ldap.MOD_ADD, 'newattr', [b'new value'])
        ]
        dn = self.data[0][0]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertEqual(data['newattr'], [b'new value'])

    def test__updates_objects_AND_raw_objects(self):
        modlist = [(ldap.MOD_ADD, 'newattr', [b'new value'])]
        dn = self.data[0][0]
        self.store.update(dn, modlist)
        self.assertEqual(self.store.objects[dn]['newattr'], ['new value'])
        self.assertEqual(self.store.raw_objects[dn]['newattr'], [b'new value'])

    def test_can_add_values_to_existing_attribute(self):
        modlist = [
            (ldap.MOD_ADD, 'objectclass', [b'eduPerson'])
        ]
        dn = self.data[0][0]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertEqual(data['objectclass'], [b'posixAccount', b'top', b'eduPerson'])

    def test_cannot_add_duplicate_values_to_existing_attribute(self):
        modlist = [
            (ldap.MOD_ADD, 'objectclass', [b'posixAccount'])
        ]
        dn = self.data[0][0]
        with self.assertRaises(ldap.TYPE_OR_VALUE_EXISTS):
            self.store.update(dn, modlist)

    def test_cannot_add_duplicate_values_to_existing_attribute_case_insensitive(self):
        modlist = [
            (ldap.MOD_ADD, 'objectclass', [b'posixaccount'])
        ]
        dn = self.data[0][0]
        with self.assertRaises(ldap.TYPE_OR_VALUE_EXISTS):
            self.store.update(dn, modlist)

    def test_can_delete_attribute(self):
        modlist = [
            (ldap.MOD_DELETE, 'loginShell', None)
        ]
        dn = self.data[0][0]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertTrue('loginShell' not in data)

    def test_can_delete_some_values_from_attribute(self):
        modlist = [
            (ldap.MOD_DELETE, 'objectclass', [b'top'])
        ]
        dn = self.data[0][0]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertEqual(data['objectclass'], [b'posixAccount'])

    def test_can_delete_some_values_from_attribute_is_case_insensitive(self):
        modlist = [
            (ldap.MOD_DELETE, 'objectclass', [b'posixaccount'])
        ]
        dn = self.data[0][0]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertEqual(data['objectclass'], [b'top'])

    def test_can_replace_existing_attribute(self):
        modlist = [
            (ldap.MOD_REPLACE, 'objectclass', [b'posixaccount'])
        ]
        dn = self.data[0][0]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertEqual(data['objectclass'], [b'posixaccount'])

    def test_can_replace_new_attribute(self):
        modlist = [
            (ldap.MOD_REPLACE, 'gecos', [b'my gecos'])
        ]
        dn = self.data[0][0]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertEqual(data['gecos'], [b'my gecos'])

    def test_can_perform_multiple_operations(self):
        modlist = [
            (ldap.MOD_DELETE, 'objectclass', [b'posixaccount']),
            (ldap.MOD_ADD, 'objectclass', [b'eduPerson']),
            (ldap.MOD_ADD, 'newattr', [b'new value']),
            (ldap.MOD_REPLACE, 'uidNumber', [b'456'])
        ]
        dn = self.data[0][0]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertEqual(data['objectclass'], [b'top', b'eduPerson'])
        self.assertEqual(data['newattr'], [b'new value'])
        self.assertEqual(data['uidNumber'], [b'456'])

    def test_invalid_operation_raises_PROTOCOL_ERROR(self):
        modlist = [
            (100, 'objectclass', [b'posixaccount']),
        ]
        with self.assertRaises(ldap.PROTOCOL_ERROR):
            dn = self.data[0][0]
            self.store.update(dn, modlist)


class TestObjectStore_update(RegisterObjectsMixin, BaseTestObjectStore_update, unittest.TestCase):
    pass


class BaseTestObjectStore_create:

    def test_can_add_new_object(self):
        self.store.create(self.dn, self.modlist)
        data = self.store.get(self.dn)
        for entry in self.modlist:
            self.assertEqual(data[entry[0]], entry[1])

    def test_create_updates_objects_AND_raw_objects(self):
        self.store.create(self.dn, self.modlist)
        self.assertTrue(self.dn in self.store.objects)
        self.assertTrue(self.dn in self.store.raw_objects)

    def test_adding_object_with_existing_dn_raises_ALREADY_EXISTS(self):
        with self.assertRaises(ldap.ALREADY_EXISTS):
            self.store.create(self.data[0][0], self.modlist)

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.store.create('uid=foo,,ou=bar,o=baz,c=country', self.modlist)

    def test_invalid_value_raises_TypeError(self):
        self.modlist.append(('gecos', 'foobar'))
        with self.assertRaises(TypeError):
            self.store.create('uid=foo,ou=bar,o=baz,c=country', self.modlist)


class TestObjectStore_create(RegisterObjectsMixin, BaseTestObjectStore_create, unittest.TestCase):

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


class TestObjectStore_search_base(unittest.TestCase):

    def setUp(self):
        self.filename = Path(__file__).parent / Path('big.json')
        self.store = ObjectStore()
        self.store.load_objects(self.filename)

    def test_returns_one_object_if_object_exists(self):
        results = self.store.search_base('uid=fred,ou=mydept,o=myorg,c=country', '(objectclass=*)')
        self.assertEqual(len(results), 1)

    def test_returns_expected_object_if_object_exists(self):
        results = self.store.search_base('uid=fred,ou=mydept,o=myorg,c=country', '(objectclass=*)')
        self.assertEqual(results[0][0], 'uid=fred,ou=mydept,o=myorg,c=country')
        self.assertEqual(results[0][1]['cn'], [b'Fred Flintstone'])

    def test_filtering_works_on_matched_objects(self):
        results = self.store.search_base('uid=fred,ou=mydept,o=myorg,c=country', '(uid=blah)')
        self.assertEqual(len(results), 0)

    def test_attrlist_works_on_matched_objects(self):
        results = self.store.search_base(
            'uid=fred,ou=mydept,o=myorg,c=country',
            '(objectclass=*)',
            attrlist=['uid', 'cn']
        )
        self.assertEqual(len(results), 1)
        data = results[0]
        self.assertEqual(list(data[1].keys()), ['cn', 'uid'])

    def test_raises_NO_SUCH_OBJECT_if_object_does_not_exist(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.store.search_base('uid=snoopy,ou=mydept,o=myorg,c=country', '(objectclass=*)')


class TestObjectStore_search_onelevel(unittest.TestCase):

    def setUp(self):
        self.filename = Path(__file__).parent / Path('big.json')
        self.store = ObjectStore()
        self.store.load_objects(self.filename)

    def test_returns_objects_only_at_the_desired_level(self):
        results = self.store.search_onelevel('ou=mydept,o=myorg,c=country', '(objectclass=*)')
        self.assertEqual(len(results), 6)
        results = self.store.search_onelevel('o=myorg,c=country', '(objectclass=*)')
        self.assertEqual(len(results), 0)
        results = self.store.search_onelevel('ou=children,ou=mydept,o=myorg,c=country', '(objectclass=*)')
        self.assertEqual(len(results), 2)

    def test_filtering_works_on_matched_objects(self):
        results = self.store.search_onelevel('ou=mydept,o=myorg,c=country', '(loginshell=/bin/bash)')
        self.assertEqual(len(results), 5)
        results = self.store.search_onelevel('ou=mydept,o=myorg,c=country', '(cn=*flintstone)')
        self.assertEqual(len(results), 2)

    def test_filtering_is_case_insensitive(self):
        results = self.store.search_onelevel('ou=mydept,o=myorg,c=country', '(CN=*flintstone)')
        self.assertEqual(len(results), 2)
        results = self.store.search_onelevel('ou=mydept,o=myorg,c=country', '(Cn=*fliNTstone)')
        self.assertEqual(len(results), 2)

    def test_attrlist_works_on_matched_objects(self):
        results = self.store.search_onelevel(
            'ou=mydept,o=myorg,c=country',
            '(objectclass=*)',
            attrlist=['uid', 'cn']
        )
        data = results[0]
        self.assertEqual(list(data[1].keys()), ['cn', 'uid'])


class TestObjectStore_search_subtree(unittest.TestCase):

    def setUp(self):
        self.filename = Path(__file__).parent / Path('big.json')
        self.store = ObjectStore()
        self.store.load_objects(self.filename)

    def test_returns_objects_all_objects_if_basedn_is_emptystr(self):
        results = self.store.search_subtree('', '(objectclass=*)')
        self.assertEqual(len(results), 8)

    def test_returns_objects_all_subtrees(self):
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(objectclass=*)')
        self.assertEqual(len(results), 8)
        results = self.store.search_subtree('o=myorg,c=country', '(objectclass=*)')
        self.assertEqual(len(results), 8)
        results = self.store.search_subtree('ou=children,ou=mydept,o=myorg,c=country', '(objectclass=*)')
        self.assertEqual(len(results), 2)

    def test_filtering_works_on_matched_objects(self):
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(loginshell=/bin/tcsh)')
        self.assertEqual(len(results), 2)
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(cn=*flintstone)')
        self.assertEqual(len(results), 3)

    def test_filtering_is_case_insensitive(self):
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(CN=*flintstone)')
        self.assertEqual(len(results), 3)
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(Cn=*fliNTstone)')
        self.assertEqual(len(results), 3)

    def test_attrlist_works_on_matched_objects(self):
        results = self.store.search_subtree(
            'ou=mydept,o=myorg,c=country',
            '(objectclass=*)',
            attrlist=['uid', 'cn']
        )
        data = results[0]
        self.assertEqual(list(data[1].keys()), ['cn', 'uid'])

    def test_operational_attributes_are_excluded(self):
        self.store.operational_attributes.add('loginShell')
        self.store.operational_attributes.add('userPassword')
        results = self.store.search_subtree(
            'ou=mydept,o=myorg,c=country',
            '(objectclass=*)',
        )
        data = results[0]
        self.assertNotIn('loginShell', data[1])
        self.assertNotIn('userPassword', data[1])

    def test_operational_attributes_are_included_if_in_attrlist(self):
        self.store.operational_attributes.add('loginShell')
        self.store.operational_attributes.add('userPassword')
        results = self.store.search_subtree(
            'ou=mydept,o=myorg,c=country',
            '(objectclass=*)',
            attrlist=["*", "loginShell"]
        )
        data = results[0]
        self.assertIn('loginShell', data[1])
        self.assertNotIn('userPassword', data[1])

    def test_include_operational_attributes_works(self):
        self.store.operational_attributes.add('loginShell')
        self.store.operational_attributes.add('userPassword')
        results = self.store.search_subtree(
            'ou=mydept,o=myorg,c=country',
            '(objectclass=*)',
            include_operational_attributes=True
        )
        data = results[0]
        self.assertIn('loginShell', data[1])
        self.assertIn('userPassword', data[1])


class TestObjectStore_search_filtering(unittest.TestCase):

    def setUp(self):
        self.filename = Path(__file__).parent / Path('big.json')
        self.store = ObjectStore()
        self.store.load_objects(self.filename)

    def test_or_works(self):
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(|(cn=*flintstone)(cn=*rubble))')
        self.assertEqual(len(results), 6)

    def test_and_works(self):
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(&(cn=*flintstone)(cn=fred*))')
        self.assertEqual(len(results), 1)

    def test_lte_works(self):
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(uidnumber<=126)')
        self.assertEqual(len(results), 4)

    def test_gte_works(self):
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(uidnumber>=128)')
        self.assertEqual(len(results), 3)

    def test_filtering_is_case_insensitive(self):
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(CN=*flintstone)')
        self.assertEqual(len(results), 3)
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(Cn=*fliNTstone)')
        self.assertEqual(len(results), 3)


class TestObjectStore_search_attrlist(unittest.TestCase):

    def setUp(self):
        self.filename = Path(__file__).parent / Path('big.json')
        self.store = ObjectStore()
        self.store.load_objects(self.filename)

    def test_attrlist_gives_requested_attrs_only(self):
        tests = [
            ['uid'],
            ['uid', 'cn'],
            ['uid', 'cn', 'loginShell']
        ]
        for t in tests:
            results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(uid=fred)', attrlist=t)
            self.assertEqual(len(results), 1)
            self.assertEqual(sorted(list(results[0][1].keys())), sorted(t))

    def test_attrlist_is_case_insensitive(self):
        """
        * the attrlist itself is case insensitive
        * the names of the attrs returned are in the same case as that requested
        """
        tests = [
            ['loginshell'],
            ['loginshell', 'gidnumber']
        ]
        for t in tests:
            results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(uid=fred)', attrlist=t)
            self.assertEqual(len(results), 1)
            self.assertEqual(sorted(list(results[0][1].keys())), sorted(t))

    def test_operational_attributes_are_omitted(self):
        """
        * the attrlist itself is case insensitive
        * the names of the attrs returned are in the same case as that requested
        """
        self.store.operational_attributes.add('userPassword')
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(uid=fred)')
        self.assertEqual(len(results), 1)
        self.assertNotIn('userPassword', results[0][1])

    def test_operational_attributes_can_be_requested(self):
        """
        * the attrlist itself is case insensitive
        * the names of the attrs returned are in the same case as that requested
        """
        self.store.operational_attributes.add('userPassword')
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(uid=fred)', attrlist=['userpassword'])
        self.assertEqual(len(results), 1)
        self.assertEqual(sorted(list(results[0][1].keys())), ['userpassword'])

    def test_operational_attributes_can_be_requested_with_all_attrs(self):
        self.store.operational_attributes.add('userPassword')
        results = self.store.search_subtree('ou=mydept,o=myorg,c=country', '(uid=fred)', attrlist=['*', 'userpassword'])
        self.assertEqual(len(results), 1)
        self.assertEqual(len(list(results[0][1].keys())), 8)


class TestObjectStore_delete(RegisterObjectsMixin, unittest.TestCase):

    def test_can_delete_existing_object(self):
        self.store.delete('uid=user,ou=mydept,o=myorg,c=country')
        self.assertFalse(self.store.exists('uid=user,ou=mydept,o=myorg,c=country'))

    def test_deletes_from_objects_AND_raw_objects(self):
        self.store.delete('uid=user,ou=mydept,o=myorg,c=country')
        self.assertTrue('uid=user,ou=mydept,o=myorg,c=country' not in self.store.objects)
        self.assertTrue('uid=user,ou=mydept,o=myorg,c=country' not in self.store.raw_objects)

    def test_delete_nonexistant_object_raises_NO_SUCH_OBJECT(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.store.delete('uid=blah,ou=mydept,o=myorg,c=country')

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.store.delete('uid=foo,,ou=bar,o=baz,c=country')
