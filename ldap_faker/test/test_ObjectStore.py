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


class TestObjectStore_exists(RegisterObjectsMixin, unittest.TestCase):

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.store.exists('uid=foo,,ou=bar,o=baz,c=country')

    def test_returns_True_if_dn_exists(self):
        self.assertTrue(self.store.exists(self.data[0][0]))

    def test_returns_False_if_dn_does_not_exist(self):
        self.assertFalse(self.store.exists("uid=not-here,ou=bar,o=baz,c=country"))


class TestObjectStore_get(RegisterObjectsMixin, unittest.TestCase):

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


class TestObjectStore_copy(RegisterObjectsMixin, unittest.TestCase):

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


class TestObjectStore_set(RegisterObjectsMixin, unittest.TestCase):

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


class TestObjectStore_update(RegisterObjectsMixin, unittest.TestCase):

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
        self.assertEqual(data['gidNumber'], [b'456'])


class TestObjectStore_create(RegisterObjectsMixin, unittest.TestCase):

    def setUp(self):
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

    def test_can_add_new_object(self):
        self.store.create(self.dn, self.modlist)
        data = self.store.get(self.dn)
        for entry in self.modlist:
            self.assertEqual(data[entry[0]], entry[1])

    def test_invalid_dn_raises_INVALID_DN_SYNTAX(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.store.create('uid=foo,,ou=bar,o=baz,c=country', self.modlist)

    def test_invalid_value_raises_TypeError(self):
        self.modlist.append('gecos', 'foobar')
        with self.assertRaises(TypeError):
            self.store.create('uid=foo,,ou=bar,o=baz,c=country', self.modlist)
