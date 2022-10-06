import copy
from pathlib import Path
import unittest

import ldap
from ldap_faker import ObjectStore


class TestObjectStore_register_object(unittest.TestCase):

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

    def test_register_object_works(self):
        store = ObjectStore()
        self.assertEqual(store.count, 0)
        store.register_object(self.data)
        self.assertEqual(store.count, 1)
        self.assertEqual(len(store.raw_objects), 1)
        self.assertEqual(len(store.objects), 1)

    def testISTS_if_dn_exists(self):
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


class TestObjectStoreCaseSensitivity(unittest.TestCase):

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


class TestObjectStore_register_objects(unittest.TestCase):

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


class TestObjectStore_get(unittest.TestCase):

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

    def test_get_of_existing_record_returns_record(self):
        store = ObjectStore()
        store.register_objects(self.data)
        data = store.get(self.data[0][0])
        self.assertIs(self.data[0][1], data)
        self.assertEqual(data['cn'], [b'Firstname User1'])
        self.assertEqual(data['uid'], [b'user'])

    def test_get_of_nonexisting_record_raises_ldap_NO_SUCH_OBJECT(self):
        store = ObjectStore()
        store.register_objects(self.data)
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            store.get('uid=fred,ou=mydept,o=myorg,c=country')


class TestObjectStore_copy(unittest.TestCase):

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

    def test_copy_does_deepcopy(self):
        store = ObjectStore()
        store.register_objects(self.data)
        data = store.copy(self.data[0][0])
        self.assertIsNot(self.data[0][1], data)
        self.assertEqual(data['cn'], [b'Firstname User1'])
        self.assertEqual(data['uid'], [b'user'])

    def test_copy_of_nonexisting_record_raises_ldap_NO_SUCH_OBJECT(self):
        store = ObjectStore()
        store.register_objects(self.data)
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            store.copy('uid=fred,ou=mydept,o=myorg,c=country')


class TestObjectStore_set(unittest.TestCase):

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

    def test_set_adds_new_record(self):
        store = ObjectStore()
        store.register_objects(self.data)
        self.assertEqual(store.count, 2)
        store.set(self.obj[0], self.obj[1])
        self.assertEqual(store.count, 3)
        self.assertTrue(self.obj[0] in store.objects)
        self.assertTrue(self.obj[0] in store.raw_objects)

    def test_set_updates_existing_record(self):
        dn = self.data[0][0]
        data = copy.deepcopy(self.data[0][1])
        data['cn'] = [b'My New Name']
        store = ObjectStore()
        store.register_objects(self.data)
        self.assertEqual(store.count, 2)
        store.set(dn, data)
        self.assertEqual(store.count, 2)
        self.assertEqual(store.raw_objects[dn]['cn'], [b'My New Name'])
        self.assertEqual(store.objects[dn]['cn'], ['My New Name'])

    def test_set_converts_values_to_str_in_searchable_object(self):
        store = ObjectStore()
        store.register_objects(self.data)
        self.assertEqual(store.count, 2)
        store.set(self.obj[0], self.obj[1])
        self.assertTrue(isinstance(store.objects[self.obj[0]]['cn'][0], str))
