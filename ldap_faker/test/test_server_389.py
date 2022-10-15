import time
import unittest

import ldap
from ldap_faker import ObjectStore

from ldap_faker.servers.server_389 import READONLY_ATTRIBUTES_389

from .test_ObjectStore import (
    BaseTestObjectStore_copy,
    BaseTestObjectStore_create,
    BaseTestObjectStore_exists,
    BaseTestObjectStore_get,
    BaseTestObjectStore_set,
    BaseTestObjectStore_update,
)


class RegisterObjectsMixin:

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
                    'nsroledn': [b'old role'],
                    'objectclass': [b'posixAccount', b'top']
                }
            )
        ]
        self.store = ObjectStore(tags=['389'])
        self.store.register_objects(self.data)


class TestObjectStore389_setup(RegisterObjectsMixin, unittest.TestCase):

    def test_controls_is_set_up(self):
        self.assertIn('roles', self.store.controls)
        self.assertIn('entry_count', self.store.controls)

    def test_operational_attributes_is_set_up(self):
        for attr in READONLY_ATTRIBUTES_389:
            self.assertIn(attr, self.store.operational_attributes)
        self.assertIn('nsroledn', self.store.operational_attributes)


class TestObjectStore389_exists(RegisterObjectsMixin, BaseTestObjectStore_exists, unittest.TestCase):
    pass


class TestObjectStore389_get(RegisterObjectsMixin, BaseTestObjectStore_get, unittest.TestCase):

    def test_get_returns_operational_attributes(self):
        data = self.store.get(self.data[0][0])
        for attr in READONLY_ATTRIBUTES_389:
            self.assertIn(attr, data)
        self.assertIn(attr, 'nsrole')


class TestObjectStore389_copy(RegisterObjectsMixin, BaseTestObjectStore_copy, unittest.TestCase):

    def test_copy_does_not_copy_readonly_attributes(self):
        data = self.store.copy(self.data[0][0])
        for attr in READONLY_ATTRIBUTES_389:
            self.assertNotIn(attr, data)


class TestObjectStore389_set(RegisterObjectsMixin, BaseTestObjectStore_set, unittest.TestCase):

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

    def test_adds_operational_attributes(self):
        self.store.set(self.obj[0], self.obj[1])
        data = self.store.get(self.obj[0])
        for attr in READONLY_ATTRIBUTES_389:
            self.assertIn(attr, data)
        self.assertIn('nsrole', data)

    def test_adds_supplied_nsroledn(self):
        self.obj[1]['nsroledn'] = [b'my roledn']
        self.store.set(self.obj[0], self.obj[1])
        data = self.store.get(self.obj[0])
        self.assertEqual(data['nsroledn'], [b'my roledn'])

    def test_add_sets_entryid(self):
        old_entry_count = self.store.controls['entry_count']
        self.store.set(self.obj[0], self.obj[1])
        data = self.store.get(self.obj[0])
        self.assertEqual(data['entryid'], [str(old_entry_count + 1).encode('utf-8')])

    def test_add_increments_entry_count(self):
        old_entry_count = self.store.controls['entry_count']
        self.store.set(self.obj[0], self.obj[1])
        self.assertEqual(self.store.controls['entry_count'], old_entry_count + 1)

    def test_does_not_add_nsrole_or_nsrole_dn_if_not_user(self):
        del self.obj[1]['userPassword']
        self.store.set(self.obj[0], self.obj[1])
        data = self.store.get(self.obj[0])
        self.assertNotIn('nsrole', data)
        self.assertNotIn('nsroledn', data)

    def test_nsrole_equals_nsroledn_when_no_ldapsubentries_are_present(self):
        """
        With no ldapsubentry objects in the store, nsrole should equal nsroledn
        """
        self.obj[1]['nsroledn'] = [b'my roledn']
        self.store.set(self.obj[0], self.obj[1])
        data = self.store.get(self.obj[0])
        self.assertEqual(data['nsrole'], data['nsroledn'])

    def test_update_handles_timestamps(self):
        self.store.set(self.obj[0], self.obj[1])
        old_create = self.store.get(self.obj[0])['createTimestamp']
        old_modify = self.store.get(self.obj[0])['modifyTimestamp']
        self.obj[1]['loginShell'] = [b'/bin/tcsh']
        time.sleep(1)
        self.store.set(self.obj[0], self.obj[1])
        self.assertEqual(old_create, self.store.get(self.obj[0])['createTimestamp'])
        self.assertNotEqual(old_modify, self.store.get(self.obj[0])['modifyTimestamp'])

    def test_update_handles_names(self):
        self.store.set(self.obj[0], self.obj[1])
        old_create = self.store.get(self.obj[0])['creatorName']
        self.obj[1]['loginShell'] = [b'/bin/tcsh']
        self.store.set(self.obj[0], self.obj[1], bind_dn='new user')
        self.assertEqual(old_create, self.store.get(self.obj[0])['creatorName'])
        self.assertEqual([b'new user'], self.store.get(self.obj[0])['modifierName'])


class TestObjectStore389_update(RegisterObjectsMixin, BaseTestObjectStore_update, unittest.TestCase):

    def test_readonly_attributes_are_readonly(self):
        dn = self.data[0][0]
        for attr in READONLY_ATTRIBUTES_389:
            modlist = [(ldap.MOD_REPLACE, attr, [b'new value'])]
            with self.assertRaises(ldap.UNWILLING_TO_PERFORM):
                self.store.update(dn, modlist)

    def test_update_updates_modifierName(self):
        dn = self.data[0][0]
        modlist = [(ldap.MOD_ADD, 'gecos', [b'new value'])]
        self.store.update(dn, modlist, bind_dn='the bind dn')
        data = self.store.get(dn)
        self.assertEqual(data['modifierName'], [b'the bind dn'])

    def test_update_does_not_update_creatorName(self):
        dn = self.data[0][0]
        modlist = [(ldap.MOD_ADD, 'gecos', [b'new value'])]
        self.store.update(dn, modlist, bind_dn='the bind dn')
        data = self.store.get(dn)
        self.assertNotEqual(data['creatorName'], [b'the bind dn'])

    def test_MOD_ADD_nsroledn_also_adds_to_nsrole(self):
        dn = self.data[0][0]
        modlist = [(ldap.MOD_ADD, 'nsroledn', [b'new role'])]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertEqual(data['nsrole'], [b'new role'])

    def test_MOD_DELETE_nsroledn_also_deletes_from_nsrole(self):
        dn = self.data[1][0]
        data = self.store.get(dn)
        self.assertEqual(data['nsrole'], [b'old role'])
        modlist = [(ldap.MOD_DELETE, 'nsroledn', [b'old role'])]
        self.store.update(dn, modlist)
        data = self.store.get(dn)
        self.assertEqual(data['nsrole'], [])


class TestObjectStore389_create(RegisterObjectsMixin, BaseTestObjectStore_create, unittest.TestCase):

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

    def test_readonly_attributes_are_ignored(self):
        for attr in READONLY_ATTRIBUTES_389:
            self.modlist.append((attr, [b'new value']))
            self.store.create(self.dn, self.modlist)
            data = self.store.get(self.dn)
            self.assertIn(attr, data)
            self.assertNotEqual(data[attr], [b'new value'])
            self.store.delete(self.dn)

    def test_create_sets_creatorName(self):
        self.store.create(self.dn, self.modlist, bind_dn='the bind dn')
        data = self.store.get(self.dn)
        self.assertEqual(data['creatorName'], [b'the bind dn'])

    def test_create_sets_modifierName(self):
        self.store.create(self.dn, self.modlist, bind_dn='the bind dn')
        data = self.store.get(self.dn)
        self.assertEqual(data['modifierName'], [b'the bind dn'])


class TestObjectStore389_managed_ldapsubentries(unittest.TestCase):

    def setUp(self):
        self.store = ObjectStore(tags=['389'])
        self.managed = [
            'cn=managed,ou=roles,o=myorg,c=country',
            {
                'objectClass': [
                    b'ldapsubentry',
                    b'nsmanagedroledefinition',
                    b'nsroledefinition',
                    b'nssimpleroledefinition',
                    b'top'
                ],
                'cn': [b'managed'],
                'description': [b'a managed role']
            }
        ]
        self.nested = [
            'cn=nested,ou=roles,o=myorg,c=country',
            {
                'objectClass': [
                    b'ldapsubentry',
                    b'nscomplexroledefinition',
                    b'nsnestedroledefinition',
                    b'nsroledefinition',
                    b'top'
                ],
                'cn': [b'managed'],
                'description': [b'a nested role'],
                'nsroledn': [b'foo', b'bar']
            }
        ]
        self.search = [
            'cn=search,ou=roles,o=myorg,c=country',
            {
                'objectClass': [
                    b'ldapsubentry',
                    b'nscomplexroledefinition',
                    b'nsfilteredroledefinition',
                    b'nsroledefinition',
                    b'top'
                ],
                'cn': [b'managed'],
                'description': [b'a search role'],
                'nsrolefilter': [b'(cn=*user2)']
            }
        ]
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

    def test_managed_roles_do_not_update_controls(self):
        self.store.register_object(self.managed)
        self.assertNotIn(self.managed[0], self.store.controls['roles'])

    def test_managed_roles_do_not_affect_user_add(self):
        self.store.register_object(self.managed)
        self.store.set(self.data[0][0], self.data[0][1])
        data = self.store.get(self.data[0][0])
        self.assertEqual(data['nsrole'], [])

    def test_managed_roles_do_not_affect_existing_users(self):
        self.store.register_objects(self.data)
        self.store.set(self.managed[0], self.managed[1])
        for obj in self.data:
            data = self.store.get(obj[0])
            self.assertEqual(data['nsrole'], [])


class TestObjectStore389_nested_ldapsubentries(unittest.TestCase):

    def setUp(self):
        self.store = ObjectStore(tags=['389'])
        self.nested = [
            'cn=nested,ou=roles,o=myorg,c=country',
            {
                'objectClass': [
                    b'ldapsubentry',
                    b'nscomplexroledefinition',
                    b'nsnestedroledefinition',
                    b'nsroledefinition',
                    b'top'
                ],
                'cn': [b'managed'],
                'description': [b'a nested role'],
                'nsroledn': [b'foo', b'bar']
            }
        ]
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

    def test_nested_roles_do_update_controls(self):
        self.store.register_object(self.nested)
        self.assertIn(self.nested[0].encode('utf-8'), self.store.controls['roles'])

    def test_nested_roles_do_not_affect_user_add_if_nsroledn_does_not_match(self):
        self.store.register_object(self.nested)
        self.store.set(self.data[0][0], self.data[0][1])
        data = self.store.get(self.data[0][0])
        self.assertEqual(data['nsrole'], [])

    def test_nested_roles_do_affect_user_adds_if_nsroledn_does_match(self):
        self.store.register_object(self.nested)
        self.data[0][1]['nsroledn'] = [b'foo']
        self.store.set(self.data[0][0], self.data[0][1])
        data = self.store.get(self.data[0][0])
        self.assertEqual(data['nsrole'], [self.nested[0].encode('utf-8'), b'foo'])

    def test_nested_roles_remove_nsrole_on_user_update_if_nsroledn_removed(self):
        # setup
        dn = self.data[0][0]
        data = self.data[0][1]
        self.store.register_object(self.nested)
        self.data[0][1]['nsroledn'] = [b'foo']
        self.store.set(dn, data)
        data = self.store.get(dn)
        self.assertEqual(data['nsroledn'], [b'foo'])
        self.assertEqual(data['nsrole'], [self.nested[0].encode('utf-8'), b'foo'])

        # now remove the trigger role
        self.store.update(dn, [(ldap.MOD_DELETE, 'nsroledn', [b'foo'])])
        data = self.store.get(dn)
        self.assertEqual(data['nsrole'], [])

    def test_nested_roles_remove_nsrole_if_ldapsubentry_deleted(self):
        # setup
        dn = self.data[0][0]
        data = self.data[0][1]
        self.store.register_object(self.nested)
        self.data[0][1]['nsroledn'] = [b'foo']
        self.store.set(dn, data)
        data = self.store.get(dn)
        self.assertEqual(data['nsroledn'], [b'foo'])
        self.assertEqual(data['nsrole'], [self.nested[0].encode('utf-8'), b'foo'])

        # now remove the trigger role
        self.store.delete(self.nested[0])
        data = self.store.get(dn)
        self.assertEqual(data['nsrole'], [b'foo'])


class TestObjectStore389_search_ldapsubentries(unittest.TestCase):

    def setUp(self):
        self.store = ObjectStore(tags=['389'])
        self.search = [
            'cn=search,ou=roles,o=myorg,c=country',
            {
                'objectClass': [
                    b'ldapsubentry',
                    b'nscomplexroledefinition',
                    b'nsfilteredroledefinition',
                    b'nsroledefinition',
                    b'top'
                ],
                'cn': [b'managed'],
                'description': [b'a nested role'],
                'nsrolefilter': [b'(gecos=trigger)']
            }
        ]
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

    def test_search_roles_do_update_controls(self):
        self.store.register_object(self.search)
        self.assertIn(self.search[0].encode('utf-8'), self.store.controls['roles'])

    def test_search_roles_do_not_affect_user_add_if_nsrolefilter_does_not_match(self):
        self.store.register_object(self.search)
        self.store.set(self.data[0][0], self.data[0][1])
        data = self.store.get(self.data[0][0])
        self.assertEqual(data['nsrole'], [])

    def test_search_roles_do_affect_user_adds_if_nsrolefilter_does_match(self):
        self.store.register_object(self.search)
        self.data[0][1]['gecos'] = [b'trigger']
        self.store.set(self.data[0][0], self.data[0][1])
        data = self.store.get(self.data[0][0])
        self.assertEqual(data['nsrole'], [self.search[0].encode('utf-8')])

    def test_search_roles_remove_nsrole_on_user_update_if_object_no_longer_matches(self):
        # setup
        dn, data = self.data[0]
        self.store.register_object(self.search)
        self.data[0][1]['gecos'] = [b'trigger']
        self.store.set(dn, data)
        data = self.store.get(dn)
        self.assertEqual(data['nsrole'], [self.search[0].encode('utf-8')])

        # now remove the trigger role
        self.store.update(dn, [(ldap.MOD_REPLACE, 'gecos', [b'bogus'])])
        data = self.store.get(dn)
        self.assertEqual(data['nsrole'], [])

    def test_search_roles_remove_nsrole_ldapsubentry_deleted(self):
        # setup
        dn, data = self.data[0]
        self.store.register_object(self.search)
        self.data[0][1]['gecos'] = [b'trigger']
        self.store.set(dn, data)
        data = self.store.get(dn)
        self.assertEqual(data['nsrole'], [self.search[0].encode('utf-8')])

        # now remove the trigger role
        self.store.delete(self.search[0])
        data = self.store.get(dn)
        self.assertEqual(data['nsrole'], [])
