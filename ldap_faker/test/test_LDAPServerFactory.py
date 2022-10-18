from pathlib import Path
import unittest

from ldap_faker import LDAPServerFactory, ObjectStore


class TestLDAPServerFactory_register(unittest.TestCase):

    def setUp(self):
        self.filenames = [
            Path(__file__).parent / Path('big.json'),
            Path(__file__).parent / Path('server1.json'),
        ]
        self.factory = LDAPServerFactory()

    def test_register_with_no_uri_sets_default(self):
        store = ObjectStore()
        store.load_objects(self.filenames[0])
        self.factory.register(store)
        self.assertIs(self.factory.default, store)
        self.assertEqual(self.factory.servers, {None: store})

    def test_register_raises_ValueError_if_default_has_been_set(self):
        store = ObjectStore()
        store.load_objects(self.filenames[0])
        self.factory.register(store)
        store2 = ObjectStore()
        store2.load_objects(self.filenames[1])
        with self.assertRaises(ValueError):
            self.factory.register(store2, 'ldap://blah')

    def test_can_register_several_stores_with_separate_uris(self):
        store = ObjectStore()
        store.load_objects(self.filenames[0])
        self.factory.register(store, uri='ldap://server1')
        store2 = ObjectStore()
        store2.load_objects(self.filenames[1])
        self.factory.register(store2, 'ldap://blah')
        self.assertEqual(self.factory.default, None)
        self.assertEqual(len(self.factory.servers), 2)
        self.assertEqual(self.factory.servers['ldap://server1'], store)
        self.assertEqual(self.factory.servers['ldap://blah'], store2)

    def test_register_warns_if_same_uri_is_used_for_different_stores(self):
        store = ObjectStore()
        store.load_objects(self.filenames[0])
        self.factory.register(store, uri='ldap://server1')
        store2 = ObjectStore()
        store2.load_objects(self.filenames[1])
        with self.assertWarns(RuntimeWarning):
            self.factory.register(store2, 'ldap://server1')

    def test_register_warns_if_multiple_default_stores_set(self):
        store = ObjectStore()
        store.load_objects(self.filenames[0])
        self.factory.register(store)
        store2 = ObjectStore()
        store2.load_objects(self.filenames[1])
        with self.assertWarns(RuntimeWarning):
            self.factory.register(store2)


class TestLDAPServerFactory_load_from_file(unittest.TestCase):

    def setUp(self):
        self.filenames = [
            Path(__file__).parent / Path('big.json'),
            Path(__file__).parent / Path('server1.json'),
        ]
        self.factory = LDAPServerFactory()

    def test_load_from_file_with_no_uri_sets_default(self):
        self.factory.load_from_file(self.filenames[0])
        self.assertIsNotNone(self.factory.default)
        self.assertIsInstance(self.factory.default, ObjectStore)
        self.assertIn(None, self.factory.servers)

    def test_load_from_file_raises_ValueError_if_default_has_been_set(self):
        self.factory.load_from_file(self.filenames[0])
        with self.assertRaises(ValueError):
            self.factory.load_from_file(self.filenames[1], uri='ldap://server1')

    def test_can_load_from_file_several_stores_with_separate_uris(self):
        self.factory.load_from_file(self.filenames[0], uri='ldap://server1')
        self.factory.load_from_file(self.filenames[1], uri='ldap://blah')
        self.assertEqual(self.factory.default, None)
        self.assertEqual(len(self.factory.servers), 2)
        self.assertIn('ldap://server1', self.factory.servers)
        self.assertIsInstance(self.factory.servers['ldap://server1'], ObjectStore)
        self.assertIn('ldap://blah', self.factory.servers)
        self.assertIsInstance(self.factory.servers['ldap://blah'], ObjectStore)

    def test_register_warns_if_same_uri_is_used_for_different_stores(self):
        self.factory.load_from_file(self.filenames[0], uri='ldap://server1')
        with self.assertWarns(RuntimeWarning):
            self.factory.register(self.filenames[1], 'ldap://server1')

    def test_register_warns_if_multiple_default_stores_set(self):
        self.factory.load_from_file(self.filenames[0])
        with self.assertWarns(RuntimeWarning):
            self.factory.load_from_file(self.filenames[1])

    def test_can_set_tags_on_default_server(self):
        self.factory.load_from_file(self.filenames[0], tags=['foo'])
        self.assertEqual(self.factory.default.tags, ['foo'])

    def test_can_set_tags_on_named_servers(self):
        self.factory.load_from_file(self.filenames[0], uri='ldap://server1', tags=['foo'])
        self.assertEqual(self.factory.servers['ldap://server1'].tags, ['foo'])
        self.factory.load_from_file(self.filenames[1], uri='ldap://server2', tags=['bar'])
        self.assertEqual(self.factory.servers['ldap://server2'].tags, ['bar'])
