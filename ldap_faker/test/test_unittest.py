import unittest

import ldap_faker

from ldap_faker.unittest import LDAPFakerMixin
from ldap_faker.test.app import MyLDAPClass


class TestLDAPFakerMixin_patches_modules(LDAPFakerMixin, unittest.TestCase):
    ldap_modules = ["ldap_faker.test.app"]

    def setUp(self):
        super().setUp()
        self.obj = MyLDAPClass()

    def test_module_was_patched(self):
        self.assertEqual(ldap_faker.test.app.ldap.initialize, self.fake_ldap.initialize)
        self.assertEqual(ldap_faker.test.app.ldap.set_option, self.fake_ldap.set_option)
        self.assertEqual(ldap_faker.test.app.ldap.get_option, self.fake_ldap.get_option)


class TestLDAPFakerMixin_patches_multiple_modules(LDAPFakerMixin, unittest.TestCase):
    ldap_modules = ["ldap_faker.test.app", "ldap_faker.test.app2"]

    def setUp(self):
        super().setUp()
        self.obj = MyLDAPClass()

    def test_module_was_patched(self):
        self.assertEqual(ldap_faker.test.app.ldap.initialize, self.fake_ldap.initialize)
        self.assertEqual(ldap_faker.test.app.ldap.set_option, self.fake_ldap.set_option)
        self.assertEqual(ldap_faker.test.app.ldap.get_option, self.fake_ldap.get_option)
        self.assertEqual(
            ldap_faker.test.app2.ldap.initialize, self.fake_ldap.initialize
        )
        self.assertEqual(
            ldap_faker.test.app2.ldap.set_option, self.fake_ldap.set_option
        )
        self.assertEqual(
            ldap_faker.test.app2.ldap.get_option, self.fake_ldap.get_option
        )


class TestLDAPFakerMixin_loads_empty_default_store_if_none_provided(
    LDAPFakerMixin, unittest.TestCase
):
    ldap_modules = ["ldap_faker.test.app"]

    def test_factory_was_loaded_with_default_store(self):
        self.assertIsNotNone(self.server_factory.default)
        store = self.server_factory.default
        self.assertEqual(len(store.objects), 0)


class TestLDAPFakerMixin_loads_default_store(LDAPFakerMixin, unittest.TestCase):
    ldap_modules = ["ldap_faker.test.app"]
    ldap_fixtures = "server1.json"

    def test_factory_was_loaded_with_default_store(self):
        self.assertIsNotNone(self.server_factory.default)
        store = self.server_factory.default
        self.assertTrue(store.exists("uid=user,ou=mydept,o=myorg,c=country"))
        self.assertTrue(store.exists("uid=user2,ou=mydept,o=myorg,c=country"))


class TestLDAPFakerMixin_loads_default_store_with_tags(
    LDAPFakerMixin, unittest.TestCase
):
    ldap_modules = ["ldap_faker.test.app"]
    ldap_fixtures = ("server1.json", ["foo"])

    def test_store_was_loaded_with_tags(self):
        self.assertIsNotNone(self.server_factory.default)
        store = self.server_factory.default
        self.assertEqual(store.tags, ["foo"])


class TestLDAPFakerMixin_loads_named_store_with_tags(LDAPFakerMixin, unittest.TestCase):
    ldap_modules = ["ldap_faker.test.app"]
    ldap_fixtures = [
        ("server1.json", "ldap://server1", ["foo"]),
        ("big.json", "ldap://server2", []),
    ]

    def test_factory_was_loaded_with_named_stores(self):
        # When using named stores, there's no default store
        self.assertIsNone(self.server_factory.default)
        # Check that the named stores were loaded correctly
        store1 = self.server_factory.get("ldap://server1")
        store2 = self.server_factory.get("ldap://server2")
        self.assertEqual(store1.tags, ["foo"])
        self.assertEqual(store2.tags, [])
