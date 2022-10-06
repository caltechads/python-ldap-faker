import unittest

from ldap_faker.unittest import LDAPFakerMixin

from ldap_faker.test.app import MyLDAPClass


class TestLDAPFakerMixin(LDAPFakerMixin, unittest.TestCase):

    ldap_modules = ['ldap_faker.test.app']
    ldap_fixtures = 'server1.json'

    def setUp(self):
        super().setUp()
        self.obj = MyLDAPClass()

    def test_initialize_was_called(self):
        self.obj.connect('uid=user,ou=mydept,o=myorg,c=country', 'the password')
        self.assertTrue('initialize' in self.fake_ldap.calls.names)

    def test_one_connection_was_made(self):
        dn = 'uid=user,ou=mydept,o=myorg,c=country'
        self.obj.connect(dn, 'the password')
        self.assertEqual(len(self.fake_ldap.connections), 1)

    def test_correct_user_was_bound(self):
        dn = 'uid=user,ou=mydept,o=myorg,c=country'
        self.obj.connect(dn, 'the password')
        self.assertEqual(self.fake_ldap.connections[0].bound_dn, dn)
