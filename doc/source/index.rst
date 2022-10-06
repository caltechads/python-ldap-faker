=================
python-ldap-faker
=================

Current version is |release|.

This package provides a fake ``python-ldap`` interface that can be used for
automated testing of code that uses ``python-ldap``.   With ``python-ldap-faker``
you will be able to test your LDAP code without having to stand up an actual
LDAP server, and also without having to use complicated
:py:func:`unittest.mock.patch` and :py:class:`unittest.mock.Mock` setups.

When writing tests for code that talks to an LDAP server with ``python-ldap``, we
want to be able to control ``python-ldap`` interactions in our tests to ensure
that our own code works properly.  This may include populating the LDAP server
with fixture data, monitoring if, when and how ``python-ldap`` calls are made by
our code, and ensuring our code handles ``python-ldap`` exceptions properly.

Managing an actual LDAP server during our tests is usually out of the question,
so typically we revert to patching the ``python-ldap`` code to use mock objects
instead, but this is very verbose and can lead to test code errors in practice.

This package provides replacement :py:func:`ldap.initialize`,
:py:func:`ldap.set_option` and :py:func:`ldap.get_option` functions, as well as
a test-instrumented :py:class:`ldap.ldap.ldapobject.LDAPObject` replacement.

Installation
============

To install from PyPI::

   pip install python-ldap-faker

If you want, you can run the tests::

   python -m unittest discover


Features:
=========

* :py:class:`LDAPFakerMixin`, a mixin class that for :py:class:`unittest.TestCase` that
  handles all test instrumentation, loads fixtures, and provides useful ``asserts``
* Populate your tests with LDAP records, and have `add_s`, `modify_s`, `search_s` all work as you would expect
* Case-sensitivity works just like it would in an actual LDAP server:

   * `dn` is case-insensitive
   * LDAP attributes are case-insensitive when searching or comparing
   * LDAP attribute values are case-insensitive when doing searches



Quickstart
==========

The easiest way to use ``python-ldap-faker`` in your :py:mod:`unittest` based tests is to
use the :py:class:`LDAPFakerMixin` mixin for :py:class:`unittest.TestCase`.

This will patch :py:func:`ldap.initialize` to use our :py:class:`FakeLDAP` interface, and load
fixtures in from JSON files to use as test data.

Let's say we have a class ``App`` in our ``myapp`` module that does LDAP work that
we want to test.

First, prepare a file named ``data.json`` with the objects you want loaded into
your fake LDAP server.   Let's say you want your data to consist of some
``posixAccount`` objects.  If we make ``data.json`` look like this::

   [
      [
         "uid=foo,ou=bar,o=baz,c=country",
         {
               "uid": ["foo"],
               "cn": ["Foo Bar"],
               "uidNumber": ["123"],
               "gidNumber": ["123"],
               "homeDirectory": ["/home/foo"],
               "userPassword": ["the password"],
               "objectclass": [
                  "posixAccount",
                  "top"
               ]
         }
      ],
      [
         "uid=fred,ou=bar,o=baz,c=country",
         {
               "uid": ["fred"],
               "cn": ["Fred Flintstone"],
               "uidNumber": ["124"],
               "gidNumber": ["124"],
               "homeDirectory": ["/home/fred"],
               "userPassword": ["the fredpassword"],
               "objectclass": [
                  "posixAccount",
                  "top"
               ]
         }
      ],
      [
         "uid=barney,ou=bar,o=baz,c=country",
         {
               "uid": ["barney"],
               "cn": ["Barney Rubble"],
               "uidNumber": ["125"],
               "gidNumber": ["125"],
               "homeDirectory": ["/home/barney"],
               "userPassword": ["the barneypassword"],
               "objectclass": [
                  "posixAccount",
                  "top"
               ]
         }
      ]
   ]

We can write our ``TestCase`` like so::

    import unittest
    from ldap_faker import LDAPFakerMixin

    from myapp import App

    class YourTestCase(LDAPFakerMixin, unittest.TestCase):

        ldap_modules = ['myapp']
        ldap_fixtures = 'data.json'

        def test_auth_works(self):
            app = App()
            # A method that does a `simple_bind_s`
            app.auth('fred', 'the fredpassword')
            self.assertLDAPObjectMethodCalled('simple_bind_s')
            conn = self.get_connections()[0]
            self.assertEqual(conn.bound_dn, 'uid=fred,ou=bar,o=baz,c=country')

        def test_correct_connection_options_were_set(self):
            app = App()
            app.auth('fred', 'the fredpassword')

        def test_tls_was_used_before_auth(self):
            app = App()
            app.auth('fred', 'the fredpassword')
            self.assertLDAPConnectiontMethodCalled('start_tls_s')
            conn = self.get_connections()[0]
            methods_called = conn.calls.names
            self.assertTrue(methods_called.index('start_tls_s') < methods_called.index('simple_bind_s'))



.. toctree::
   :maxdepth: 2

   objectstore
   binds
   unittest
   api