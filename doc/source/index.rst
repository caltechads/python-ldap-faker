.. module:: ldap_faker
  :noindex:

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

* These ``python-ldap`` global functions are faked:

    * ``ldap.initialize``
    * ``ldap.set_option``
    * ``ldap.get_option``

* These ``ldap.ldapobject.LDAPObject`` methods are faked:

    * ``set_option``
    * ``get_option``
    * ``start_tls_s``
    * ``simple_bind_s``
    * ``unbind_s``
    * ``search_s``
    * ``search_ext``
    * ``result3``
    * ``compare_s``
    * ``add_s``
    * ``modify_s``
    * ``rename_s``
    * ``delete_s``
    * ``modrdn_s``

* For ``search_ext`` and ``search_s``, your filter string will be validated as a
  valid LDAP filter, and your filter will be applied directly to your objects in
  our fake "server" to generate the result list.  No canned searches!
* For search, both Paged Results (OID 1.2.840.113556.1.4.319) and server side
  sorting (OID 1.2.840.113556.1.4.473) are supported and are advertised when
  the server side checks what controls it supports.
* Virtual List View (VLV) control (OID 2.16.840.1.113730.3.4.9) is supported for
  efficient pagination of large result sets and is advertised in the Root DSE.
* Inspect your call history for all calls (name, arguments), and test the order
  in which they were made
* Simulate multiple fake LDAP "servers" with different sets of objects that
  correspond to different LDAP URIs.
* Ease your test setup with :py:class:`LDAPFakerMixin`, a mixin for
  :py:class:`unittest.TestCase`

    * Automatically manages patching ``python-ldap`` for the code under test
    * Populate objects into one or more LDAP "servers" with fixture files
    * Provides the following test instrumentation for inspecting state after the test:

        * Access to the full object store for each LDAP uri accessed
        * All connections made
        * All ``python-ldap`` API calls made
        * All ``python-ldap`` LDAP options set

    * Provides test isolation: object store changes, connections, call history,
      option changes are all reset between tests
    * Use handy LDAP specific asserts to ease your testing

* Define your own hooks to change the behavior of your fake "servers"
* Support behavior for specific LDAP implementations:

    * Redhat Directory Server/389 implementation support: have your test believe
      it's talking to an RHDS/389 server.

Quickstart
==========

The easiest way to use ``python-ldap-faker`` in your :py:mod:`unittest` based
tests is to use the :py:class:`LDAPFakerMixin` mixin for
:py:class:`unittest.TestCase`.

This will patch :py:func:`ldap.initialize`, :py:func:`ldap.set_option` and
:py:func:`ldap.get_option` to use our :py:class:`FakeLDAP` interface, and load
fixtures in from JSON files to use as test data.

Let's say we have a class ``App`` in our ``myapp`` module that does LDAP work
that we want to test.

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

    import ldap
    from ldap_faker import LDAPFakerMixin

    from myapp import App

    class YourTestCase(LDAPFakerMixin, unittest.TestCase):

        ldap_modules = ['myapp']
        ldap_fixtures = 'data.json'

        def test_auth_works(self):
            app = App()
            # A method that does a `simple_bind_s`
            app.auth('fred', 'the fredpassword')
            conn = self.get_connections()[0]
            self.assertLDAPConnectionMethodCalled(
                conn, 'simple_bind_s',
                {'who': 'uid=fred,ou=bar,o=baz,c=country', 'cred': 'the fredpassword'}
            )

        def test_correct_connection_options_were_set(self):
            app = App()
            app.auth('fred', 'the fredpassword')
            conn = self.get_connections()[0]
            self.assertLDAPConnectionOptionSet(conn, ldap.OPT_X_TLX_NEWCTX, 0)

        def test_tls_was_used_before_auth(self):
            app = App()
            app.auth('fred', 'the fredpassword')
            conn = self.get_connections()[0]
            self.assertLDAPConnectiontMethodCalled(conn, 'start_tls_s')
            self.assertLDAPConnectionMethodCalledAfter(conn, 'simple_bind_s', 'start_tls_s')



.. toctree::
   :maxdepth: 2

   objectstore
   implementations
   binds
   unittest
   hooks
   api