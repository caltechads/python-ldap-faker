.. module:: ldap_faker
  :noindex:

Using ldap_faker with unittest
==============================

Most of the purpose of ``python-ldap-faker`` is to make automated testing
of code that uses ``python-ldap`` easier.

To this end, ``python-ldap-faker`` provides :py:class:`LDAPFakerMixin`, a mixin class
for :py:class:`unittest.TestCase` which handles all the hard work of patching
and instrumenting the appropriate ``python-ldap`` functions, objects and
methods.

:py:class:`LDAPFakerMixin` will do the following things for you:

* Read data from JSON fixture files to populate one or more
  :py:class:`ObjectStore` objects (our fake LDAP server class)
* Associate those :py:class:`ObjectStore` objects with particular LDAP URIs
* Patch :py:func:`ldap.initialize` to return :py:class:`FakeLDAPObject` objects
  configured with the appropriate :py:class:`ObjectStore` for the LDAP URI passed
  into :py:meth:`FakeLDAP.initialize`


Configuring your LDAPFakerMixin TestCase
----------------------------------------

We need to give two things :py:class:`LDAPFakerMixin` in order for it to
properly set up your tests:

* The list of your code's modules in which to patch :py:func:`ldap.initialize`
* A list of JSON fixture files with which to create the :py:class:`ObjectStore` objects

How LDAPFakerMixin patches your code
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:py:class:`LDAPFakerMixin` uses :py:func:`unittest.mock.patch` to patch your
code so that it uses our fake version of :py:func:`ldap.initialize` instead of
the real one.  The way ``patch`` works is that it must apply the patch within
the context of your module that does ``import ldap``, not within the ``ldap``
module itself.  Thus, to make :py:class:`LDAPFakerMixin` work for you, you must
list all the modules for code under test in which you do ``import ldap``.

To list all the modules in which the code under test does ``import ldap``, use
the :py:attr:`LDAPFakerMixin.ldap_modules` class attribute.

For example, if you have a class ``MyLDAPUsingClass`` in the module
``myapp.myldapstuff``, and you do ``import ldap`` in ``myapp.myldapstuff``, for
instance::

  import ldap

  class MyLDAPUsingClass:

      def connect(self, uid: str, password: str):
          self.conn = ldap.initialize('ldap://server')
          self.conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
          self.conn.start_tls_s()
          self.conn.simple_bind_s(
            f'uid={uid},ou=bar,o=baz,c=country',
            'the password'
          )


To test this code, you would do::

  import unittest
  from ldap_faker import LDAPFakerMixin

  from myapp.myldapstuff import MyLDAPUsingClass

  class TestMyLDAPUsingCLass(LDAPFakerMixin, unittest.TestCase):

      ldap_modules = ['myapp.myldapstuff']
      ldap_fixtures = 'data.json'

      def test_stuff(self):
          c = MyLDAPUsingClass
          c.connect('foo', 'the password')
          conn = self.get_connections()[0]
          self.assertLDAPConnectionOptionSet(conn, ldap.OPT_X_TLS_NEWCTX, 0)
          self.assertLDAPConnectiontMethodCalled(conn, 'start_tls_s')
          self.assertLDAPConnectiontMethodCalled(conn, 'simple_bind_s'
            {'who': 'uid=foo,ou=bar,o=baz,c=country', 'cred': 'the password'}
          )
          self.assertLDAPConnectiontMethodCalledAfter(conn, 'simple_bind_s', 'start_tls_s')
