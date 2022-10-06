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

We need to set two class attributes on  :py:class:`LDAPFakerMixin` in order for
it to properly set up your tests:

* :py:attr:`LDAPFakerMixin.ldap_modules`: The list of your code's modules in
  which to patch :py:func:`ldap.initialize`, :py:func:`ldap.set_option` and
  :py:func:`ldap.get_option``
* :py:attr:`LDAPFakerMixin.ldap_fixtures`: A list of JSON fixture files with
  which to create the :py:class:`ObjectStore` objects

LDAPFakerMixin.ldap_modules
^^^^^^^^^^^^^^^^^^^^^^^^^^^

:py:class:`LDAPFakerMixin` uses :py:func:`unittest.mock.patch` to patch your
code so that it uses our fake versions of :py:func:`ldap.initialize`,
:py:func:`ldap.set_option` and :py:func:`ldap.get_option` instead of the real
one.  The way ``patch`` works is that it must apply the patch within the context
of your module that does ``import ldap``, not within the ``ldap`` module itself.
Thus, to make :py:class:`LDAPFakerMixin` work for you, you must list all the
modules for code under test in which you do ``import ldap``.

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


To test this code, you would use this for ``ldap_modules``::

  import unittest
  from ldap_faker import LDAPFakerMixin

  from myapp.myldapstuff import MyLDAPUsingClass

  class TestMyLDAPUsingCLass(LDAPFakerMixin, unittest.TestCase):

      ldap_modules = ['myapp.myldapstuff']


LDAPFakerMixin.ldap_fixtures
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to effectively test your ``python-ldap`` using code, you'll need to
populate an :py:class:`LDAPServerFactory` one or more :py:class:`ObjectStore`
objects bound to LDAP URIs.  We use :py:attr:`LDAPFakerMixin.ldap_fixtures` to
declare file paths to fixture files to use to populate those
:py:class:`ObjectClass` objects.

* Fixture files are JSON files in the format described in :ref:`File format for ObjectStore.load_objects`.
* File paths are either absolute paths or are treated as relative to the folder
  in which your ``TestCase`` resides.
* Fixtures are loaded into the :py:class:`LDAPServerFactory` **once** per
  :py:class:`unittest.TestCase` via the :py:meth:`unittest.TestCase.setUpClass`
  classmethod.

You can configure your :py:class:`LDAPFakerMixin` to use fixtures one of two ways:

* Use a single default fixture that will be used no matter which LDAP URI is
  passed to :py:meth:`FakeLDAP.initialize`
* Bind each fixture to specific a LDAP URI.  This allows you simulate talking to
  several different LDAP servers.

.. note::

  When binding fixtures to particular LDAP URIs, if your tries to use
  :py:meth:`FakeLDAP.initialize` with an LDAP URI that was not explicitly configured,
  ``python-ldap-faker`` will raise :py:exc:`ldap.SERVER_DOWN`

This form sets up one default fixture::

    import unittest
    from ldap_faker import LDAPFakerMixin

    from myapp.myldapstuff import MyLDAPUsingClass

    class TestMyLDAPUsingCLass(LDAPFakerMixin, unittest.TestCase):

        ldap_fixtures = 'objects.json'


This form binds fixtures to LDAP URIs::

    import unittest
    from ldap_faker import LDAPFakerMixin

    from myapp.myldapstuff import MyLDAPUsingClass

    class TestMyLDAPUsingCLass(LDAPFakerMixin, unittest.TestCase):

        ldap_fixtures = [
          ('server1.json', 'ldap://server1.example.com'),
          ('server2.json', 'ldap://server2.example.com')
        ]


Test isolation
--------------

Each test method on your :py:class:`unittest.TestCase` will get a fresh, unaltered
**copy** of the fixture data, and connections, call histories, options set from previous
test methods will be cleared.


Test support offered by LDAPFakerMixin
--------------------------------------

For each test you run, your test will have access to the :py:class:`FakeLDAP`
instance used for that test through the :py:attr:`LDAPFakerMixin.fake_ldap`
instance attribute.  Each test gets a fresh :py:class:`FakeLDAP` instance.

.. note::
  For detailed information on any of the below, see the :ref:`api`.

Some things to know about your :py:class:`FakeLDAP` instance:

* :py:attr:`FakeLDAP.connections` lists all the :py:class:`FakeLDAPObject`
  connections created during your test method, in the order they were made.  One
  such object is created each time :py:meth:`FakeLDAP.initialize` is called by
  your code.
* :py:attr:`FakeLDAP.options` is a :py:class:`OptionStore` object that records
  all the global LDAP options set during your test
* :py:attr:`FakeLDAP.calls` is a :py:class:`CallHistory` object that records
  calls (with arguments) to :py:meth:`FakeLDAP.initialize`,
  :py:meth:`FakeLDAP.set_option`, :py:meth:`FakeLDAP.get_option`

Some things to know about the :py:class:`FakeLDAPObject` objects in
:py:attr:`FakeLDAP.connections`:

* :py:attr:`FakeLDAPObject.uri` is the LDAP URI requested
* :py:attr:`FakeLDAPObject.store` is our :py:class:`ObjectStore` copy
* :py:attr:`FakeLDAP.options` is a :py:class:`OptionStore` object that records
  all the LDAP options set on this connection during your test method
* :py:attr:`FakeLDAPObject.calls` is a :py:class:`CallHistory` that records all
  ``python-ldap`` api calls (with arguments) that your code made to this
  ``FakeLDAPObject``
* :py:attr:`FakeLDAPObject.bound_dn` is the ``dn`` of the user bound via
  ``simple_bind_s``, if any. If this is ``None``, we did anonymous binding.
* :py:attr:`FakeLDAPObject.tls_enabled` will be set to ``True`` if ``start_tls_s``
  was used on this connection