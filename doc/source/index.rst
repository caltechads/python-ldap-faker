=================
python-ldap-faker
=================

Current version is |release|.

This package provides a fake `python-ldap` interface that can be used for
automated testing of code that uses `python-ldap`.

When writing tests for code that talks to an LDAP server with `python-ldap`, we
want to be able to control `python-ldap` interactions in our tests to ensure
that our own code works properly.  This may include populating the LDAP server
with fixture data, monitoring if, when and how `python-ldap` calls are made by
our code, and ensuring our code handles `python-ldap` exceptions properly.

Managing an actual LDAP server during our tests is usually out of the question,
so typically we revert to patching the `python-ldap` code to use mock objects
instead, but this is very verbose and can lead to test code errors in practice.

This package provides replacement :py:func:`ldap.initialize`, :py:func:`ldap.set_option` and
:py:func:`ldap.get_option` functions, as well as a test-instrumented :py:class:`ldap.ldap.ldapobject.LDAPObject`
replacement.

Installation
============

To install from PyPI::

   pip install python-ldap-faker

If you want, you can run the tests::

   python -m unittest discover


Quickstart
==========


.. toctree::
   :maxdepth: 2

   unittest
   api