Using ldap_faker with unittest
==============================

Most of the purpose of ``python-ldap-faker`` was to make automated testing
of code that uses ``python-ldap`` easier.

To this end, ``python-ldap-faker`` provides :py:class:`LDAPFakerMixin`, a mixin class
for :py:class:`unittest.TestCase` which handles all the hard work of patching
and instrumenting the appropriate ``python-ldap`` functions, objects and
methods.

:py:module:`LDAPFakerMixin` will do the following things for you:

* Read data from JSON fixture files to populate one or more
  :py:class:`ObjectStore` objects (our fake LDAP server class)
* Associate those :py:class:`ObjectStore` objects with particular LDAP URIs
* Patch :py:func:`ldap.initialize` to return :py:class:`FakeLDAPObject` objects
  configured with the appropriate :py:class:`ObjectStore` for the LDAP URI passed
  into :py:meth:`FakeLDAP.initialize`


Usage
-----
