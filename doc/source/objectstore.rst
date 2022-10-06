.. module:: ldap_faker
  :noindex:

Faking LDAP servers
===================

``python-ldap-faker`` stores all LDAP objects in a fake LDAP "server"
class: :py:class:`ObjectStore`, and all our fake ``python-ldap`` methods
operate on the LDAP objects in that object store via the exposed methods
on :py:class:`ObjectStore`.

You won't typically use :py:class:`ObjectStore` directly, but instead you'll use
:py:class:`LDAPServerFactory` to register :py:class:`ObjectStore` objects to
correspond to specific LDAP URIs (e.g. ``ldap://server.example.com``).   Our
main fake ``python-ldap`` interface class :py:class:`FakeLDAP` uses the
:py:class:`LDAPServerFactory` to assign the correct :py:class:`ObjectStore` when
:py:meth:`FakeLDAP.initialize` is called by our code under test.

Structure of LDAP records
-------------------------

``python-ldap-faker`` tries to pretend it is ``python-ldap`` as much as
possible.  Important to this is to mimic how ``python-ldap`` and LDAP servers
represent LDAP objects.

LDAP objects have these characteristics:

* The primary key for an LDAP object is the ``dn``.  The ``dn`` is
  case-insensitive in all ``python-ldap`` methods.  For example, these
  two statements should operate on the same object::

      ldap_obj.simple_bind_s("uid=foo,ou=bar,o=baz,c=country", "the password")
      ldap_obj.simple_bind_s("UID=FOO,OU=BAR,O=BAZ,C=COUNTRY", "the password")

* Simliarly, ``basedn``, wherever required, is case-insensitive.

* When doing searches (``search_s``, ``search_ext``), LDAP object attributes
  and values are compared case-insensitively.  These searches should all return
  the same set of objects::

      ldap_obj.search_s("ou=bar,o=baz,c=country", ldap.SCOPE_SUBTREE, '(uid=bar)')
      ldap_obj.search_s("ou=bar,o=baz,c=country", ldap.SCOPE_SUBTREE, '(UID=bar)')
      ldap_obj.search_s("ou=bar,o=baz,c=country", ldap.SCOPE_SUBTREE, '(uid=bAr)')

* LDAP objects returned by :py:func:`ldap.search_s` have this type:
  ``Tuple[str, Dict[str, List[bytes]]``. and this structure::

    ('the dn', {'attribute1': [b'value1', b'value2'], ...})

LDAPServerFactory
-----------------

:py:class:`LDAPServerFactory` objects allow you to register
:py:class:`ObjectStore` bound to particular LDAP URIs so that when someone uses
our :py:meth:`FakeLDAP.initialize` method, it gets properly instrumented with a
**copy** of the ``ObjectStore`` from the ``LDAPServerFactory``.
:py:class:`FakeLDAP` takes a fully loaded :py:class:`LDAPServerFactory` object
as a constructor object.

.. note::

  Note that we said a **copy** of the ``ObjectStore``.  Since the primary use of
  ``python-ldap-faker`` is in testing, and we want to ensure good test
  isolation, we should start each test with a fresh copy of original
  ``ObjectStore`` data for our LDAP URI so that we can ensure that any
  modifications to that data came only from our code under test.


ObjectStore
-----------

The core of ``python-ldap-faker`` is the :py:class:`ObjectStore` class.  This
behaves as the LDAP "server" with which our fake ``python-ldap`` interface
interacts.  In order to do meaningful work with it, it needs to be loaded with
LDAP objects.  There are three methods on :py:class:`ObjectStore` that
you can use to load your objects:

* :py:meth:`ObjectStore.register_object`: load a single object into the object store
* :py:meth:`ObjectStore.register_objects`: load a list of objects into the object store
* :py:meth:`ObjectStore.load_objects`: load a list of objects from a JSON file into the object store

Once loaded into :py:class:`ObjectStore`, we make a fully case-insensitive
internal-only copy of the object (stored in :py:attr:`ObjectStore.objects` for
use in executing searches, but the data returned will be the case-sensitive
versions of those objects (the case-sensitive versions are stored in
:py:attr:`ObjectStore.raw_objects`).

Data Types for ObjectStore.register_object(s)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each object loaded into :py:meth:`ObjectStore.register_object` or
:py:meth:`ObjectStore.register_objects` must be of this type:

.. autodata:: ldap_faker.types.LDAPRecord
  :noindex:

Example::

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
    )

Thus:

  * ``dn`` is a ``str``
  * Attribute names are ``str``
  * Attribute values are ``List[bytes]``


.. _File format for ObjectStore.load_objects:

File format for ObjectStore.load_objects
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Unfortunately, JSON has neither a ``Tuple`` type nor a ``bytes`` type, so we
need to use lists and strings instead, and convert them to the appropriate types
after reading the JSON file.  Thus in our JSON files, we must provide our data
as ``List[List[str, Dict[str, List[str]]]]`` instead.  Example::

  [
    [
      'uid=foo,ou=bar,o=baz,c=country',
      {
        "uid": ["foo"],
        "cn": ["Foo Bar"],
        "uidNumer": ["123"],
        "gidNumer": ["123"],
        "homeDirectory": ["/home/foo"],
        "userPassword": ["the password"],
        "ojectclass": [
          "posixAccount",
          "top"
        ]
      }
    ]
  ]

If you structure your file of LDAP objects like that, and pass in the filename
to :py:meth:`ObjectStore`, we'll load the data from the file and convert that
struct to ``List[Tuple[str, List[bytes]]]`` before using the result with
:py:meth:`ObjectStore.register_objects`.`

