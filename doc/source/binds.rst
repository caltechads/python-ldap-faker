Authentication and Authorization
================================

Just like with real LDAP, you'll need to bind to the fake LDAP "server" before
you can do certain LDAP operations.

Authorization within python-ldap-faker
--------------------------------------

Like a real LDAP server, these write operations require you to successfully do a
non-anonymous bind:

* ``add_s``
* ``delete_s``
* ``modify_s``
* ``rename_s``

Anonymous binds
---------------

You don't need to do anything special to allow anonymous binds.  This should work::

    ldap_obj = fake_ldap.initialize('ldap://server')
    ldap_obj.simple_bind_s()

So does this::

    ldap_obj = fake_ldap.initialize('ldap://server')
    ldap_obj.search_s('ou=bar,o=baz,c=country', ldap.SCOPE_SUBTREE, '(uid=user)')


Authenticated binds
-------------------

To do an authenticated bind, you'll need to load an appropriately configured
user object into the :py:class:`ObjectStore` for your connection.

When you do an authenticated bind via :py:meth:`FakeLDAPObject.simple_bind_s`,
``python-ldap-faker`` will look in its :py:class:`ObjectStore` for an object
with the ``dn`` of ``who``, and it will compare ``cred`` with the first
value of that object's ``userPassword`` attribute specifically.

.. warning:

  :py:meth:`FakeLDAPObject.simple_bind_s` will not do any hashing when comparing
  ``cred`` to ``userPassword``, thus you should store the password you want to use
  verbatim in the ``userPassword`` attribute.

If, for example, your code wants to bind as ``uid=foo,ou=bar,o=baz,c=country``
with password ``the password``, then ``python-ldap-faker`` will expect an object
in the :py:class:`ObjectStore`  that minimally looks like this::

  (
    'uid=foo,ou=bar,o=baz,c=country',
    {
        "userPassword": [b"the password"],
    }
  )
