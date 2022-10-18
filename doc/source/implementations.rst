Specific LDAP implementations supported
=======================================

Out of the box, our "server" class :py:class:`ObjectStore` supports searching,
adding, updating and deleting objects like a regular LDAP server.

Real LDAP implementations (Redhat Directory Server, 389, openldap, Active
Directory) can have special behavior and side-effects that you may need to
support in order to run your tests properly.

Currently, we support some special behavior for one implementation: `Redhat Directory Server/389 <https://access.redhat.com/documentation/en-us/red_hat_directory_server/11/html/administration_guide/index>`_.

Redhat Directory Server/389
---------------------------

To get these behaviors, add the ``389`` tag to your :py:class:`ObjectStore`::

    >>> store = ObjectStore(tags=['389'])

In :py:class:`LDAPFakerMixin`, apply the tags with like this for a single, default server::

    import unittest
    from ldap_faker import LDAPFakerMixin


    class TestDefaultTaggedServer(LDAPFakerMixin, unittest.TestCase):

        ldap_modules = ['myapp']
        ldap_fixtures = ('data.json', ['389'])


Or like this for a named server::

    import unittest
    from ldap_faker import LDAPFakerMixin


    class TestDefaultTaggedServer(LDAPFakerMixin, unittest.TestCase):

        ldap_modules = ['myapp']
        ldap_fixtures = [
            ('server1.json', 'ldap://server1', ['389']),
        ]


Features supported
^^^^^^^^^^^^^^^^^^

Operational attributes

    * ``entryid``
    * ``nsUniqueId``
    * ``entrydn``
    * ``createTimestamp``
    * ``modifyTimestamp``
    * ``creatorName``
    * ``modifierName``

    These work like they should in RHDS/389.  They are not returned unless specifically
    asked for during searches, and they are read-only.  The timestamps and names will be
    updated automatically.


``nsrole`` and ``nsroledn``

    User objects support the ``nsroledn`` (writeable) and ``nsrole`` (read-only) attributes.
    Adding a DN to ``nsroledn`` makes it appear automatically in ``nsrole``, and any objects
    with ```objectClass`` of ``ldapsubentry`` will affect ``nsrole`` as it does in RHDS/389.

    ``nsrole`` and ``nsroledn`` are operational attributes; they must be specifically requested
    during searches.

    .. important::
        In RHDS/389, users do not seem to be identified by objectclass.  We're
        simulating this by assuming that any object with a ``userPassword``
        attribute on it is a user.

ldapsubentries

    The three ``ldapsubentry`` objectclasses are supported and behave as they do in RHDS/389:

    * ``nsManagedRoleDefinition``:  does nothing when added or removed
    * ``nsNestedRoleDefinition``:  user objects will gain the proper DN if they match one
      of this object's ``nsroledn`` entries.
    * ``nsFilteredRoleDefinition``:  user objects will gain the proper DN if they match this
      object's ``nsRoleFilter``.



