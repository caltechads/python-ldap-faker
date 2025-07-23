Specific LDAP implementations supported
=======================================

Out of the box, our "server" class :py:class:`ObjectStore` supports searching,
adding, updating and deleting objects like a regular LDAP server.

Real LDAP implementations (Redhat Directory Server, 389, openldap, Active
Directory) can have special behavior and side-effects that you may need to
support in order to run your tests properly.

Currently, we support some special behavior for one implementation: `Redhat
Directory Server/389
<https://access.redhat.com/documentation/en-us/red_hat_directory_server/11/html/administration_guide/index>`_.

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


Virtual List View (VLV) Control Support
---------------------------------------

Virtual List View (VLV) is an LDAP control extension that provides efficient pagination
of large result sets. It allows clients to request a specific "window" of results
around a target position, which is particularly useful for implementing pagination
in user interfaces.

VLV is supported out of the box in python-ldap-faker and is automatically advertised
in the Root DSE when clients query for supported controls.

VLV Request Control
^^^^^^^^^^^^^^^^^^^

The VLV request control (OID: ``2.16.840.1.113730.3.4.9``) allows clients to specify:

* **beforeCount**: Number of entries to return before the target position
* **afterCount**: Number of entries to return after the target position
* **target**: The target position (0-based index) in the result set
* **contextID**: Optional context identifier for maintaining state

Example usage::

    import ldap
    from ldap.controls import LDAPControl

    # Create VLV control: get 1 entry before and after position 1
    vlv_value = "1,1,1".encode('utf-8')
    vlv_control = LDAPControl(
        '2.16.840.1.113730.3.4.9',
        True,
        vlv_value,
    )

    # Perform VLV search
    msgid = conn.search_ext(
        'dc=example,dc=com',
        ldap.SCOPE_SUBTREE,
        '(objectClass=person)',
        serverctrls=[vlv_control]
    )

    # Get results
    rtype, rdata, rmsgid, rctrls = conn.result3(msgid)

VLV Response Control
^^^^^^^^^^^^^^^^^^^^

The VLV response control (OID: ``2.16.840.1.113730.3.4.10``) is automatically
returned with VLV search results and contains:

* **targetPosition**: The actual target position used (may be adjusted if requested
  position was beyond available entries)
* **contentCount**: Total number of entries in the result set
* **contextID**: The context identifier if one was provided

The response control value is encoded as a comma-separated string: ``"targetPosition,contentCount"``.

Edge Cases
^^^^^^^^^^

* **Target beyond available entries**: If the requested target position is beyond
  the available entries, the target is clamped to the last valid position
* **Empty result sets**: VLV response control is still returned with target position 0
  and content count 0
* **Invalid control values**: Malformed VLV control values are handled gracefully

Root DSE Advertisement
^^^^^^^^^^^^^^^^^^^^^^

VLV support is automatically advertised in the Root DSE when clients query for
supported controls::

    rdata = conn.search_s(
        "",
        ldap.SCOPE_BASE,
        "(objectClass=*)",
        attrlist=["supportedControl"]
    )

    # VLV OID will be present in supportedControl
    vlv_oid = b"2.16.840.1.113730.3.4.9"