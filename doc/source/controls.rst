.. _ldap_controls:

LDAP Controls Support
=====================

python-ldap-faker supports the following LDAP controls:

* `Virtual List View (VLV) <https://tools.ietf.org/html/rfc2891>`_
* `Server Side Sort <https://tools.ietf.org/html/rfc2891>`_
* `Simple Paged Results <https://tools.ietf.org/html/rfc2696>`_

Root DSE Advertisement
----------------------

Our LDAP Control support is automatically advertised in the Root DSE when
clients query for supported controls::

    rdata = conn.search_s(
        "",
        ldap.SCOPE_BASE,
        "(objectClass=*)",
        attrlist=["supportedControl"]
    )

    # Example: VLV OID will be present in supportedControl
    vlv_oid = b"2.16.840.1.113730.3.4.9"

Simple Paged Results Control Support
------------------------------------

Simple Paged Results Control is an LDAP control extension that allows clients to
request a specific "window" of results around a target position, which is
particularly useful for implementing pagination in user interfaces.

Simple Paged Results Control is supported out of the box in ``python-ldap-faker``
and is automatically advertised in the Root DSE when clients query for supported
controls.

This is easy to use because ``python-ldap`` supports it directly:

.. code-block:: python

    import ldap
    from ldap.controls import SimplePagedResultsControl

    # Create paged results control
    paged_results_control = SimplePagedResultsControl(
        True,  # critical
        "1000",  # size
        "",  # initial cookie
    )

    while True:
        # Perform paged search
        msgid = conn.search_ext(
            'ou=users,dc=example,dc=com',
            ldap.SCOPE_SUBTREE,
            '(objectClass=person)',
            serverctrls=[paged_results_control]
        )

        # Retrieve results
        rtype, rdata, rmsgid, rctrls = conn.result3(msgid)

        # Get paged results control
        paged_results_control = rctrls[0]

        # Get paged results cookie
        paged_results_control.cookie = paged_results_control.cookie

        # If there are no more results, break
        if not paged_results_cookie:
            break

        # Update paged results control with new cookie
        paged_results_control.cookie = paged_results_cookie

Server Side Sort Control Support
--------------------------------

Server Side Sort Control is an LDAP control extension that allows clients to request
that search results be sorted by the server before being returned. This is particularly
useful for implementing ordered lists in user interfaces and for use with pagination
controls like Virtual List View (VLV).

Server Side Sort Control is supported out of the box in python-ldap-faker and is
automatically advertised in the Root DSE when clients query for supported controls.

Sort Request Control
^^^^^^^^^^^^^^^^^^^^

The Sort request control (OID: ``1.2.840.113556.1.4.473``) allows clients to specify
one or more sort keys for ordering search results. Each sort key contains:

* **attributeType**: The LDAP attribute name to sort by (required)
* **orderingRule**: Optional ordering rule OID (defaults to attribute's natural ordering)
* **reverseOrder**: Optional boolean flag for descending order (defaults to false)

The control value must be BER-encoded according to RFC 2891. Example usage:

.. code-block:: python

    import ldap
    from ldap.controls import LDAPControl
    from pyasn1.codec.ber import encoder
    from pyasn1.type import namedtype, univ

    # Define SortKey ASN.1 structure
    class SortKey(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("attributeType", univ.OctetString()),
            namedtype.OptionalNamedType("orderingRule", univ.OctetString()),
            namedtype.DefaultedNamedType("reverseOrder", univ.Boolean(False))
        )

    class SortKeyList(univ.SequenceOf):
        componentType = SortKey()

    # Create sort control for single attribute
    sort_key = SortKey()
    sort_key.setComponentByName("attributeType", "cn")

    sort_key_list = SortKeyList()
    sort_key_list.setComponentByPosition(0, sort_key)

    encoded_value = encoder.encode(sort_key_list)

    sort_control = LDAPControl(
        '1.2.840.113556.1.4.473',
        True,
        encoded_value
    )

    # Perform sorted search
    msgid = conn.search_ext(
        'ou=users,dc=example,dc=com',
        ldap.SCOPE_SUBTREE,
        '(objectClass=person)',
        serverctrls=[sort_control]
    )

    # Get sorted results
    rtype, rdata, rmsgid, rctrls = conn.result3(msgid)

Multi-key sorting is also supported::

    # Create sort control for multiple attributes (sort by cn, then uid)
    sort_key_list = SortKeyList()

    # First sort key: cn (ascending)
    cn_key = SortKey()
    cn_key.setComponentByName("attributeType", "cn")
    sort_key_list.setComponentByPosition(0, cn_key)

    # Second sort key: uid (ascending)
    uid_key = SortKey()
    uid_key.setComponentByName("attributeType", "uid")
    sort_key_list.setComponentByPosition(1, uid_key)

    encoded_value = encoder.encode(sort_key_list)
    sort_control = LDAPControl('1.2.840.113556.1.4.473', True, encoded_value)

For descending order, set the reverseOrder flag::

    # Sort by cn in descending order
    sort_key = SortKey()
    sort_key.setComponentByName("attributeType", "cn")
    sort_key.setComponentByName("reverseOrder", True)

Sort Response Control
^^^^^^^^^^^^^^^^^^^^^

Unlike some LDAP controls, Server Side Sort does not return a response control.
The sorting is applied directly to the search results returned in the normal
search response. If sorting fails or is not supported for a particular attribute,
the results may be returned unsorted, but no error is typically generated.

Integration with Other Controls
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Server Side Sort Control works seamlessly with other LDAP controls:

* **Paged Results**: Sorting is applied first, then paging is applied to the sorted results
* **Virtual List View (VLV)**: VLV **requires** a sort control to be present (RFC 2891)
* **Size Limit**: Size limits are applied after sorting

Example with VLV:

.. code-block:: python

    # Sort control is required for VLV
    sort_control = LDAPControl('1.2.840.113556.1.4.473', True, encoded_sort_value)

    # VLV control for pagination
    vlv_control = LDAPControl(
        '2.16.840.1.113730.3.4.9',
        True,
        "1,1,5".encode('utf-8')  # 1 before, 1 after, target position 5
    )

    # Perform sorted VLV search
    msgid = conn.search_ext(
        'ou=users,dc=example,dc=com',
        ldap.SCOPE_SUBTREE,
        '(objectClass=person)',
        serverctrls=[sort_control, vlv_control]
    )

Edge Cases
^^^^^^^^^^

* **Missing attributes**: Entries without the sort attribute are placed at the beginning
  of the sorted results
* **Case sensitivity**: Sorting is performed case-insensitively on string attributes
* **Multi-valued attributes**: Only the first value of multi-valued attributes is used
  for sorting
* **Invalid sort keys**: Malformed BER encoding or unknown attributes in sort keys
  are handled gracefully, with results potentially returned unsorted
* **Empty result sets**: Sort controls are processed normally even when no results
  match the search filter


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

Example usage:

.. code-block:: python

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
