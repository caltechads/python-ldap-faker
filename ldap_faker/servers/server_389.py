from copy import deepcopy
from datetime import datetime
import textwrap
from typing import Final, List, Set
import uuid

import ldap
from ldap_filter import Filter

from ..hooks import hooks
from ..db import ObjectStore
from ..types import LDAPData, LDAPRecord, ModList, AddModList


READONLY_ATTRIBUTES_389: Final[List[str]] = [
    "entryid",
    "nsUniqueId",
    "entrydn",
    "createTimestamp",
    "modifyTimestamp",
    "creatorName",
    "modifierName",
    "nsrole",
]


# ====================
# Helper functions
# ====================


def filterstr_for_users_with_attr(values: List[str], attr: str) -> str:
    """
    Return an LDAP filter string for LDAP "user" records that have at least one
    of the values from ``values`` in their ``attr`` attribute.

    Note:
        In 389 users do not seem to be identified by objectclass.  We're
        simulating this by giving assuming that any object with a
        ``userPassword`` attribute on it is a user.

    Args:
        dns: a list of nsroledns
        attr: the attr to compare against

    Returns:
        A filter string
    """
    if len(values) > 1:
        parts = "".join([f"({attr}={v})" for v in values])
        filterstr = f"(|{parts})"
    else:
        filterstr = f"({attr}={values[0]})"
    # We're cheating here by assuming that objects with userPassword should also
    # have nsroledn
    filterstr = f"(&(userpassword=*){filterstr})"
    return filterstr


def remove_dn_from_nsrole(store: ObjectStore, dn: str) -> None:
    """
    Remove ``dn`` from all objects who have it in their ``nsrole`` attribute.

    Args:
        store: the object store to work upon
        dn: the DN to remove form ``nsrole``
    """
    dn_bytes = dn.encode("utf-8")
    # Remove dn_bytes from all entries
    for obj in store.search_subtree(
        "",
        filterstr_for_users_with_attr([dn], "nsrole"),
        include_operational_attributes=True,
    ):
        obj[1]["nsrole"].remove(dn_bytes)
        store._set(obj[0], obj[1])


# ====================
# Hooks
# ====================


def post_objectstore_init_setup_controls(
    store: ObjectStore,
) -> None:
    """
    This "pre_objectstore_init" hook adds some controls to ``store`` that we'll
    need later:

    * ``store.controls['entry_count']``: (``int``) counter for use with ``entryid``
    * ``store.controls['roles']``: (``Dict[str, ldap_filter.Filter]``)

    Also register our operational attributes on the store:

    * ``entrydn``
    * ``entryid``
    * ``nsUniqueId``
    * ``createTimestamp``
    * ``creatorsName``
    * ``modifyTimestamp``
    * ``modifiersName``
    * ``nsrole``
    * ``nsroledn``

    Args:
        store: the object store to work upon
    """
    store.controls["entry_count"] = 0
    store.controls["roles"] = {}
    store.operational_attributes.update(set(READONLY_ATTRIBUTES_389))
    store.operational_attributes.add("nsroledn")


def pre_set_add_audit_fields(
    store: ObjectStore, record: LDAPRecord, bind_dn: str | None = "Directory Manager"
) -> None:
    """
    This "pre_set" hook manages the 389 server auditing attributes:

    * ``createTimestamp``
    * ``creatorsName``
    * ``modifyTimestamp``
    * ``modifiersName``

    Args:
        store: the object store to work upon
        record: the record to work with

    Keyword Args:
        bind_dn: the dn of the bound user, if any
    """
    if bind_dn is None:
        bind_dn = "Directory Manager"
    data = record[1]
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%SZ").encode("utf8")
    if "createTimestamp" not in data:
        data["createTimestamp"] = [ts]
        data["creatorName"] = [bind_dn.encode("utf-8")]
    data["modifyTimestamp"] = [ts]
    data["modifierName"] = [bind_dn.encode("utf-8")]


def pre_set_add_operational_attributes(
    store: ObjectStore, record: LDAPRecord, bind_dn: str | None = "Directory Manager"
) -> None:
    """
    This "pre_set" hook adds the 389 server auditing attributes, if they don't
    already exist:

    * ``entrydn``
    * ``entryid``
    * ``nsUniqueId``

    For "user" objects (those with the "userPassword" attribute), add:

    * ``nsrole``
    * ``nsroledn``

    Args:
        store: the object store to work upon
        record: the record to work with

    Keyword Args:
        bind_dn: the dn of the bound user, if any
    """
    dn, data = record
    if "entrydn" not in data:
        data["entrydn"] = [dn.encode("utf-8")]
    if "entryid" not in data:
        if "entry_count" not in store.controls:
            store.controls["entry_count"] = 0
        store.controls["entry_count"] += 1
        data["entryid"] = [str(store.controls["entry_count"]).encode("utf-8")]
    if "nsUniqueId" not in data:
        # This produces something like "b6c1f72b-242711e9-8e8bdd83-32f45163"
        data["nsUniqueId"] = [
            "-".join(textwrap.wrap(uuid.uuid4().hex, 8)).encode("utf-8")
        ]
    # Deal with "user" specific operational attributes
    attrs = [attr.lower() for attr in data]
    if "userpassword" in attrs:
        # this is a "user"
        if "nsroledn" not in attrs:
            data["nsroledn"] = []
        if "nsrole" not in attrs:
            data["nsrole"] = deepcopy(data["nsroledn"])


def pre_update_prevent_readonly_attribute_modify(
    store: ObjectStore,
    dn: str,
    modlist: ModList,
    bind_dn: str | None = "Directory Manager",
) -> None:
    """
    This "pre_update" hook raises :py:exce:`ldap.UNWILLING_TO_PERFORM` if we try
    to update any of these attributes:

    * ``entrydn``
    * ``entryid``
    * ``nsUniqueId``
    * ``createTimestamp``
    * ``creatorsName``
    * ``modifyTimestamp``
    * ``modifiersName``
    * ``nsrole``

    Args:
        store: the object store to work upon
        record: the record to work with

    Keyword Args:
        bind_dn: the dn of the bound user, if any

    Raises:
        ldap.UNWILLING_TO_PERFORM: we tried to update a readonly attribute
    """
    for entry in modlist:
        if entry[1] in READONLY_ATTRIBUTES_389:
            raise ldap.UNWILLING_TO_PERFORM(
                {
                    "msgtype": ldap.RES_MODIFY,
                    "msgid": 3,
                    "result": 53,
                    "desc": "Server is unwilling to perform",
                    "ctrls": [],
                }
            )


def pre_create_prevent_readonly_attribute_create(
    store: ObjectStore,
    dn: str,
    modlist: AddModList,
    bind_dn: str | None = "Directory Manager",
) -> None:
    """
    This "pre_create" hook ignores these attributes:

    * ``entrydn``
    * ``entryid``
    * ``nsUniqueId``
    * ``createTimestamp``
    * ``creatorsName``
    * ``modifyTimestamp``
    * ``modifiersName``
    * ``nsrole``

    Args:
        store: the object store to work upon
        record: the record to work with

    Keyword Args:
        bind_dn: the dn of the bound user, if any
    """

    modlist[:] = [entry for entry in modlist if not entry[0] in READONLY_ATTRIBUTES_389]


def post_copy_remove_readonly_attributes_on_copy(
    store: ObjectStore,
    data: LDAPData,
) -> LDAPData:
    """
    This "post_copy" hook removes all readonly attributes from the copied
    object.

    * ``entrydn``
    * ``entryid``
    * ``nsUniqueId``
    * ``createTimestamp``
    * ``creatorsName``
    * ``modifyTimestamp``
    * ``modifiersName``
    * ``nsrole``

    Args:
        store: the object store to work upon
        data: the ldap attributes to work with
    """
    return {k: v for k, v in data.items() if k not in READONLY_ATTRIBUTES_389}


def pre_set_update_nsrole_from_nsroledn(
    store: ObjectStore, record: LDAPRecord, bind_dn: str | None = "Directory Manager"
) -> None:
    """
    This "pre_set" hook looks at the ``nsroledn`` attribute and compare it to
    what we currently have on our object.

    * Remove any DNs from ``nsrole`` that are not in ``nsroledn`` on ``record``
      but are on the existing object
    * Add any DN from ``nsrole`` that is in ``nsroledn`` on ``record`` but not
      in ``nsroledn`` on the old object

    Args:
        store: the object store to work upon
        record: the record to work with

    Keyword Args:
        bind_dn: the dn of the bound user, if any
    """
    dn, data = record
    if not store.exists(dn):
        # This is a new object.  nsroledn -> nsrole will have been taken care of
        # in hook_add_operational_attributes
        return
    if "userPassword" in data:
        new_dns: Set[bytes] = set(data.get("nsroledn", []))
        old_data = store.get(dn)
        old_dns: Set[bytes] = set(old_data.get("nsroledn", []))
        adds = list(new_dns - old_dns)
        removes = list(old_dns - new_dns)
        if "nsrole" not in data:
            data["nsrole"] = []
        data["nsrole"] = [dn for dn in data["nsrole"] if dn not in removes]
        data["nsrole"].extend(adds)
        data["nsrole"].sort()
        data["nsroledn"].sort()


def pre_set_manage_user_nsrole(
    store: ObjectStore, record: LDAPRecord, bind_dn: str | None = "Directory Manager"
) -> None:
    """
    This "pre_set" hook manages the ``nsrole`` attribute on any object that is a
    "user".  This applies all nested and filter roles to the our ``record`` and
    adjusts ``nsrole`` accordingly.

    Note:
        The ``nsrole`` and ``nsroledn`` attributes in 389 are not assigned by
        objectclass, but are instead given to "users".  We're simulating this by
        giving assuming that any object with a ``userPassword`` attribute on it
        is a user.

    Args:
        store: the object store to work upon
        record: the record to work with

    Keyword Args:
        bind_dn: the dn of the bound user, if any
    """
    data = record[1]
    # ldap_filter.Filter.match needs Dict[str, List[str]]
    cidata = store.convert_LDAPData(data)
    if "userPassword" in data:
        for dn_bytes, filt in store.controls["roles"].items():
            if filt.match(cidata):
                if dn_bytes not in data["nsrole"]:
                    data["nsrole"].append(dn_bytes)
            else:
                if dn_bytes in data["nsrole"]:
                    data["nsrole"].remove(dn_bytes)
        data["nsrole"].sort()


def post_set_handle_ldapsubentry_nestedrole_set(
    store: ObjectStore, record: LDAPRecord, bind_dn: str | None = None
) -> None:
    """
    This "post_set" hook deals with adding or updating nsNestedRoleDefinition
    objects.

    This will update the ``nsrole`` attribute of all "user" objects with one
    of this object`s ``nsroledn`` DNs to have this object's DN, and remove this
    object's DN from the ``nsrole`` attribute of all other "user"  objects.
    Args:
        store: the object store to work upon
        record: the record to work with

    Keyword Args:
        bind_dn: the dn of the bound user, if any
    """
    dn, data = record
    keys = {attr.lower(): attr for attr in data}
    objectclasses = [o.lower() for o in data.get(keys["objectclass"], [])]
    if b"nsnestedroledefinition" not in objectclasses:
        return
    # First remove dn_bytes from all entries
    remove_dn_from_nsrole(store, dn)
    # Then add dn_bytes to all that have one of our nsroledns
    dn_bytes = dn.encode("utf-8")
    dns = [role.decode("utf-8") for role in data["nsroledn"]]
    filterstr = filterstr_for_users_with_attr(dns, "nsroledn")
    for obj in store.search_subtree("", filterstr, include_operational_attributes=True):
        if dn_bytes not in data["nsrole"]:
            obj[1]["nsrole"].append(dn_bytes)
            obj[1]["nsrole"].sort()
            store._set(obj[0], obj[1])
    # Save the compiled filter for use by pre_set_manage_user_nsrole
    store.controls["roles"][dn_bytes] = Filter.parse(filterstr)


def post_set_handle_ldapsubentry_searchrole_set(
    store: ObjectStore, record: LDAPRecord, bind_dn: str | None = None
) -> None:
    """
    This "post_set" hook deals with adding or updating nsFilteredRoleDefinition
    objects.

    This will update the ``nsrole`` attribute of all "user" objects with one
    of this object`s ``nsroledn`` DNs to have this object's DN, and remove this
    object's DN from the ``nsrole`` attribute of all other "user"  objects.

    Args:
        store: the object store to work upon
        record: the record to work with

    Keyword Args:
        bind_dn: the dn of the bound user, if any
    """
    dn, data = record
    keys = {attr.lower(): attr for attr in data}
    objectclasses = [o.lower() for o in data.get(keys["objectclass"], [])]
    if b"nsfilteredroledefinition" not in objectclasses:
        return
    # First remove our dn from all entries
    remove_dn_from_nsrole(store, dn)
    # Then add dn_bytes to all that match our filterstr
    dn_bytes = dn.encode("utf-8")
    if "nsrolefilter" in data:
        filterstr = data["nsrolefilter"][0].decode("utf-8")
        filterstr = f"(&(userpassword=*){filterstr})"
        for obj in store.search_subtree(
            "", filterstr, include_operational_attributes=True
        ):
            if dn_bytes not in data["nsrole"]:
                obj[1]["nsrole"].append(dn_bytes)
                obj[1]["nsrole"].sort()
                store._set(obj[0], obj[1])
    # Save the compiled filter for use by pre_set_manage_user_nsrole
    store.controls["roles"][dn_bytes] = Filter.parse(filterstr)


def post_delete_handle_ldapsubentry_delete(
    store: ObjectStore, record: LDAPRecord, bind_dn: str | None = None
) -> None:
    """
    This "post_delete" hook deals with deleting nsFilteredRoleDefinition or
    nsNestedRoleDefinition objects.

    This will remove the dn of our ldapsubentry from ``nsrole`` attribute of all
    "user" objects.

    Args:
        store: the object store to work upon
        record: the record to work with

    Keyword Args:
        bind_dn: the dn of the bound user, if any
    """
    dn, data = record
    keys = {attr.lower(): attr for attr in data}
    targets = set([b"nsfilteredroledefinition", b"nsnestedroledefinition"])
    objectclasses = {o.lower() for o in data.get(keys["objectclass"], [])}
    if not objectclasses.intersection(targets):
        return
    # Remove our dn from all entries
    remove_dn_from_nsrole(store, dn)
    # Delete the compiled filter
    del store.controls["roles"][dn.encode("utf-8")]


# Register our hooks

hooks.register_hook(
    "post_objectstore_init", post_objectstore_init_setup_controls, tags=["389"]
)
hooks.register_hook(
    "post_copy", post_copy_remove_readonly_attributes_on_copy, tags=["389"]
)
hooks.register_hook("pre_set", pre_set_add_audit_fields, tags=["389"])
hooks.register_hook("pre_set", pre_set_add_operational_attributes, tags=["389"])
hooks.register_hook("pre_set", pre_set_update_nsrole_from_nsroledn, tags=["389"])
hooks.register_hook("pre_set", pre_set_manage_user_nsrole, tags=["389"])
hooks.register_hook(
    "pre_update", pre_update_prevent_readonly_attribute_modify, tags=["389"]
)
hooks.register_hook(
    "pre_create", pre_create_prevent_readonly_attribute_create, tags=["389"]
)
hooks.register_hook(
    "post_set", post_set_handle_ldapsubentry_nestedrole_set, tags=["389"]
)
hooks.register_hook(
    "post_set", post_set_handle_ldapsubentry_searchrole_set, tags=["389"]
)
hooks.register_hook("post_delete", post_delete_handle_ldapsubentry_delete, tags=["389"])
