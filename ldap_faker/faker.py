from __future__ import annotations

import inspect
import json
import sys
from functools import wraps
from typing import TYPE_CHECKING, Any, TextIO, cast
from urllib.parse import urlparse

import ldap
from pyasn1.codec.ber import decoder
from pyasn1.type import namedtype, tag, univ


# SortKey definition
class SortKey(univ.Sequence):
    """
    SortKey definition for the Server Side Sort control, OID 1.2.840.113556.1.4.473.
    """

    componentType: namedtype.NamedTypes = namedtype.NamedTypes(  # noqa: N815
        namedtype.NamedType("attributeType", univ.OctetString()),
        namedtype.OptionalNamedType(
            "orderingRule",
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.DefaultedNamedType(
            "reverseOrder",
            univ.Boolean(False).subtype(  # noqa: FBT003
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
    )


# SortKeyList is a sequence of SortKeys
class SortKeyList(univ.SequenceOf):
    """
    SortKeyList is a sequence of SortKeys.  Used to decode the controlValue for the
    Server Side Sort control, OID 1.2.840.113556.1.4.473.
    """

    componentType: univ.Sequence = SortKey()  # type: ignore[assignment]  # noqa: N815


def decode_sort_control_value(control_value: bytes) -> list[str]:
    """
    Decode BER-encoded controlValue for Server Side Sort control using python-asn1.

    The controlValue should contain a SEQUENCE of SEQUENCEs, each with an
    attributeType (OCTET STRING).  See RFC 2891 for the Server Side Sort control
    ASN.1 definition.

    Args:
        control_value: BER-encoded control value

    Returns:
        List of attribute names to sort by

    """
    if not control_value:
        return []
        # Extract the controlValue
    ber_value = control_value

    # Decode using pyasn1
    decoded, remainder = decoder.decode(ber_value, asn1Spec=SortKeyList())

    sort_keys = []
    # Loop through each sort key
    for key in decoded:
        attr = str(key.getComponentByName("attributeType"))

        rule = key.getComponentByName("orderingRule")
        rule = str(rule) if rule.isValue else None

        reverse_order = key.getComponentByName("reverseOrder")
        reverse_order = bool(reverse_order) if reverse_order.isValue else False
        if reverse_order:
            attr = f"-{attr}"
        sort_keys.append(attr)
    return sort_keys


from .db import (
    CallHistory,
    LDAPCallRecord,
    LDAPServerFactory,
    ObjectStore,
    OptionStore,
)
from .logging import logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from .types import AddModList, LDAPOptionValue, LDAPRecord, ModList, Result3

# ====================================
# Decorators
# ====================================


class BytesEncoder(json.JSONEncoder):
    """
    Encode bytes as strings.
    """

    def default(self, o: Any) -> str | int | float | bool | None:
        if isinstance(o, bytes):
            return o.decode()
        return json.JSONEncoder.default(self, o)


def record_call(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Save a record of the call to ``func`` so that our tests can inspect it later.
    """

    @wraps(func)
    def inner(*args, **kwargs) -> Any:
        sig = inspect.signature(func)
        args_dict = dict(sig.bind(*args, **kwargs).arguments)
        args_dict["self"].calls.register(func.__name__, args_dict)
        del args_dict["self"]
        logger.debug("record_call api=%s, arguments=%s", func.__name__, args_dict)
        return func(*args, **kwargs)

    return inner


def needs_bind(func):
    @wraps(func)
    def inner(self, dn: str, *args, **kwargs):
        if not self.bound_dn:
            raise ldap.INSUFFICIENT_ACCESS(
                {
                    "msgtype": 105,
                    "msgid": 1,
                    "result": 50,
                    "desc": "Insufficient access",
                    "ctrls": [],
                    "info": (
                        f"Insufficient '{func.__name__}' privilege for the "
                        f"entry '{dn}'\n"
                    ),
                }
            )
        return func(self, dn, *args, **kwargs)

    return inner


def handle_return_value(func):
    """
    Check to see whether we have a specific return value configured for this
    call to ``func`` with these particular ``args`` and ``kwargs``.
    """

    @wraps(func)
    def inner(self, *args, **kwargs):
        # We're dumping the args and kwargs to a JSON string here because that
        # will be hashable, whereas the (args, kwargs) tuple may not be.
        key = json.dumps([*args, *kwargs.values()], cls=BytesEncoder)
        try:
            value = self.return_value_maps[func.__name__][key]
            logger.debug(
                "handle_return_value.found method=%s key=%s", func.__name__, key
            )
        except KeyError:
            return func(*args, **kwargs)
        if isinstance(value, Exception):
            raise value
        return value

    return inner


# =========================
# Global LDAP object
# =========================


class FakeLDAP:
    """
    We use this class to house our replacement code for these three prime
    ``python-ldap`` functions:

    * :py:func:`ldap.initialize`
    * :py:func:`ldap.set_option`
    * :py:func:`ldap.get_option`

    The class takes a fully configured :py:class:`LDAPServerFactory` as an
    argument, and will use that factory's collection of :py:class:`OptionStore`
    objects to construct new :py:class:`FakeLDAPObject` objects.

    As a test runs, :py:class:`FakeLDAP` keeps track of each LDAP connection
    made and each global LDAP call made so that they can be inspected after your
    code has run.

    Note:
        This is meant to be a disposable object, recreated for each test method.
        When used properly, all internal state (connections made, calls made,
        options set) will be empty at the start of every test.

    Args:
        server_factory: a fully configured :py:class:`LDAPServerFactory`

    """

    def __init__(self, server_factory: LDAPServerFactory) -> None:
        #: List of :py:class:`FakeLDAPObject` connections created in the order
        #: in which they were requested
        self.connections: list[FakeLDAPObject] = []
        #: Call history for global LDAP function calls
        self.calls: CallHistory = CallHistory()
        #: A dictionary of LDAP options set
        self.options: OptionStore = OptionStore()
        #: A dictionary of LDAP stores
        self.stores: dict[str, ObjectStore] = {}
        #: The server factory used to create LDAP connections
        self.server_factory: LDAPServerFactory = server_factory

    @record_call
    def initialize(
        self,
        uri: str,
        trace_level: int = 0,  # noqa: ARG002
        trace_file: TextIO = sys.stdout,  # noqa: ARG002
        trace_stack_limit: int | None = None,  # noqa: ARG002
        fileno: Any = None,  # noqa: ARG002
    ) -> FakeLDAPObject:
        """
        We use this to patch :py:func:`ldap.initialize` when we are testing our
        LDAP code. When it is called, we will ask our
        :py:attr:`FakeLDAP.server_factory` factory for the
        :py:class:`ObjectStore` most appropriate for the LDAP URI ``uri``,
        create a :py:class:`FakeLDAPObject` with a :py:func:`copy.deepcopy` of
        that :py:class:`ObjectStore`, and return the :py:class:`FakeLDAPObject`.

        Note:
            Of all the arguments in our signature, we only actually use ``uri``.
            The other arguments are recorded in our :py:attr:`FakeLDAP.calls`
            call history, but are otherwise ignored.

        Args:
            uri: an LDAP URI
            trace_level: logging level (ignored)
            trace_file: file descriptor to which to write traces (ignored)
            trace_stack_limit: stack limit of tracebacks in the debug log (ignored)
            fileno: a socket or file descriptor (ignored)

        Raises:
            ldap.SERVER_DOWN: could not find an appropriate
                :py:class:`ObjectStore` for ``uri``

        Returns:
            A properly configured :py:class:`FakeLDAPObject`

        """
        if uri not in self.stores:
            self.stores[uri] = self.server_factory.get(uri)
        conn = FakeLDAPObject(uri, store=self.stores[uri])
        self.connections.append(conn)
        return conn

    @record_call
    def set_option(self, option: int, invalue: LDAPOptionValue) -> None:
        """
        Set a global ``python-ldap option``.  This will create a key ``option`` in our
        :py:attr:`FakeLDAP.options` dictionary and set its value to ``value``.

        Example:
            In your test code, you can thus test whether your code set the
            proper global LDAP option like so::

                from unittest import TestCase
                import ldap
                from ldap_faker import LDAPFakerMixin

                from my_code import App

                class MyTest(LDAPFakerMixin, TestCase):

                    ldap_modules = ['my_code']
                    ldap_fixtures = 'myfixture.json'

                    def test_option_was_set(self):
                        app = MyApp()
                        app.set_the_option(ldap.OPT_DEBUG_LEVEL, 1)
                        self.assertEqual(self.ldap_faker.options[ldap.OPT_DEBUG_LEVEL], 1)

        Args:
            option: an option from python-ldap
            invalue: the value to set for the option

        """  # noqa: E501
        self.options.set(option, invalue)

    @record_call
    def get_option(self, option: int) -> LDAPOptionValue | dict[str, int | str]:
        """
        Get a global python-ldap option.  If our code hasn't set an ``option`` yet,
        return the default from ``python-ldap`` for that option.

        Args:
            option: an option from python-ldap

        Returns:
            The value currently set for the option.

        """
        return self.options.get(option)

    # Test instrumentation

    def has_connection(self, uri: str) -> bool:
        """
        Test to see whether an :py:func:`ldap.initialize` call was made with
        LDAP URI of ``uri``.

        Args:
            uri: The LDAP URI to look for in our connection history

        Returns:
            ``True`` if at least one connection to ``uri`` was made, ``False``
            otherwise.

        """
        return any(conn.uri == uri for conn in self.connections)

    def get_connections(self, uri: str) -> list[FakeLDAPObject]:
        """
        Return a list of :py:class:`FakeLDAPObject` connections to LDAP URI ``uri``.

        Args:
            uri: The LDAP URI to look for in our connection history

        Returns:
            A list of :py:class:`FakeLDAPObject` objects associated with LDAP
            URI ``uri``.

        """
        return [conn for conn in self.connections if conn.uri == uri]

    def connection_calls(
        self, api_name: str | None = None, uri: str | None = None
    ) -> CallHistory:
        """
        Filter our the call history for our connections by function name and
        optionally LDAP URI.

        Keyword Args:
            api_name: restrict through our history for calls to this function
            uri: restrict our search to only calls to this URI

        Returns:
            A :py:class:`CallHistory` with combined calls from the filtered connections.

        """
        results: list[LDAPCallRecord] = []
        for conn in self.connections:
            if uri and conn.uri != uri:
                continue
            if api_name:
                results.extend(conn.calls.filter_calls(api_name))
            else:
                results.extend(conn.calls._calls)
        return CallHistory(results)


# =========================
# LDAPObject
# =========================


class FakeLDAPObject:
    """
    Simulates most of the interface of ``ldap.ldapobject.LDAPObject`` which is
    the object that gets returned when you call ``ldap.initialize()``.

    Note:
        This is a disposable object that should be recreated for each test, mostly
        because changes to our ``ObjectStore`` can't be undone without re-copying
        from its source in ``Servers``.

    Args:
        uri: the LDAP URI of the connection

    Keyword Args:
        directory: a populated :py:class:`ObjectStore`

    """

    def __init__(
        self,
        uri: str,
        store: ObjectStore | None = None,
    ):
        # cookie and _async_results are used for the paged search implementation
        self.current_msgid: int = 0
        self._async_results: dict[int, dict[str, ldap.controls.LDAPControl]] = {}

        # This is the URI to which we connected
        self.uri: str = uri  #: the LDAP URI for this connection
        self.hostname: str = urlparse(
            self.uri
        ).netloc  #: the host:port for this connection

        self.options: OptionStore = (
            OptionStore()
        )  #: we store data from :py:meth:`set_option` calls here
        # directory is our our prepared LDAP data objects and faked searches
        self.store: ObjectStore  #: our copy of our ObjectStore for this connection
        if store:
            self.store = store
        else:
            self.store = ObjectStore()

        # calls is our call history
        self.calls: CallHistory = CallHistory()  #: The method call history

        self.tls_enabled: bool = (
            False  #: Set to True if :py:meth:`start_tls_s` was called
        )
        self.bound_dn: str | None = (
            None  #: Set by :py:meth:`simple_bind_s` to the dn of the user after success
        )

        # Other standard LDAPObject attributes that test code might look at
        self.deref: int = (
            ldap.DEREF_NEVER
        )  #: Controls whether aliases are automatically dereferenced
        self.protocol_version: int = (
            ldap.VERSION3
        )  #: Version of LDAP in use (always :py:attr:`ldap.VERSION3``)
        self.sizelimit: int = (
            ldap.NO_LIMIT
        )  #: Limit on size of message to receive from server
        self.network_timeout: int = (
            ldap.NO_LIMIT
        )  #: Limit on waiting for a network response, in seconds.
        self.timelimit: int = (
            ldap.NO_LIMIT
        )  #: Limit on waiting for any response, in seconds.
        self.timeout: int = (
            ldap.NO_LIMIT
        )  #: Limit on waiting for any response, in seconds.

    # LDAPObject methods

    @record_call
    def set_option(self, option: int, invalue: LDAPOptionValue) -> None:
        """
        Sets the value of the :py:class:`ldap.ldap.ldapobject.LDAPObject``
        option specified by ``option`` to ``invalue``.

        Args:
            option: the option
            invalue: the value to set the option to

        Raises:
            ValueError: ``option`` is not a valid ``python-ldap`` option

        """
        self.options.set(option, invalue)

    @record_call
    def get_option(self, option: int) -> LDAPOptionValue | dict[str, int | str]:
        """
        Returns the value of the :py:class:`ldap.ldap.ldapobject.LDAPObject``
        option specified by ``option``.

        .. note::
            If your code did not call :py:meth:`FakeLDAPOption.set_option` for
            this option, we'll get ``KeyError``

        Args:
            option: the option

        Raises:
            ValueError: ``option`` is not a valid ``python-ldap`` option
            KeyError: ``option`` is not a valid ``python-ldap`` option

        Returns:
            The value of the option

        """
        if option == ldap.OPT_URI:
            return self.uri
        if option == ldap.OPT_HOST_NAME:
            return self.hostname
        return self.options.get(option)

    @record_call
    def simple_bind_s(
        self,
        who: str | None = None,
        cred: str | None = None,
        serverctrls: list[ldap.controls.LDAPControl] | None = None,  # noqa: ARG002
        clientctrls: list[ldap.controls.LDAPControl] | None = None,  # noqa: ARG002
    ) -> Result3 | None:
        """
        Perform a bind.  This will look in the object store for an object with dn of
        ``who`` and compare ``cred`` to the ``userPassword`` attribute for that
        object.

        Keyword Args:
            who: the dn of the user with which to bind
            cred:  the password for that user
            serverctrls: server controls (ignored)
            clientctrls: client controls (ignored)

        Raises:
            ldap.INVALID_CREDENTIALS: the ``who`` did not match the ``cred``

        """
        if who is None and cred is None:
            return None
        who = cast("str", who)
        cred = cast("str", cred)
        if self.store.exists(who, validate=False) and self.compare_s(
            who.lower(), "userPassword", cred.encode("utf-8")
        ):
            self.bound_dn = who
            return (ldap.RES_BIND, [], 3, [])
        raise ldap.INVALID_CREDENTIALS(
            {
                "msgtype": 97,
                "msgid": 2,
                "result": 49,
                "desc": "Invalid credentials",
                "ctrls": [],
            }
        )

    @record_call
    def whoami_s(self) -> str:
        """
        Implements the LDAP "Who Am I?" extended operation.

        It is useful for finding out to find out which identity is assumed by
        the LDAP server after a bind.

        Returns:
            Empty string if we haven't bound as an identity, otherwise "dn: {the dn}"

        """
        if self.bound_dn:
            return f"dn: {self.bound_dn}"
        return ""

    @record_call
    def search_ext(
        self,
        base: str,
        scope: int,
        filterstr: str = "(objectClass=*)",
        attrlist: list[str] | None = None,
        attrsonly: int = 0,
        serverctrls: list[ldap.controls.LDAPControl] | None = None,
        clientctrls: list[ldap.controls.LDAPControl] | None = None,  # noqa: ARG002
        timeout: int = -1,  # noqa: ARG002
        sizelimit: int = 0,
    ) -> int:
        """
        Performs a search.

        This method supports the following LDAP controls in the serverctrls list:

        - 1.2.840.113556.1.4.319 (Paged Results): Sets a cookie on the control for paging
        - 1.2.840.113556.1.4.473 (Server Side Sort): Sorts results by specified attributes

        Examples:
            Paged Search:

            .. code-block:: python

                import ldap
                from ldap.controls import SimplePagedResultsControl

                # Create paged results control
                page_control = SimplePagedResultsControl(True, size=10, cookie='')

                # Perform paged search
                msgid = conn.search_ext(
                    'ou=users,dc=example,dc=com',
                    ldap.SCOPE_SUBTREE,
                    '(objectClass=person)',
                    serverctrls=[page_control]
                )

                # Get results
                rtype, rdata, rmsgid, rctrls = conn.result3(msgid)

                # Check for more pages
                for ctrl in rctrls:
                    if ctrl.controlType == '1.2.840.113556.1.4.319':
                        if ctrl.cookie:
                            # More pages available
                            page_control.cookie = ctrl.cookie
                            # Continue with next page...

            Server Side Sort:

            .. code-block:: python

                import ldap
                from ldap.controls import LDAPControl

                # Create sort control (sort by cn, then by uid)
                # The controlValue should contain the sort keys in BER format
                # For this fake implementation, we'll use simple UTF-8 encoding
                sort_keys = ['cn', 'uid']
                control_value = ','.join(sort_keys).encode('utf-8')
                encoded_control_value = ldap.encode_sort_control_value(control_value)
                sort_control = LDAPControl(
                    '1.2.840.113556.1.4.473',
                    True,
                    encoded_control_value,
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

            Paged Search with Server Side Sort:

            .. code-block:: python

                import ldap
                from ldap.controls import SimplePagedResultsControl, LDAPControl

                # Create both controls
                page_control = SimplePagedResultsControl(True, size=5, cookie='')
                sort_keys = ['cn']
                control_value = ','.join(sort_keys).encode('utf-8')
                encoded_control_value = ldap.encode_sort_control_value(control_value)
                sort_control = LDAPControl(
                    '1.2.840.113556.1.4.473',
                    True,
                    encoded_control_value,
                )

                # Perform paged and sorted search
                msgid = conn.search_ext(
                    'ou=users,dc=example,dc=com',
                    ldap.SCOPE_SUBTREE,
                    '(objectClass=person)',
                    serverctrls=[page_control, sort_control]
                )

                # Get results (sorted and paged)
                rtype, rdata, rmsgid, rctrls = conn.result3(msgid)

        Keyword Args:
            base: the base DN for the search
            scope: the scope of the search
            filterstr: the filter to use for the search
            attrlist: the list of attributes to return for each object
            attrsonly: if 1, return only the attribute values; if 0, return the
            entire object
            serverctrls: server controls (supports Paged Results and Server Side Sort)
            clientctrls: client controls (ignored)
            timeout: timeout for the search (ignored)
            sizelimit: size limit for the search (applied after sorting)

        Returns:
            The message ID of the search

        """  # noqa: E501
        msgid = self.current_msgid
        if serverctrls:
            # Find the Paged Results control (OID: 1.2.840.113556.1.4.319) and
            # set the cookie on it
            for ctrl in serverctrls:
                if getattr(ctrl, "controlType", None) == "1.2.840.113556.1.4.319":
                    ctrl.cookie = b"%d" % msgid
                    break
        self._async_results[msgid] = {}
        self._async_results[msgid]["ctrls"] = serverctrls
        value = self._search_s(base, scope, filterstr, attrlist, attrsonly)

        # --- LDAP sort control simulation ---
        # If a control with OID 1.2.840.113556.1.4.473 is present, sort the results.
        # We decode the BER-encoded controlValue to get the sort keys.
        if serverctrls:
            for ctrl in serverctrls:
                if getattr(ctrl, "controlType", None) == "1.2.840.113556.1.4.473":
                    # Decode the BER-encoded controlValue to get sort keys
                    control_value = getattr(ctrl, "controlValue", None)
                    if control_value:
                        sort_keys = decode_sort_control_value(control_value)
                        if sort_keys:
                            # value is a list of (dn, attrs) tuples
                            def sort_func(item):
                                dn, attrs = item
                                # Support multi-key sort
                                return tuple(
                                    attrs.get(key, [b""])[0].lower()
                                    if attrs.get(key)
                                    else b""
                                    for key in sort_keys  # noqa: B023
                                )

                            value = sorted(value, key=sort_func)
                    break
        # --- end sort control simulation ---

        # --- LDAP size limit simulation ---
        # Apply size limit if specified (0 means no limit)
        if sizelimit > 0 and len(value) > sizelimit:
            value = value[:sizelimit]
        # --- end size limit simulation ---

        self._async_results[msgid]["data"] = value
        self.current_msgid += 1
        return msgid

    @record_call
    def result3(
        self,
        msgid: int = ldap.RES_ANY,
        all: int = 1,  # noqa: A002, ARG002
        timeout: int | None = None,  # noqa: ARG002
    ) -> Result3:
        """
        Retrieve the results of our :py:meth:`FakeLDAPObject.search_ext` call.

        .. note::
            The ``all`` and ``timeout`` keyword arguments are ignored here.

        Keyword Args:
            msgid: the ``msgid`` returned by the
                :py:meth:`FakeLDAPObject.search_ext` call
            all: if 1, return all results at once; if 0, return them one at a
                time (ignored)
            timeout: timeout for the search (ignored)

        Returns:
            A :py:func:`ldap.result3` 4-tuple.

        """
        if self._async_results:
            if msgid == ldap.RES_ANY:
                msgid = next(iter(self._async_results.keys()))
        if msgid in self._async_results:
            data = self._async_results[msgid]["data"]
            controls = self._async_results[msgid]["ctrls"]
            del self._async_results[msgid]
        else:
            data = []
            controls = None
        if controls is not None and len(controls) > 0:
            controls[0].cookie = None
        return ldap.RES_SEARCH_RESULT, data, msgid, controls  # type: ignore[return-value]

    @record_call
    def search_s(
        self,
        base: str,
        scope: int,
        filterstr: str = "(objectClass=*)",
        attrlist: list[str] | None = None,
        attrsonly: int = 0,
    ) -> list[LDAPRecord]:
        return self._search_s(base, scope, filterstr, attrlist, attrsonly)

    @record_call
    def start_tls_s(self) -> None:
        """
        Negotiate TLS with server.

        This sets our :py:attr:`tls_enabled` attribute to ``True``.

        Raises:
            ldap.LOCAL_ERROR: :py:meth:`start_tls_s` was done twice on the same
                connection

        """
        if not self.tls_enabled:
            self.tls_enabled = True
        else:
            raise ldap.LOCAL_ERROR(
                {
                    "result": -2,
                    "desc": "Local error",
                    "errno": 35,
                    "ctrls": [],
                    "info": (
                        "Start TLS request accepted.Server willing to negotiate SSL.",
                    ),
                }
            )

    @record_call
    def compare_s(self, dn: str, attr: str, value: bytes) -> bool:
        """
        Perform an LDAP comparison between the attribute named ``attr`` of entry
        ``dn``, and the value ``value``.   For multi-valued attributes, the test
        is whether any of the values match ``value``.

        Args:
            dn: the dn of the object to look at
            attr: the name of the attribute on our object to compare
            value: the value to which to compare the object value

        Raises:
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our object store

        Returns:
            ``True`` if the values are equal, ``False`` otherwise.

        """
        if not isinstance(value, bytes):
            msg = f"a bytes-like object is required, not '{type(value)}'"
            raise TypeError(msg)
        try:
            return value in self.store.get(dn)[attr]
        except KeyError:
            return False

    @needs_bind
    @record_call
    def modify_s(self, dn, modlist: ModList) -> Result3:
        """
        Modify the object with dn of ``dn`` using the modlist ``modlist``.

        Each element in the list modlist should be a tuple of the form
        ``(mod_op: int, mod_type: str, mod_vals: bytes | List[bytes])``, where
        ``mod_op`` indicates the operation (one of :py:attr:`ldap.MOD_ADD`,
        :py:attr:`ldap.MOD_DELETE`, or :py:attr:`ldap.MOD_REPLACE`, ``mod_type``
        is a string indicating the attribute type name, and ``mod_vals`` is
        either a bytes value or a list of bytes values to add, delete or
        replace respectively. For the delete operation, ``mod_vals`` may be ``None``
        indicating that all attributes are to be deleted.

        Note:
            :py:func:`ldap.modlist.modifyModlist` MAY be your friend here for
            generating modlists.  Do read the note in those docs about
            :py:attr:`ldap.MOD_DELETE` / :py:attr:`ldap.MOD_ADD` vs.
            :py:attr:`ldap.MOD_REPLACE` to see whether that will affect you poorly.


        Example:
            Here is an example of constructing a modlist for ``modify_s``:

            >>> import ldap
            >>> modlist = [
                (ldap.MOD_ADD, 'mail', [b'user@example.com', b'user+foo@example.com']),
                (ldap.MOD_REPLACE, 'cn', [b'My Name']),
                (ldap.MOD_DELETE, 'gecos', None)
            ]

        Args:
            dn: the dn of the object to delete
            modlist: a modlist suitable for ``modify_s``

        Raises:
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our object store
            ldap.TYPE_OR_VALUE_EXISTS: you tried to add an value to an
                attribute, but it was already in the value list
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before
                doing this

        Returns:
            A :py:func:`ldap.result3` type 4-tuple.

        """
        self.store.update(dn, modlist, bind_dn=self.bound_dn)
        return (ldap.RES_MODIFY, [], 3, [])

    @needs_bind
    @record_call
    def delete_s(self, dn: str) -> None:
        """
        Delete the object with dn of ``dn`` from our object store.

        Each element in the list modlist should be a tuple of the form
        ``(mod_type: str, mod_vals: List[bytes])``, where ``mod_type`` is a
        string indicating the attribute type name, and ``mod_vals`` is either a
        string value or a list of string values to add, delete or replace
        respectively. For the delete operation, mod_vals may be ``None``
        indicating that all attributes are to be deleted.

        Args:
            dn: the dn of the object to delete

        Raises:
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our object store
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before
                doing this

        """
        self.store.delete(dn)

    @needs_bind
    @record_call
    def add_s(self, dn: str, modlist: AddModList) -> None:
        """
        Add an object with dn of ``dn``.

        ``modlist`` is similar the one passed to :py:meth:`modify_s`, except
        that the operation integer is omitted from the tuples in ``modlist``. You
        might want to look into sub-module refmodule{ldap.modlist} for
        generating the modlist.

        Example:
            Here is an example of constructing a modlist for ``add_s``:

            >>> modlist = [
                ('uid', [b'user']),
                ('gidNumber', [b'1000']),
                ('uidNumber', [b'1000']),
                ('loginShell', [b'/bin/bash']),
                ('homeDirectory', [b'/home/user']),
                ('userPassword', [b'the password']),
                ('cn', [b'My Name']),
                ('objectClass', [b'top', b'posixAccount']),
            ]

        Args:
            dn: the dn of the object to add
            modlist: the add modlist

        Raises:
            ldap.ALREADY_EXISTS: an object with dn of ``dn`` already exists in
                our object store
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before
                doing this

        """
        self.store.create(dn, modlist, bind_dn=self.bound_dn)

    @needs_bind
    @record_call
    def rename_s(
        self,
        dn: str,
        newrdn: str,
        newsuperior: str | None = None,
        delold: int = 1,
        serverctrls: list[ldap.controls.LDAPControl] | None = None,  # noqa: ARG002
        clientctrls: list[ldap.controls.LDAPControl] | None = None,  # noqa: ARG002
    ) -> None:
        """
        Take ``dn`` (the DN of the entry whose RDN is to be changed, and
        ``newrdn``, the new RDN to give to the entry. The optional parameter
        ``newsuperior`` is used to specify a new parent DN for moving an entry
        in the tree (not all LDAP servers support this).

        Args:
            dn: the dn of the object to rename
            newrdn: the new RDN

        Keyword Args:
            newsuperior: the new basedn
            delold: if 1, delete the old entry after renaming, if 0, don't.
            serverctrls: server controls (ignored)
            clientctrls: client controls (ignored)

        Raises:
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our object store
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before
                doing this

        """
        entry = self.store.copy(dn)
        basedn = newsuperior if newsuperior else ",".join(dn.split(",")[1:])
        newdn = newrdn + "," + basedn
        attr, value = newrdn.split("=")
        entry[attr] = [value.encode("utf-8")]
        self.store.set(newdn, entry, bind_dn=self.bound_dn)
        if delold and dn != newrdn:
            self.store.delete(dn, bind_dn=self.bound_dn)

    @needs_bind
    @record_call
    def modrdn_s(
        self,
        dn: str,
        newrdn: str,
        delold: int = 1,
        serverctrls: list[ldap.controls.LDAPControl] | None = None,  # noqa: ARG002
        clientctrls: list[ldap.controls.LDAPControl] | None = None,  # noqa: ARG002
    ) -> None:
        """
        Modify the RDN (Relative Distinguished Name) of an entry.

        This method changes the RDN of the entry with DN ``dn`` to ``newrdn``.
        Unlike :py:meth:`rename_s`, this method does not support moving entries
        to a different parent DN.

        Args:
            dn: the DN of the object whose RDN is to be changed
            newrdn: the new RDN

        Keyword Args:
            delold: if 1, delete the old entry after renaming, if 0, don't
            serverctrls: server controls (ignored)
            clientctrls: client controls (ignored)

        Raises:
            ldap.NO_SUCH_OBJECT: no object with DN of ``dn`` exists in our object store
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before
                doing this

        """
        entry = self.store.copy(dn)
        # Extract the base DN (everything after the first RDN)
        basedn = ",".join(dn.split(",")[1:])
        newdn = newrdn + "," + basedn
        # Extract the attribute name and value from the new RDN
        attr, value = newrdn.split("=")
        entry[attr] = [value.encode("utf-8")]
        self.store.set(newdn, entry, bind_dn=self.bound_dn)
        if delold and dn != newrdn:
            self.store.delete(dn, bind_dn=self.bound_dn)

    @record_call
    def unbind_s(self) -> None:
        """
        Unbind from the server.

        This sets our :py:attr:`bound_dn` to ``None``.
        """
        self.bound_dn = None

    #
    # Internal implementations
    #

    def _search_s(
        self,
        base: str,
        scope: int,
        filterstr: str = "(objectClass=*)",
        attrlist: list[str] | None = None,
        attrsonly: int = 0,  # noqa: ARG002
    ) -> list[LDAPRecord]:
        """
        We can do a SCOPE_BASE search with the default filter and simple
        SCOPE_ONELEVEL with query of the form (attribute_name=some_value).
        Beyond that, you're on your own.

        Args:
            base: the base DN for the search
            scope: the scope of the search

        Keyword Args:
            filterstr: the filter to use for the search
            attrlist: the list of attributes to return for each object
            attrsonly: if 1, return only the attribute values; if 0, return the
                entire object

        """
        # Handle Root DSE queries (empty string DN)
        if scope == ldap.SCOPE_BASE and base == "":
            return self._get_root_dse(filterstr, attrlist)

        if scope == ldap.SCOPE_BASE:
            return self.store.search_base(base, filterstr, attrlist=attrlist)
        if scope == ldap.SCOPE_ONELEVEL:
            return self.store.search_onelevel(base, filterstr, attrlist=attrlist)
        return self.store.search_subtree(base, filterstr, attrlist=attrlist)

    def _get_root_dse(
        self,
        filterstr: str = "(objectClass=*)",
        attrlist: list[str] | None = None,
    ) -> list[LDAPRecord]:
        """
        Return a fake Root DSE entry that includes supported controls.

        Args:
            filterstr: the filter to use for the search
            attrlist: the list of attributes to return for each object

        Returns:
            A list containing the Root DSE entry with supported controls.
        """
        # Define the Root DSE entry with supported controls
        root_dse = {
            "objectClass": [b"top"],
            "supportedControl": [
                b"1.2.840.113556.1.4.473",  # Server Side Sort (RFC 2891)
                b"1.2.840.113556.1.4.319",  # Paged Results (RFC 2696)
            ],
            "supportedSASLMechanisms": [b"PLAIN", b"LOGIN"],
            "supportedLDAPVersion": [b"3"],
            "namingContexts": [b"dc=example,dc=com"],
        }

        # Filter attributes if attrlist is specified
        if attrlist is not None:
            filtered_dse = {}
            for attr in attrlist:
                if attr in root_dse:
                    filtered_dse[attr] = root_dse[attr]
            root_dse = filtered_dse

        # For now, we'll return the Root DSE for any filter that matches objectClass=*
        # This is a simplified approach - in a real implementation, you might want
        # to parse the filter and apply it properly
        if filterstr == "(objectClass=*)" or "objectClass" in filterstr:
            return [("", root_dse)]

        # If the filter doesn't match, return empty result
        return []
