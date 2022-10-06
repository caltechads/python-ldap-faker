from __future__ import annotations

from functools import wraps
import inspect
import json
import sys
from typing import Any, Dict, List, Optional, TextIO, Tuple

import ldap

from .db import (
    CallHistory,
    LDAPServerFactory,
    ObjectStore,
    OptionStore,
)
from .logging import logger
from .types import (
    LDAPCallRecord,
    LDAPOptionValue,
    LDAPRecord,
    ModList,
    AddModList
)


# ====================================
# Global objects
# ====================================

LDAPGlobalOptions = OptionStore()
GlobalLDAPCallHistory = CallHistory()
Servers = LDAPServerFactory()


# ====================================
# Decorators
# ====================================

class BytesEncoder(json.JSONEncoder):

    def default(self, o):
        if isinstance(o, bytes):
            return o.decode()
        return json.JSONEncoder.default(self, o)


def record_call(func):
    """
    Save a record of the call to ``func`` so that our tests can inspect it later.
    """
    @wraps(func)
    def inner(*args, **kwargs):
        sig = inspect.signature(func)
        args_dict = dict(sig.bind(*args, **kwargs).arguments)
        if 'self' in args_dict:
            args_dict['self'].calls.register(func.__name__, args_dict)
            del args_dict['self']
            logger.debug("record_call api=%s, arguments=%s", func.__name__, args_dict)
        else:
            logger.debug("record_call.global api=%s, arguments=%s", func.__name__, args_dict)
            GlobalLDAPCallHistory.register_global(func.__name__, args_dict)
        return func(*args, **kwargs)
    return inner


def needs_bind(func):
    @wraps(func)
    def inner(self, dn: str, *args, **kwargs):
        if not self.bound_dn:
            raise ldap.INSUFFICIENT_ACCESS({
                'msgtype': 105,
                'msgid': 1,
                'result': 50,
                'desc': 'Insufficient access',
                'ctrls': [],
                'info': f"Insufficient '{func.__name__}' privilege for the entry '{dn}'\n"
            })
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
            logger.debug("handle_return_value.found method=%s key=%s", func.__name__, key)
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
    We use this class to house our replacement code for these three prime ``python-ldap``
    functions:

    * :py:func:`ldap.initialize`
    * :py:func:`ldap.set_option`
    * :py:func:`ldap.get_option`

    The class takes a fully configured :py:class:`LDAPServerFactory` as an argument, and
    will use that factory's collection of :py:class:`OptionStore` objects to construct new
    :py:class:`FakeLDAPObject` objects.

    As a test runs, :py:class:`FakeLDAP` keeps track of each LDAP connection made and
    each global LDAP call made so that they can be inspected after your code has run.

    Note:
        This is meant to be a disposable object, recreated for each test method.
        When used properly, all internal state (connections made, calls made,
        options set) will be empty at the start of every test.

    Args:
        server_factory: a fully configured :py:class:`LDAPServerFactory`
    """

    def __init__(self, server_factory: LDAPServerFactory) -> None:
        self.connections: List["FakeLDAPObject"] = []  #: list of :py:class:`FakeLDAPObject` connections created in the order in which they were requested
        self.calls: CallHistory = CallHistory()  #: The call history for global ldap function calls
        self.options: OptionStore = OptionStore()  #: A dictionary of LDAP options set
        self.stores: Dict[str, ObjectStore] = {}
        self.server_factory: LDAPServerFactory = server_factory

    @record_call
    def initialize(
        self,
        uri: str,
        trace_level: int = 0,
        trace_file: TextIO = sys.stdout,
        trace_stack_limit: int = None,
        fileno: Any = None
    ) -> "FakeLDAPObject":
        """
        This is the method we use to patch :py:func:`ldap.initialize` when we
        are testing our LDAP code.  When it is called, we will ask our
        :py:attr:`FakeLDAP.server_factory` factory for the :py:class:`ObjectStore` most
        appropriate for the LDAP uri ``uri``, create a :py:class:`FakeLDAPObject`
        with a :py:func:`copy.deepcopy` of that :py:class:`ObjectStore`, and return
        the :py:class:`FakeLDAPObject`.

        Note:
            Of all the arguments in our signature, we only actually use ``uri``.  The
            other arguments are recorded in our :py:attr:`FakeLDAP.calls` call history, but
            are otherwise ignored.

        Args:
            uri: an LDAP URI
            trace_level: logging level (ignored)
            trace_file: file descriptor to which to write traces (ignored)
            trace_stack_limit: stack limit of tracebacks in the debug log (ignored)
            fileno: a socket or file descriptor (ignored)

        Raises:
            ldap.SERVER_DOWN: could not find an appropriate :py:class:`ObjectStore` for ``uri``

        Returns:
            A properly configured :py:class:`FakeLDAPObject`
        """
        if uri not in self.stores:
            self.stores[uri] = self.server_factory.get(uri)
        conn = FakeLDAPObject(directory=self.stores[uri], uri=uri)
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
        """
        self.options.set(option, invalue)

    @record_call
    def get_option(self, option: int) -> LDAPOptionValue:
        """
        Get a global python-ldap option.  If our code hasn't set an ``option`` yet,
        return the default from ``python-ldap`` for that option.

        Args:
            option: an option from python-ldap

        Returns:
            The value currently set for the option.
        """
        return self.options.get(option, ldap.get_option(option))

    # Test instrumentation

    def has_connection(self, uri: str) -> bool:
        """
        Test to see whether an :py:func:`ldap.initialize` call was made with LDAP URI of ``uri``.

        Args:
            uri: The LDAP URI to look for in our connection history

        Returns:
            ``True`` if at least one connection to ``uri`` was made, ``False`` otherwise.
        """
        for conn in self.connections:
            if conn.uri == uri:
                return True
        return False

    def get_connections(self, uri: str) -> List["FakeLDAPObject"]:
        """
        Return a list of :py:class:`FakeLDAPObject` connections to LDAP URI ``uri``.

        Args:
            uri: The LDAP URI to look for in our connection history

        Returns:
            A list of :py:class:`FakeLDAPObject` objects associated with LDAP URI ``uri``.
        """
        return [conn for conn in self.connections if conn.uri == uri]

    def filter_calls(self, api_name: str = None, uri: str = None) -> List[LDAPCallRecord]:
        """
        Filter our call history by function name and optionally LDAP URI.

        Args:

        Keyword Args:
            api_name: restrict through our history for calls to this function
            uri: restrict our search to only calls to this URI

        Returns:
            A list of (``api_name``, ``arguments``) tuples in the order in which the
            calls were made.  Arguments is a ``Dict[str, Any]``.
        """
        results: List[LDAPCallRecord] = []
        for conn in self.connections:
            if uri and not conn.uri == uri:
                continue
            if api_name:
                results.extend(conn.calls.filter_calls(api_name))
            else:
                results.extend(conn.calls._calls)
        return results


# =========================
# LDAPObject
# =========================

class FakeLDAPObject:
    """
    This class simulates most of the interface of ``ldap.ldapobject.LDAPObject``
    which is the object that gets returned when you call ``ldap.initialize()``.

    Note:
        This is a disposable object that should be recreated for each test, mostly
        because changes to our ``ObjectStore`` can't be undone without re-copying
        from its source in ``Servers``.

    Args:
        uri: the LDAP URI of the connection

    Keyword Args:
        directory: a populated :py:class:`ObjectStore`
    """

    def __init__(self, directory: ObjectStore = None, uri: str = None):
        # cookie and _async_results are used for the paged search implementation
        self.cookie: int = 0
        self._async_results: Dict[int, Dict[str, ldap.controls.LDAPControl]] = {}

        # This is the URI to which we connected
        self.uri: str = uri  #: the LDAP URI for this connection
        self.options: OptionStore  = OptionStore()  #: we store data from :py:meth:`set_option` calls here
        # directory is our our prepared LDAP data objects and faked searches
        if directory:
            self.directory: ObjectStore = directory
        else:
            self.directory = ObjectStore()
        # calls is our call history
        self.calls: CallHistory = CallHistory()  #: The method call history
        self.tls_enabled: bool = False  #: Set to True if :py:meth:`start_tls_s` was called
        self.bound_dn: Optional[str] = None  #: Set by :py:meth:`simple_bind_s` to the dn of the user after success

    # LDAPObject methods

    @record_call
    def set_option(self, option: int, invalue: LDAPOptionValue) -> None:
        self.options.set(option, invalue)

    @record_call
    def get_option(self, option: int) -> LDAPOptionValue:
        return self.options.get(option)

    @record_call
    def simple_bind_s(self, who: str = '', cred: str = '') -> None:
        """
        Perform a bind.  This will look in the object store for an object with dn of
        ``who`` and compare ``cred`` to the ``userPassword`` attribute for that
        object.

        Keyword Args:
            who: the dn of the user with which to bind
            cred:  the password for that user

        Raises:
            ldap.INVALID_CREDENTIALS: the ``who`` did not match the ``cred``
        """
        if (who == '' and cred == ''):
            return

        if self.directory.exists(who) and self._compare_s(who.lower(), 'userPassword', cred):
            self.bound_dn = who
            return
        raise ldap.INVALID_CREDENTIALS({
            'msgtype': 97,
            'msgid': 2,
            'result': 49,
            'desc': 'Invalid credentials',
            'ctrls': []
        })

    @record_call
    def search_ext(
        self,
        base: str,
        scope: int,
        filterstr: str = '(objectClass=*)',
        attrlist: List[str] = None,
        attrsonly: int = 0,
        serverctrls: List[ldap.controls.LDAPControl] = None,
        clientctrls: List[ldap.controls.LDAPControl] = None,
        timeout: int = -1,
        sizelimit: int = 0
    ) -> int:
        msgid = self.cookie
        serverctrls[0].cookie = b'%d' % msgid  # type: ignore
        self._async_results[self.cookie] = {}
        self._async_results[self.cookie]['ctrls'] = serverctrls
        value = self._search_s(base, scope, filterstr, attrlist, attrsonly)
        self._async_results[self.cookie]['data'] = value
        self.cookie += 1
        return msgid

    @record_call
    def result3(
        self,
        msgid: int = ldap.RES_ANY,
        all: int = 1,
        timeout: int = None
    ) -> Tuple[int, List[LDAPRecord], int, List[ldap.controls.LDAPControl]]:
        if self._async_results:
            if msgid == ldap.RES_ANY:
                msgid = list(self._async_results.keys())[0]
        if msgid in self._async_results:
            data = self._async_results[msgid]['data']
            controls = self._async_results[msgid]['ctrls']
            del self._async_results[msgid]
        else:
            data = []
        controls[0].cookie = None
        return ldap.RES_SEARCH_RESULT, data, msgid, controls

    @record_call
    @handle_return_value
    def search_s(
        self,
        base: str,
        scope: int,
        filterstr: str = '(objectClass=*)',
        attrlist: List[str] = None,
        attrsonly: int = 0
    ) -> List[LDAPRecord]:
        return self._search_s(base, scope, filterstr, attrlist, attrsonly)

    def start_tls_s(self) -> None:
        self.tls_enabled = True

    @record_call
    def compare_s(self, dn: str, attr: str, value: Any) -> bool:
        return self._compare_s(dn, attr, value)

    @record_call
    def modify_s(self, dn, modlist: ModList) -> None:
        """
        Modify the object with dn of ``dn`` using the modlist ``modlist``.

        Each element in the list modlist should be a tuple of the form
        ``(mod_op: int, mod_type: str, mod_vals: Union[bytes, List[bytes]])``, where
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
            ldap.TYPE_OR_VALUE_EXISTS: you tried to add an value to an attribute, but it was
                already in the value list
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before doing this
        """
        entry = self.directory.get(dn)
        for item in mod_attrs:
            op, key, value = item
            if op == ldap.MOD_ADD:
                if key not in entry:
                    entry[key] = value
                else:
                    # TODO: note we're not dealing with multi-valued attributes
                    # that need unique items here
                    entry[key].extend(value)
            elif op == ldap.MOD_DELETE:
                # do a MOD_DELETE
                row = entry[key]
                if isinstance(row, list):
                    for i in range(len(row)):
                        if value == row[i]:
                            del row[i]
                else:
                    del entry[key]
                self.directory.set(dn, entry)
            elif op == ldap.MOD_REPLACE:
                # do a MOD_REPLACE
                entry[key] = value
        self.directory.set(dn, entry)

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
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before doing this
        """
        self.directory.delete(dn)

    @needs_bind
    @record_call
    def add_s(self, dn: str, modlist: AddModList) -> None:
        """
        Delete the object with dn of ``dn`` from our object store.

        Args:
            dn: the dn of the object to delete

        Raises:
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our object store
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before doing this
        """
        # change the record into the proper format for the internal directory
        entry = {}
        for item in modlist:
            entry[item[0]] = item[1]
        try:
            self.directory.get(dn)
            raise ldap.ALREADY_EXISTS({'info': '', 'desc': 'Object already exists'})
        except KeyError:
            self.directory.set(dn, entry)

    @needs_bind
    @record_call
    def rename_s(
        self,
        dn: str,
        newrdn: str,
        newsuperior: str = None,
        delold: int = 1,
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

        Raises:
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our object store
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before doing this
        """
        entry = self.directory.copy(dn)
        if not superior:
            basedn = ','.join(dn.split(',')[1:])
        else:
            basedn = superior
        newdn = newrdn + ',' + basedn
        attr, value = newrdn.split('=')
        entry[attr] = [value.encode('utf-8')]
        self.directory.set(newdn, entry)
        if dn != newrdn:
            self.directory.delete(dn)

    @record_call
    def unbind_s(self) -> None:
        self.bound_dn = None

    #
    # Internal implementations
    #

    def _compare_s(self, dn: str, attr: str, value: Any) -> bool:
        try:
            found = value.encode('utf-8') in self.directory.get(dn)[attr]
        except KeyError:
            found = False
        return found

    def _search_s(
        self,
        base: str,
        scope: int,
        filterstr: str = '(objectClass=*)',
        attrlist: List[str] = None,
        attrsonly: int = 0
    ) -> List[LDAPRecord]:
        """
        We can do a SCOPE_BASE search with the default filter and simple
        SCOPE_ONELEVEL with query of the form (attribute_name=some_value).
        Beyond that, you're on your own.
        """
        if scope == ldap.SCOPE_BASE:
            return self.directory.search_base(base, filterstr, attrlist=attrlist)
        if scope == ldap.SCOPE_ONELEVEL:
            return self.directory.search_onelevel(base, filterstr, attrlist=attrlist)
        return self.directory.search_subtree(base, filterstr, attrlist=attrlist)
