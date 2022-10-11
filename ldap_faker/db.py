from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
import re
from typing import List, Dict, Any, Optional, Set, cast
import warnings

import ldap
from ldap_filter import Filter
from ldap_filter.parser import ParseError

from .types import (
    AddModList,
    LDAPObjectStore,
    CILDAPData,
    LDAPSearchResult,
    LDAPOptionStore,
    LDAPOptionValue,
    LDAPData,
    RawLDAPObjectStore,
    LDAPRecord,
    ModList
)


@dataclass
class LDAPCallRecord:
    """
    This is a single LDAP call record, used by :py:class:`CallHistory` to store
    information about calls to LDAP api functions.

    :py:attr:`api_name` is the name of the LDAP api call made
    (e.g. ``simple_bind_s``, ``search_s``).

    :py:attr:`args` is the argument list of the call, including defaults for
    keyword arguments not passed.  This is a dict where the key is the name of
    the positional or keyword argument, and the value is the passed in (or
    default) value for that argument.

    Example:

        If we make this call to a patched :py:class:`FakeLDAPObject`::

            ldap_obj.search_s('ou=bar,o=baz,c=country', ldap.SCOPE_SUBTREE, '(uid=foo)')

        This will be recorded as::

            LDAPCallRecord(
                api_name='search_s',
                args={
                    'base': 'ou=bar,o=baz,c=country',
                    'scope': 2,
                    'filterstr': '(uid=foo)',
                    'attrlist': None,
                    'attrsonly': 0
                }
            )

    """
    api_name: str  #: the name LDAP api call
    args: Dict[str, Any]   #: the args and kwargs dict


class LDAPServerFactory:
    """
    This class registers :py:class:`ObjectStore` objects to be used by
    ``FakeLDAP.initialize()`` in constructing :py:class:`FakeLDAPObject` objects.
    :py:class:`ObjectStore` objects are named registered here by LDAP uri (in reality,
    any string).

    You may do one of two things, but not both:

    * Configure a default :py:class:`ObjectStore` that will be used for all
      :py:func:`ldap.initialize` calls regardless of ``uri``
    * Assign a specific :py:class:`ObjectStore` for each ``uri`` you will be using
      in your code.

    Example:

        To register a default :py:class:`ObjectStore` that will be used for every
        ``uri`` passed to :py:meth:`FakeLDAP.initialize`:

        >>> from ldap_faker import ObjectStore, LDAPServerFactory, FakeLDAP
        >>> data = [ ... ]   # some LDAP records
        >>> factory = LDAPServerFactory()
        >>> store = ObjectStore(objects=data)
        >>> factory.register(store)
        >>> fake_ldap = FakeLDAP(factory)

        Now any time your code does an ``ldap.initialize()`` to our patched
        version of that function, it will get a a :py:class:`FakeLDAPObject` configured
        with a :py:func:`copy.deepcopy` of the :py:class:`ObjectStore` ``store``, no matter what
        ``uri`` it passes to ``ldap.initialize()``.

        To register a different ``ObjectStores`` that will be used for specific
        ``uris``:

        >>> from ldap_faker import ObjectStore, Servers
        >>> data1 = [ ... ]   # some LDAP records
        >>> factory = LDAPServerFactory()
        >>> store1 = ObjectStore(objects=data1)
        >>> factory.register(store1, uri='ldap://server1')
        >>> data2 = [ ... ]   # some different LDAP records
        >>> store2 = ObjectStore(objects=data2)
        >>> factory.register(store2, uri='ldap://server2')
        >>> fake_ldap = FakeLDAP(factory)

        Now if your code does ``ldap.initialize('ldap://server1')``, it will get
        a :py:class:`FakeLDAPObject` configured with a :py:func:`copy.deepcopy` of the
        :py:class:`ObjectStore` object ``store1``, while if it does
        ``ldap.initialize('ldap://server2' )``, it will get a :py:class:`FakeLDAPObject`
        configured with a :py:func:`copy.deepcopy` of the :py:class:`ObjectStore` object ``store2``.
    """

    def __init__(self) -> None:
        self.servers: Dict[str, "ObjectStore"] = {}
        self.default: Optional["ObjectStore"] = None

    def load_from_file(self, filename: str, uri: str = None) -> None:
        """
        Given a file path to a JSON file with the objects for an :py:class:`ObjectStore`,
        create a new :py:class:`ObjectStore`, load it with that JSON File and register it
        with uri of ``uri``.

        Args:
            filename: the full path to our JSON file

        Keyword Args:
            uri: the uri to assign to the :py:class:`ObjectStore` we create

        Raises:
            ValueError: raised if a default is already configured while trying to
                register the :py:class:`ObjectStore` with a specific ``uri``
            RuntimeWarning: raised if we try to overwrite an already registered object
                store with our new one
        """
        store = ObjectStore()
        store.load_objects(filename)
        self.register(store, uri=uri)

    def register(self, directory: "ObjectStore", uri: str = None) -> None:
        """
        Register a new :py:class:`ObjectStore` to be used as our fake LDAP server for when
        we run our  fake ``initialize`` function.

        Args:
            directory: a configured :py:class:`ObjectStore`

        Keyword Args:
            uri: the LDAP uri to associated with ``directory``

        Raises:
            ValueError: raised if a default is already configured while trying to
                register an :py:class:`ObjectStore` with a specific ``uri``
            RuntimeWarning: raised if we try to overwrite an already registered object
                store with a new one
        """
        if uri and self.default is not None:
            raise ValueError(
                f'You cannot regster an ObjectStore for uri="{uri}" because '
                'a default server has already been set'
            )
        if not uri:
            if self.default is not None:
                warnings.warn(
                    'LDAPServerFactory: overriding existing default ObjectStore',
                    RuntimeWarning
                )
            self.default = directory
        if uri in self.servers:
            warnings.warn(
                f'LDAPServerFactory: overriding existing ObjectStore for uri={uri}',
                RuntimeWarning
            )
        self.servers[cast(str, uri)] = directory

    def get(self, uri: str) -> "ObjectStore":
        """
        Return a :py:func:`copy.deepcopy` of the :py:class:`ObjectStore` identified by ``uri``.

        Args:
            uri: use this uri to look up which :py:class:`ObjectStore` to use

        Raises:
            ldap.SERVER_DOWN: no :py:class:`ObjectStore` could be found for ``uri``

        Returns:
            A :py:func:`copy.deepcopy` of the :py:class:`ObjectStore`
        """
        if self.default is not None:
            return deepcopy(self.default)
        try:
            return deepcopy(self.servers[uri])
        except KeyError as exc:
            raise ldap.SERVER_DOWN({'desc': "Can't contact LDAP Server"}) from exc


class CallHistory:
    """
    This class records the ``python-ldap`` call history for a particular
    :py:class:`FakeLDAPObject` as :py:class:`LDAPCallRecord` objects.  It works
    in conjunction with the ``@record_call`` decorator.  An
    :py:class:`CallHistory` object will be configured on each
    :py:class:`FakeLDAPObject` and on each :py:class:`FakeLDAP` object capture
    their call history.

    We use this in our tests with appropriate asserts to ensure that our code
    called the ``python-ldap`` methods we expected, in the order we expected,
    with the arguments we expected.
    """

    def __init__(self, calls: List[LDAPCallRecord] = None):
        self._calls: List[LDAPCallRecord] = []
        if calls:
            self._calls = calls

    def register(self, api_name: str, arguments: Dict[str, Any]) -> None:
        """
        Register a new call record.  This is used by the ``@record_call``
        decorator to register :py:class:`FakeLDAPObject` method calls.

        Args:
            api_name: the name of the function or method called
            arguments: a dict where the keys are argument names, and the values are passed in
                values for those arguments

        :meta private:
        """
        self._calls.append(LDAPCallRecord(api_name, arguments))

    def filter_calls(self, api_name: str) -> List[LDAPCallRecord]:
        """
        Filter our call history by function name.

        Args:
            api_name: look through our history for calls to this function

        Returns:
            A list of (``api_name``, ``arguments``) tuples in the order in which the
            calls were made.  Arguments is a ``Dict[str, Any]``.
        """
        return [call for call in self._calls if call.api_name == api_name]

    @property
    def calls(self) -> List[LDAPCallRecord]:
        """
        This property returns the list of all calls made against the parent object.

        Example:

            To test that your code did a :py:func:`ldap.simple_bind_s` call with the usernam
            and password you expected, you could do::

                from unittest import TestCase
                import ldap
                from ldap_faker import LDAPFakerMixin

                from my_code import App

                class MyTest(LDAPFakerMixin, TestCase):

                    ldap_modules = ['my_code']
                    ldap_fixtures = 'myfixture.json'

                    def test_option_was_set(self):
                        app = MyApp()
                        app.do_the_thing()
                        conn = self.ldap_faker.connections[0]
                        self.assertEqual(
                            conn.calls,
                            [('simple_bind_s', {'who': 'uid=foo,ou=dept,o=org,c=country', 'cred': 'pass'})]
                        )

        Returns:
            Returns a list of 2-tuples, one for each method call made since
            the last reset. Each tuple contains the name of the API and a dictionary
            of arguments. Argument defaults are included.
        """
        return self._calls

    @property
    def names(self) -> List[str]:
        """
        Returns the list names of ``python-ldap`` functions or methods called, in
        the order they were called.  You can use this to test whether an particulary

        Example:

            To test that your code did at least one :py:func:`ldap.add_s` call, you
            could do::

                from unittest import TestCase
                import ldap
                from ldap_faker import LDAPFakerMixin

                from my_code import App

                class MyTest(LDAPFakerMixin, TestCase):

                    ldap_modules = ['my_code']
                    ldap_fixtures = 'myfixture.json'

                    def test_option_was_set(self):
                        app = MyApp()
                        app.do_the_thing()
                        conn = self.ldap_faker.connections[0]
                        self.assertEqual('add_s" in conn.calls.names)

        Returns:
            A list of method names, in the order they were called.
        """
        return [call.api_name for call in self._calls]


class OptionStore:
    """
    We use this to store options set via ``set_option``.
    """

    def __init__(self):
        self.options: LDAPOptionStore = {}

    def set(self, option: int, invalue: LDAPOptionValue) -> None:
        """
        Set an option.

        Args:
            option: the code for the option (e.g. :py:data:`ldap.OPT_X_TLS_NEWCTX`)
            value: the value we want the option to be set to

        Raises:
            ValueError: ``option`` is not a valid ``python-ldap`` option
        """
        if option not in ldap.OPT_NAMES_DICT:
            raise ValueError(f'unknown option {option}')
        self.options[option] = invalue

    def get(self, option: int) -> LDAPOptionValue:
        """
        Get the value for a previosly set option that was set via :py:meth:`OptionStore.set`.

        Args:
            option: the code for the option (e.g. :py:data:`ldap.OPT_X_TLS_NEWCTX`)

        Raises:
            ValueError: ``option`` is not a valid ``python-ldap`` option

        Returns:
            The value for the option, or the default.
        """
        if option not in ldap.OPT_NAMES_DICT:
            raise ValueError(f'unknown option {option}')
        if option in (ldap.OPT_API_INFO, ldap.OPT_SUCCESS):
            # Even though we declare the output as "int | str", openldap at least returns
            # a dict for this
            return {  # type: ignore
                'info_version': 1,
                'api_version': 3001,
                'vendor_name': 'python-ldap-faker',
                'vendor_version': '1.0.0'
            }
        if option == ldap.OPT_PROTOCOL_VERSION:
            return 3
        return self.options[option]


class ObjectStore:
    """
    This class represents our actual simulated LDAP object store.  Copies of this
    will be used to configure :py:class:`FakeLDAPObject` objects.
    """

    _QUERY_RE = re.compile(r"\(\w+=.+\)$")
    _DEFAULT_SEARCH_RE = re.compile(r"^\(objectclass=*\)$", re.I)

    def __init__(self):
        # raw_objects preserves the object attribute case as it was given to us
        # by register_object, and retains the values as List[bytes]
        self.raw_objects: RawLDAPObjectStore = RawLDAPObjectStore()  #: LDAP records as they would have been returned by ``python-ldap```
        # objects has the same data as raw_objects, but here we forces the
        # attribute names on each object to be case insensitive, and we convert
        # values to List[str].  We need that because in LDAP searches, attribute
        # names and values are compared as case-insensitive, and Filter.match()
        # expects the filter and values to be strings
        self.objects: LDAPObjectStore = LDAPObjectStore()  #: LDAP records set up to make searching better

    def __convert_LDAPData(self, data: LDAPData) -> CILDAPData:
        """
        Convert an incoming ``LDAPData` dict (``Dict[str, List[bytes]``])
        to a ``CILDAPData`` dict (``CaseInsensitiveDict[str, List[str]])``)

        Args:
            data: the LDAPData dict to convert

        Returns:
            The convered CILDAPData dict.
        """
        # We need self.objects to be a case insensitive Dict[str, List[str]]
        # so that filtering works like it would in a real ldap serverindee
        d: Dict[str, Any] = deepcopy(data)
        for key, value in d.items():
            d[key] = [v.decode('utf8') for v in value]
        return CILDAPData(d)

    ## Object store construction

    def load_objects(self, filename: str) -> None:
        """
        Load a list of LDAP records stored as JSON from a file into our internal
        database.  Use this when
        setting up the data you will use to run your tests.

        Note:
            One caveat with this method vs.
            :py:meth:`ObjectStore.register_objects` is that the records returned
            by ``python-ldap`` are of type ``Tuple[str, Dict[str,
            List[bytes]]]`` but JSON has no concept of ``bytes`` or ``tuple``.
            Thus we will expect the LDAP records in the file to have type
            ``List[str, Dict[str, List[str]]]`` and we will convert them to
            ``Tuple[str, Dict[str, List[bytes]]]`` before saving to
            :py:attr:`raw_objects`

        Args:
            filename: the path to the JSON file to load

        Raises:
            ldap.ALREADY_EXISTS: there is already an object in our object store
                with this dn
            ldap.INVALID_DN_SYNTAX: one of the object DNs is not well formed
        """
        with open(filename, 'r', encoding='utf-8') as fd:
            objects = json.load(fd)
        for obj in objects:
            dn, data = obj
            new_data: LDAPData = {}
            for attr, value in data.items():
                new_data[attr] = [entry.encode('utf-8') for entry in value]
            self.register_object((dn, new_data))

    def register_objects(self, objs: List[LDAPRecord]) -> None:
        """
        Load a list of LDAP records into our  internal database.  Use this when
        setting up the data you will use to run your tests.  Each record in the
        list should be in exactly the format that ``python-ldap`` itself returns: a
        2-tuple with dn as the first element and the attribute/value dict as the
        second element.

        Example:
            Adding a several PosixAccount objects:

                >>> obj = [
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
                    ),
                    (
                        'uid=user2,ou=mydept,o=myorg,c=country',
                        {
                            'cn': [b'Firstname User2'],
                            'uid': [b'user2'],
                            'uidNumber': [b'124'],
                            'gidNumber': [b'457'],
                            'homeDirectory': [b'/home/user1'],
                            'loginShell': [b'/bin/bash'],
                            'userPassword': [b'the password'],
                            'objectclass': [b'posixAccount', b'top']
                        }
                    )
                ]
                >>> directory = ObjectStore()
                >>> directory.register_objects(obj)

        Args:
            objs: A list of  LDAP records as they would have been returned by
                ``ldap.ldapobject.LDAPObject.search_s()``.  These are 2-tuples, where
                the first element is the `dn` (a ``str``) and the second element is
                a dict where the keys are ``str`` and the values are lists of
                ``bytes``.

        Raises:
            ldap.ALREADY_EXISTS: there is already an object in our object store
                with this dn
            ldap.INVALID_DN_SYNTAX: one of the object DNs is not well formed
            TypeError: the LDAPData portion for an object was not of type ``Dict[str, List[bytes]]``
        """
        for obj in objs:
            self.register_object(obj)

    def register_object(self, obj: LDAPRecord) -> None:
        """
        Add an LDAP record our internal database.  Use this to add a single
        record when setting up the data you will use to run your tests.  The
        data should be in exactly the format that python-ldap itself returns: a
        2-tuple with dn as the first element and the attribute/value dict as the
        second element.

        Example:
            Adding a PosixAccount object:

                >>> obj = (
                    'uid=user,ou=mydept,o=myorg,c=country',
                    {
                        'cn': [b'Firstname Lastname'],
                        'uid': [b'user'],
                        'uidNumber': [b'123'],
                        'gidNumber': [b'456'],
                        'homeDirectory': [b'/home/user'],
                        'loginShell': [b'/bin/bash'],
                        'userPassword': [b'the password']
                        'objectclass': [b'posixAccount', b'top']
                    }
                )
                >>> directory = ObjectStore()
                >>> directory.register_object(obj)

        Args:
            obj: An LDAP record as it would have been returned by
                ``ldap.ldapobject.LDAPObject.search_s()``.  This is a 2-tuple, where
                the first element is the `dn` (a ``str``) and the second element is
                a dict where the keys are ``str`` and the values are lists of
                ``bytes``.

        Raises:
            ldap.ALREADY_EXISTS: there is already an object in our object store
                with this dn
            ldap.INVALID_DN_SYNTAX: the DN is not well formed
            TypeError: the LDAPData portion was not of type ``Dict[str, List[bytes]]``
        """
        if self.exists(obj[0]):
            raise ldap.ALREADY_EXISTS
        self.set(obj[0], obj[1])

    # Helpers

    def __is_default_filter(self, filterstr: str) -> bool:
        """
        Test whether ``filterstr`` is the default filter string ``(objectClass=*)``.

        Args:
            filterstr: an LDAP filter string

        Returns:
            Returns ``True`` if ``filterstr`` is the default filter string
            case-insensitive, ``False`` otherwise.
        """
        if self._DEFAULT_SEARCH_RE.search(filterstr):
            return True
        return False

    def __check_bytes(self, value: Any) -> None:
        """
        Check a value list, ensuring that we got ``List[bytes]`` and not another type.

        Args:
            value: the value to check

        Raises:
            TypeError: ``value`` is not a ``List[bytes]``
        """
        for v in value:
            if not isinstance(v, bytes):
                raise TypeError(f"('Tuple_to_LDAPMod(): expected a byte string in the list', '{v}')")

    def __validate_dn(self, dn: str, operation: int = ldap.RES_ANY) -> None:
        """
        Validate that ``dn`` is a well formed DN.

        Args:
            dn: the DN to validate

        Keyword Args:
            operation: the ``msgtype`` to set on the exception

        Raises:
            ldap.INVALID_DN_SYNTAX: the dn was not well-formed
        """
        if not ldap.dn.is_dn(dn):
            raise ldap.INVALID_DN_SYNTAX({
                'msgtype': operation,
                'msgid': 3,
                'result': 34,
                'desc': 'Invalid DN syntax',
                'ctrls': [],
                'info': 'DN value invalid per syntax\n'
            })

    def __validate_LDAPRecord(self, obj: LDAPRecord) -> None:
        dn, data = obj
        self.__validate_dn(dn)
        for attr, value in data.items():
            if not isinstance(attr, str):
                raise TypeError(f"attributes must be of type str: '{attr!r}'")
            if not isinstance(value, list):
                raise TypeError(f"values nust be of type List[bytes]: '{value!r}'")
            for v in value:
                if not isinstance(v, bytes):
                    raise TypeError(f"values nust be of type List[bytes]: '{v!r}'")

    def __parse_filterstr(self, filterstr: str) -> Filter:
        try:
            filt = Filter.parse(filterstr)
        except ParseError as exc:
            raise ldap.FILTER_ERROR({
                'result': -7,
                'desc': 'Bad search filter',
                'errno': 35,
                'ctrls': [],
                'info': 'Resource temporarily unavailable'
            }) from exc
        return filt

    # Main methods

    @property
    def count(self):
        return len(self.objects)

    def exists(self, dn: str, validate: bool = True) -> bool:
        """
        Test whether an object with dn ``dn`` exists.

        Args:
            dn: the dn of the object to look for

        Keyword Args:
            validate: if ``True``, validate that ``dn`` is a valid dn

        Returns:
            ``True`` if the object exists, ``False`` otherwise.

        """
        if validate:
            self.__validate_dn(dn, ldap.RES_SEARCH_ENTRY)
        return dn in self.objects

    def get(self, dn: str) -> LDAPData:
        """
        Return data for an object from our object store.

        Args:
            dn: the dn of the object to copy.

        Raises:
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our object store

        Returns:
            The data for an LDAP object
        """
        self.__validate_dn(dn, ldap.RES_SEARCH_ENTRY)
        try:
            return self.raw_objects[dn]
        except KeyError as exc:
            raise ldap.NO_SUCH_OBJECT(
                {
                    'msgtype': 101,
                    'msgid': 4,
                    'result': 32,
                    'desc': 'No such object',
                    'ctrls': [],
                }) from exc

    def copy(self, dn: str) -> LDAPData:
        """
        Return a copy of the data for an object from our object store.

        Args:
            dn: the dn of the object to copy.

        Raises:
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our object store

        Returns:
            The data for an LDAP object
        """
        self.__validate_dn(dn, ldap.RES_SEARCH_ENTRY)
        return deepcopy(self.get(dn))

    def set(self, dn: str, data: LDAPData) -> None:
        """
        Add or update data for the object with dn ``dn``.

        Args:
            dn: the dn of the object to copy.
            data: the dict of data for this object

        Raises:
            ldap.INVALID_DN_SYNTAX: the DN is not well formed
            TypeError: the LDAPData portion was not of type ``Dict[str, List[bytes]]``
        """
        self.__validate_LDAPRecord((dn, data))
        self.raw_objects[dn] = data
        self.objects[dn] = self.__convert_LDAPData(data)

    def update(self, dn: str,  modlist: ModList) -> None:
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
            ldap.INVALID_DN_SYNTAX: the dn was not well-formed
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our
                object store
            ldap.TYPE_OR_VALUE_EXISTS: you tried to add an value to an
                attribute, but it was already in the value list
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before
                doing this
        """

        def get_overlaps(source: List[bytes], other: List[bytes]) -> Set[bytes]:
            """
            Given two lists of bytes, return a set of the items that are in
            both, ignoring the case of the values.

            Args:
                source: the source list
                other: the list of values to compare with

            Returns:
                The list of items that are in both.  These items will be lowercased.
            """
            current = {v.lower() for v in source}
            updates = {v.lower() for v in other}
            return current.intersection(updates)

        self.__validate_dn(dn, ldap.RES_MODIFY)
        obj = self.get(dn)
        for item in modlist:
            op, key, value = item
            if op not in (ldap.MOD_ADD, ldap.MOD_DELETE, ldap.MOD_REPLACE):
                raise ldap.PROTOCOL_ERROR({
                    'msgtype': ldap.RES_MODIFY,
                    'msgid': 4,
                    'result': 2,
                    'desc': 'Protocol error',
                    'info': 'unrecognized modify operation',
                    'ctrls': []
                })
            if op == ldap.MOD_ADD:
                self.__check_bytes(value)
                if key not in obj:
                    obj[key] = value
                else:
                    # Enforce case-insensitive uniqueness in the value list
                    overlaps = get_overlaps(obj[key], value)
                    if not overlaps:
                        obj[key].extend(value)
                    else:
                        raise ldap.TYPE_OR_VALUE_EXISTS({
                            'msgtype': ldap.RES_MODIFY,
                            'msgid': 4,
                            'result': 20,
                            'desc': 'Type or value exists',
                            'ctrls': []
                        })
            elif op == ldap.MOD_DELETE:
                if value is None:
                    # If value was None, delete the whole attribute
                    del obj[key]
                else:
                    # otherwise just remove the values from value from obj[key]
                    self.__check_bytes(value)
                    overlaps = get_overlaps(obj[key], value)
                    obj[key] = [v for v in obj[key] if v.lower() not in overlaps]
            elif op == ldap.MOD_REPLACE:
                self.__check_bytes(value)
                obj[key] = value
        self.set(dn, obj)

    def create(self, dn: str, modlist: AddModList) -> None:
        """
        Create an object in our store with dn of ``dn``.

        ``modlist`` is similar the one passed to :py:meth:`modify_s`, except
        that the operation integer is omitted from the tuples in ``modlist``. You
        might want to look into sub-module refmodule{ldap.modlist} for
        generating the modlist.

        Example:
            Here is an example of constructing a modlist for ``create``:

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
            ldap.INVALID_DN_SYNTAX: the dn was not well-formed
            ldap.ALREADY_EXISTS: an object with dn of ``dn`` already exists in our object store
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before doing this
        """
        self.__validate_dn(dn, ldap.RES_ADD)
        if self.exists(dn):
            raise ldap.ALREADY_EXISTS({'info': '', 'desc': 'Object already exists'})
        entry = {}
        for item in modlist:
            attr, value = item
            if not isinstance(attr, str):
                raise TypeError(f'Tuple_to_LDAPMod() argument 1 must be str, not {type(attr)}')
            self.__check_bytes(value)
            entry[attr] = value
        self.set(dn, entry)

    def delete(self, dn: str) -> None:
        """
        Delete an object from our objects directory.

        Args:
            dn: the dn of the object to delete

        Raises:
            ldap.INVALID_DN_SYNTAX: the dn was not well-formed
        """
        self.__validate_dn(dn, ldap.RES_DELETE)
        try:
            del self.objects[dn]
            del self.raw_objects[dn]
        except KeyError as exc:
            raise ldap.NO_SUCH_OBJECT from exc

    def _filter_attributes(self, obj: LDAPData, attrlist: List[str] = None) -> LDAPData:
        """
        Return just the attributes on ``obj`` named in ``attrlist``.   If
        ``attrlist`` is ``None`` or "``*``"  is in ``attrlist``, return all
        attributes on ``obj``.

        Note:
            We're doing a pretty simplistic implementation of this here, and we
            don't currently support the "operational" attributes, e.g.
            ``nsroledn``.

        Args:
            obj: the data for an LDAP object

        Keyword Args:
            attrlist: a list of attributes to include on ``obj``, removing
                attributes not named

        Returns:
            A filtered set version of obj with only the attributes named in ``attrlist``.
        """
        if not attrlist or '*' in attrlist:
            return deepcopy(obj)
        return {attr: value for attr, value in obj.items() if attr in attrlist}

    def search_base(
        self,
        base: str,
        filterstr: str,
        attrlist: List[str] = None,
    ) -> LDAPSearchResult:
        """
        Do a :py:data:`ldap.SCOPE_BASE` search.  Return the requested attributes of the
        object in our object store with ``dn`` of ``base`` that also matches
        ``filterstr``.

        Args:
            base: the dn of the object to return
            filterstr: the ldap filter string

        Keyword Args:
            attrlist: the list of attributes to return for each object

        Raises:
            ldap.INVALID_DN_SYNTAX: ``base`` was not a well-formed DN
            ldap.FILTER_ERROR: ``filterstr`` is has bad filter syntax
            ldap.NO_SUCH_OBJECT: no object with dn of ``base`` exists in the object store

        Returns:
            A list with one element -- the object with dn of ``base``.

        """
        self.__validate_dn(base, ldap.RES_SEARCH_RESULT)
        data = self.get(base)
        ci_data = self.objects[base]
        results: LDAPSearchResult = []
        if not self.__is_default_filter(filterstr):
            filt = self.__parse_filterstr(filterstr)
            if filt.match(ci_data):
                # We need to do the filter against the the case-insensitive
                # versions of our attribute names, because that's how LDAP
                # works.  Filter.match() will take care of doing
                # case-insensitive value comparisons
                results.append((base, self._filter_attributes(data, attrlist)))
        else:
            results.append((base, self._filter_attributes(data, attrlist)))
        return results

    def search_onelevel(
        self,
        base: str,
        filterstr: str,
        attrlist: List[str] = None,
    ) -> LDAPSearchResult:
        """
        Do a :py:data:`ldap.SCOPE_ONELEVEL` search, for objects directly under
        basedn ``base`` that match ``filterstr``.

        Args:
            base: the dn of the object to return
            filterstr: the ldap filter string

        Keyword Args:
            attrlist: the list of attributes to return for each object

        Raises:
            ldap.INVALID_DN_SYNTAX: ``base`` was not a well-formed DN
            ldap.FILTER_ERROR: ``filterstr`` is has bad filter syntax

        Returns:
            A list of LDAP objects -- 2-tuples of ``(dn, data)``.
        """
        self.__validate_dn(base, ldap.RES_SEARCH_RESULT)
        basedn_parts = ldap.dn.explode_dn(base.lower(), flags=ldap.DN_FORMAT_LDAPV3)
        filt = None
        if not self._DEFAULT_SEARCH_RE.search(filterstr):
            filt = self.__parse_filterstr(filterstr)
        results: LDAPSearchResult = []
        for dn, data in self.objects.items():
            dn_parts = ldap.dn.explode_dn(dn.lower(), flags=ldap.DN_FORMAT_LDAPV3)
            if dn_parts[1:] != basedn_parts:
                continue
            if filt:
                if filt.match(data):
                    results.append((dn, self._filter_attributes(self.raw_objects[dn], attrlist)))
            else:
                results.append((dn, self._filter_attributes(self.raw_objects[dn], attrlist)))
        return results

    def search_subtree(
        self,
        base: str,
        filterstr: str,
        attrlist: List[str] = None
    ) -> LDAPSearchResult:
        """
        Do a :py:data:`ldap.SCOPE_SUBTREE` search, for objects under basedn
        ``base`` that match ``filterstr``.

        Args:
            base: the dn of the object to return
            filterstr: the ldap filter string

        Keyword Args:
            attrlist: the list of attributes to return for each object

        Raises:
            ldap.INVALID_DN_SYNTAX: ``base`` was not a well-formed DN
            ldap.FILTER_ERROR: ``filterstr`` is has bad filter syntax

        Returns:
            A list of LDAP objects -- 2-tuples of ``(dn, data)``.
        """
        self.__validate_dn(base, ldap.RES_SEARCH_RESULT)
        basedn_parts = ldap.dn.explode_dn(base.lower(), flags=ldap.DN_FORMAT_LDAPV3)
        filt = None
        if not self._DEFAULT_SEARCH_RE.search(filterstr):
            filt = self.__parse_filterstr(filterstr)
        results: LDAPSearchResult = []
        for dn, data in self.objects.items():
            dn_parts = ldap.dn.explode_dn(dn.lower(), flags=ldap.DN_FORMAT_LDAPV3)
            if dn_parts[-len(basedn_parts):] != basedn_parts:
                continue
            if filt:
                if filt.match(data):
                    results.append((dn, self._filter_attributes(self.raw_objects[dn], attrlist)))
            else:
                results.append((dn, self._filter_attributes(self.raw_objects[dn], attrlist)))
        return results
