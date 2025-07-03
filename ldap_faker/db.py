from __future__ import annotations

import json
import re
import warnings
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import ldap
from ldap_filter import Filter  # type: ignore[reportUnknownVariableType]
from ldap_filter.parser import ParseError

from .hooks import hooks
from .types import (
    AddModList,
    Attrlist,
    CILDAPData,
    LDAPData,
    LDAPObjectStore,
    LDAPOptionStore,
    LDAPOptionValue,
    LDAPRecord,
    LDAPSearchResult,
    ModList,
    RawLDAPObjectStore,
)


@dataclass
class LDAPCallRecord:
    """
    A single LDAP call record, used by :py:class:`CallHistory` to store
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
    args: dict[str, Any]  #: the args and kwargs dict


class LDAPServerFactory:
    """
    Registers :py:class:`ObjectStore` objects to be used by
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
        version of that function, it will get a a :py:class:`FakeLDAPObject`
        configured with a :py:func:`copy.deepcopy` of the
        :py:class:`ObjectStore` ``store``, no matter what ``uri`` it passes to
        ``ldap.initialize()``.

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
        a :py:class:`FakeLDAPObject` configured with a :py:func:`copy.deepcopy`
        of the :py:class:`ObjectStore` object ``store1``, while if it does
        ``ldap.initialize('ldap://server2' )``, it will get a
        :py:class:`FakeLDAPObject` configured with a :py:func:`copy.deepcopy` of
        the :py:class:`ObjectStore` object ``store2``.

    """

    def __init__(self) -> None:
        self.servers: dict[str, ObjectStore] = {}
        self.default: ObjectStore | None = None

    def load_from_file(
        self, filename: str, uri: str | None = None, tags: list[str] | None = None
    ) -> None:
        """
        Given a file path to a JSON file with the objects for an
        :py:class:`ObjectStore`, create a new :py:class:`ObjectStore`, load it
        with that JSON File and register it with uri of ``uri``.

        Args:
            filename: the full path to our JSON file

        Keyword Args:
            uri: the uri to assign to the :py:class:`ObjectStore` we create
            tags: the list of tags to apply to the the :py:class:`ObjectStore`

        Raises:
            ValueError: raised if a default is already configured while trying to
                register the :py:class:`ObjectStore` with a specific ``uri``
            RuntimeWarning: raised if we try to overwrite an already registered object
                store with our new one

        """
        if not tags:
            tags = []
        store = ObjectStore(tags=tags)
        store.load_objects(filename)
        self.register(store, uri=uri)

    def register(self, store: ObjectStore, uri: str | None = None) -> None:
        """
        Register a new :py:class:`ObjectStore` to be used as our fake LDAP
        server for when we run our  fake ``initialize`` function.

        Args:
            store: a configured :py:class:`ObjectStore`

        Keyword Args:
            uri: the LDAP uri to associated with ``directory``

        Raises:
            ValueError: raised if a default is already configured while trying to
                register an :py:class:`ObjectStore` with a specific ``uri``
            RuntimeWarning: raised if we try to overwrite an already registered object
                store with a new one

        """
        if uri and self.default is not None:
            msg = (
                f'You cannot regster an ObjectStore for uri="{uri}" because '
                "a default server has already been set"
            )
            raise ValueError(msg)
        if not uri:
            if self.default is not None:
                warnings.warn(
                    "LDAPServerFactory: overriding existing default ObjectStore",
                    RuntimeWarning,
                    stacklevel=2,
                )
            self.default = store
        if uri in self.servers:
            warnings.warn(
                f"LDAPServerFactory: overriding existing ObjectStore for uri={uri}",
                RuntimeWarning,
                stacklevel=2,
            )
        self.servers[cast("str", uri)] = store

    def get(self, uri: str) -> ObjectStore:
        """
        Return a :py:func:`copy.deepcopy` of the :py:class:`ObjectStore`
        identified by ``uri``.

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
            raise ldap.SERVER_DOWN({"desc": "Can't contact LDAP Server"}) from exc  # type: ignore[attr-defined]


class CallHistory:
    """
    Records the ``python-ldap`` call history for a particular
    :py:class:`FakeLDAPObject` as :py:class:`LDAPCallRecord` objects.  It works
    in conjunction with the ``@record_call`` decorator.  An
    :py:class:`CallHistory` object will be configured on each
    :py:class:`FakeLDAPObject` and on each :py:class:`FakeLDAP` object capture
    their call history.

    We use this in our tests with appropriate asserts to ensure that our code
    called the ``python-ldap`` methods we expected, in the order we expected,
    with the arguments we expected.
    """

    def __init__(self, calls: list[LDAPCallRecord] | None = None):
        self._calls: list[LDAPCallRecord] = []
        if calls:
            self._calls = calls

    def register(self, api_name: str, arguments: dict[str, Any]) -> None:
        """
        Register a new call record.  This is used by the ``@record_call``
        decorator to register :py:class:`FakeLDAPObject` method calls.

        Args:
            api_name: the name of the function or method called
            arguments: a dict where the keys are argument names, and the values
                are passed in values for those arguments

        :meta private:

        """
        self._calls.append(LDAPCallRecord(api_name, arguments))

    def filter_calls(self, api_name: str) -> list[LDAPCallRecord]:
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
    def calls(self) -> list[LDAPCallRecord]:
        """
        Returns the list of all calls made against the parent object.

        Example:
            To test that your code did a :py:func:`ldap.simple_bind_s` call with
            the usernam and password you expected, you could do::

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

        """  # noqa: E501
        return self._calls

    @property
    def names(self) -> list[str]:
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

    def __init__(self) -> None:
        self.options: LDAPOptionStore = {}

    def set(self, option: int, invalue: LDAPOptionValue) -> None:
        """
        Set an option.

        Args:
            option: the code for the option (e.g. :py:data:`ldap.OPT_X_TLS_NEWCTX`)
            invalue: the value we want the option to be set to

        Raises:
            ValueError: ``option`` is not a valid ``python-ldap`` option

        """
        if option not in ldap.OPT_NAMES_DICT:  # type: ignore[reportUnknownVariableType]
            msg = f"unknown option {option}"
            raise ValueError(msg)
        self.options[option] = invalue

    def get(self, option: int) -> LDAPOptionValue | dict[str, int | str]:
        """
        Get the value for a previosly set option that was set via
        :py:meth:`OptionStore.set`.

        Args:
            option: the code for the option (e.g. :py:data:`ldap.OPT_X_TLS_NEWCTX`)

        Raises:
            ValueError: ``option`` is not a valid ``python-ldap`` option

        Returns:
            The value for the option, or the default.

        """
        if option not in ldap.OPT_NAMES_DICT:  # type: ignore[reportUnknownVariableType]
            msg = f"unknown option {option}"
            raise ValueError(msg)
        if option in (ldap.OPT_API_INFO, ldap.OPT_SUCCESS):  # type: ignore[attr-defined]
            # Even though we declare the output as "int | str", openldap at
            # least returns a dict for this
            return {
                "info_version": 1,
                "api_version": 3001,
                "vendor_name": "python-ldap-faker",
                "vendor_version": "1.0.0",
            }
        if option == ldap.OPT_PROTOCOL_VERSION:  # type: ignore[attr-defined]
            return 3
        return self.options[option]


class ObjectStore:
    """
    Represents our actual simulated LDAP object store.  Copies of this
    will be used to configure :py:class:`FakeLDAPObject` objects.
    """

    _QUERY_RE: re.Pattern[str] = re.compile(r"\(\w+=.+\)$")
    _DEFAULT_SEARCH_RE: re.Pattern[str] = re.compile(
        r"^\(objectclass=*\)$", re.IGNORECASE
    )

    def __init__(self, tags: list[str] | None = None):
        # raw_objects preserves the object attribute case as it was given to us
        # by register_object, and retains the values as List[bytes]
        self.raw_objects: RawLDAPObjectStore = (
            RawLDAPObjectStore()
        )  #: LDAP records as they would have been returned by ``python-ldap```
        # objects has the same data as raw_objects, but here we forces the
        # attribute names on each object to be case insensitive, and we convert
        # values to List[str].  We need that because in LDAP searches, attribute
        # names and values are compared as case-insensitive, and Filter.match()
        # expects the filter and values to be strings
        self.objects: LDAPObjectStore = (
            LDAPObjectStore()
        )  #: LDAP records set up to make searching better
        self.tags: list[str] = (
            tags if tags is not None else []
        )  #: used when filtering hooks to apply
        self.controls: dict[str, Any] = {}  #: can be used by hooks to store state
        self.operational_attributes: set[str] = (
            set()
        )  #: list of attributes that have to be specifically requested
        for hook_func in hooks.get("post_objectstore_init", self.tags):  # type: ignore[reportUnknownVariableType]
            hook_func(self)

    def convert_LDAPData(self, data: LDAPData) -> CILDAPData:  # noqa: N802
        """
        Convert an incoming ``LDAPData` dict (``Dict[str, List[bytes]``])
        to a ``CILDAPData`` dict (``CaseInsensitiveDict[str, List[str]])``)

        We need the data dict to have values as ``List[str]`` so that our
        filtering works properly -- ``ldap_filter.Filter.match`` only works with
        strings, not bytes.

        Args:
            data: the LDAPData dict to convert

        Returns:
            The convered CILDAPData dict.

        """
        # We need self.objects to be a case insensitive Dict[str, List[str]]
        # so that filtering works like it would in a real ldap serverindee
        d: dict[str, Any] = deepcopy(data)
        for key, value in d.items():
            d[key] = [v.decode("utf8") for v in value]
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
            by ``python-ldap`` are of type ``tuple[str, dict[str,
            list[bytes]]]`` but JSON has no concept of ``bytes`` or ``tuple``.
            Thus we will expect the LDAP records in the file to have type
            ``list[str, dict[str, list[str]]]`` and we will convert them to
            ``tuple[str, dict[str, list[bytes]]]`` before saving to
            :py:attr:`raw_objects`

        Args:
            filename: the path to the JSON file to load

        Raises:
            ldap.ALREADY_EXISTS: there is already an object in our object store
                with this dn
            ldap.INVALID_DN_SYNTAX: one of the object DNs is not well formed

        """
        for hook_func in hooks.get("pre_load_objects", self.tags):
            hook_func(self, filename)
        with Path(filename).open(encoding="utf-8") as fd:
            objects = json.load(fd)
        for obj in objects:
            dn, data = obj
            new_data: LDAPData = {}
            for attr, value in data.items():
                new_data[attr] = [entry.encode("utf-8") for entry in value]
            self.register_object((dn, new_data))
        for hook_func in hooks.get("post_load_objects", self.tags):
            hook_func(self)

    def register_objects(self, objs: list[LDAPRecord]) -> None:
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
            TypeError: the LDAPData portion for an object was not of type
            ``Dict[str, List[bytes]]``

        """
        for hook_func in hooks.get("pre_register_objects", self.tags):
            hook_func(self, objs)
        for obj in objs:
            self.register_object(obj)
        for hook_func in hooks.get("post_register_objects", self.tags):
            hook_func(self)

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
            TypeError: the LDAPData portion was not of type ``dict[str, list[bytes]]``

        """
        for hook_func in hooks.get("pre_register_object", self.tags):
            hook_func(self, obj)
        if self.exists(obj[0]):
            raise ldap.ALREADY_EXISTS({"desc": "Object already exists"})  # type: ignore[attr-defined]
        self.set(obj[0], obj[1])
        for hook_func in hooks.get("post_register_object", self.tags):
            hook_func(self, obj)

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
        return bool(self._DEFAULT_SEARCH_RE.search(filterstr))

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
                msg = (
                    f"('Tuple_to_LDAPMod(): expected a byte string in the list', '{v}')"
                )
                raise TypeError(msg)

    def __validate_dn(self, dn: str, operation: int = ldap.RES_ANY) -> None:  # type: ignore[attr-defined]
        """
        Validate that ``dn`` is a well formed DN.

        Args:
            dn: the DN to validate

        Keyword Args:
            operation: the ``msgtype`` to set on the exception

        Raises:
            ldap.INVALID_DN_SYNTAX: the dn was not well-formed

        """
        if not ldap.dn.is_dn(dn):  # type: ignore[attr-defined]
            raise ldap.INVALID_DN_SYNTAX(  # type: ignore[attr-defined]
                {
                    "msgtype": operation,
                    "msgid": 3,
                    "result": 34,
                    "desc": "Invalid DN syntax",
                    "ctrls": [],
                    "info": "DN value invalid per syntax\n",
                }
            )

    def __validate_LDAPRecord(self, obj: LDAPRecord) -> None:  # noqa: N802
        dn, data = obj
        self.__validate_dn(dn)
        for attr, value in data.items():
            if not isinstance(attr, str):
                msg = f"attributes must be of type str: '{attr!r}'"
                raise TypeError(msg)
            if not isinstance(value, list):
                msg = f"values nust be of type List[bytes]: '{value!r}'"
                raise TypeError(msg)
            for v in value:
                if not isinstance(v, bytes):
                    msg = f"values nust be of type List[bytes]: '{v!r}'"
                    raise TypeError(msg)

    def __parse_filterstr(self, filterstr: str) -> Any:
        try:
            filt = Filter.parse(filterstr)
        except ParseError as exc:
            raise ldap.FILTER_ERROR(  # type: ignore[attr-defined]
                {
                    "result": -7,
                    "desc": "Bad search filter",
                    "errno": 35,
                    "ctrls": [],
                    "info": "Resource temporarily unavailable",
                }
            ) from exc
        return filt

    def __filter_attributes(
        self,
        obj: LDAPData,
        attrlist: list[str] | None = None,
        include_operational_attributes: bool = False,
    ) -> LDAPData:
        """
        Return just the attributes on ``obj`` named in ``attrlist``.   If
        ``attrlist`` is ``None`` or "``*``"  is in ``attrlist``, return all
        attributes on ``obj``.

        Any attribute named in :py:attr:`operational_attributes` will be omitted
        unless specifically named ``attrlist``.

        Note:
            We return a :py:func:`copy.deepcopy` of the object, not the actual
            object.  This ensures that if the caller modifies the object they
            don't update the objects in us unintentionally.

        Args:
            obj: the data for an LDAP object

        Keyword Args:
            attrlist: a list of attributes to include on ``obj``, removing
                attributes not named
            include_operational_attributes: include all operational attributes
                even if they weren't requested in ``attrlist``

        Returns:
            A filtered version of ``obj`` with only the attributes named in
            ``attrlist``, omitting the operational attributes unless specifically
            requested.

        """
        if not attrlist:
            attrlist = ["*"]
        obj_attrs = set()
        if attrlist and "*" in attrlist:
            obj_attrs = set(obj.keys())
            if not include_operational_attributes:
                obj_attrs -= self.operational_attributes
        if attrlist:
            obj_attrs.update({attr for attr in attrlist if attr != "*"})
        _obj_attrs: Attrlist = Attrlist()
        for attr in obj_attrs:
            _obj_attrs[attr] = attr
        return {
            _obj_attrs[attr]: deepcopy(value)
            for attr, value in obj.items()
            if attr in _obj_attrs
        }

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
            self.__validate_dn(dn, ldap.RES_SEARCH_ENTRY)  # type: ignore[attr-defined]
        return dn in self.objects

    def get(self, dn: str) -> LDAPData:
        """
        Return all data for an object from our object store.

        Args:
            dn: the dn of the object to copy.

        Raises:
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our object store

        Returns:
            The data for an LDAP object

        """
        self.__validate_dn(dn, ldap.RES_SEARCH_ENTRY)  # type: ignore[attr-defined]
        try:
            return self.raw_objects[dn]
        except KeyError as exc:
            raise ldap.NO_SUCH_OBJECT(  # type: ignore[attr-defined]
                {
                    "msgtype": 101,
                    "msgid": 4,
                    "result": 32,
                    "desc": "No such object",
                    "ctrls": [],
                }
            ) from exc

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
        self.__validate_dn(dn, ldap.RES_SEARCH_ENTRY)  # type: ignore[attr-defined]
        for hook_func in hooks.get("pre_copy", self.tags):
            hook_func(self, dn)
        data = deepcopy(self.get(dn))
        for hook_func in hooks.get("post_copy", self.tags):
            data = hook_func(self, data)
        return data

    def _set(self, dn: str, data: LDAPData) -> None:
        """
        Add or update data for the object with dn ``dn``.  This differs
        from :py:meth:`set` in that no hooks will be applied.

        Args:
            dn: the dn of the object to copy.
            data: the dict of data for this object

        Raises:
            ldap.INVALID_DN_SYNTAX: the DN is not well formed
            TypeError: the LDAPData portion was not of type ``Dict[str, List[bytes]]``

        """
        self.__validate_LDAPRecord((dn, data))
        self.raw_objects[dn] = data
        self.objects[dn] = self.convert_LDAPData(data)

    def set(self, dn: str, data: LDAPData, bind_dn: str | None = None) -> None:
        """
        Add or update data for the object with dn ``dn``.

        Args:
            dn: the dn of the object to copy.
            data: the dict of data for this object

        Keyword Args:
            bind_dn: the dn of the user doing the set, if any

        Raises:
            ldap.INVALID_DN_SYNTAX: the DN is not well formed
            TypeError: the LDAPData portion was not of type ``Dict[str, List[bytes]]``

        """
        self.__validate_LDAPRecord((dn, data))
        for hook_func in hooks.get("pre_set", self.tags):
            hook_func(self, (dn, data), bind_dn)
        self._set(dn, data)
        self.raw_objects[dn] = data
        self.objects[dn] = self.convert_LDAPData(data)
        for hook_func in hooks.get("post_set", self.tags):
            hook_func(self, (dn, data), bind_dn)

    def update(self, dn: str, modlist: ModList, bind_dn: str | None = None) -> None:  # noqa: PLR0912
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

        Keyword Args:
            bind_dn: the dn of the user doing the update, if any

        Raises:
            ldap.INVALID_DN_SYNTAX: the dn was not well-formed
            ldap.NO_SUCH_OBJECT: no object with dn of ``dn`` exists in our
                object store
            ldap.TYPE_OR_VALUE_EXISTS: you tried to add an value to an
                attribute, but it was already in the value list
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before
                doing this

        """

        def get_overlaps(source: list[bytes], other: list[bytes]) -> set[bytes]:
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

        self.__validate_dn(dn, ldap.RES_MODIFY)  # type: ignore[attr-defined]
        for hook_func in hooks.get("pre_update", self.tags):
            hook_func(self, dn, modlist, bind_dn)
        # We want to use a deepcopy of our data here so we don't act directly
        # on the data in the store before we do our self.set(); something may
        # go wrong partway through the update (e.g. bad opcode) and we don't
        # want partial updates to be reflected.
        # may need to look at what the object used to look like in a "pre_set"
        # hook.

        # We can't use self.copy(dn) here, because hooks may muck with the data
        # returned, thus this:
        obj = deepcopy(self.get(dn))
        for item in modlist:
            op, key, value = item
            if op not in (ldap.MOD_ADD, ldap.MOD_DELETE, ldap.MOD_REPLACE):  # type: ignore[attr-defined]
                raise ldap.PROTOCOL_ERROR(  # type: ignore[attr-defined]
                    {
                        "msgtype": ldap.RES_MODIFY,  # type: ignore[attr-defined]
                        "msgid": 4,
                        "result": 2,
                        "desc": "Protocol error",
                        "info": "unrecognized modify operation",
                        "ctrls": [],
                    }
                )
            if op == ldap.MOD_ADD:  # type: ignore[attr-defined]
                self.__check_bytes(value)
                if key not in obj:
                    obj[key] = value
                else:
                    # Enforce case-insensitive uniqueness in the value list
                    overlaps = get_overlaps(obj[key], value)
                    if not overlaps:
                        obj[key].extend(value)
                    else:
                        raise ldap.TYPE_OR_VALUE_EXISTS(  # type: ignore[attr-defined]
                            {
                                "msgtype": ldap.RES_MODIFY,  # type: ignore[attr-defined]
                                "msgid": 4,
                                "result": 20,
                                "desc": "Type or value exists",
                                "ctrls": [],
                            }
                        )
            elif op == ldap.MOD_DELETE:  # type: ignore[attr-defined]
                if value is None:
                    # If value was None, delete the whole attribute
                    del obj[key]
                else:
                    # otherwise just remove the values from value from obj[key]
                    self.__check_bytes(value)
                    overlaps = get_overlaps(obj[key], value)
                    obj[key] = [v for v in obj[key] if v.lower() not in overlaps]
            elif op == ldap.MOD_REPLACE:  # type: ignore[attr-defined]
                self.__check_bytes(value)
                obj[key] = value
        self.set(dn, obj, bind_dn=bind_dn)
        for hook_func in hooks.get("post_update", self.tags):
            hook_func(self, obj, bind_dn)

    def create(self, dn: str, modlist: AddModList, bind_dn: str | None = None) -> None:
        """
        Create an object in our store with dn of ``dn``.

        ``modlist`` is similar the one passed to :py:meth:`modify_s`, except
        that the operation integer is omitted from the tuples in ``modlist``.
        You might want to look into sub-module ldap.modlist for generating the
        modlist.

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

        Keyword Args:
            bind_dn: the dn of the user doing the create, if any

        Raises:
            ldap.INVALID_DN_SYNTAX: the dn was not well-formed
            ldap.ALREADY_EXISTS: an object with dn of ``dn`` already exists in
                our object store
            ldap.INSUFFICIENT_ACCESS: you need to do a non-anonymous bind before
                doing this

        """
        self.__validate_dn(dn, ldap.RES_ADD)  # type: ignore[attr-defined]
        for hook_func in hooks.get("pre_create", self.tags):
            hook_func(self, dn, modlist, bind_dn)
        if self.exists(dn):
            # TODO: probably this error dict is not complete
            raise ldap.ALREADY_EXISTS(  # type: ignore[attr-defined]
                {"info": "", "desc": "Object already exists"}
            )
        entry = {}
        for item in modlist:
            attr, value = item
            if not isinstance(attr, str):
                msg = f"Tuple_to_LDAPMod() argument 1 must be str, not {type(attr)}"
                raise TypeError(msg)
            self.__check_bytes(value)
            entry[attr] = value
        self.set(dn, entry, bind_dn=bind_dn)
        for hook_func in hooks.get("post_create", self.tags):
            hook_func(self, (dn, entry), bind_dn)

    def delete(self, dn: str, bind_dn: str | None = None) -> None:
        """
        Delete an object from our objects directory.

        Args:
            dn: the dn of the object to delete

        Keyword Args:
            bind_dn: the dn of the user doing the delete, if any

        Raises:
            ldap.INVALID_DN_SYNTAX: the dn was not well-formed

        """
        self.__validate_dn(dn, ldap.RES_DELETE)  # type: ignore[attr-defined]
        if not self.exists(dn):
            raise ldap.NO_SUCH_OBJECT(  # type: ignore[attr-defined]
                {
                    "msgtype": 101,
                    "msgid": 4,
                    "result": 32,
                    "desc": "No such object",
                    "ctrls": [],
                }
            )
        obj = self.copy(dn)
        for hook_func in hooks.get("pre_delete", self.tags):
            hook_func(self, (dn, obj), bind_dn=bind_dn)
        del self.objects[dn]
        del self.raw_objects[dn]
        for hook_func in hooks.get("post_delete", self.tags):
            hook_func(self, (dn, obj), bind_dn=bind_dn)

    def search_base(
        self,
        base: str,
        filterstr: str,
        attrlist: list[str] | None = None,
    ) -> LDAPSearchResult:
        """
        Do a :py:data:`ldap.SCOPE_BASE` search.  Return the requested attributes
        of the object in our object store with ``dn`` of ``base`` that also
        matches ``filterstr``.

        Note:
            We return a :py:func:`copy.deepcopy` of the object, not the actual
            object.  This ensures that if the caller modifies the object they
            don't update the objects in us unintentionally.

        Note:
            Some attributes are "operational" and are not returned by default
            They must be named specifically if you want them.  Example:

            >>> store.search_base(
            'thebasedn', '(objectclass=*)', ['*', 'createTimestamp'])

        Args:
            base: the dn of the object to return
            filterstr: the ldap filter string

        Keyword Args:
            attrlist: the list of attributes to return for each object

        Raises:
            ldap.INVALID_DN_SYNTAX: ``base`` was not a well-formed DN
            ldap.FILTER_ERROR: ``filterstr`` is has bad filter syntax
            ldap.NO_SUCH_OBJECT: no object with dn of ``base`` exists in the
                object store

        Returns:
            A list with one element -- the object with dn of ``base``.

        """
        self.__validate_dn(base, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
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
                results.append((base, self.__filter_attributes(data, attrlist)))
        else:
            results.append((base, self.__filter_attributes(data, attrlist)))
        return results

    def search_onelevel(
        self,
        base: str,
        filterstr: str,
        attrlist: list[str] | None = None,
    ) -> LDAPSearchResult:
        """
        Do a :py:data:`ldap.SCOPE_ONELEVEL` search, for objects directly under
        basedn ``base`` that match ``filterstr``.

        Note:
            We return a :py:func:`copy.deepcopy` of each object, not the actual
            object.  This ensures that if the caller modifies the object they
            don't update the objects in us unintentionally.

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
        self.__validate_dn(base, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        basedn_parts = ldap.dn.explode_dn(base.lower(), flags=ldap.DN_FORMAT_LDAPV3)  # type: ignore[attr-defined]
        filt = None
        if not self._DEFAULT_SEARCH_RE.search(filterstr):
            filt = self.__parse_filterstr(filterstr)
        results: LDAPSearchResult = []
        for dn, data in self.objects.items():
            dn_parts = ldap.dn.explode_dn(dn.lower(), flags=ldap.DN_FORMAT_LDAPV3)  # type: ignore[attr-defined]
            if dn_parts[1:] != basedn_parts:
                continue
            if filt:
                if filt.match(data):
                    results.append(
                        (dn, self.__filter_attributes(self.raw_objects[dn], attrlist))
                    )
            else:
                results.append(
                    (dn, self.__filter_attributes(self.raw_objects[dn], attrlist))
                )
        return results

    def search_subtree(
        self,
        base: str,
        filterstr: str,
        attrlist: list[str] | None = None,
        include_operational_attributes: bool = False,
    ) -> LDAPSearchResult:
        """
        Do a :py:data:`ldap.SCOPE_SUBTREE` search, for objects under basedn
        ``base`` that match ``filterstr``.

        Args:
            base: the dn of the object to return
            filterstr: the ldap filter string

        Note:
            We return a :py:func:`copy.deepcopy` of each object, not the actual
            object.  This ensures that if the caller modifies the object they
            don't update the objects in us unintentionally.

        Keyword Args:
            attrlist: the list of attributes to return for each object
            include_operational_attributes: include all operational attributes even
                if they are not named in ``attrlist``

        Raises:
            ldap.INVALID_DN_SYNTAX: ``base`` was not a well-formed DN
            ldap.FILTER_ERROR: ``filterstr`` is has bad filter syntax

        Returns:
            A list of LDAP objects -- 2-tuples of ``(dn, data)``.

        """
        self.__validate_dn(base, ldap.RES_SEARCH_RESULT)  # type: ignore[attr-defined]
        basedn_parts = ldap.dn.explode_dn(base.lower(), flags=ldap.DN_FORMAT_LDAPV3)  # type: ignore[attr-defined]

        filt = None
        if not self._DEFAULT_SEARCH_RE.search(filterstr):
            filt = self.__parse_filterstr(filterstr)
        results: LDAPSearchResult = []
        for dn, data in self.objects.items():
            if basedn_parts:
                # ``base`` was not the Root DN, so see if the object is under ``base``
                dn_parts = ldap.dn.explode_dn(dn.lower(), flags=ldap.DN_FORMAT_LDAPV3)  # type: ignore[attr-defined]
                if dn_parts[-len(basedn_parts) :] != basedn_parts:
                    continue
            if filt:
                if filt.match(data):
                    results.append(
                        (
                            dn,
                            self.__filter_attributes(
                                self.raw_objects[dn],
                                attrlist,
                                include_operational_attributes=include_operational_attributes,
                            ),
                        )
                    )
            else:
                results.append(
                    (
                        dn,
                        self.__filter_attributes(
                            self.raw_objects[dn],
                            attrlist,
                            include_operational_attributes=include_operational_attributes,
                        ),
                    )
                )
        return results
