from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast
from unittest.mock import patch

from .db import LDAPServerFactory, ObjectStore
from .faker import FakeLDAP, FakeLDAPObject

if TYPE_CHECKING:
    from .types import LDAPFixtureList, LDAPOptionValue


class LDAPFakerMixin:
    """
    A mixin for use with :py:class:`unittest.TestCase`.  Properly configured, it
    will patch :py:func:`ldap.initialize` to use our
    :py:meth:`FakeLDAP.initialize` fake function instead, which will return
    :py:class:`FakeLDAPObject` objects instead of
    :py:class:`ldap.ldapobject.LDAPObject` objects.

    :py:attr:`ldap_modules` is a list of python module paths in which we should
    patch :py:func:`ldap.initialize` with our :py:meth:`FakeLDAP.initialize`
    method.  For example::

        class TestMyStuff(LDAPFakerMixin, unittest.TestCase):

            ldap_modules = ['myapp.module']

    will cause :py:class:`LDAPFakerMixin` to patch
    ``myapp.module.ldap.initialize``.

    :py:attr:`ldap_fixtures` names one or more JSON
    files containing LDAP records to load into a :py:class:`ObjectStore` via
    :py:meth:`ObjectStore.load_objects`.  :py:attr:`ldap_fixtures`
    can be either a single string, a ``Tuple[str, List[str]]``, or a list
    of ``Tuple[str, str, List[str]]``.

    If we define our test class like so::

        class TestMyStuff(LDAPFakerMixin, unittest.TestCase):

            ldap_fixtures = 'myfixture.json'

    We will build our ``LDAPServerFactory`` with a single default
    ``ObjectStore`` with the contents of ``myfixture.json`` loaded in.

    If we define our test class like so::

        class TestMyStuff(LDAPFakerMixin, unittest.TestCase):

            ldap_fixtures = ('myfixture.json', ['389'])

    We will build our ``LDAPServerFactory`` with a single default
    ``ObjectStore`` with the contents of ``myfixture.json`` loaded in,
    with the tag `389` applied to it.

    If we define our test class like this instead::

            class TestMyStuff(LDAPFakerMixin, unittest.TestCase):

                ldap_fixtures = [
                    ('server1.json', 'ldap://server1', []),
                    ('server2.json', 'ldap://read-server2', ['389']),
                ]

    we will build our :py:class:`LDAPServerFactory` with two
    :py:class:`ObjectStore` objects.  The first will have the data from
    ``server1.json`` and will be used with uri ``ldap://server1``. The
    second will be used with uri ``ldap://server2`` and have the data from with
    the contents of ``server2.json`` loaded in, and will have the tag ``389``
    applied to it.

    .. note::
        The tags are used when configuring behavior for our
        :py:class:`ObjectStore``.  The ``389`` tag tells the
        :py:class:`ObjectStore` to emulate a 389 type LDAP server (Redhat
        Directory Server).
    """

    #: The list of python paths to modules that import ``ldap``
    ldap_modules: ClassVar[list[str]] = []
    ldap_fixtures: LDAPFixtureList | None = (
        None  #: The filenames of fixtures to load into our fake LDAP servers
    )

    def __init__(self, *args, **kwargs) -> None:
        #: The :py:class:`LDAPServerFactory` configured by our :py:meth:`setUpClass`
        self.server_factory: LDAPServerFactory
        #: The :py:class:`FakeLDAP` instance created by :py:meth:`setUp`
        self.fake_ldap: FakeLDAP
        self.patches: list[Any]
        self.check()
        super().__init__(*args, **kwargs)

    def check(self):
        """
        Run some sanity checks on how the user has configured us.

        :meta private:
        """
        if not self.ldap_modules:
            msg = (
                'Set the "ldap_modules" class variable to the list of python paths '
                'to modules in which we will need to patch "ldap.initialize".  These '
                'should be the paths of all python files in which you see "import '
                'ldap".'
            )
            raise ValueError(msg)

    @classmethod
    def resolve_file(cls, filename: str) -> str:
        """
        Given ``filename``, if that filename is a non-absolute path, resolve
        that filename to an absolute path under the folder in which our
        subclass' file resides.  If ``filename`` is an absoute path, don't change
        it.

        Args:
            filename: the non-absolute file path to a fixture file

        Raises:
            FileNotFoundError: the fixture file did not exist

        Returns:
            The absolute path to the fixture file.

        """
        full_path = Path(filename)
        if not full_path.is_absolute():
            dirname = Path(cast("str", sys.modules[cls.__module__].__file__)).parent
            full_path = dirname / filename
        if not full_path.exists():
            msg = f"{full_path} does not exist"
            raise FileNotFoundError(msg)
        return str(full_path)

    @classmethod
    def load_servers(cls, server_factory: LDAPServerFactory) -> None:
        """
        Configure ``server_factory`` with one or more ``ObjectStore`` objects by
        looking at :py:attr:`ldap_fixtures`, a dict where the key is a uri and the
        value is the name of a JSON file to use as the objects for the associated
        ``ObjectStore``

        Note:
            If you want to populate your :py:class:`LDAPServerFactory` in a
            different way than loading directly from the JSON files listed in
            :py:attr:`ldap_fixtures`, this is the classmethod you want to
            override.

        Args:
            server_factory: the ``LDAPServerFactory`` object to populate

        """
        if cls.ldap_fixtures:
            if isinstance(cls.ldap_fixtures, list):
                for item in cls.ldap_fixtures:
                    filename, uri, tags = item
                    full_path = cls.resolve_file(filename)
                    server_factory.load_from_file(full_path, uri=uri, tags=tags)
            elif isinstance(cls.ldap_fixtures, tuple):
                filename, tags = cls.ldap_fixtures
                full_path = cls.resolve_file(filename)
                server_factory.load_from_file(full_path, tags=tags)
            else:
                full_path = cls.resolve_file(cls.ldap_fixtures)
                server_factory.load_from_file(full_path)
        else:
            # No servers were provided, so load a default empty ObjectStore
            server_factory.register(ObjectStore())

    @classmethod
    def setUpClass(cls):
        """
        Build the ``LDAPServerFactory`` we'll use and save it as a class attribute.

        We do this as a classmethod because constructing our
        :py:class:`ObjectStore` objects is time consuming and we don't want to
        have to do it for each of our tests.
        """
        cls.server_factory = LDAPServerFactory()
        cls.load_servers(cls.server_factory)

    @classmethod
    def tearDownClass(cls):
        """
        Delete our :py:attr:`server_factory` so we con't corrupt future tests or
        leak memory.
        """
        del cls.server_factory

    def setUp(self) -> None:
        """
        Create a :py:class:`FakeLDAP` instance, make it use the
        :py:attr:`server_factory` that our :py:meth:`setUpClass` created, and
        :py:func:`patch <unittest.mock.patch>` :py:func:`ldap.initialize` in
        each of the modules named in :py:attr:`ldap_modules`.  Save the
        :py:class:`FakeLDAP` instance to our :py:attr:`fake_ldap` attribute for
        later use in our test code.
        """
        self.fake_ldap = FakeLDAP(self.server_factory)
        self.patches = []
        for mod in self.ldap_modules:
            init_patch = patch(f"{mod}.ldap.initialize", self.fake_ldap.initialize)
            init_patch.start()
            self.patches.append(init_patch)
            set_patch = patch(f"{mod}.ldap.set_option", self.fake_ldap.set_option)
            set_patch.start()
            self.patches.append(set_patch)
            get_patch = patch(f"{mod}.ldap.get_option", self.fake_ldap.get_option)
            get_patch.start()
            self.patches.append(get_patch)

    def tearDown(self):
        """
        Undo the patches we made in :py:meth:`setUp`
        """
        for p in self.patches:
            p.stop()

    # Helpers

    def last_connection(self) -> FakeLDAPObject | None:
        """
        Return the :py:class:`FakeLDAPObject` for the last connection made
        during ourtest.  Hopefully a useful shortcut for when we only make one
        connection.

        Returns:
            The last connection made

        """
        if self.fake_ldap.connections:
            return self.fake_ldap.connections[-1]
        return None

    def get_connections(self, uri: str | None = None) -> list[FakeLDAPObject]:
        """
        Return a the list of :py:class:`FakeLDAPObject` objects generated during
        our test, optionally filtered by LDAP URI.

        Keyword Args:
            uri: the LDAP URI by which to filter our connections


        """
        if not uri:
            return self.fake_ldap.connections
        return [conn for conn in self.fake_ldap.connections if conn.uri == uri]

    # Asserts

    def assertGlobalOptionSet(self, option: int, value: LDAPOptionValue) -> None:  # noqa: N802
        """
        Assert that a global LDAP option was set.

        Args:
            option: an LDAP option (e.g. ldap.OPT_DEBUG_LEVEL)
            value: the value we expect the option to be set to

        """
        self.assertGlobalFunctionCalled("set_option")
        self.assertTrue(option in self.fake_ldap.options)  # type: ignore[attr-defined,operator]
        self.assertEqual(self.fake_ldap.options[option], value)  # type: ignore[attr-defined,operator,index]

    def assertGlobalFunctionCalled(self, api_name: str) -> None:  # noqa: N802
        """
        Assert that a global LDAP function was called.

        Args:
            api_name: the name of the function to look for (e.g. ``initialize``)

        """
        self.assertTrue(api_name in self.fake_ldap.calls.names)

    def assertLDAPConnectionOptionSet(  # noqa: N802
        self,
        conn: FakeLDAPObject,
        option: str,
        value: LDAPOptionValue,
    ) -> None:
        """
        Assert that a specific :py:class:`FakeLDAPObject` option was set with a
        specific value.

        Args:
            conn: the connection object to examine
            option: the code for the option (e.g. :py:data:`ldap.OPT_X_TLS_NEWCTX`)
            value: the value we expect the option to be set to

        """
        self.assertLDAPConnectionMethodCalled(conn, "set_option")
        self.assertTrue(option in conn.options)  # type: ignore[attr-defined,operator]
        self.assertEqual(conn.options[option], value)  # type: ignore[attr-defined,operator,index]

    def assertLDAPConnectionMethodCalled(  # noqa: N802
        self,
        conn: FakeLDAPObject,
        api_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """
        Assert that a specific :py:class:`FakeLDAPObject` method was called, possibly
        specifying the specific arguments it should have been called with.

        Args:
            conn: the connection object to examine
            api_name: the name of the function to look for (e.g. ``simple_bind_s``)

        Keyword Args:
            arguments: if given, assert that the call exists AND was called this set
                of arguments.  See :py:class:`LDAPCallRecord` for how the ``arguments``
                dict should be constructed.

        """
        if not arguments:
            self.assertNotEqual(api_name in conn.calls.names)
        for call in conn.calls.filter_calls(api_name):
            if call.args == arguments:
                return
        msg = f'No call for "{api_name}" with args {arguments} found.'
        self.fail(msg)

    def assertLDAPConnectionMethodCalledAfter(  # noqa: N802
        self, conn: FakeLDAPObject, api_name: str, target_api_name: str
    ) -> None:
        """
        Assert that a specific :py:class:`FakeLDAPObject` method was called
        after another specific :py:class:`FakeLDAPObject` method.

        Args:
            conn: the connection object to examine
            api_name: the name of the function to look for (e.g. ``simple_bind_s``)
            target_api_name: the name of the function which should appear before
                ``api_name`` in the call history

        """
        self.assertLDAPConnectionMethodCalled(conn, target_api_name)
        self.assertLDAPConnectionMethodCalled(conn, api_name)
        api_names = conn.calls.names
        self.assertTrue(api_names.index(api_name) > api_names.index(target_api_name))
        self.assertNotEqual(api_name in conn.calls.names)
