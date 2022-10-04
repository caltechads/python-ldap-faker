from __future__ import annotations
from pathlib import Path
import sys
from typing import List, Optional, cast
from unittest.mock import patch

from .db import LDAPServerFactory
from .faker import FakeLDAP
from .types import LDAPFixtureList


class LDAPFakerMixin:
    """
    This is a mixin for use with :py:class:`unittest.TestCase`.  Properly
    configured, it will patch :py:func:`ldap.initialize` to use our
    :py:meth:`FakeLDAP.initialize` fake function instead, which will
    return :py:class:`FakeLDAPObject` objects
    instead of :py:class:`ldap.ldapobject.LDAPObject` objects.

    :py:attr:`ldap_fixtures` names one or more JSON
    files containing LDAP records to load into a :py:class:`ObjectStore` via
    `:py:meth:`ObjectStore.load_objects`.  :py:attr:`ldap_fixtures`
    can be either a single string, or a list of ``Tuple[str, str]``.

    If we define our test class like so::

        class TestMyStuff(LDAPFakerMixin, unittest.TestCase):

            ldap_fixtures = 'myfixture.json'

    We will build our ``LDAPServerFactory`` with a single default
    ``ObjectStore`` with the contents of ``myfixture.json`` loaded in.

    If we define our test class like this instead::

            class TestMyStuff(LDAPFakerMixin, unittest.TestCase):

                ldap_fixtures = [
                    ('server1.json', 'ldap://server1'),
                    ('server2.json', 'ldap://read-server2'),
                ]

    we will build our :py:class:`LDAPServerFactory` with two
    :py:class:`ObjectStore` objects.  The first will have the data from
    ``server1.json`` and will be used with uri ``ldap://server1``, and the
    second will be used with uri ``ldap://server2`` and have the data from with
    the contents of ``server2.json`` loaded in.
    """

    ldap_modules: List[str] = []  #: The list of python paths to modules that import ``ldap``
    ldap_fixtures: Optional[LDAPFixtureList] = None  #: The fixture or fixtures to load into our fake LDAP servers

    def __init__(self, *args, **kwargs):
        self.server_factory: LDAPServerFactory  #: The :py:class:`LDAPServerFactory` configured by our :py:meth:`setUpClass`
        self.fake_ldap: FakeLDAP  #: the :py:class:`FakeLDAP` instance created by :py:meth:`setUp`
        self.check()
        super().__init__(*args, **kwargs)

    def check(self):
        """
        Run some sanity checks on how the user has configured us.

        :meta private:
        """
        if not self.ldap_modules:
            raise ValueError(
                'Set the "ldap_modules" class variable to the list of python paths to modules '
                'in which we will need to patch "ldap.initialize".  These should be the paths '
                'of all python files in which you see "import ldap".'
            )

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
            dirname = Path(cast(str, sys.modules[cls.__module__].__file__)).parent
            full_path = dirname / filename
        if not full_path.exists():
            raise FileNotFoundError(f'{full_path} does not exist')
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
        if not cls.ldap_fixtures:
            raise ValueError(
                'Set the "ldap_fixtures" class variable either to the name of a JSON file to use '
                'as your LDAP ObjectStore data, or to a list of (filename, ldap_uri) tuples.'
            )
        if cls.ldap_fixtures:
            if isinstance(cls.ldap_fixtures, list):
                for item in cls.ldap_fixtures:
                    filename, uri = item
                    full_path = cls.resolve_file(filename)
                    server_factory.load_from_file(full_path, uri)
            else:
                full_path = cls.resolve_file(cls.ldap_fixtures)
                server_factory.load_from_file(full_path)

    @classmethod
    def setUpClass(cls):
        """
        Build the ``LDAPServerFactory`` we'll use and save it as a class attribute.

        We do this as a classmethod because constructing our
        :py:class:`ObjectStore` objects is time consuming and we don't want to have to do it
        for each of our tests.
        """
        cls.server_factory = LDAPServerFactory()
        cls.load_servers(cls.server_factory)

    @classmethod
    def tearDownClass(cls):
        """
        Delete our :py:attr:`server_factory` so we con't corrupt future tests or leak memory.
        """
        del cls.server_factory

    def setUp(self):
        """
        Create a :py:class:`FakeLDAP` instance, make it use the
        :py:attr:`server_factory` that our :py:meth:`setUpClass` created, and
        :py:func:`patch <unittest.mock.patch>` :py:func:`ldap.initialize` in
        each of the modules named in :py:attr:`ldap_modules`.  Save the
        :py:class:`FakeLDAP` instance to our :py:attr:`fake_ldap` attribute for
        later use in our test code.
        """
        self.fake_ldap: FakeLDAP = FakeLDAP(self.server_factory)
        self.patches = []
        for mod in self.ldap_modules:
            ldap_patch = patch(f'{mod}.ldap.initialize', self.fake_ldap.initialize)
            ldap_patch.start()
            self.patches.append(ldap_patch)

    def tearDown(self):
        """
        Undo the patches we made in :py:meth:`setUp`
        """
        for ldap_patch in self.patches:
            ldap_patch.stop()
