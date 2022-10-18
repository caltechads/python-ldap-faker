.. module:: ldap_faker
  :noindex:

Hooks: modifying ObjectStore behavior
=====================================

``python-ldap-faker`` provides a hook system to allow you to arbitrarily modify
behavior of :py:class:`ObjectStore`.  Primarily this is provided so that you can
emulate the behavior of the various LDAP implementations (Redhat Directory
Server, Active Directory, openldap, etc.).

You can also use hooks in your test code to produce behavior that may not be
available out of the box from ``python-ldap-faker``.

Rules about hooks:

* Hooks are run in the order they are registered
* Each hook needs a callable with a particular signature
* Hooks are global -- they apply to all :py:class:`ObjectStore` instances and
  instances instantiated (unless they are tagged hooks)

Registering hooks
-----------------

Hooks have a name and a callable signature.  Here is an example of registering a
hook to the ``pre_set`` hook, which will be run in :py:meth:`ObjectStore.set`
before the object is saved to the internal storage, and requires the callable
signature ``Callable[[ObjectStore, LDAPRecord, Optional[str]], None]``::

    from ldap_faker import hooks, ObjectStore, LDAPRecord


    def pre_set_do_something_special(store: ObjectStore, record: LDAPRecord, bind_dn: str = None) -> None:
        ...


    hooks.register('pre_set', pre_set_do_something_special)


Thereafter, whenever any code calls :py:meth:`ObjectStore.set`, this function
will be called with the store as the first argument, the record to be written as
the second argument and the ``bind_dn`` of the binding user as the third
argument.

Tagged hooks
------------

Using tags, you can register a hook that will only apply to
:py:class:`ObjectStore` instances which are themselves tagged with one of those
tags::

    from ldap_faker import hooks, ObjectStore, LDAPRecord


    def pre_set_do_something_special(store: ObjectStore, record: LDAPRecord, bind_dn: str = None) -> None:
        print(f'{bind_dn} ran pre_set_do_something_sepcial')


    hooks.register('pre_set', pre_set_do_something_special, tags=['special'])


This hook will only be executed for :py:meth:`ObjectStore` instances whose tags
include ``special``::

    >>> store = ObjectStore(tags=['special'])
    >>> obj = ('mydn', {'objectclass': [b'top']))
    >>> store.set(obj, bind_dn='auser')
    auser ran pre_set_do_something_special


It will not be executed for :py:meth:`ObjectStore` instances whose tags do not
include special::

    >>> store = ObjectStore(tags=['other'])
    >>> obj = ('mydn', {'objectclass': [b'top']))
    >>> store.set(obj, bind_dn='auser')


Tagging ObjectClass instances in LDAPFakerMixin
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using :py:class:`LDAPFakerMixin`, you can tag ``ldap_fixtures`` with particular tags.

To tag the default "server", specify the fixture as a 2-tuple, where the first element
is the filename of the fixture file, and the second element is a list of tags::

    import unittest
    from ldap_faker import LDAPFakerMixin


    class TestDefaultTaggedServer(LDAPFakerMixin, unittest.TestCase):

        ldap_modules = ['myapp']
        ldap_fixtures = ('data.json', ['special'])


To tag named "servers", you can tag individual servers by providing a 3-tuple
instad of a 2-tuple, where the third element is the list of tags::

    import unittest
    from ldap_faker import LDAPFakerMixin


    class TestDefaultTaggedServer(LDAPFakerMixin, unittest.TestCase):

        ldap_modules = ['myapp']
        ldap_fixtures = [
            ('server1.json', 'ldap://server1', ['special']),
            ('server2.json', 'ldap://server2')
        ]

Above, ``ldap://server1`` will use all hooks tagged with ``special`` in addition
to any untagged hooks, while ``ldap://server2`` will use only the untagged
hooks.

Available hooks
---------------

``pre_objectstore_init``
    Signature: ``Callable[[store: ObjectStore], None]``

    Where ``store`` is the :py:class:`ObjectStore` object.

    This will be at the end of :py:meth:`ObjectStore.__init__`.

    You can use this to set up any state you might need for later hooks by
    adding keys to :py:attr:`ObjectStore.controls`, or to add attributes to
    :py:attr:`ObjectStore.operational_attributes`.

``pre_set``
    Signature: ``Callable[[store: ObjectStore, record: LDAPRecord, bind_dn: Optional[str] = None], None]``

    Where ``store`` is the :py:class:`ObjectStore` object, ``record`` is the
    record to be ``set`` and ``bind_dn`` is the dn of the user doing the ``set``
    (possibly ``None``)

    This will be executed on :py:meth:`ObjectStore.set` before the object
    actually gets saved.

    :py:meth:`ObjectStore.set` is called for every write operation:

    * :py:meth:`ObjectStore.load_objects`
    * :py:meth:`ObjectStore.register_objects`
    * :py:meth:`ObjectStore.register_object`
    * :py:meth:`FakeLDAPObject.add_s`
    * :py:meth:`FakeLDAPObject.modify_s`
    * :py:meth:`FakeLDAPObject.delete_s`
    * :py:meth:`FakeLDAPObject.rename_s`

``post_set``
    Signature: ``Callable[[store: ObjectStore, record: LDAPRecord, bind_dn: Optional[str] = None], None]``

    Where ``store`` is the :py:class:`ObjectStore` object, ``record`` is the
    record to be ``set`` and ``bind_dn`` is the dn of the user doing the ``set``
    (possibly ``None``).

    This will be executed on :py:meth:`ObjectStore.set` after the object
    gets saved.

``pre_copy``
    Signature: ``Callable[[store: ObjectStore, dn: str], None]``

    Where ``store`` is the :py:class:`ObjectStore` object, and ``dn`` is the
    DN of the object to copy.

    This will be executed on :py:meth:`ObjectStore.copy` before the object
    actually gets retrieved from the store to be copied.

``post_copy``
    Signature: ``Callable[[store: ObjectStore, data: LDAPData], LDAPData]``

    Where ``store`` is the :py:class:`ObjectStore` object, and ``dn`` is the
    DN of the object to copy.  It should return the modified ``LDAPData`` dict.

    This will be executed on :py:meth:`ObjectStore.copy` after the object is
    retrieved from the store and :py:func:``copy.deepcopy`` has run, but before
    returning the data to the caller.

``pre_create``
    Signature: ``Callable[[store: ObjectStore, dn: str, modlist: AddModlist, bind_dn: str = None], None]``

    Where ``store`` is the :py:class:`ObjectStore` object, ``dn`` is the record
    to be created, ``modlist`` is modlist to be used for creating the record,
    and ``bind_dn`` is the dn of the user doing the ``create`` (possibly
    ``None``).

    This will be executed on :py:meth:`ObjectStore.create` before the modlist
    gets processed.

    :py:meth:`ObjectStore.create` is what actually does the work when
    :py:meth:`FakeLDAPObject.add_s` is called.

``post_create``
    Signature: ``Callable[[store: ObjectStore, record: LDAPRecord, bind_dn: Optional[str] = None], None]``

    Where ``store`` is the :py:class:`ObjectStore` object, ``record`` is the
    record to be created, and ``bind_dn`` is the dn of the user doing the
    ``create`` (possibly ``None``).

    This will be executed on :py:meth:`ObjectStore.create` after the modlist has
    processed to build the object, but before it has been writen to the data store.

``pre_update``
    Signature: ``Callable[[store: ObjectStore, dn: str, modlist: Modlist, bind_dn: str = None], None]``

    Where ``store`` is the :py:class:`ObjectStore` object, ``dn`` is the
    record to be modified`, ``modlist`` is modlist to be applied to the record,
    and ``bind_dn`` is the dn of the user doing the ``update`` (possibly ``None``).

    This will be executed on :py:meth:`ObjectStore.update` before the object
    actually gets saved.

    :py:meth:`ObjectStore.update` is what actually does the work when
    :py:meth:`FakeLDAPObject.modify_s` is called.

``post_update``
    Signature: ``Callable[[store: ObjectStore, record: LDAPRecord, bind_dn: Optional[str] = None], None]``

    Where ``store`` is the :py:class:`ObjectStore` object, ``record`` is the
    updated record and ``bind_dn`` is the dn of the user doing the ``update``
    (possibly ``None``)

    This will be executed on :py:meth:`ObjectStore.update` after the modlist has
    been applied to the object, but before it has been writen to the data store.

``pre_delete``
    Signature: ``Callable[[store: ObjectStore, record: LDAPRecord, bind_dn: Optional[str] = None], None]``

    Where ``store`` is the :py:class:`ObjectStore` object, ``record`` is the
    record to deleted, and ``bind_dn`` is the dn of the user doing the ``set``
    (possibly ``None``).

    This will be executed on :py:meth:`ObjectStore.delete` before the object
    actually gets deleted from the data store.

    :py:meth:`ObjectStore.delete` is what actually does the work when
    :py:meth:`FakeLDAPObject.delete_s` is called, and is also called
    during :py:meth:`FakeLDAPObject.rename_s` to delete the old object.

``post_delete``
    Signature: ``Callable[[store: ObjectStore, record: LDAPRecord, bind_dn: Optional[str] = None], None]``

    Where ``store`` is the :py:class:`ObjectStore` object, ``record`` is the
    record deleted, and ``bind_dn`` is the dn of the user doing the ``set``
    (possibly ``None``).

    This will be executed on :py:meth:`ObjectStore.delete` after the object
    actually gets deleted from the data store.

``pre_register_object``
    Signature: ``Callable[[store: ObjectStore, record: LDAPRecord], None]``

    Where ``store`` is the :py:class:`ObjectStore` object and ``record`` is the
    record to be registered.

    This will be executed on :py:meth:`ObjectStore.register_object` before the object
    actually gets saved.

``post_register_object``
    Signature: ``Callable[[store: ObjectStore, record: LDAPRecord], None]``

    Where ``store`` is the :py:class:`ObjectStore` object and ``record`` is the
    record that was registered.

    This will be executed on :py:meth:`ObjectStore.register_object` after the object
    gets saved.

``pre_register_objects``
    Signature: ``Callable[[store: ObjectStore, records: List[LDAPRecord]], None]``

    Where ``store`` is the :py:class:`ObjectStore` object and ``records`` is the
    list of records to be registered.

    This will be executed on :py:meth:`ObjectStore.register_objects` before the
    objects actually get saved.

``post_register_objects``
    Signature: ``Callable[[store: ObjectStore, records: List[LDAPRecord]], None]``

    Where ``store`` is the :py:class:`ObjectStore` object and ``records`` are the
    records that were registered.

    This will be executed on :py:meth:`ObjectStore.register_objects` after the
    objects get saved.

``pre_load_objects``
    Signature: ``Callable[[store: ObjectStore, filename: str], None]``

    Where ``store`` is the :py:class:`ObjectStore` object and ``filename`` is the
    name of the data file to load.

    This will be executed on :py:meth:`ObjectStore.load_objects` before the
    file gets loaded.

``post_load_objects``
    Signature: ``Callable[[store: ObjectStore, records: List[LDAPRecord]], None]``

    Where ``store`` is the :py:class:`ObjectStore` object and ``records`` are the
    records that were loaded from the file.

    This will be executed on :py:meth:`ObjectStore.load_objects` after the
    objects loaded from the file get saved.