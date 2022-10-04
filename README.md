# python-ldap-faker

This package provides a fake `python-ldap` interface that can be used for
automated testing of code that uses `python-ldap`.  

When writing tests for code that talks to an LDAP server with `python-ldap`, we
want to be able to control `python-ldap` interactions in our tests to ensure
that our own code works properly.  This may include populating the LDAP server
with fixture data, monitoring if, when and how `python-ldap` calls are made by
our code, and ensuring our code handles `python-ldap` exceptions properly.

Managing an actual LDAP server during our tests is usually out of the question,
so typically we revert to patching the `python-ldap` code to use mock objects
instead, but this is very verbose and can lead to test code errors in practice.

This package provides replacement `ldap.initialize`, `ldap.set_option` and
`ldap.get_option` functions, as well as a test-instrumented `ldap.ldapobject.LDAPObject`
replacement.

## Installation

To install from PyPI:

```shell
pip install python-ldap-faker
```

If you want, you can run the tests:

```shell
python setup.py nosetests
```

## Usage

The ``FakeLDAPObject`` class replaces the ``LDAPObject`` of the `python-ldap module.
The easiest way to use it, is to overwrite ``ldap.initialize`` to return
``MockLDAP`` instead of ``LDAPObject``. The example below uses Python 3's
Mock_ library to achieve that::

```python
    import unittest
    from unittest.mock import patch
    from ldap_faker import initialize, LDAPObjectStore

    class YourTestCase(unittest.TestCase):

        def setUpClass(self):
            # Populate the fake object store with some data
            objects = [
                (
                    'uid=foo,ou=bar,o=baz,c=country',
                    {
                        'uid': [b'foo],
                        'cn': [b'Foo Bar'],
                        'uidNumber': [b'123'],
                        'gidNumber': [b'123'],
                        'homeDirectory': [b'/home/foo'],
                        'userPassword': [b'the password'],
                        'objectclass': [
                            b'posixAccount',
                            b'top'
                        ]
                    }
                ),
                (
                    'uid=fred,ou=bar,o=baz,c=country',
                    {
                        'uid': [b'fred'],
                        'cn': [b'Fred Flintstone'],
                        'uidNumber': [b'124'],
                        'gidNumber': [b'124'],
                        'homeDirectory': [b'/home/fred'],
                        'userPassword': [b'the fredpassword'],
                        'objectclass': [
                            b'posixAccount',
                            b'top'
                        ]
                    }
                )
            ]
            for obj in objects:
                LDAPObjectStore.register_object(obj)

        def setUp(self):
            self.ldap_patcher = patch('app.module.ldap.initialize')
            self.mock_ldap = self.ldap_patcher.start()
            self.mock_ldap.return_value = _mock_ldap

        def tearDown(self):
            LDAPCallHistory.reset()
            self.ldap_patcher.stop()

        def tearDownClass(self):
            LDAPObjectStore.reset()
```

The mock ldap object implements the following ldap operations:

- add_s
- compare_s
- delete_s
- modify_s
- rename_s
- result3
- search_ext
- search_s
- simple_bind_s
- unbind_s

This is an example how to use ``MockLDAP`` with fixed return values:

```python
def test_some_ldap_group_stuff(self):
    # Define the expected return value for the ldap operation
    return_value = ("cn=testgroup,ou=group,dc=30loops,dc=net", {
        'objectClass': ['posixGroup'],
        'cn': 'testgroup',
        'gidNumber': '2030',
    })

    # Register a return value with the MockLDAP object
    _mock_ldap.set_return_value('add_s',
        ("cn=testgroup,ou=groups,dc=30loops,dc=net", (
            ('objectClass', ('posixGroup')),
            ('cn', 'testgroup'),
            ('gidNumber', '2030'))),
        (105,[], 10, []))

    # Run your actual code, this is just an example
    group_manager = GroupManager()
    result = group_manager.add("testgroup")

    # assert that the return value of your method and of the MockLDAP
    # are as expected, here using python-nose's eq() test tool:
    eq_(return_value, result)

    # Each actual ldap call your software makes gets recorded. You could
    # prepare a list of calls that you expect to be issued and compare it:
    called_records = []

    called_records.append(('simple_bind_s',
        {'who': 'cn=admin,dc=30loops,dc=net', 'cred': 'ldaptest'}))

    called_records.append(('add_s', {
        'dn': 'cn=testgroup,ou=groups,dc=30loops,dc=net",
        'record': [
            ('objectClass', ['posixGroup']),
            ('gidNumber', '2030'),
            ('cn', 'testgroup'),
            ]}))

    # And again test the expected behaviour
    eq_(called_records, _mock_ldap.ldap_methods_called_with_arguments())
```

Besides of fixing return values for specific calls, you can also imitate a full
ldap server with a directory of entries:

```python
# Create an instance of MockLDAP with a preset directory
tree = {
    "cn=admin,dc=30loops,dc=net": {
            "userPassword": "ldaptest"
    }
}
mock_ldap = MockLDAP(tree)

record = [
    ('uid', 'crito'),
    ('userPassword', 'secret'),
]
# The return value I expect when I add another record to the directory
eq_(
    (105,[],1,[]),
    mock_ldap.add_s("uid=crito,ou=people,dc=30loops,dc=net", record)
)

# The expected directory
directory = {
    "cn=admin,dc=30loops,dc=net": {"userPassword": "ldaptest"},
    "uid=crito,ou=people,dc=30loops,dc=net": {
        "uid": "crito", "userPassword": "secret"}
}
# Compare the expected directory with the MockLDAP directory
eq_(directory, mock_ldap.directory)
```

.. _Mock: http://www.voidspace.org.uk/python/mock/
