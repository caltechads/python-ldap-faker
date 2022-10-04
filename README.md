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

The `FakeLDAPObject` object implements the following ldap operations:

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
