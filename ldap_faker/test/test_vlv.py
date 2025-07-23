"""
Tests for VLV (Virtual List View) support in python-ldap-faker.
"""

import ldap
from ldap.controls import LDAPControl

from ldap_faker import FakeLDAP, LDAPServerFactory, ObjectStore


class TestVLVSupport:
    """Test VLV (Virtual List View) functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create server factory and object store
        self.factory = LDAPServerFactory()
        self.store = ObjectStore()
        self.factory.register(self.store)

        # Create LDAP faker
        self.faker = FakeLDAP(self.factory)

        # Add test data to the store
        self.store.set(
            "dc=example,dc=com",
            {
                "objectClass": [b"dcObject", b"organization"],
                "dc": [b"example"],
                "o": [b"Example Organization"],
            },
        )

        self.store.set(
            "cn=admin,dc=example,dc=com",
            {
                "objectClass": [b"person", b"simpleSecurityObject"],
                "cn": [b"admin"],
                "userPassword": [b"admin"],
            },
        )

        self.store.set(
            "uid=alice,dc=example,dc=com",
            {
                "objectClass": [b"person", b"posixAccount"],
                "uid": [b"alice"],
                "cn": [b"Alice Smith"],
            },
        )

        self.store.set(
            "uid=bob,dc=example,dc=com",
            {
                "objectClass": [b"person", b"posixAccount"],
                "uid": [b"bob"],
                "cn": [b"Bob Johnson"],
            },
        )

        self.store.set(
            "uid=charlie,dc=example,dc=com",
            {
                "objectClass": [b"person", b"posixAccount"],
                "uid": [b"charlie"],
                "cn": [b"Charlie Brown"],
            },
        )

        # Initialize connection
        self.conn = self.faker.initialize("ldap://localhost:389")
        self.conn.simple_bind_s("cn=admin,dc=example,dc=com", "admin")

    def test_vlv_basic_functionality(self):
        """Test basic VLV functionality."""
        # Test VLV control - get 1 entry before and after position 1
        vlv_value = "1,1,1".encode("utf-8")
        vlv_control = LDAPControl(
            "2.16.840.1.113730.3.4.9",
            True,
            vlv_value,
        )

        # Perform VLV search
        msgid = self.conn.search_ext(
            "dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            "(objectClass=person)",
            serverctrls=[vlv_control],
        )

        # Get results
        rtype, rdata, rmsgid, rctrls = self.conn.result3(msgid)

        # Should return 3 entries: admin (pos 0), alice (pos 1), bob (pos 2)
        assert len(rdata) == 3
        assert len(rctrls) == 2  # Original control + VLV response control

        # Check for VLV response control
        vlv_response_found = False
        for ctrl in rctrls:
            if ctrl.controlType == "2.16.840.1.113730.3.4.10":
                vlv_response_found = True
                vlv_response = ctrl.controlValue.decode("utf-8")
                parts = vlv_response.split(",")
                assert len(parts) >= 2
                target_pos = int(parts[0])
                total_count = int(parts[1])
                assert target_pos == 1
                assert total_count == 4  # admin, alice, bob, charlie
                break

        assert vlv_response_found, "VLV response control not found"

    def test_vlv_edge_cases(self):
        """Test VLV edge cases."""
        # Test VLV with target beyond available entries
        vlv_value = "1,1,10".encode("utf-8")  # Target position 10, but only 4 entries
        vlv_control = LDAPControl(
            "2.16.840.1.113730.3.4.9",
            True,
            vlv_value,
        )

        msgid = self.conn.search_ext(
            "dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            "(objectClass=person)",
            serverctrls=[vlv_control],
        )

        rtype, rdata, rmsgid, rctrls = self.conn.result3(msgid)

        # Should return 2 entries: bob (pos 2), charlie (pos 3) since target is clamped to 3
        # and we want 1 before and 1 after position 3
        assert len(rdata) == 2

        # Check VLV response control
        for ctrl in rctrls:
            if ctrl.controlType == "2.16.840.1.113730.3.4.10":
                vlv_response = ctrl.controlValue.decode("utf-8")
                parts = vlv_response.split(",")
                target_pos = int(parts[0])
                total_count = int(parts[1])
                assert target_pos == 3  # Last position (0-based)
                assert total_count == 4
                break

    def test_vlv_with_empty_result(self):
        """Test VLV with empty search result."""
        # Test VLV with filter that returns no results
        vlv_value = "1,1,0".encode("utf-8")
        vlv_control = LDAPControl(
            "2.16.840.1.113730.3.4.9",
            True,
            vlv_value,
        )

        msgid = self.conn.search_ext(
            "dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            "(objectClass=nonexistent)",
            serverctrls=[vlv_control],
        )

        rtype, rdata, rmsgid, rctrls = self.conn.result3(msgid)

        # Should return no entries
        assert len(rdata) == 0
        assert len(rctrls) == 2  # Original control + VLV response control

        # Check VLV response control
        for ctrl in rctrls:
            if ctrl.controlType == "2.16.840.1.113730.3.4.10":
                vlv_response = ctrl.controlValue.decode("utf-8")
                parts = vlv_response.split(",")
                target_pos = int(parts[0])
                total_count = int(parts[1])
                assert target_pos == 0
                assert total_count == 0
                break

    def test_vlv_root_dse_advertisement(self):
        """Test that VLV is advertised in Root DSE."""
        # Search Root DSE for supported controls
        rdata = self.conn.search_s(
            "", ldap.SCOPE_BASE, "(objectClass=*)", attrlist=["supportedControl"]
        )

        assert len(rdata) == 1
        root_dse = rdata[0][1]
        supported_controls = root_dse.get("supportedControl", [])

        # Check that VLV control is advertised
        vlv_oid = b"2.16.840.1.113730.3.4.9"
        assert vlv_oid in supported_controls, (
            f"VLV OID {vlv_oid} not found in supported controls: {supported_controls}"
        )
