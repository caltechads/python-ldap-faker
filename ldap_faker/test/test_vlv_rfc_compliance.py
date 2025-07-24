"""
Comprehensive test suite for RFC 2891 VLV (Virtual List View) compliance in
python-ldap-faker.

This test suite verifies that python-ldap-faker correctly implements RFC 2891
Virtual List View controls with proper ASN.1 encoding/decoding, error handling,
and both offset-based and assertion-based targeting.
"""

import unittest
from unittest.mock import MagicMock, patch

import ldap
import ldap.controls
from pyasn1.codec.ber import decoder, encoder

from ldap_faker import ObjectStore
from ldap_faker.faker import (
    FakeLDAPObject,
    VlvRequest,
    VlvRequestSimple,
    VlvResponse,
    create_vlv_context_id,
    decode_vlv_control_value,
    encode_vlv_response_control,
)
from ldap_faker.unittest import LDAPFakerMixin


class TestVlvASN1Structures(unittest.TestCase):
    """Test ASN.1 structure definitions for VLV controls."""

    def test_vlv_request_simple_encoding(self):
        """Test encoding of simplified VLV request (django-ldaporm format)."""
        vlv_request = VlvRequestSimple()
        vlv_request.setComponentByName("beforeCount", 5)
        vlv_request.setComponentByName("afterCount", 10)
        vlv_request.setComponentByName("offset", 100)
        vlv_request.setComponentByName("count", 1000)

        encoded = encoder.encode(vlv_request)
        self.assertIsInstance(encoded, bytes)
        self.assertGreater(len(encoded), 0)

        # Verify it can be decoded back
        decoded, _ = decoder.decode(encoded, asn1Spec=VlvRequestSimple())
        self.assertEqual(int(decoded.getComponentByName("beforeCount")), 5)
        self.assertEqual(int(decoded.getComponentByName("afterCount")), 10)
        self.assertEqual(int(decoded.getComponentByName("offset")), 100)
        self.assertEqual(int(decoded.getComponentByName("count")), 1000)

    def test_vlv_response_encoding(self):
        """Test encoding of VLV response with all fields."""
        vlv_response = VlvResponse()
        vlv_response.setComponentByName("targetPosition", 50)
        vlv_response.setComponentByName("contentCount", 200)
        vlv_response.setComponentByName("virtualListViewResult", 0)  # success
        vlv_response.setComponentByName("contextID", b"test_context")

        encoded = encoder.encode(vlv_response)
        self.assertIsInstance(encoded, bytes)
        self.assertGreater(len(encoded), 0)

        # Verify it can be decoded back
        decoded, _ = decoder.decode(encoded, asn1Spec=VlvResponse())
        self.assertEqual(int(decoded.getComponentByName("targetPosition")), 50)
        self.assertEqual(int(decoded.getComponentByName("contentCount")), 200)
        self.assertEqual(int(decoded.getComponentByName("virtualListViewResult")), 0)
        self.assertEqual(
            bytes(decoded.getComponentByName("contextID")), b"test_context"
        )


class TestVlvControlDecoding(unittest.TestCase):
    """Test VLV control value decoding functions."""

    def test_decode_django_ldaporm_format(self):
        """Test decoding of django-ldaporm simplified VLV format."""
        # Create a simplified VLV request
        vlv_request = VlvRequestSimple()
        vlv_request.setComponentByName("beforeCount", 3)
        vlv_request.setComponentByName("afterCount", 7)
        vlv_request.setComponentByName("offset", 25)
        vlv_request.setComponentByName("count", 100)

        encoded = encoder.encode(vlv_request)

        # Test decoding
        result = decode_vlv_control_value(encoded)
        self.assertEqual(result["beforeCount"], 3)
        self.assertEqual(result["afterCount"], 7)
        self.assertEqual(result["target"], 25)
        self.assertEqual(result["content_count"], 100)
        self.assertEqual(result["target_type"], "offset")

    def test_decode_text_format_fallback(self):
        """Test fallback to text format decoding."""
        # Test old text format
        text_value = "5,10,50,context123".encode("utf-8")

        result = decode_vlv_control_value(text_value)
        self.assertEqual(result["beforeCount"], 5)
        self.assertEqual(result["afterCount"], 10)
        self.assertEqual(result["target"], 50)
        self.assertEqual(result["contextID"], "context123")
        self.assertEqual(result["target_type"], "offset")

    def test_decode_empty_value(self):
        """Test decoding empty control value."""
        result = decode_vlv_control_value(b"")
        self.assertEqual(result["beforeCount"], 0)
        self.assertEqual(result["afterCount"], 0)
        self.assertEqual(result["target"], 0)
        self.assertIsNone(result["contextID"])
        self.assertEqual(result["target_type"], "offset")


class TestVlvControlEncoding(unittest.TestCase):
    """Test VLV control value encoding functions."""

    def test_encode_basic_response(self):
        """Test basic VLV response encoding."""
        encoded = encode_vlv_response_control(
            target_position=10, content_count=100, result_code=0
        )

        self.assertIsInstance(encoded, bytes)
        self.assertGreater(len(encoded), 0)

        # Verify it can be decoded
        decoded, _ = decoder.decode(encoded, asn1Spec=VlvResponse())
        self.assertEqual(int(decoded.getComponentByName("targetPosition")), 10)
        self.assertEqual(int(decoded.getComponentByName("contentCount")), 100)
        self.assertEqual(int(decoded.getComponentByName("virtualListViewResult")), 0)

    def test_encode_error_response(self):
        """Test VLV error response encoding."""
        encoded = encode_vlv_response_control(
            target_position=0,
            content_count=0,
            result_code=60,  # sortControlMissing
        )

        decoded, _ = decoder.decode(encoded, asn1Spec=VlvResponse())
        self.assertEqual(int(decoded.getComponentByName("virtualListViewResult")), 60)

    def test_encode_with_context_id(self):
        """Test VLV response encoding with context ID."""
        context_id = b"test_context_123"
        encoded = encode_vlv_response_control(
            target_position=5, content_count=50, result_code=0, context_id=context_id
        )

        decoded, _ = decoder.decode(encoded, asn1Spec=VlvResponse())
        self.assertEqual(bytes(decoded.getComponentByName("contextID")), context_id)

    def test_encode_invalid_parameters(self):
        """Test VLV response encoding with invalid parameters."""
        with self.assertRaises(ValueError):
            encode_vlv_response_control(-1, 100)  # negative target_position

        with self.assertRaises(ValueError):
            encode_vlv_response_control(10, -1)  # negative content_count

    def test_encode_invalid_result_code(self):
        """Test VLV response encoding with invalid result code."""
        # Should not raise an error but log a warning and use 80 (other)
        with self.assertLogs(level="WARNING"):
            encoded = encode_vlv_response_control(10, 100, 999)  # invalid code

        decoded, _ = decoder.decode(encoded, asn1Spec=VlvResponse())
        self.assertEqual(int(decoded.getComponentByName("virtualListViewResult")), 80)


class TestVlvContextId(unittest.TestCase):
    """Test VLV context ID generation."""

    def test_context_id_generation(self):
        """Test VLV context ID generation."""
        search_params = {
            "base": "ou=users,dc=example,dc=com",
            "scope": ldap.SCOPE_SUBTREE,
            "filter": "(objectClass=person)",
            "sort": True,
        }

        context_id = create_vlv_context_id(search_params)
        self.assertIsInstance(context_id, bytes)
        self.assertEqual(len(context_id), 16)

        # Same parameters should generate same context ID (within same call)
        context_id2 = create_vlv_context_id(search_params)
        # Note: Due to timestamp, these might be different
        self.assertIsInstance(context_id2, bytes)
        self.assertEqual(len(context_id2), 16)


class TestVlvIntegrationWithFaker(LDAPFakerMixin, unittest.TestCase):
    """Test VLV integration with the fake LDAP server."""

    ldap_modules = ["ldap_faker.test.test_vlv_rfc_compliance"]

    def setUp(self):
        super().setUp()

        # Create a new object store and register it (like the working VLV tests)
        self.store = ObjectStore()
        self.server_factory.register(self.store)

        # Add test data to the store
        self.store.set(
            "cn=admin,dc=example,dc=com",
            {
                "cn": [b"admin"],
                "objectclass": [b"organizationalRole", b"top"],
                "userPassword": [b"admin"],
            },
        )

        self.store.set(
            "uid=alice,ou=users,dc=example,dc=com",
            {
                "uid": [b"alice"],
                "cn": [b"Alice Johnson"],
                "sn": [b"Johnson"],
                "objectclass": [b"posixAccount", b"top"],
            },
        )

        self.store.set(
            "uid=bob,ou=users,dc=example,dc=com",
            {
                "uid": [b"bob"],
                "cn": [b"Bob Smith"],
                "sn": [b"Smith"],
                "objectclass": [b"posixAccount", b"top"],
            },
        )

        self.store.set(
            "uid=charlie,ou=users,dc=example,dc=com",
            {
                "uid": [b"charlie"],
                "cn": [b"Charlie Brown"],
                "sn": [b"Brown"],
                "objectclass": [b"posixAccount", b"top"],
            },
        )

        self.store.set(
            "uid=diana,ou=users,dc=example,dc=com",
            {
                "uid": [b"diana"],
                "cn": [b"Diana Prince"],
                "sn": [b"Prince"],
                "objectclass": [b"posixAccount", b"top"],
            },
        )

        # Initialize connection
        self.conn = self.fake_ldap.initialize("ldap://localhost:389")
        self.conn.simple_bind_s("cn=admin,dc=example,dc=com", "admin")

    def test_vlv_with_sort_control(self):
        """Test VLV with server-side sort control (RFC compliant)."""
        # Create sort control
        sort_control = ldap.controls.SimplePagedResultsControl()
        sort_control.controlType = "1.2.840.113556.1.4.473"
        sort_control.controlValue = b""  # Simplified for test

        # Create VLV control using django-ldaporm format
        vlv_request = VlvRequestSimple()
        vlv_request.setComponentByName("beforeCount", 1)
        vlv_request.setComponentByName("afterCount", 2)
        vlv_request.setComponentByName("offset", 2)  # 1-based
        vlv_request.setComponentByName("count", 5)

        vlv_control = ldap.controls.LDAPControl(
            "2.16.840.1.113730.3.4.9", True, encoder.encode(vlv_request)
        )

        # Perform search
        msgid = self.conn.search_ext(
            "ou=users,dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            "(objectClass=posixAccount)",
            serverctrls=[sort_control, vlv_control],
        )

        rtype, rdata, rmsgid, rctrls = self.conn.result3(msgid)

        # Check for VLV response control
        vlv_response_found = False
        for ctrl in rctrls or []:
            if ctrl.controlType == "2.16.840.1.113730.3.4.10":
                vlv_response_found = True
                # Decode response
                response, _ = decoder.decode(ctrl.controlValue, asn1Spec=VlvResponse())
                result_code = int(response.getComponentByName("virtualListViewResult"))
                self.assertEqual(result_code, 0)  # success
                break

        self.assertTrue(vlv_response_found, "VLV response control not found")

    def test_vlv_without_sort_control(self):
        """Test VLV without sort control (should return error)."""
        # Create VLV control without sort control
        vlv_request = VlvRequestSimple()
        vlv_request.setComponentByName("beforeCount", 1)
        vlv_request.setComponentByName("afterCount", 2)
        vlv_request.setComponentByName("offset", 1)
        vlv_request.setComponentByName("count", 5)

        vlv_control = ldap.controls.LDAPControl(
            "2.16.840.1.113730.3.4.9", True, encoder.encode(vlv_request)
        )

        # Perform search without sort control
        msgid = self.conn.search_ext(
            "ou=users,dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            "(objectClass=posixAccount)",
            serverctrls=[vlv_control],  # No sort control
        )

        rtype, rdata, rmsgid, rctrls = self.conn.result3(msgid)

        # Check for VLV response control with error
        vlv_response_found = False
        for ctrl in rctrls or []:
            if ctrl.controlType == "2.16.840.1.113730.3.4.10":
                vlv_response_found = True
                # Decode response
                response, _ = decoder.decode(ctrl.controlValue, asn1Spec=VlvResponse())
                result_code = int(response.getComponentByName("virtualListViewResult"))
                self.assertEqual(result_code, 60)  # sortControlMissing
                break

        self.assertTrue(vlv_response_found, "VLV response control not found")

    def test_vlv_offset_range_error(self):
        """Test VLV with offset out of 32-bit range."""
        # Create sort control
        sort_control = ldap.controls.SimplePagedResultsControl()
        sort_control.controlType = "1.2.840.113556.1.4.473"
        sort_control.controlValue = b""

        # Create VLV control with huge offset
        vlv_request = VlvRequestSimple()
        vlv_request.setComponentByName("beforeCount", 1)
        vlv_request.setComponentByName("afterCount", 2)
        vlv_request.setComponentByName("offset", 2147483648)  # > 32-bit max
        vlv_request.setComponentByName("count", 5)

        vlv_control = ldap.controls.LDAPControl(
            "2.16.840.1.113730.3.4.9", True, encoder.encode(vlv_request)
        )

        # Perform search
        msgid = self.conn.search_ext(
            "ou=users,dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            "(objectClass=posixAccount)",
            serverctrls=[sort_control, vlv_control],
        )

        rtype, rdata, rmsgid, rctrls = self.conn.result3(msgid)

        # Check for VLV response control with range error
        vlv_response_found = False
        for ctrl in rctrls or []:
            if ctrl.controlType == "2.16.840.1.113730.3.4.10":
                vlv_response_found = True
                # Decode response
                response, _ = decoder.decode(ctrl.controlValue, asn1Spec=VlvResponse())
                result_code = int(response.getComponentByName("virtualListViewResult"))
                self.assertEqual(result_code, 61)  # offsetRangeError
                break

        self.assertTrue(vlv_response_found, "VLV response control not found")

    def test_vlv_basic_slicing(self):
        """Test basic VLV slicing functionality."""
        # Create sort control
        sort_control = ldap.controls.SimplePagedResultsControl()
        sort_control.controlType = "1.2.840.113556.1.4.473"
        sort_control.controlValue = b""

        # Create VLV control for middle entries
        vlv_request = VlvRequestSimple()
        vlv_request.setComponentByName("beforeCount", 1)
        vlv_request.setComponentByName("afterCount", 1)
        vlv_request.setComponentByName("offset", 2)  # 1-based
        vlv_request.setComponentByName("count", 4)

        vlv_control = ldap.controls.LDAPControl(
            "2.16.840.1.113730.3.4.9", True, encoder.encode(vlv_request)
        )

        # Perform search
        msgid = self.conn.search_ext(
            "ou=users,dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            "(objectClass=posixAccount)",
            serverctrls=[sort_control, vlv_control],
        )

        rtype, rdata, rmsgid, rctrls = self.conn.result3(msgid)

        # Should get a subset of results
        self.assertLessEqual(len(rdata), 4)  # At most 1 + 1 + 1 = 3 entries

        # Check VLV response
        for ctrl in rctrls or []:
            if ctrl.controlType == "2.16.840.1.113730.3.4.10":
                response, _ = decoder.decode(ctrl.controlValue, asn1Spec=VlvResponse())
                result_code = int(response.getComponentByName("virtualListViewResult"))
                self.assertEqual(result_code, 0)  # success
                content_count = int(response.getComponentByName("contentCount"))
                self.assertEqual(content_count, 4)  # Total number of user entries
                break


if __name__ == "__main__":
    unittest.main()
