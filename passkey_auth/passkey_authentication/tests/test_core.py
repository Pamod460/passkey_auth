"""Unit tests for passkey_auth core utilities."""
import unittest

try:
    import frappe
    HAS_FRAPPE = True
except ImportError:
    HAS_FRAPPE = False


class TestBase64URL(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        from passkey_auth.passkey_authentication.serialization import base64url_encode, base64url_decode
        for data in [b"hello", b"\x00\x01\x02", b"\xff\xfe", b"x" * 100]:
            self.assertEqual(data, base64url_decode(base64url_encode(data)))

    def test_encode_no_padding(self):
        from passkey_auth.passkey_authentication.serialization import base64url_encode
        for length in range(0, 20):
            self.assertNotIn("=", base64url_encode(b"x" * length))

    def test_no_url_unsafe_chars(self):
        from passkey_auth.passkey_authentication.serialization import base64url_encode
        encoded = base64url_encode(bytes(range(256)))
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)

    def test_hex_conversion(self):
        from passkey_auth.passkey_authentication.serialization import base64url_to_hex, hex_to_base64url
        h = "deadbeef0123456789abcdef"
        self.assertEqual(h, base64url_to_hex(hex_to_base64url(h)))

    def test_type_errors(self):
        from passkey_auth.passkey_authentication.serialization import base64url_encode, base64url_decode
        with self.assertRaises(TypeError):
            base64url_encode("not bytes")
        with self.assertRaises(TypeError):
            base64url_decode(123)


class TestChallengeGeneration(unittest.TestCase):
    def test_challenge_length(self):
        import os
        challenge = os.urandom(32)
        self.assertEqual(len(challenge), 32)

    def test_challenge_randomness(self):
        import os
        challenges = {os.urandom(32) for _ in range(100)}
        self.assertEqual(len(challenges), 100)


@unittest.skipUnless(HAS_FRAPPE, "frappe not available")
class TestChallengeManagement(unittest.TestCase):
    def test_generate_challenge_length(self):
        from passkey_auth.passkey_authentication.challenges import generate_challenge
        self.assertEqual(len(generate_challenge()), 32)


@unittest.skipUnless(HAS_FRAPPE, "frappe not available")
class TestSecurityValidation(unittest.TestCase):
    def test_validate_rp_id_valid(self):
        from passkey_auth.passkey_authentication.security import validate_rp_id
        for rp_id in ["erp.example.com", "localhost", "127.0.0.1", "sub.domain.com"]:
            self.assertTrue(validate_rp_id(rp_id), f"Expected valid: {rp_id}")

    def test_validate_rp_id_invalid(self):
        from passkey_auth.passkey_authentication.security import validate_rp_id
        for rp_id in ["", "https://erp.example.com", "http://erp.example.com", "erp.example.com/path"]:
            self.assertFalse(validate_rp_id(rp_id), f"Expected invalid: {rp_id}")


if __name__ == "__main__":
    unittest.main()
