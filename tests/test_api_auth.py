"""Unit tests for the GL.iNet challenge/response authentication (no network)."""
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path

# Load api.py directly: importing the package would pull in Home Assistant.
_API_PATH = Path(__file__).resolve().parents[1] / "custom_components" / "glinet" / "api.py"
_SPEC = importlib.util.spec_from_file_location("glinet_api", _API_PATH)
glinet_api = importlib.util.module_from_spec(_SPEC)
sys.modules["glinet_api"] = glinet_api
_SPEC.loader.exec_module(glinet_api)

GLiNetAPI = glinet_api.GLiNetAPI

USERNAME = "root"
PASSWORD = "MotDePasseTest123"
SALT = "8LnBS9BauXW5eCzi"

# openssl passwd -5 -salt 8LnBS9BauXW5eCzi MotDePasseTest123
SHA256_CIPHER = "$5$8LnBS9BauXW5eCzi$7K7nSiHcf/aiyKhSXPK2pVSNKqj.e59M1UXQANN4VV/"


class FakeResponse:
    """Minimal stand-in for a requests.Response."""

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class FakeSession:
    """Router stub: answers `challenge` and `login` over the JSON-RPC endpoint."""

    def __init__(self, alg, hash_method, expected_hash_method, password=PASSWORD):
        self.alg = alg
        self.hash_method = hash_method
        self.expected_hash_method = expected_hash_method
        self.password = password
        self.nonce_counter = 0
        self.issued_nonce = None
        self.used_nonces = set()
        self.login_attempts = 0

    def post(self, url, json=None, headers=None, timeout=None):
        method = json["method"]
        if method == "challenge":
            self.nonce_counter += 1
            self.issued_nonce = f"nonce-{self.nonce_counter}"
            return FakeResponse(
                {
                    "result": {
                        "alg": self.alg,
                        "salt": SALT,
                        "nonce": self.issued_nonce,
                        "hash-method": self.hash_method,
                    }
                }
            )

        if method == "login":
            self.login_attempts += 1
            nonce = self.issued_nonce
            if nonce in self.used_nonces:  # single-use nonce
                return FakeResponse({"error": {"message": "Access denied", "code": -32000}})
            self.used_nonces.add(nonce)

            cipher = GLiNetAPI(
                "router", USERNAME, self.password
            )._create_cipher_password(SALT, self.password, self.alg)
            expected = hashlib.new(
                self.expected_hash_method,
                f"{USERNAME}:{cipher}:{nonce}".encode(),
            ).hexdigest()

            if json["params"]["hash"] == expected:
                return FakeResponse({"result": {"sid": "test-sid"}})
            return FakeResponse({"error": {"message": "Access denied", "code": -32000}})

        raise AssertionError(f"unexpected RPC method: {method}")


def make_api(session):
    api = GLiNetAPI("router", USERNAME, PASSWORD)
    api.session = session
    return api


class TestCipherPassword(unittest.TestCase):
    """The crypt(3) cipher must match what the router computes."""

    def setUp(self):
        self.api = GLiNetAPI("router", USERNAME, PASSWORD)

    def test_alg5_matches_openssl_passwd_5(self):
        self.assertEqual(
            self.api._create_cipher_password(SALT, PASSWORD, 5), SHA256_CIPHER
        )

    def test_alg5_carries_no_rounds_field(self):
        # glibc omits `rounds=` at the default 5000; the router expects the same.
        self.assertNotIn("rounds=", self.api._create_cipher_password(SALT, PASSWORD, 5))

    def test_unknown_alg_defaults_to_sha256(self):
        self.assertEqual(
            self.api._create_cipher_password(SALT, PASSWORD, 99), SHA256_CIPHER
        )

    def test_alg1_uses_md5_crypt_with_8_char_salt(self):
        cipher = self.api._create_cipher_password(SALT, PASSWORD, 1)
        self.assertTrue(cipher.startswith(f"$1${SALT[:8]}$"), cipher)

    def test_alg6_uses_sha512_crypt_without_rounds_field(self):
        cipher = self.api._create_cipher_password(SALT, PASSWORD, 6)
        self.assertTrue(cipher.startswith(f"$6${SALT}$"), cipher)
        self.assertNotIn("rounds=", cipher)

    def test_long_salt_is_truncated_to_16_chars(self):
        cipher = self.api._create_cipher_password(SALT + "OVERFLOW", PASSWORD, 5)
        self.assertEqual(cipher, SHA256_CIPHER)


class TestAuthenticate(unittest.TestCase):
    """authenticate() must follow the alg / hash-method from the challenge."""

    def test_firmware_48x_alg5_sha256(self):
        session = FakeSession(alg=5, hash_method="sha256", expected_hash_method="sha256")
        api = make_api(session)
        self.assertTrue(api.authenticate())
        self.assertEqual(api.sid, "test-sid")
        self.assertEqual(session.login_attempts, 1)

    def test_firmware_43x_alg1_md5(self):
        session = FakeSession(alg=1, hash_method="md5", expected_hash_method="md5")
        api = make_api(session)
        self.assertTrue(api.authenticate())
        self.assertEqual(api.sid, "test-sid")
        self.assertEqual(session.login_attempts, 1)

    def test_missing_hash_method_defaults_to_md5(self):
        session = FakeSession(alg=1, hash_method=None, expected_hash_method="md5")
        api = make_api(session)
        self.assertTrue(api.authenticate())

    def test_falls_back_when_advertised_method_is_wrong(self):
        # Router advertises md5 but actually verifies sha256: the retry must
        # succeed, and each retry must use a freshly issued nonce.
        session = FakeSession(alg=5, hash_method="md5", expected_hash_method="sha256")
        api = make_api(session)
        self.assertTrue(api.authenticate())
        self.assertEqual(api.sid, "test-sid")
        self.assertEqual(session.login_attempts, 2)
        self.assertEqual(session.nonce_counter, 2)

    def test_wrong_password_fails_after_trying_every_method(self):
        session = FakeSession(
            alg=5, hash_method="sha256", expected_hash_method="sha256", password="other"
        )
        api = make_api(session)
        self.assertFalse(api.authenticate())
        self.assertIsNone(api.sid)
        self.assertEqual(session.login_attempts, 3)


if __name__ == "__main__":
    unittest.main()
