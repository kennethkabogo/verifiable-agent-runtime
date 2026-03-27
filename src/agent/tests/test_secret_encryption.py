"""
Tests for the agent-side secret encryption helpers.

These tests exercise the Python encrypt_secret() function in isolation —
they do NOT require a running enclave.  The Zig side is tested in protocol.zig.

Requires: pip install cryptography
"""
import base64
import os
import pytest

pytest.importorskip("cryptography", reason="pip install cryptography")

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import the functions under test.
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agent import encrypt_secret, provision_secret


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_keypair():
    """Return (private_key, public_key_hex) for a fresh X25519 keypair."""
    priv = X25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return priv, pub_hex


def _decrypt_payload(payload_b64: str, enc_priv: X25519PrivateKey) -> bytes:
    """Decrypt a base64 ESECRET payload using the recipient's private key."""
    raw = base64.b64decode(payload_b64)
    eph_pub_bytes = raw[:32]
    nonce         = raw[32:44]
    ct_and_tag    = raw[44:]

    eph_pub_key = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared = enc_priv.exchange(eph_pub_key)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"VAR-secret-v1",
    ).derive(shared)

    return AESGCM(aes_key).decrypt(nonce, ct_and_tag, b"")


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestEncryptSecret:
    def test_decrypts_to_original(self):
        priv, pub_hex = _make_keypair()
        plaintext = "sk-ant-api-key-value"
        payload = encrypt_secret(plaintext, pub_hex)
        recovered = _decrypt_payload(payload, priv)
        assert recovered.decode() == plaintext

    def test_different_call_different_ciphertext(self):
        """Fresh ephemeral key each call → different ciphertext every time."""
        _, pub_hex = _make_keypair()
        p1 = encrypt_secret("same-secret", pub_hex)
        p2 = encrypt_secret("same-secret", pub_hex)
        assert p1 != p2

    def test_wrong_key_cannot_decrypt(self):
        """A different recipient key must not yield the plaintext."""
        _, pub_hex = _make_keypair()
        wrong_priv, _ = _make_keypair()

        payload = encrypt_secret("sensitive", pub_hex)
        with pytest.raises(Exception):
            _decrypt_payload(payload, wrong_priv)

    def test_long_secret(self):
        """Secrets up to MAX_SECRET_VALUE_LEN (8 KiB) must round-trip."""
        priv, pub_hex = _make_keypair()
        plaintext = "x" * 8192
        payload = encrypt_secret(plaintext, pub_hex)
        assert _decrypt_payload(payload, priv).decode() == plaintext

    def test_invalid_enc_pub_raises(self):
        with pytest.raises((ValueError, Exception)):
            encrypt_secret("secret", "notvalidhex!!")

    def test_short_enc_pub_raises(self):
        with pytest.raises((ValueError, Exception)):
            encrypt_secret("secret", "deadbeef")  # only 4 bytes, not 32

    def test_payload_structure(self):
        """Verify raw layout: eph_pub(32) | nonce(12) | ct+tag."""
        _, pub_hex = _make_keypair()
        plaintext = "hello"
        payload = encrypt_secret(plaintext, pub_hex)
        raw = base64.b64decode(payload)
        # ephemeral pub (32) + nonce (12) + ciphertext (5) + tag (16) = 65
        assert len(raw) == 32 + 12 + len(plaintext) + 16

    def test_unicode_secret(self):
        """Non-ASCII secret must survive the encode/decode round-trip."""
        priv, pub_hex = _make_keypair()
        plaintext = "café-secret-🔑"
        payload = encrypt_secret(plaintext, pub_hex)
        recovered = _decrypt_payload(payload, priv)
        assert recovered.decode("utf-8") == plaintext


class TestProvisionSecret:
    """provision_secret() integration: builds the correct packet."""

    def test_uses_esecret_when_enc_pub_present(self):
        from unittest.mock import MagicMock
        fake_sock = MagicMock()
        _, pub_hex = _make_keypair()

        provision_secret(fake_sock, "MY_KEY", "my-value", pub_hex)
        
        # Verify sendall was called with the ESECRET format.
        call_args = fake_sock.sendall.call_args[0][0]
        assert call_args.startswith(b"ESECRET:MY_KEY:")

    def test_falls_back_to_cleartext_when_no_enc_pub(self):
        from unittest.mock import MagicMock
        fake_sock = MagicMock()

        provision_secret(fake_sock, "MY_KEY", "my-value", None)
        fake_sock.sendall.assert_called_once_with(b"SECRET:MY_KEY:my-value\n")
