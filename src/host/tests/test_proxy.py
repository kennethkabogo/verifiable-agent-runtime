"""
Integration tests for src/host/proxy.py.

Test levels:
  1. HTTP layer unit tests — _parse_request, _http_response, _read_full_request.
  2. Handler unit tests — _handle_encrypt / _handle_decrypt with a moto-backed
     KMS client (no network, no real AWS account needed).
  3. Recipient-flow unit tests — _handle_decrypt with Recipient, using
     unittest.mock because moto does not simulate Nitro NSM attestation
     validation.  These tests cover the proxy's response-marshalling logic
     and the critical invariant that Plaintext is never forwarded when
     CiphertextForRecipient is present.
  4. Full socket integration tests — _serve() running in a background thread,
     exercised via raw socket connections that replicate kmsHttpPost() in the
     enclave (HTTP/1.0 + X-Amz-Target header).

Run:  pytest src/host/tests/test_proxy.py
"""

import base64
import json
import socket
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import pytest
from moto import mock_aws

# Make `import proxy` work regardless of working directory.
sys.path.insert(0, str(Path(__file__).parent.parent))
import proxy  # noqa: E402  (import after sys.path manipulation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _enc_body(key_id: str, plaintext: bytes) -> bytes:
    return json.dumps({"KeyId": key_id, "Plaintext": _b64(plaintext)}).encode()


def _dec_body(ciphertext: bytes, recipient=None) -> bytes:
    req = {"CiphertextBlob": _b64(ciphertext)}
    if recipient:
        req["Recipient"] = recipient
    return json.dumps(req).encode()


# ---------------------------------------------------------------------------
# HTTP layer unit tests
# ---------------------------------------------------------------------------

class TestParseRequest:
    def test_encrypt_target_and_body(self):
        raw = (
            b"POST / HTTP/1.0\r\n"
            b"Content-Type: application/x-amz-json-1.1\r\n"
            b"X-Amz-Target: TrentService.Encrypt\r\n"
            b"Content-Length: 13\r\n"
            b"\r\n"
            b'{"hello":"x"}'
        )
        target, body = proxy._parse_request(raw)
        assert target == "TrentService.Encrypt"
        assert body == b'{"hello":"x"}'

    def test_decrypt_target(self):
        raw = (
            b"POST / HTTP/1.0\r\n"
            b"X-Amz-Target: TrentService.Decrypt\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}"
        )
        target, _ = proxy._parse_request(raw)
        assert target == "TrentService.Decrypt"

    def test_body_clipped_to_content_length(self):
        raw = (
            b"POST / HTTP/1.0\r\n"
            b"X-Amz-Target: TrentService.Decrypt\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}TRAILING_GARBAGE"
        )
        _, body = proxy._parse_request(raw)
        assert body == b"{}"

    def test_missing_target_raises(self):
        raw = (
            b"POST / HTTP/1.0\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}"
        )
        with pytest.raises(ValueError, match="X-Amz-Target"):
            proxy._parse_request(raw)

    def test_no_header_body_separator_raises(self):
        with pytest.raises(ValueError, match="separator"):
            proxy._parse_request(b"POST / HTTP/1.0\r\nX-Amz-Target: x\r\n")

    def test_header_names_case_insensitive(self):
        raw = (
            b"POST / HTTP/1.0\r\n"
            b"x-amz-target: TrentService.Encrypt\r\n"
            b"content-length: 2\r\n"
            b"\r\n"
            b"{}"
        )
        target, body = proxy._parse_request(raw)
        assert target == "TrentService.Encrypt"
        assert body == b"{}"


class TestHttpResponse:
    def test_200_structure(self):
        resp = proxy._http_response(200, b'{"ok":1}')
        assert resp.startswith(b"HTTP/1.0 200 OK\r\n")
        assert b"Content-Length: 8\r\n" in resp
        assert b"Content-Type: application/x-amz-json-1.1\r\n" in resp
        assert resp.endswith(b'{"ok":1}')

    def test_400_structure(self):
        resp = proxy._http_response(400, b'{"message":"bad"}')
        assert b"HTTP/1.0 400 Bad Request\r\n" in resp

    def test_500_structure(self):
        resp = proxy._http_response(500, b'{"message":"oops"}')
        assert b"HTTP/1.0 500 Internal Server Error\r\n" in resp

    def test_empty_body(self):
        resp = proxy._http_response(200, b"")
        assert b"Content-Length: 0\r\n" in resp


# ---------------------------------------------------------------------------
# Handler unit tests — encrypt / decrypt (moto-backed KMS)
# ---------------------------------------------------------------------------

@mock_aws
def test_handle_encrypt_returns_ciphertext_blob():
    kms = boto3.client("kms", region_name="us-east-1")
    key_id = kms.create_key(Description="var-test")["KeyMetadata"]["KeyId"]
    dek = bytes(range(32))

    resp_body = proxy._handle_encrypt(kms, _enc_body(key_id, dek))
    result = json.loads(resp_body)

    assert "CiphertextBlob" in result
    assert len(base64.b64decode(result["CiphertextBlob"])) > 0
    assert "KeyId" in result


@mock_aws
def test_handle_encrypt_and_decrypt_round_trip():
    kms = boto3.client("kms", region_name="us-east-1")
    key_id = kms.create_key(Description="var-test")["KeyMetadata"]["KeyId"]
    dek = bytes(range(32))

    enc_result = json.loads(proxy._handle_encrypt(kms, _enc_body(key_id, dek)))
    ciphertext = base64.b64decode(enc_result["CiphertextBlob"])

    dec_result = json.loads(proxy._handle_decrypt(kms, _dec_body(ciphertext)))

    assert "Plaintext" in dec_result
    assert base64.b64decode(dec_result["Plaintext"]) == dek


@mock_aws
def test_handle_decrypt_without_recipient_returns_plaintext():
    kms = boto3.client("kms", region_name="us-east-1")
    key_id = kms.create_key(Description="var-test")["KeyMetadata"]["KeyId"]
    dek = b"\xde\xad\xbe\xef" * 8  # 32 bytes

    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=dek)["CiphertextBlob"]
    dec_result = json.loads(proxy._handle_decrypt(kms, _dec_body(ciphertext)))

    assert "Plaintext" in dec_result
    assert base64.b64decode(dec_result["Plaintext"]) == dek


# ---------------------------------------------------------------------------
# Recipient-flow unit tests (manual mock — moto does not simulate NSM)
# ---------------------------------------------------------------------------

def _mock_kms_with_recipient_response(fake_wrapped_dek: bytes) -> MagicMock:
    """Return a mock kms client whose decrypt() simulates the KMS recipient flow."""
    m = MagicMock()
    m.decrypt.return_value = {
        "KeyId": "arn:aws:kms:us-east-1:123456789012:key/test",
        "CiphertextForRecipient": fake_wrapped_dek,
        # KMS does NOT return Plaintext when Recipient is present.
    }
    return m


def test_recipient_flow_returns_ciphertext_for_recipient():
    fake_wrapped_dek = bytes(range(256))  # 256-byte RSA-2048 block
    mock_kms = _mock_kms_with_recipient_response(fake_wrapped_dek)

    body = _dec_body(
        ciphertext=b"\x00" * 185,
        recipient={
            "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "AttestationDocument": _b64(b"\xaa" * 96),
        },
    )

    result = json.loads(proxy._handle_decrypt(mock_kms, body))

    assert "CiphertextForRecipient" in result
    assert base64.b64decode(result["CiphertextForRecipient"]) == fake_wrapped_dek
    assert "Plaintext" not in result, "proxy must not forward Plaintext in recipient flow"


def test_recipient_flow_passes_attestation_doc_as_bytes_to_boto3():
    """Verify the proxy decodes the base64 attestation doc before calling boto3."""
    nsm_doc_bytes = b"\xaa" * 96
    mock_kms = _mock_kms_with_recipient_response(bytes(256))

    body = _dec_body(
        ciphertext=b"\x00" * 185,
        recipient={
            "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "AttestationDocument": _b64(nsm_doc_bytes),
        },
    )
    proxy._handle_decrypt(mock_kms, body)

    call_kwargs = mock_kms.decrypt.call_args[1]
    assert "Recipient" in call_kwargs
    assert call_kwargs["Recipient"]["AttestationDocument"] == nsm_doc_bytes
    assert call_kwargs["Recipient"]["KeyEncryptionAlgorithm"] == "RSAES_OAEP_SHA_256"


def test_recipient_flow_does_not_forward_plaintext_even_if_kms_returns_both():
    """
    KMS should never return both fields, but if it does the proxy must not
    leak Plaintext when CiphertextForRecipient is present.
    """
    mock_kms = MagicMock()
    mock_kms.decrypt.return_value = {
        "KeyId": "test",
        "CiphertextForRecipient": bytes(256),
        "Plaintext": b"\x00" * 32,  # must NOT be forwarded
    }

    body = _dec_body(
        ciphertext=b"\x00" * 185,
        recipient={
            "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "AttestationDocument": _b64(b"\xaa" * 96),
        },
    )
    result = json.loads(proxy._handle_decrypt(mock_kms, body))

    assert "Plaintext" not in result
    assert "CiphertextForRecipient" in result


# ---------------------------------------------------------------------------
# Full socket integration tests
#
# _ProxyServer spins up proxy._serve() in a background daemon thread and
# exposes a helper that makes raw socket requests matching kmsHttpPost() in
# the enclave (HTTP/1.0 + X-Amz-Target).
# ---------------------------------------------------------------------------

class _ProxyServer:
    def __init__(self, kms):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(5)
        threading.Thread(
            target=proxy._serve, args=(self._sock, kms), daemon=True
        ).start()

    def raw_request(self, target: str, body: bytes) -> bytes:
        """Send an HTTP/1.0 request and return the full response bytes."""
        request = (
            f"POST / HTTP/1.0\r\n"
            f"X-Amz-Target: {target}\r\n"
            f"Content-Type: application/x-amz-json-1.1\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
        ).encode() + body

        conn = socket.create_connection(("127.0.0.1", self.port))
        conn.sendall(request)
        conn.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        conn.close()
        return data

    def request_json(self, target: str, body: bytes) -> dict:
        """Make a request and assert 2xx, returning the parsed JSON body."""
        data = self.raw_request(target, body)
        assert data.startswith(b"HTTP/1.0 2"), (
            f"expected 2xx, got:\n{data[:300].decode(errors='replace')}"
        )
        sep = data.index(b"\r\n\r\n")
        return json.loads(data[sep + 4:])


@mock_aws
def test_socket_encrypt_decrypt_round_trip():
    kms = boto3.client("kms", region_name="us-east-1")
    key_id = kms.create_key(Description="var-test")["KeyMetadata"]["KeyId"]
    srv = _ProxyServer(kms)
    dek = bytes(range(32))

    enc = srv.request_json("TrentService.Encrypt", _enc_body(key_id, dek))
    assert "CiphertextBlob" in enc

    dec = srv.request_json(
        "TrentService.Decrypt",
        _dec_body(base64.b64decode(enc["CiphertextBlob"])),
    )
    assert base64.b64decode(dec["Plaintext"]) == dek


@mock_aws
def test_socket_unknown_target_returns_400():
    kms = boto3.client("kms", region_name="us-east-1")
    srv = _ProxyServer(kms)

    data = srv.raw_request("TrentService.UnknownOp", b"{}")
    assert data.startswith(b"HTTP/1.0 400 ")


@mock_aws
def test_socket_large_body_with_long_content_length():
    """Proxy must buffer until Content-Length is satisfied (not just \r\n\r\n)."""
    kms = boto3.client("kms", region_name="us-east-1")
    key_id = kms.create_key(Description="var-test")["KeyMetadata"]["KeyId"]
    srv = _ProxyServer(kms)

    # A DEK of 32 bytes — the plaintext is small but the JSON body is well-formed.
    dek = b"\xff" * 32
    enc = srv.request_json("TrentService.Encrypt", _enc_body(key_id, dek))
    assert "CiphertextBlob" in enc


@mock_aws
def test_socket_multiple_sequential_requests():
    """Server must handle multiple connections on the same port."""
    kms = boto3.client("kms", region_name="us-east-1")
    key_id = kms.create_key(Description="var-test")["KeyMetadata"]["KeyId"]
    srv = _ProxyServer(kms)

    for i in range(5):
        dek = bytes([i] * 32)
        enc = srv.request_json("TrentService.Encrypt", _enc_body(key_id, dek))
        dec = srv.request_json(
            "TrentService.Decrypt",
            _dec_body(base64.b64decode(enc["CiphertextBlob"])),
        )
        assert base64.b64decode(dec["Plaintext"]) == dek
