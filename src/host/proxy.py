#!/usr/bin/env python3
"""
var_kms_proxy.py — Host-side KMS forwarding proxy for the Verifiable Agent Runtime.

The enclave has no direct network access.  This proxy:
  1. Listens on vsock port VAR_KMS_PROXY_PORT (default 8443) using
     VMADDR_CID_ANY so it accepts connections from any enclave on the host.
     Falls back to TCP 127.0.0.1 when AF_VSOCK is unavailable (simulation).
  2. Parses the minimal HTTP/1.0 request emitted by kmsHttpPost() in the enclave.
  3. Routes to the appropriate boto3 KMS call; IAM auth is handled by the
     standard credential chain (instance role, env vars, ~/.aws/credentials).
  4. Returns an HTTP/1.0 response the enclave can parse.

Supported X-Amz-Target values:
  TrentService.Encrypt  →  kms:Encrypt
  TrentService.Decrypt  →  kms:Decrypt   (passes Recipient field through when
                                           present; KMS returns
                                           CiphertextForRecipient so this proxy
                                           never sees the plaintext DEK)

Environment variables:
  VAR_KMS_PROXY_PORT   listen port (default 8443; must match enclave setting)
  AWS_DEFAULT_REGION   AWS region (standard boto3 chain; required if not set
                                   via instance metadata or ~/.aws/config)

Usage on the Nitro parent instance:
  python3 var_kms_proxy.py [--vsock] [--port PORT] [--region REGION] [--verbose]
"""

import argparse
import base64
import json
import logging
import os
import socket
import sys
import threading
from http import HTTPStatus

import boto3
from botocore.exceptions import ClientError

LOG = logging.getLogger("var-kms-proxy")

# vsock constants (match vsock.zig: VMADDR_CID_ANY = 0xFFFFFFFF)
_VMADDR_CID_ANY = getattr(socket, "VMADDR_CID_ANY", 0xFFFFFFFF)

DEFAULT_PORT = 8443
# Safety cap: largest plausible request is an NSM attestation doc (~3 KiB)
# base64-encoded inside a JSON body (~4 KiB) plus HTTP headers.
MAX_REQUEST_BYTES = 64 * 1024  # 64 KiB


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_response(status: int, body: bytes) -> bytes:
    phrase = HTTPStatus(status).phrase
    header = (
        f"HTTP/1.0 {status} {phrase}\r\n"
        f"Content-Type: application/x-amz-json-1.1\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    )
    return header.encode() + body


def _parse_request(raw: bytes):
    """Return (target, body_bytes) from a raw HTTP/1.0 request, or raise ValueError."""
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        raise ValueError("incomplete request: no header/body separator")

    header_block = raw[:sep].decode("ascii", errors="replace")
    body = raw[sep + 4:]

    target = None
    content_length = None
    for line in header_block.splitlines()[1:]:  # skip the request line
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name == "x-amz-target":
            target = value
        elif name == "content-length":
            content_length = int(value)

    if target is None:
        raise ValueError("missing X-Amz-Target header")
    if content_length is not None:
        body = body[:content_length]
    return target, body


def _read_full_request(conn) -> bytes:
    """Read until we have a complete HTTP/1.0 request (headers + declared body)."""
    raw = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        raw += chunk
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request too large")

        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            continue  # still reading headers

        # Parse Content-Length from the headers we have so far.
        header_block = raw[:sep].decode("ascii", errors="replace")
        content_length = None
        for line in header_block.splitlines()[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "content-length":
                content_length = int(value.strip())
                break

        if content_length is None or len(raw) >= sep + 4 + content_length:
            break  # body complete (or no body)

    return raw


# ---------------------------------------------------------------------------
# KMS action handlers
# ---------------------------------------------------------------------------

def _handle_encrypt(kms, body_bytes: bytes) -> bytes:
    req = json.loads(body_bytes)
    plaintext = base64.b64decode(req["Plaintext"])
    resp = kms.encrypt(KeyId=req["KeyId"], Plaintext=plaintext)
    result = {
        "CiphertextBlob": base64.b64encode(resp["CiphertextBlob"]).decode(),
        "KeyId": resp["KeyId"],
        "EncryptionAlgorithm": resp.get("EncryptionAlgorithm", "SYMMETRIC_DEFAULT"),
    }
    return json.dumps(result).encode()


def _handle_decrypt(kms, body_bytes: bytes) -> bytes:
    req = json.loads(body_bytes)
    ciphertext = base64.b64decode(req["CiphertextBlob"])
    kwargs = {"CiphertextBlob": ciphertext}

    if "Recipient" in req:
        recip = req["Recipient"]
        # AttestationDocument arrives as base64 from the enclave JSON; boto3
        # expects raw bytes.  KMS verifies the NSM signature, trusts the
        # embedded RSA public key, and returns CiphertextForRecipient instead
        # of Plaintext — this proxy never sees the plaintext DEK.
        kwargs["Recipient"] = {
            "KeyEncryptionAlgorithm": recip["KeyEncryptionAlgorithm"],
            "AttestationDocument": base64.b64decode(recip["AttestationDocument"]),
        }

    resp = kms.decrypt(**kwargs)

    result = {"KeyId": resp.get("KeyId", "")}
    if "CiphertextForRecipient" in resp:
        # Recipient flow: return the RSA-wrapped DEK; proxy never touches plaintext.
        result["CiphertextForRecipient"] = base64.b64encode(
            resp["CiphertextForRecipient"]
        ).decode()
    elif "Plaintext" in resp:
        # Non-recipient fallback (simulation path or legacy callers).
        result["Plaintext"] = base64.b64encode(resp["Plaintext"]).decode()
    return json.dumps(result).encode()


_HANDLERS = {
    "TrentService.Encrypt": _handle_encrypt,
    "TrentService.Decrypt": _handle_decrypt,
}


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

def _handle_connection(conn, kms):
    try:
        raw = _read_full_request(conn)
        if not raw:
            return

        target, body = _parse_request(raw)
        handler = _HANDLERS.get(target)
        if handler is None:
            LOG.warning("unknown target: %s", target)
            conn.sendall(_http_response(
                400,
                json.dumps({"message": f"unsupported target: {target}"}).encode(),
            ))
            return

        LOG.info("→ %s (%d bytes body)", target, len(body))
        resp_body = handler(kms, body)
        LOG.info("← %s 200 (%d bytes)", target, len(resp_body))
        conn.sendall(_http_response(200, resp_body))

    except ClientError as exc:
        http_status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
        msg = exc.response["Error"]["Message"]
        LOG.error("KMS error %d: %s", http_status, msg)
        conn.sendall(_http_response(
            http_status,
            json.dumps({"message": msg}).encode(),
        ))
    except Exception as exc:
        LOG.exception("unhandled error: %s", exc)
        conn.sendall(_http_response(
            500,
            json.dumps({"message": str(exc)}).encode(),
        ))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Server loop
# ---------------------------------------------------------------------------

def _serve(server_sock, kms):
    LOG.info("proxy ready")
    while True:
        conn, addr = server_sock.accept()
        LOG.debug("connection from %s", addr)
        threading.Thread(
            target=_handle_connection, args=(conn, kms), daemon=True
        ).start()


def main():
    parser = argparse.ArgumentParser(
        description="VAR host-side KMS forwarding proxy",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--vsock", action="store_true",
        help="listen on AF_VSOCK (production Nitro host); default is TCP simulation",
    )
    parser.add_argument(
        "--port", type=int,
        default=int(os.environ.get("VAR_KMS_PROXY_PORT", DEFAULT_PORT)),
        help="listen port (matches VAR_KMS_PROXY_PORT in the enclave)",
    )
    parser.add_argument(
        "--region", default=os.environ.get("AWS_DEFAULT_REGION"),
        help="AWS region for KMS (default: from credential chain)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    kms_kwargs = {}
    if args.region:
        kms_kwargs["region_name"] = args.region
    kms = boto3.client("kms", **kms_kwargs)
    LOG.info("KMS client ready (region=%s)", kms.meta.region_name)

    if args.vsock:
        if not hasattr(socket, "AF_VSOCK"):
            LOG.error("AF_VSOCK not available on this platform; omit --vsock for simulation")
            sys.exit(1)
        server_sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((_VMADDR_CID_ANY, args.port))
        LOG.info("listening on vsock port %d", args.port)
    else:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", args.port))
        LOG.info("listening on tcp://127.0.0.1:%d (simulation mode)", args.port)

    server_sock.listen(5)

    try:
        _serve(server_sock, kms)
    except KeyboardInterrupt:
        LOG.info("shutting down")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
