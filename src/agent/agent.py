#!/usr/bin/env python3
"""
VAR Demo Agent
==============
A minimal autonomous agent that runs inside the Verifiable Agent Runtime
enclave and demonstrates the full end-to-end trust chain:

  1. Connects to the VAR runtime (vsock on Nitro, TCP in simulation).
  2. Receives and validates the Bundle Header (session root-of-trust anchor).
  3. Provisions the runtime vault with its API key.
  4. Executes a sensitive task via the Anthropic Messages API (or a mock).
  5. Requests and prints the signed evidence bundle.

Line-oriented protocol (all messages newline-terminated):
  Enclave → Agent   BUNDLE_HEADER:magic=VARB:...
  Enclave → Agent   READY
  Agent   → Enclave SECRET:<key>:<value>
  Agent   → Enclave LOG:<message>
  Agent   → Enclave EXEC:<cmd> [arg1] [arg2]…
  Enclave → Agent   EXEC_RESULT:exit=<N>:stdout_b64=<b64>:stderr_b64=<b64>:stdout_hash=<hex>:stderr_hash=<hex>
  Agent   → Enclave GET_EVIDENCE
  Enclave → Agent   EVIDENCE:stream=<hex>:state=<hex>:sig=<...>

On AWS Nitro: set VSOCK_CID to the enclave's CID (typically 16).
In simulation (dev/Mac): the runtime listens on TCP 127.0.0.1:5005.
"""

import base64
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from typing import Optional

# ── Secret encryption ────────────────────────────────────────────────────────
# Used when the enclave advertises enc_pub in the bundle header.
# Falls back gracefully to cleartext if the `cryptography` package is absent
# (e.g., bare CI environment without extra deps), but logs a warning.
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

# ── Transport config ────────────────────────────────────────────────────────
VSOCK_CID   = int(os.environ.get("VSOCK_CID", "16"))   # enclave CID on Nitro
TCP_HOST    = os.environ.get("VAR_HOST", "127.0.0.1")
PORT        = int(os.environ.get("VAR_PORT", "5005"))
GATEWAY_URL = os.environ.get("VAR_GATEWAY_URL", "http://127.0.0.1:8765")

# ── Anthropic API ────────────────────────────────────────────────────────────
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL   = "claude-haiku-4-5-20251001"


# ── Transport ────────────────────────────────────────────────────────────────

def connect() -> socket.socket:
    """Connect to the VAR runtime. Tries AF_VSOCK first, falls back to TCP."""
    try:
        # AF_VSOCK is Linux-only; AttributeError is raised on macOS/Windows.
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)  # type: ignore[attr-defined]
        sock.connect((VSOCK_CID, PORT))
        print(f"[agent] Connected via AF_VSOCK (cid={VSOCK_CID}, port={PORT})")
        return sock
    except (AttributeError, OSError):
        pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TCP_HOST, PORT))
    print(f"[agent] Connected via TCP ({TCP_HOST}:{PORT})")
    return sock


def readline(sock: socket.socket) -> str:
    """Read one newline-terminated line from the socket."""
    buf = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            break
        if ch == b"\n":
            break
        if ch != b"\r":
            buf += ch
    return buf.decode()


def sendline(sock: socket.socket, msg: str) -> None:
    sock.sendall((msg + "\n").encode())


# ── Anthropic API (raw HTTP — no SDK dependency) ─────────────────────────────

def call_anthropic(api_key: str, prompt: str) -> str:
    """Call the Anthropic Messages API and return the assistant's reply."""
    payload = json.dumps({
        "model": ANTHROPIC_MODEL,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read())
            return body["content"][0]["text"]
    except urllib.error.HTTPError as e:
        return f"[API error {e.code}]: {e.read().decode()[:200]}"
    except Exception as e:
        return f"[error]: {e}"


def mock_response(prompt: str) -> str:
    """Deterministic mock response used when no API key is available."""
    _ = prompt
    return (
        "Mock analysis complete. "
        "The dataset [1, 2, 3, 999, 4, 5] contains one anomaly at index 3 (value=999). "
        "Recommendation: flag for human review. "
        "[Simulated — no ANTHROPIC_API_KEY was provided]"
    )


# ── Secret provisioning ──────────────────────────────────────────────────────

def encrypt_secret(plaintext: str, enc_pub_hex: str) -> str:
    """
    Encrypt *plaintext* for the enclave identified by *enc_pub_hex*.

    Wire format (base64-encoded):
        ephemeral_x25519_pub[32] | nonce[12] | AES-256-GCM(plaintext) | tag[16]

    Key derivation:
        shared  = X25519(ephemeral_priv, enclave_pub)
        aes_key = HKDF-SHA256(ikm=shared, salt=b"", info=b"VAR-secret-v1", length=32)

    Raises RuntimeError if the `cryptography` package is not installed.
    """
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "cryptography package required for secret encryption; "
            "run: pip install cryptography"
        )

    enc_pub_bytes = bytes.fromhex(enc_pub_hex)
    if len(enc_pub_bytes) != 32:
        raise ValueError(f"enc_pub must be 32 bytes, got {len(enc_pub_bytes)}")

    # Ephemeral X25519 keypair (fresh per secret).
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub  = ephemeral_priv.public_key().public_bytes_raw()

    # ECDH shared secret.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    enclave_pub_key = X25519PublicKey.from_public_bytes(enc_pub_bytes)
    shared = ephemeral_priv.exchange(enclave_pub_key)

    # HKDF-SHA256 → 32-byte AES key.
    aes_key = HKDF(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"VAR-secret-v1",
    ).derive(shared)

    # AES-256-GCM encrypt (12-byte nonce, 16-byte tag appended by AESGCM).
    nonce = os.urandom(12)
    ct_and_tag = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), b"")

    payload = base64.b64encode(ephemeral_pub + nonce + ct_and_tag).decode()
    return payload


def exec_command(sock: socket.socket, cmd: list[str]) -> dict:
    """
    Send EXEC:<cmd> over the vsock line protocol and return a result dict:
      exit_code (int), stdout (bytes), stderr (bytes),
      stdout_hash (str hex), stderr_hash (str hex).
    """
    sendline(sock, "EXEC:" + " ".join(cmd))
    line = readline(sock)
    if line.startswith("EXEC_ERROR:"):
        raise RuntimeError(f"enclave exec error: {line[11:]}")
    if not line.startswith("EXEC_RESULT:"):
        raise RuntimeError(f"unexpected exec response: {line!r}")
    fields: dict = {}
    for part in line[len("EXEC_RESULT:"):].split(":"):
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k] = v
    return {
        "exit_code": int(fields.get("exit", "255")),
        "stdout": base64.b64decode(fields.get("stdout_b64", "")),
        "stderr": base64.b64decode(fields.get("stderr_b64", "")),
        "stdout_hash": fields.get("stdout_hash", ""),
        "stderr_hash": fields.get("stderr_hash", ""),
    }


def exec_command_http(gateway_url: str, cmd: list[str]) -> dict:
    """
    Run a command via the HTTP gateway's POST /exec endpoint.

    This is the "Verifiable Sidecar" path: any language or framework
    co-located with the enclave can call the gateway over loopback without
    speaking the vsock line protocol.

    Returns the same dict shape as exec_command():
      exit_code (int), stdout (bytes), stderr (bytes),
      stdout_hash (str hex), stderr_hash (str hex).
    """
    payload = json.dumps({"cmd": cmd}).encode()
    req = urllib.request.Request(
        f"{gateway_url}/exec",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"gateway /exec HTTP {e.code}: {e.read().decode()[:200]}")
    except Exception as e:
        raise RuntimeError(f"gateway /exec error: {e}")

    return {
        "exit_code": int(body.get("exit_code", 255)),
        "stdout": base64.b64decode(body.get("stdout_b64", "")),
        "stderr": base64.b64decode(body.get("stderr_b64", "")),
        "stdout_hash": body.get("stdout_hash", ""),
        "stderr_hash": body.get("stderr_hash", ""),
    }


def get_evidence_http(gateway_url: str) -> dict:
    """Fetch the signed evidence bundle from the HTTP gateway (GET /evidence)."""
    req = urllib.request.Request(f"{gateway_url}/evidence", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"gateway /evidence error: {e}")


def provision_secret(sock: socket.socket, name: str, value: str,
                     enc_pub_hex: Optional[str]) -> None:
    """Send a secret to the enclave, encrypting if enc_pub is available."""
    if enc_pub_hex and _CRYPTO_AVAILABLE:
        payload = encrypt_secret(value, enc_pub_hex)
        sendline(sock, f"ESECRET:{name}:{payload}")
    else:
        if enc_pub_hex and not _CRYPTO_AVAILABLE:
            print(
                "[agent] WARNING: enc_pub present but cryptography package missing — "
                "falling back to cleartext SECRET",
                file=sys.stderr,
            )
        sendline(sock, f"SECRET:{name}:{value}")


# ── Bundle Header parser ─────────────────────────────────────────────────────

def parse_header(header: str) -> dict:
    """
    Extract key=value pairs from a header line like:
      BUNDLE_HEADER:magic=VARB:version=01:session=<hex>:nonce=<hex>:QUOTE:...
    """
    fields = {}
    for part in header.split(":"):
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k] = v
    return fields


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="VAR Demo Agent")
    parser.add_argument(
        "--use-http",
        action="store_true",
        help=(
            "Use the HTTP gateway (POST /exec, GET /evidence) instead of the "
            "vsock line protocol for subprocess execution and evidence retrieval. "
            "Demonstrates the language-agnostic Verifiable Sidecar interface."
        ),
    )
    parser.add_argument(
        "--gateway-url",
        default=GATEWAY_URL,
        help=f"HTTP gateway base URL (default: {GATEWAY_URL})",
    )
    args = parser.parse_args()

    api_key: Optional[str] = os.environ.get("ANTHROPIC_API_KEY")
    use_real_api = api_key is not None

    print("\n" + "=" * 60)
    print("  VAR Demo Agent — Verifiable Agent Runtime")
    if args.use_http:
        print(f"  Mode: HTTP Sidecar  ({args.gateway_url})")
    else:
        print("  Mode: vsock line protocol")
    print("=" * 60)

    # 1. Connect to the VAR runtime.
    sock = connect()

    # 2. Receive and display Bundle Header.
    header = readline(sock)
    fields = parse_header(header)

    enc_pub_hex: Optional[str] = fields.get("enc_pub")
    encrypted_mode = bool(enc_pub_hex) and _CRYPTO_AVAILABLE

    print(f"\n[agent] Bundle Header received:")
    print(f"  Magic           : {fields.get('magic', '?')}")
    print(f"  Version         : {fields.get('version', '?')}")
    print(f"  Session ID      : {fields.get('session', '?')}")
    print(f"  Bootstrap Nonce : {fields.get('nonce', '?')}")
    print(f"  Enc Public Key  : {enc_pub_hex[:16]}…" if enc_pub_hex else "  Enc Public Key  : (none — cleartext mode)")
    print(f"  Secret mode     : {'ECDH+AES-256-GCM' if encrypted_mode else 'cleartext (simulation)'}")

    if fields.get("magic") != "VARB":
        print("[agent] ERROR: unexpected magic bytes — aborting.", file=sys.stderr)
        sock.close()
        return

    # 3. Wait for READY signal.
    ready = readline(sock)
    if ready != "READY":
        print(f"[agent] ERROR: expected READY, got {ready!r}", file=sys.stderr)
        sock.close()
        return

    # 4. Provision the vault with the API key.
    #    When the enclave advertises enc_pub in the bundle header the secret is
    #    encrypted with X25519 ECDH + HKDF-SHA256 + AES-256-GCM so that only the
    #    attested enclave can decrypt it — the vsock transport never carries the
    #    plaintext.  In simulation (no enc_pub or no cryptography package) the key
    #    is sent in cleartext over the local loopback socket.
    key_to_send = api_key or "sk-ant-mock-key-for-demo-purposes-only"
    provision_secret(sock, "ANTHROPIC_API_KEY", key_to_send, enc_pub_hex)
    print(f"\n[agent] Provisioned ANTHROPIC_API_KEY ({'real key' if use_real_api else 'mock key'}, {'encrypted' if encrypted_mode else 'cleartext'})")

    # 5. Execute the agent task.
    task = (
        "You are a data analyst inside a secure enclave. "
        "Analyze this dataset and identify anomalies: [1, 2, 3, 999, 4, 5]. "
        "Be concise."
    )
    print(f"\n[agent] Task:\n  {task}")
    sendline(sock, f"LOG:TASK: {task}")

    print("\n[agent] Calling LLM...")
    if use_real_api:
        response = call_anthropic(key_to_send, task)
    else:
        response = mock_response(task)

    print(f"\n[agent] Response:\n  {response}")
    sendline(sock, f"LOG:RESPONSE: {response}")

    # 6. Run verifiable subprocesses inside the enclave.
    #    Two commands so we can demonstrate the full audit log (not just last-one-wins).
    demo_commands = [["uname", "-a"], ["date", "-u"]]

    for cmd in demo_commands:
        print(f"\n[agent] EXEC: {' '.join(cmd)}")
        try:
            if args.use_http:
                exec_result = exec_command_http(args.gateway_url, cmd)
            else:
                exec_result = exec_command(sock, cmd)
            stdout_text = exec_result["stdout"].decode(errors="replace").strip()
            print(f"  exit_code  : {exec_result['exit_code']}")
            print(f"  stdout     : {stdout_text}")
            print(f"  stdout_hash: {exec_result['stdout_hash']}")
            sendline(sock, f"LOG:EXEC: {' '.join(cmd)} → {stdout_text}")
        except RuntimeError as exc:
            print(f"  [FAILED] {exc}", file=sys.stderr)

    # 7. Fetch and display the signed evidence bundle (full execution audit log).
    print("\n[agent] Fetching evidence bundle...")
    if args.use_http:
        try:
            ev = get_evidence_http(args.gateway_url)
        except RuntimeError as exc:
            print(f"[agent] Evidence fetch failed: {exc}", file=sys.stderr)
            ev = {}
    else:
        sendline(sock, "GET_EVIDENCE")
        raw = readline(sock)
        ev = {}
        for part in raw.split(":"):
            if "=" in part:
                k, v = part.split("=", 1)
                ev[k] = v

    executions: list = ev.get("executions", [])

    print("\n" + "=" * 60)
    print("  Evidence Bundle")
    print("=" * 60)
    print(f"  Sequence         : {ev.get('sequence', ev.get('seq', '?'))}")
    print(f"  Prev Hash  (L1-1): {ev.get('prev_stream', '?')}")
    print(f"  Stream Hash (L1) : {ev.get('stream', '?')}")
    print(f"  State Hash  (L2) : {ev.get('state', '?')}")
    print(f"  Signature        : {ev.get('sig', '?')}")
    print(f"\n  Execution Audit Log ({len(executions)} command(s)):")
    if executions:
        for i, rec in enumerate(executions):
            print(f"    [{i}] cmd={rec.get('cmd','?')}  "
                  f"exit={rec.get('exit_code','?')}  "
                  f"seq={rec.get('seq','?')}  "
                  f"stdout_hash={rec.get('stdout_hash','?')[:16]}…")
    else:
        print("    (no executions recorded or vsock mode — see stream hash)")
    print()
    print("  Every command's stdout is committed into the L1 chain in order.")
    print("  An auditor verifying the chain will see ALL commands, not just")
    print("  the last one — hiding a malicious command is not possible.")
    print("=" * 60)

    sock.close()


if __name__ == "__main__":
    main()
