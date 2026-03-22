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
  Agent   → Enclave GET_EVIDENCE
  Enclave → Agent   EVIDENCE:stream=<hex>:state=<hex>:sig=<...>

On AWS Nitro: set VSOCK_CID to the enclave's CID (typically 16).
In simulation (dev/Mac): the runtime listens on TCP 127.0.0.1:5005.
"""

import json
import os
import socket
import sys
import urllib.error
import urllib.request
from typing import Optional

# ── Transport config ────────────────────────────────────────────────────────
VSOCK_CID  = int(os.environ.get("VSOCK_CID", "16"))   # enclave CID on Nitro
TCP_HOST   = os.environ.get("VAR_HOST", "127.0.0.1")
PORT       = int(os.environ.get("VAR_PORT", "5005"))

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
    api_key: Optional[str] = os.environ.get("ANTHROPIC_API_KEY")
    use_real_api = api_key is not None

    print("\n" + "=" * 60)
    print("  VAR Demo Agent — Verifiable Agent Runtime")
    print("=" * 60)

    # 1. Connect to the VAR runtime.
    sock = connect()

    # 2. Receive and display Bundle Header.
    header = readline(sock)
    fields = parse_header(header)

    print(f"\n[agent] Bundle Header received:")
    print(f"  Magic           : {fields.get('magic', '?')}")
    print(f"  Version         : {fields.get('version', '?')}")
    print(f"  Session ID      : {fields.get('session', '?')}")
    print(f"  Bootstrap Nonce : {fields.get('nonce', '?')}")

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
    #    In a real enclave the host seals the key with the enclave's public key;
    #    only the enclave's NSM-attested private key can decrypt it.
    #    In simulation we send it over the local loopback socket directly.
    key_to_send = api_key or "sk-ant-mock-key-for-demo-purposes-only"
    sendline(sock, f"SECRET:ANTHROPIC_API_KEY:{key_to_send}")
    print(f"\n[agent] Provisioned ANTHROPIC_API_KEY ({'real key' if use_real_api else 'mock key'})")

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

    # 6. Request the signed evidence bundle.
    sendline(sock, "GET_EVIDENCE")
    evidence = readline(sock)

    # Parse the evidence fields for display.
    ev_fields = {}
    for part in evidence.split(":"):
        if "=" in part:
            k, v = part.split("=", 1)
            ev_fields[k] = v

    print("\n" + "=" * 60)
    print("  Evidence Bundle")
    print("=" * 60)
    print(f"  Prev Hash  (L1-1): {ev_fields.get('prev_stream', '?')}")
    print(f"  Stream Hash (L1) : {ev_fields.get('stream', '?')}")
    print(f"  State Hash  (L2) : {ev_fields.get('state', '?')}")
    print(f"  Signature        : {ev_fields.get('sig', '?')}")
    print()
    print("  The stream hash is anchored to this session's bootstrap nonce.")
    print("  An auditor can replay the raw log bytes through a VT parser and")
    print("  independently verify the L2 state hash without trusting this agent.")
    print("=" * 60)

    sock.close()


if __name__ == "__main__":
    main()
