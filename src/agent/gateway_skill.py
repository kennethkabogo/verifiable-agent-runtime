#!/usr/bin/env python3
"""
gateway_skill.py — OpenClaw-style skill using the VAR HTTP gateway.

Demonstrates how any modular agent skill (Python, JS, Rust, …) can
participate in the VAR verifiable evidence chain via simple HTTP calls,
without speaking the custom vsock line protocol.

Usage:
    # Terminal 1 — start the gateway:
    #   zig build && ./zig-out/bin/VAR-gateway
    #
    # Terminal 2 — run this demo skill:
    #   python3 src/agent/gateway_skill.py
    #
    # Environment variables:
    #   VAR_GATEWAY       base URL of the gateway (default: http://127.0.0.1:8765)
    #   SKILL_ID          name logged on every /log call  (default: demo-skill)
    #   ANTHROPIC_API_KEY provisioned into the vault instead of a plaintext config
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

GATEWAY = os.environ.get("VAR_GATEWAY", "http://127.0.0.1:8765")
SKILL_ID = os.environ.get("SKILL_ID", "demo-skill")


# ── HTTP helpers ───────────────────────────────────────────────────────────

def _req(method: str, path: str, payload: dict | None = None) -> dict:
    url = f"{GATEWAY}{path}"
    body = json.dumps(payload).encode() if payload else None
    headers = {
        "Content-Type": "application/json",
        "X-Skill-Id": SKILL_ID,
    }
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"error": exc.read().decode()}
    except OSError as exc:
        return {"error": str(exc)}


# ── VAR gateway API ────────────────────────────────────────────────────────

def health_check() -> bool:
    return _req("GET", "/health").get("status") == "healthy"


def provision_secret(key: str, value: str) -> None:
    """Store a credential in the enclave vault instead of a plaintext file."""
    result = _req("POST", "/vault/secret", {"key": key, "value": value})
    if result.get("status") != "ok":
        raise RuntimeError(f"vault error: {result}")


def log(msg: str) -> None:
    """Append an entry to the hash-chained evidence log."""
    result = _req("POST", "/log", {"msg": msg})
    if result.get("status") != "ok":
        raise RuntimeError(f"log error: {result}")


def get_evidence() -> dict:
    """Return the signed evidence bundle (stream hash + state hash)."""
    return _req("GET", "/evidence")


def get_attestation() -> dict:
    """Return the hardware attestation quote for this enclave session."""
    return _req("GET", "/attestation")


# ── Demo workflow ──────────────────────────────────────────────────────────

def main() -> None:
    print(f"[{SKILL_ID}] Connecting to VAR gateway at {GATEWAY} ...")
    if not health_check():
        print(f"ERROR: gateway unreachable at {GATEWAY}", file=sys.stderr)
        sys.exit(1)
    print(f"[{SKILL_ID}] Gateway healthy.\n")

    # Step 1 — provision the API key into the vault.
    # The key never touches a config file or env var of any child process.
    api_key = os.environ.get("ANTHROPIC_API_KEY", "sk-demo-key")
    provision_secret("ANTHROPIC_API_KEY", api_key)
    print(f"[{SKILL_ID}] API key provisioned into enclave vault.")

    # Step 2 — execute a workflow, logging each action into the evidence chain.
    # Every POST /log call advances the stream hash: H[n] = SHA-256(H[n-1] || msg)
    tasks = [
        "Starting document analysis workflow",
        "Fetched remote dataset: 42 records",
        "Classified 38 records as high-priority",
        "Wrote summary to /tmp/report.txt",
        "Workflow complete",
    ]
    print(f"[{SKILL_ID}] Executing workflow ({len(tasks)} steps) ...")
    for task in tasks:
        log(task)
        print(f"  logged: {task}")
        time.sleep(0.05)

    # Step 3 — retrieve the evidence bundle.
    # This is the cryptographic proof that covers every logged action above.
    evidence = get_evidence()
    print(f"\n[{SKILL_ID}] Evidence bundle:")
    print(f"  stream hash : {evidence.get('stream', 'n/a')}")
    print(f"  state  hash : {evidence.get('state', 'n/a')}")
    print(f"  signature   : {evidence.get('sig', 'n/a')}")

    # Step 4 — retrieve the attestation quote.
    # An independent verifier can use this to confirm the evidence was produced
    # inside a real TEE and bind the session root to the hardware measurement.
    attest = get_attestation()
    print(f"\n[{SKILL_ID}] Attestation:")
    pcr0 = attest.get("pcr0", "n/a")
    pk = attest.get("public_key", "n/a")
    print(f"  pcr0        : {pcr0[:32]}{'...' if len(pcr0) > 32 else ''}")
    print(f"  public_key  : {pk[:32]}{'...' if len(pk) > 32 else ''}")

    print(f"\n[{SKILL_ID}] Done. All {len(tasks)} actions verifiably logged.")


if __name__ == "__main__":
    main()
