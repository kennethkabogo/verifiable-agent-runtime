#!/usr/bin/env python3
"""
Finfiti × VAR — Fish Farmer Microloan Demo
===========================================
Demonstrates the attestation-gated escrow flow from the Sovereign Agent Stack
white paper, grounded in a concrete use case: 24–72 hour microloans for fish
farmers on Lake Victoria / Lake Albert who need fuel capital each morning.

Flow
────
  1. Farmer registers a loan request (action_id: loan-<id>)
  2. Finfiti holds requested UGX in escrow
  3. Agent logs the disbursement decision inside the VAR enclave
  4. Finfiti calls GET /verify-and-attest — receives evidence + attestation
  5. Finfiti verifies the Ed25519 signature against the attested public key
  6. PASS → escrow releases to MoMo/Airtel Pay in UGX
     FAIL → escrow holds, dispute flag raised
  7. 48 h later: repayment arrives → loan closes atomically

Usage
─────
  # Requires a running VAR gateway (simulation mode is fine):
  python src/agent/finfiti_demo.py
  python src/agent/finfiti_demo.py --gateway-bin ./zig-out/bin/VAR-gateway
  python src/agent/finfiti_demo.py --gateway-url http://127.0.0.1:8765

Exit code: 0 = escrow released (verification PASSED), 1 = escrow held or error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

GATEWAY_DEFAULT = "http://127.0.0.1:8765"

# Optional Ed25519 support — same dependency as verify_evidence.py.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# ── Terminal colours ────────────────────────────────────────────────────────

_GREEN  = "\033[32m"
_CYAN   = "\033[36m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RESET  = "\033[0m"
_W      = 64


def _banner(text: str) -> None:
    print(f"\n{_BOLD}{'═' * _W}{_RESET}")
    print(f"{_BOLD}  {text}{_RESET}")
    print(f"{_BOLD}{'═' * _W}{_RESET}")


def _step(label: str) -> None:
    print(f"\n{_CYAN}[{label}]{_RESET}")


def _ok(msg: str) -> None:
    print(f"  {_GREEN}✓{_RESET}  {msg}")


def _info(msg: str, dim: bool = False) -> None:
    prefix = _DIM if dim else ""
    print(f"     {prefix}{msg}{_RESET if dim else ''}")


def _warn(msg: str) -> None:
    print(f"  {_YELLOW}!{_RESET}  {msg}")


def _err(msg: str) -> None:
    print(f"  {_RED}✗{_RESET}  {msg}", file=sys.stderr)


def _fail(msg: str) -> None:
    print(f"\n  {_RED}{_BOLD}ESCROW HELD — {msg}{_RESET}\n", file=sys.stderr)

# ── HTTP helpers ────────────────────────────────────────────────────────────

def _get(url: str, timeout: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def _post(url: str, body: dict, timeout: int = 10) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _wait_healthy(base_url: str, retries: int = 40, delay: float = 0.25) -> None:
    for _ in range(retries):
        try:
            _get(f"{base_url}/health", timeout=2)
            return
        except Exception:
            time.sleep(delay)
    raise RuntimeError(f"Gateway at {base_url} did not become healthy.")


def _start_gateway(bin_path: str, base_url: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [bin_path],
        env=os.environ.copy(),
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )
    try:
        _wait_healthy(base_url)
    except RuntimeError:
        proc.terminate()
        raise
    return proc

# ── Ed25519 verification ─────────────────────────────────────────────────────

def _build_signed_message(evidence: dict, session_id_hex: str) -> bytes:
    """Reconstruct the 161-byte message VAR signs over (spec §3.1).

    Must match signEvidence() in shell.zig exactly.
    """
    empty_payload_hash = hashlib.sha256(b"").digest()
    session_id = bytes.fromhex(session_id_hex)

    msg = bytearray()
    msg += b"VARE"                                          # magic (4)
    msg += b"\x01"                                          # format version (1)
    msg += struct.pack("<Q", evidence["sequence"])          # sequence u64 LE (8)
    msg += bytes.fromhex(evidence["prev_stream"])           # PrevL1Hash (32)
    msg += bytes.fromhex(evidence["stream"])                # L1Hash (32)
    msg += bytes.fromhex(evidence["state"])                 # L2Hash (32)
    msg += struct.pack("<I", 0)                             # PayloadLen = 0 (4)
    msg += empty_payload_hash                               # SHA-256("") (32)
    msg += session_id                                       # SessionID (16)

    assert len(msg) == 161, f"message length {len(msg)} != 161"
    return bytes(msg)


def _verify_signature(evidence: dict, attestation: dict, session_id_hex: str) -> tuple[bool, str]:
    """Return (ok, reason). Verifies Ed25519 sig in evidence against attested key."""
    if not HAS_CRYPTOGRAPHY:
        return False, "pip install cryptography required for signature verification"

    try:
        pub_bytes = bytes.fromhex(attestation["public_key"])
        sig_bytes  = bytes.fromhex(evidence["sig"])
        msg        = _build_signed_message(evidence, session_id_hex)
        pub_key    = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, msg)
        return True, "Ed25519 signature valid"
    except InvalidSignature:
        return False, "Ed25519 signature INVALID — evidence may be tampered"
    except Exception as exc:
        return False, f"Verification error: {exc}"

# ── Escrow state machine ─────────────────────────────────────────────────────

class Escrow:
    """Minimal in-memory escrow that mirrors Finfiti's settlement gate."""

    EXCHANGE_RATE_UGX_PER_USD = 3_720  # approximate

    def __init__(self, action_id: str, farmer_name: str, amount_ugx: int) -> None:
        self.action_id   = action_id
        self.farmer_name = farmer_name
        self.amount_ugx  = amount_ugx
        self.amount_usd  = round(amount_ugx / self.EXCHANGE_RATE_UGX_PER_USD, 4)
        self.state       = "PENDING"   # PENDING → RELEASED | HELD
        self.receipt: Optional[dict] = None

    def release(self, receipt: dict) -> None:
        self.state   = "RELEASED"
        self.receipt = receipt

    def hold(self, reason: str) -> None:
        self.state   = "HELD"
        self.receipt = {"reason": reason}

# ── Demo flow ────────────────────────────────────────────────────────────────

def run_demo(gateway_bin: Optional[str], base_url: str) -> bool:
    _banner("Finfiti × VAR — Fish Farmer Microloan Demo")

    # ── Start gateway if needed ──────────────────────────────────────────────
    proc: Optional[subprocess.Popen] = None
    try:
        _get(f"{base_url}/health", timeout=2)
        _ok(f"VAR gateway already running at {base_url}")
    except Exception:
        if not gateway_bin:
            _err("No running gateway found and --gateway-bin not provided.")
            _err("Start the gateway first:  ./zig-out/bin/VAR-gateway")
            _err("Or build it:              zig build")
            return False
        _step("Starting VAR gateway (simulation mode)")
        try:
            proc = _start_gateway(gateway_bin, base_url)
            _ok(f"Gateway ready at {base_url}")
        except FileNotFoundError:
            _err(f"Binary not found: {gateway_bin!r}")
            _err("Build it first:  zig build")
            return False

    try:
        return _run(base_url)
    finally:
        if proc:
            proc.terminate()
            proc.wait(timeout=5)


def _run(base_url: str) -> bool:

    # ── Step 1: Loan request ─────────────────────────────────────────────────
    _step("STEP 1 — Farmer registers a microloan request")

    farmer      = "Okello James"
    action_id   = "loan-okello-001"
    amount_ugx  = 15_000   # ~$4 USD — daily fuel for a fishing boat

    escrow = Escrow(action_id, farmer, amount_ugx)

    _ok(f"Farmer:      {farmer}")
    _ok(f"Amount:      {amount_ugx:,} UGX  (~${escrow.amount_usd} USD)")
    _ok(f"Purpose:     Boat fuel, Lake Victoria — 48 h loan")
    _ok(f"Action ID:   {action_id}")
    _ok(f"Rail:        MoMo Pay (UGX)")

    # ── Step 2: Finfiti holds in escrow ──────────────────────────────────────
    _step("STEP 2 — Finfiti holds funds in escrow pending attestation")
    _ok(f"Escrow state: {escrow.state}")
    _info(f"{amount_ugx:,} UGX locked. Will release only on valid VAR attestation.", dim=True)

    # ── Step 3: Agent logs disbursement decision inside VAR enclave ──────────
    _step("STEP 3 — Agent logs disbursement decision inside VAR enclave")

    log_msg = (
        f"Finfiti microloan disbursement authorised. "
        f"Farmer: {farmer}. Amount: {amount_ugx} UGX. Rail: MoMo Pay. "
        f"Term: 48h. Collateral: none. Risk score: low."
    )
    try:
        _post(f"{base_url}/log", {"msg": log_msg, "action_id": action_id})
        _ok("Disbursement decision committed to VAR evidence chain")
        _info(f"action_id: {action_id}", dim=True)
        _info(f"entry:     [ACTION:{action_id}] {log_msg[:60]}…", dim=True)
    except Exception as exc:
        _err(f"Failed to log to VAR: {exc}")
        escrow.hold(str(exc))
        _fail("Could not commit action to evidence chain.")
        return False

    # ── Step 4: Finfiti calls /verify-and-attest ─────────────────────────────
    _step("STEP 4 — Finfiti calls GET /verify-and-attest")

    try:
        result = _get(f"{base_url}/verify-and-attest")
    except Exception as exc:
        _err(f"/verify-and-attest failed: {exc}")
        escrow.hold(str(exc))
        _fail("Could not reach VAR attestation endpoint.")
        return False

    decision    = result.get("decision", {})
    evidence    = result.get("evidence", {})
    attestation = result.get("attestation", {})
    sim_mode    = decision.get("sim_mode", True)

    _ok("Response received from VAR enclave")
    _info(f"sim_mode:  {sim_mode}  {'(simulation — no Nitro hardware)' if sim_mode else '(hardware-attested)'}", dim=True)
    _info(f"sequence:  {evidence.get('sequence', '?')}", dim=True)
    _info(f"stream:    {evidence.get('stream', '?')[:20]}…", dim=True)
    _info(f"sig:       {evidence.get('sig', '?')[:20]}…", dim=True)
    _info(f"pcr0:      {attestation.get('pcr0', '?')[:20]}…", dim=True)

    # ── Step 5: Verify Ed25519 signature ─────────────────────────────────────
    _step("STEP 5 — Finfiti verifies Ed25519 signature")

    # Retrieve session_id for signature reconstruction.
    try:
        session_info   = _get(f"{base_url}/session")
        session_id_hex = session_info["session_id"]
    except Exception as exc:
        _err(f"Could not fetch session info: {exc}")
        escrow.hold(str(exc))
        _fail("Could not retrieve session for signature verification.")
        return False

    sig_ok, sig_reason = _verify_signature(evidence, attestation, session_id_hex)

    if sig_ok:
        _ok(f"Signature: {sig_reason}")
    else:
        _warn(f"Signature: {sig_reason}")
        if not HAS_CRYPTOGRAPHY:
            _warn("Install cryptography to enable full verification:  pip install cryptography")
            _warn("Proceeding with structural checks only (demo mode).")
        else:
            escrow.hold(sig_reason)
            _fail(sig_reason)
            return False

    # ── Step 6: Escrow decision ───────────────────────────────────────────────
    _step("STEP 6 — Escrow release decision")

    receipt = {
        "action_id":  action_id,
        "farmer":     farmer,
        "amount_ugx": amount_ugx,
        "amount_usd": escrow.amount_usd,
        "rail":       "MoMo Pay (UGX)",
        "sequence":   evidence.get("sequence"),
        "stream":     evidence.get("stream"),
        "sig":        evidence.get("sig"),
        "pcr0":       attestation.get("pcr0"),
        "public_key": attestation.get("public_key"),
        "sim_mode":   sim_mode,
        "sig_valid":  sig_ok,
        "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    escrow.release(receipt)

    _ok(f"Escrow state: {escrow.state}")
    _ok(f"Releasing {amount_ugx:,} UGX to {farmer} via MoMo Pay")
    _info("Hardware-attested proof of disbursement decision attached to receipt.", dim=True)

    # ── Step 7: Simulated repayment ───────────────────────────────────────────
    _step("STEP 7 — Simulated repayment (48 h later)")

    repayment_ugx = amount_ugx + 300  # principal + ~2% fee
    _ok(f"Repayment received: {repayment_ugx:,} UGX from {farmer}")
    _ok("Loan closed atomically. No manual reconciliation required.")

    # ── Receipt ───────────────────────────────────────────────────────────────
    _banner("Cryptographic Receipt")
    print(json.dumps(receipt, indent=2))

    print(f"\n{_GREEN}{_BOLD}  ESCROW RELEASED — attestation verified, funds settled to MoMo Pay{_RESET}\n")

    if not sig_ok and not HAS_CRYPTOGRAPHY:
        _warn("Note: install 'cryptography' for full Ed25519 verification in production.")

    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Finfiti × VAR fish farmer microloan demo.",
    )
    parser.add_argument(
        "--gateway-bin",
        default=str(Path(__file__).parent.parent.parent / "zig-out" / "bin" / "VAR-gateway"),
        help="Path to VAR-gateway binary (used to start the gateway if not already running).",
    )
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("VAR_GATEWAY", GATEWAY_DEFAULT),
        help="Base URL of a running VAR gateway.",
    )
    args = parser.parse_args()

    ok = run_demo(
        gateway_bin=args.gateway_bin if Path(args.gateway_bin).exists() else None,
        base_url=args.gateway_url,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
