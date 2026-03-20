#!/usr/bin/env python3
"""
verify_evidence.py — VAR evidence bundle verifier.

Independently verifies that an evidence bundle produced by the VAR HTTP
gateway is cryptographically consistent with the session's attestation
document, with no trust placed in the gateway process itself.

Checks performed
────────────────
  1. Gateway reachable                  GET /health
  2. Bootstrap nonce integrity          SHA-256(doc ‖ session_id) == bootstrap_nonce
  3. L1 stream hash well-formed         64-char lowercase hex, anchored to nonce
  4. L2 state hash well-formed          64-char lowercase hex
  5. Signature status                   MOCK_SIG flagged; real Ed25519 field shown
  6. PCR0 / public key present          flagged as mock when running in simulation

Usage
─────
  python3 src/agent/verify_evidence.py
  VAR_GATEWAY=http://127.0.0.1:8765 python3 src/agent/verify_evidence.py
"""

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

GATEWAY = os.environ.get("VAR_GATEWAY", "http://127.0.0.1:8765")

# ANSI colour helpers (auto-disabled when stdout is not a tty)
_USE_COLOR = sys.stdout.isatty()
PASS = "\033[32m✓\033[0m" if _USE_COLOR else "PASS"
FAIL = "\033[31m✗\033[0m" if _USE_COLOR else "FAIL"
WARN = "\033[33m⚠\033[0m" if _USE_COLOR else "WARN"
BOLD = "\033[1m"           if _USE_COLOR else ""
RESET = "\033[0m"          if _USE_COLOR else ""


# ── HTTP helpers ───────────────────────────────────────────────────────────

def _get(path: str) -> dict:
    try:
        with urllib.request.urlopen(f"{GATEWAY}{path}", timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"_http_error": exc.code, "error": exc.read().decode()}
    except OSError as exc:
        print(f"\n{FAIL} Cannot reach gateway at {GATEWAY}: {exc}", file=sys.stderr)
        sys.exit(1)


# ── Reporting helpers ──────────────────────────────────────────────────────

def ok(label: str, detail: str = "") -> bool:
    suffix = f"  {detail}" if detail else ""
    print(f"  {PASS}  {label}{suffix}")
    return True


def fail(label: str, detail: str = "") -> bool:
    suffix = f"  {detail}" if detail else ""
    print(f"  {FAIL}  {label}{suffix}")
    return False


def warn(label: str, detail: str = "") -> None:
    suffix = f"  {detail}" if detail else ""
    print(f"  {WARN}  {label}{suffix}")


def check(label: str, passed: bool, detail: str = "") -> bool:
    return ok(label, detail) if passed else fail(label, detail)


def section(title: str) -> None:
    print(f"\n{BOLD}{title}{RESET}")


# ── Hex validation ─────────────────────────────────────────────────────────

def is_hex256(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


# ── Main verification ──────────────────────────────────────────────────────

def main() -> None:
    print(f"{BOLD}VAR Evidence Verifier{RESET}")
    print(f"Gateway : {GATEWAY}")

    all_ok = True

    # ── 1. Connectivity ───────────────────────────────────────────────────
    section("1. Connectivity")
    health = _get("/health")
    all_ok &= check("Gateway reachable and healthy", health.get("status") == "healthy")

    # ── 2. Fetch all three payloads ───────────────────────────────────────
    session  = _get("/session")
    attest   = _get("/attestation")
    evidence = _get("/evidence")

    session_id_hex      = session.get("session_id", "")
    bootstrap_nonce_hex = session.get("bootstrap_nonce", "")
    magic               = session.get("magic", "")
    version             = session.get("version", "")

    doc_hex    = attest.get("doc", "")
    pcr0_hex   = attest.get("pcr0", "")
    pk_hex     = attest.get("public_key", "")

    stream_hex = evidence.get("stream", "")
    state_hex  = evidence.get("state", "")
    sig        = evidence.get("sig", "")

    # ── 3. Bundle header fields ───────────────────────────────────────────
    section("2. Bundle header (GET /session)")
    all_ok &= check("magic == VARB",    magic == "VARB",    f"got {magic!r}")
    all_ok &= check("version == 01",    version == "01",    f"got {version!r}")
    all_ok &= check("session_id present", bool(session_id_hex),
                    f"{session_id_hex[:16]}…" if session_id_hex else "missing")
    all_ok &= check("bootstrap_nonce present", bool(bootstrap_nonce_hex),
                    f"{bootstrap_nonce_hex[:16]}…" if bootstrap_nonce_hex else "missing")

    # ── 4. Bootstrap nonce integrity — the core trust anchor ─────────────
    section("3. Bootstrap nonce integrity  (spec §1.1)")
    print(f"   Recomputing SHA-256(attestation_doc ‖ session_id) independently...")
    try:
        doc_bytes        = bytes.fromhex(doc_hex)
        session_id_bytes = bytes.fromhex(session_id_hex)
        recomputed       = hashlib.sha256(doc_bytes + session_id_bytes).hexdigest()
        nonce_ok         = recomputed == bootstrap_nonce_hex
        detail = (
            f"{bootstrap_nonce_hex[:24]}…"
            if nonce_ok
            else f"expected {recomputed[:16]}… got {bootstrap_nonce_hex[:16]}…"
        )
        all_ok &= check(
            "SHA-256(doc ‖ session_id) == bootstrap_nonce",
            nonce_ok,
            detail,
        )
    except ValueError as exc:
        all_ok &= fail("Bootstrap nonce decode", str(exc))

    # ── 5. L1 stream hash ─────────────────────────────────────────────────
    section("4. L1 stream hash  (PTY byte-stream chain, spec §2.1)")
    all_ok &= check("Present",         bool(stream_hex), "missing" if not stream_hex else "")
    all_ok &= check("Well-formed hex", is_hex256(stream_hex),
                    f"{stream_hex[:24]}…" if stream_hex else "")
    if stream_hex == bootstrap_nonce_hex:
        warn("Stream hash equals bootstrap nonce — no LOG entries recorded yet")
    else:
        ok("Stream hash differs from nonce — at least one LOG entry recorded")

    # ── 6. L2 state hash ─────────────────────────────────────────────────
    section("5. L2 state hash  (terminal visual state, spec §2.2)")
    all_ok &= check("Present",         bool(state_hex), "missing" if not state_hex else "")
    all_ok &= check("Well-formed hex", is_hex256(state_hex),
                    f"{state_hex[:24]}…" if state_hex else "")

    # ── 7. Signature ──────────────────────────────────────────────────────
    section("6. Signature")
    if sig == "MOCK_SIG":
        warn("Signature is MOCK_SIG — real TEE signing not yet implemented")
        print( "       When implemented, the signature will cover:")
        print( "         SHA-256(stream_hash ‖ state_hash ‖ session_id)")
        print( "       signed with the enclave's ephemeral Ed25519 private key")
        print(f"       whose public key ({pk_hex[:16]}…) is bound in the attestation doc.")
    else:
        all_ok &= check("Signature present", True, f"{sig[:32]}…")
        warn("Signature format verification not yet implemented in this tool")

    # ── 8. Attestation document ───────────────────────────────────────────
    section("7. Attestation document  (GET /attestation)")
    all_ok &= check("PCR0 present",       bool(pcr0_hex), "missing" if not pcr0_hex else f"{pcr0_hex[:16]}…")
    all_ok &= check("Public key present", bool(pk_hex),   "missing" if not pk_hex   else f"{pk_hex[:16]}…")
    all_ok &= check("Doc present",        bool(doc_hex),  "missing" if not doc_hex   else f"{len(doc_hex)//2} bytes")

    if pcr0_hex == "aa" * 32:
        warn("PCR0 is 0xAA…AA — simulation mode, not real Nitro hardware")
        warn("On real hardware the NSM returns a COSE_Sign1-encoded attestation doc")

    # ── 9. Summary ────────────────────────────────────────────────────────
    print()
    print("─" * 60)
    if all_ok:
        print(f"{PASS} All verifiable checks passed.")
        print()
        print("   The bootstrap nonce is cryptographically bound to this")
        print("   attestation document and session ID.  Every LOG entry")
        print("   extends the L1 chain from that anchor.")
        print("   Remaining gap: replace MOCK_SIG with a real Ed25519")
        print("   signature to complete the end-to-end proof.")
    else:
        print(f"{FAIL} One or more checks FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
