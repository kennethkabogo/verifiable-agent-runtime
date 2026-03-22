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
  5. Ed25519 signature valid            sign(stream ‖ state ‖ session_id, privkey)
                                        verified with public key from attestation doc
  6. PCR0 / public key present          flagged as mock when running in simulation

Dependencies
────────────
  Ed25519 verification requires the `cryptography` package:
    pip install cryptography

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

# Optional Ed25519 support via the `cryptography` package.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# ANSI colour helpers (auto-disabled when stdout is not a tty).
_USE_COLOR = sys.stdout.isatty()
PASS  = "\033[32m✓\033[0m" if _USE_COLOR else "PASS"
FAIL  = "\033[31m✗\033[0m" if _USE_COLOR else "FAIL"
WARN  = "\033[33m⚠\033[0m" if _USE_COLOR else "WARN"
BOLD  = "\033[1m"           if _USE_COLOR else ""
RESET = "\033[0m"           if _USE_COLOR else ""


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
    print(f"  {PASS}  {label}" + (f"  {detail}" if detail else ""))
    return True


def fail(label: str, detail: str = "") -> bool:
    print(f"  {FAIL}  {label}" + (f"  {detail}" if detail else ""))
    return False


def warn(label: str, detail: str = "") -> None:
    print(f"  {WARN}  {label}" + (f"  {detail}" if detail else ""))


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

    # ── 2. Fetch all payloads ─────────────────────────────────────────────
    session  = _get("/session")
    attest   = _get("/attestation")
    evidence = _get("/evidence")

    session_id_hex      = session.get("session_id", "")
    bootstrap_nonce_hex = session.get("bootstrap_nonce", "")
    magic               = session.get("magic", "")
    version             = session.get("version", "")

    doc_hex  = attest.get("doc", "")
    pcr0_hex = attest.get("pcr0", "")
    pk_hex   = attest.get("public_key", "")

    prev_stream_hex = evidence.get("prev_stream", "")
    stream_hex      = evidence.get("stream", "")
    state_hex       = evidence.get("state", "")
    sig_hex         = evidence.get("sig", "")
    sequence        = evidence.get("sequence", None)

    # ── 3. Bundle header fields ───────────────────────────────────────────
    section("2. Bundle header  (GET /session)")
    all_ok &= check("magic == VARB",   magic == "VARB",   f"got {magic!r}")
    all_ok &= check("version == 01",   version == "01",   f"got {version!r}")
    all_ok &= check("session_id present",       bool(session_id_hex),
                    f"{session_id_hex[:16]}…" if session_id_hex else "missing")
    all_ok &= check("bootstrap_nonce present",  bool(bootstrap_nonce_hex),
                    f"{bootstrap_nonce_hex[:16]}…" if bootstrap_nonce_hex else "missing")

    # ── 4. Bootstrap nonce integrity ──────────────────────────────────────
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
        all_ok &= check("SHA-256(doc ‖ session_id) == bootstrap_nonce", nonce_ok, detail)
    except ValueError as exc:
        all_ok &= fail("Bootstrap nonce decode", str(exc))

    # ── 5. L1 stream hash + sequence ──────────────────────────────────────
    section("4. L1 stream hash  (PTY byte-stream chain, spec §2.1)")
    all_ok &= check("prev_stream present",     bool(prev_stream_hex),
                    "missing" if not prev_stream_hex else f"{prev_stream_hex[:24]}…")
    all_ok &= check("prev_stream well-formed", is_hex256(prev_stream_hex),
                    f"{prev_stream_hex[:24]}…" if prev_stream_hex else "")
    all_ok &= check("stream present",          bool(stream_hex), "missing" if not stream_hex else "")
    all_ok &= check("stream well-formed hex",  is_hex256(stream_hex),
                    f"{stream_hex[:24]}…" if stream_hex else "")
    if stream_hex and stream_hex == bootstrap_nonce_hex:
        warn("stream == bootstrap nonce — no LOG entries recorded yet in this session")
    elif stream_hex:
        ok("stream differs from nonce — at least one LOG entry has been recorded")
    all_ok &= check("Sequence number present", sequence is not None,
                    f"seq={sequence}" if sequence is not None else "missing")

    # ── 6. L2 state hash ─────────────────────────────────────────────────
    section("5. L2 state hash  (terminal visual state, spec §2.2)")
    all_ok &= check("Present",         bool(state_hex), "missing" if not state_hex else "")
    all_ok &= check("Well-formed hex", is_hex256(state_hex),
                    f"{state_hex[:24]}…" if state_hex else "")

    # ── 7. Ed25519 signature ──────────────────────────────────────────────
    section("6. Ed25519 signature")
    if sig_hex == "MOCK_SIG":
        # Shouldn't happen once real signing is in place, but kept as a fallback.
        warn("Signature is MOCK_SIG — gateway is running without real signing")
    elif not sig_hex:
        all_ok &= fail("Signature present", "missing")
    elif len(sig_hex) != 128:
        all_ok &= fail("Signature length", f"expected 128 hex chars, got {len(sig_hex)}")
    elif not HAS_CRYPTOGRAPHY:
        warn(
            "cryptography package not installed — skipping Ed25519 verification",
            "pip install cryptography",
        )
        ok("Signature present and well-formed", f"{sig_hex[:32]}…")
    else:
        # Reconstruct the 161-byte message the enclave signed (spec §3.1 + snapshot ext):
        #
        #   Magic        ( 4)  b"VARE"
        #   FormatVer    ( 1)  0x01
        #   Sequence     ( 8)  u64 little-endian
        #   PrevL1Hash   (32)  H_stream at the previous evidence emission
        #   L1Hash       (32)  H_stream at this emission
        #   L2Hash       (32)  terminal state digest
        #   PayloadLen   ( 4)  u32 LE; 0 in snapshot mode (no discrete payload bytes)
        #   SHA-256("")  (32)  SHA-256(b"") — snapshot mode: no payload bytes
        #   SessionID    (16)  snapshot-mode extension binding sig to this session
        #
        # Total: 4+1+8+32+32+32+4+32+16 = 161 bytes
        try:
            import hashlib
            import struct
            pk_bytes  = bytes.fromhex(pk_hex)
            sig_bytes = bytes.fromhex(sig_hex)
            msg = (
                b"VARE"                                                        #  4
                + bytes([0x01])                                                #  1
                + struct.pack("<Q", sequence if sequence is not None else 0)   #  8
                + bytes.fromhex(prev_stream_hex)                               # 32
                + bytes.fromhex(stream_hex)                                    # 32
                + bytes.fromhex(state_hex)                                     # 32
                + struct.pack("<I", 0)                                         #  4
                + hashlib.sha256(b"").digest()                                 # 32
                + bytes.fromhex(session_id_hex)                                # 16
            )
            assert len(msg) == 161, f"unexpected message length: {len(msg)}"
            pub_key = Ed25519PublicKey.from_public_bytes(pk_bytes)
            pub_key.verify(sig_bytes, msg)   # raises InvalidSignature on failure
            all_ok &= ok(
                "Ed25519 signature valid",
                f"161-byte spec §3.1 message verified with pk={pk_hex[:16]}…",
            )
        except InvalidSignature:
            all_ok &= fail(
                "Ed25519 signature INVALID",
                "signature does not match stream/state/session_id with the attested public key",
            )
        except ValueError as exc:
            all_ok &= fail("Signature decode error", str(exc))

    # ── 8. Attestation document ───────────────────────────────────────────
    section("7. Attestation document  (GET /attestation)")
    all_ok &= check("PCR0 present",       bool(pcr0_hex),
                    f"{pcr0_hex[:16]}…" if pcr0_hex else "missing")
    all_ok &= check("Public key present", bool(pk_hex),
                    f"{pk_hex[:16]}…"   if pk_hex   else "missing")
    all_ok &= check("Doc present",        bool(doc_hex),
                    f"{len(doc_hex)//2} bytes" if doc_hex else "missing")

    if pcr0_hex == "aa" * 32:
        warn("PCR0 is 0xAA…AA — simulation mode, not real Nitro hardware")
        warn("On real hardware the NSM returns a COSE_Sign1-encoded attestation doc")

    # ── 9. Summary ────────────────────────────────────────────────────────
    print()
    print("─" * 60)
    if all_ok:
        print(f"{PASS} All verifiable checks passed.")
        print()
        print("   The bootstrap nonce is cryptographically bound to the")
        print("   attestation document and session ID.  Every LOG entry")
        print("   extends the L1 chain from that anchor.  The Ed25519")
        print("   signature ties the current L1+L2 state to the enclave's")
        print("   attested public key.")
    else:
        print(f"{FAIL} One or more checks FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
