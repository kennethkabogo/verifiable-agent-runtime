#!/usr/bin/env python3
"""
verify_evidence.py — VAR evidence bundle verifier.

Independently verifies that an evidence bundle produced by the VAR HTTP
gateway is cryptographically consistent with the session's attestation
document, with no trust placed in the gateway process itself.

Checks performed
────────────────
  1. Gateway reachable                  GET /health
  2. Bundle header fields               magic, version, session_id, nonce
  3. Bootstrap nonce integrity          SHA-256(doc ‖ session_id) == bootstrap_nonce
  4. L1 stream hash well-formed         64-char lowercase hex, anchored to nonce
  5. L2 state hash well-formed          64-char lowercase hex
  6. Ed25519 signature valid            sign(msg_161, privkey) verified with
                                        attested public key  (spec §3.1 + §3.2)
  7. Attestation document               PCR0 / public key present; sim detection
  8. COSE_Sign1 validation              cert chain → AWS Nitro root CA; ECDSA P-384
                                        signature over Sig_Structure (real hardware
                                        only; skipped in simulation mode)

Dependencies
────────────
  Ed25519 + COSE_Sign1 verification requires:
    pip install cryptography cbor2

Usage
─────
  python3 src/agent/verify_evidence.py [--json]
  VAR_GATEWAY=http://127.0.0.1:8765 python3 src/agent/verify_evidence.py
"""

import argparse
import base64
import hashlib
import json
import os
import struct
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

# Optional COSE_Sign1 support for Nitro attestation doc verification.
# Requires:  pip install cbor2 cryptography
try:
    import cbor2 as _cbor2
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature as _enc_dss
    from cryptography.x509 import (
        load_der_x509_certificate as _load_cert,
        load_pem_x509_certificate as _load_pem_cert,
    )
    from cryptography.exceptions import InvalidSignature as _InvalidSig
    HAS_COSE = True
except ImportError:
    HAS_COSE = False

# AWS Nitro Enclaves root CA certificate (DER).
# Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
# SHA256(ZIP):  8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c
# SHA256(DER):  3cbb6f612339e9290fc9c9349760e0f2535d8f8d257c1833995cdf810c1da36a
# Verify before trusting: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
_AWS_NITRO_ROOT_PEM = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL\n"
    b"MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD\n"
    b"VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4\n"
    b"MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL\n"
    b"DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG\n"
    b"BQuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb\n"
    b"48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE\n"
    b"h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF\n"
    b"R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC\n"
    b"MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW\n"
    b"rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N\n"
    b"IwLz3/Y=\n"
    b"-----END CERTIFICATE-----\n"
)

# Decode once at import time into DER bytes for fast comparison in _verify_nitro_cose.
if HAS_COSE:
    _AWS_NITRO_ROOT_DER: bytes = _load_pem_cert(_AWS_NITRO_ROOT_PEM).public_bytes(_ser.Encoding.DER)
else:
    _AWS_NITRO_ROOT_DER = b""  # populated once cryptography is available


def _verify_nitro_cose(doc_bytes: bytes) -> "tuple[bool, str, dict | None]":
    """
    Verify a Nitro COSE_Sign1 attestation document end-to-end.

    Steps:
      1. CBOR-decode the COSE_Sign1 structure (tag 18 or bare 4-element array).
      2. CBOR-decode the payload to extract the certificate chain.
      3. Verify each cert in the chain is signed by the next.
      4. Verify the chain root matches the embedded AWS Nitro root CA.
      5. Verify the COSE_Sign1 ECDSA P-384 signature with the leaf cert's key.

    Returns (ok, detail_string, payload_dict_or_None).
    """
    # 1. Parse outer COSE_Sign1
    try:
        obj = _cbor2.loads(doc_bytes)
        cose_arr = obj.value if hasattr(obj, "value") else obj
        if not isinstance(cose_arr, list) or len(cose_arr) != 4:
            return False, f"not a 4-element COSE_Sign1 (got {type(cose_arr).__name__})", None
        protected_bstr, _unprotected, payload_bstr, sig_bstr = cose_arr
    except Exception as exc:
        return False, f"CBOR outer parse failed: {exc}", None

    # 2. Parse payload
    try:
        payload = _cbor2.loads(payload_bstr)
    except Exception as exc:
        return False, f"CBOR payload parse failed: {exc}", None

    # 3. Extract certificate chain
    leaf_der  = payload.get("certificate")
    cabundle  = payload.get("cabundle") or []
    if leaf_der is None:
        return False, "payload missing 'certificate' field", None

    # Nitro cabundle order: [leaf_parent, ..., root] (leaf-to-root, leaf not included).
    # If verification fails on real hardware with "cert[0] not signed by cert[1]",
    # try reversing: chain_ders = [leaf_der] + list(reversed(cabundle))
    chain_ders = [leaf_der] + list(cabundle)
    try:
        certs = [_load_cert(der) for der in chain_ders]
    except Exception as exc:
        return False, f"DER cert parse failed: {exc}", None

    # 4a. Verify each cert is signed by the next in the chain
    for i in range(len(certs) - 1):
        try:
            issuer_pk = certs[i + 1].public_key()
            issuer_pk.verify(
                certs[i].signature,
                certs[i].tbs_certificate_bytes,
                _ec.ECDSA(certs[i].signature_hash_algorithm),
            )
        except _InvalidSig:
            return False, f"cert[{i}] not signed by cert[{i + 1}]", None
        except Exception as exc:
            return False, f"cert chain error at [{i}]: {exc}", None

    # 4b. Verify root cert matches the embedded AWS Nitro root CA
    root_der_actual = certs[-1].public_bytes(_ser.Encoding.DER)
    if root_der_actual != _AWS_NITRO_ROOT_DER:
        return False, "root cert does not match embedded AWS Nitro root CA", None

    # 5. Verify COSE_Sign1 signature (ES384: ECDSA P-384 + SHA-384, raw r‖s)
    sig_structure = _cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
    try:
        # P-384 raw signatures are exactly 48 bytes for r and 48 bytes for s.
        # An explicit length check prevents int.from_bytes from silently
        # producing wrong r/s values from a truncated or padded signature.
        if len(sig_bstr) != 96:
            return False, f"COSE_Sign1 signature wrong length: {len(sig_bstr)} (expected 96)", None
        r = int.from_bytes(sig_bstr[:48], "big")
        s = int.from_bytes(sig_bstr[48:], "big")
        der_sig  = _enc_dss(r, s)
        leaf_pk  = certs[0].public_key()
        leaf_pk.verify(der_sig, sig_structure, _ec.ECDSA(_hashes.SHA384()))
    except _InvalidSig:
        return False, "COSE_Sign1 ECDSA signature invalid", None
    except Exception as exc:
        return False, f"COSE signature verify error: {exc}", None

    depth = len(certs)
    try:
        from cryptography.x509.oid import NameOID as _NameOID
        cn_attrs = certs[0].subject.get_attributes_for_oid(_NameOID.COMMON_NAME)
        leaf_cn  = cn_attrs[0].value[:40] if cn_attrs else "(no CN)"
    except Exception:
        leaf_cn = "(unknown)"
    return True, f"chain depth={depth}, leaf={leaf_cn}", payload

# ANSI colour helpers (auto-disabled when stdout is not a tty or --json is used).
_USE_COLOR = sys.stdout.isatty()
PASS  = "\033[32m✓\033[0m" if _USE_COLOR else "PASS"
FAIL  = "\033[31m✗\033[0m" if _USE_COLOR else "FAIL"
WARN  = "\033[33m⚠\033[0m" if _USE_COLOR else "WARN"
BOLD  = "\033[1m"           if _USE_COLOR else ""
RESET = "\033[0m"           if _USE_COLOR else ""

# Accumulated check results for --json output.
_report: list[dict] = []
_current_section: str = ""


# ── HTTP helpers ────────────────────────────────────────────────────────────

def _get(path: str) -> dict:
    try:
        with urllib.request.urlopen(f"{GATEWAY}{path}", timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"_http_error": exc.code, "error": exc.read().decode()}
    except OSError as exc:
        print(f"\n{FAIL} Cannot reach gateway at {GATEWAY}: {exc}", file=sys.stderr)
        sys.exit(1)


# ── Reporting helpers ────────────────────────────────────────────────────────

def ok(label: str, detail: str = "") -> bool:
    _report.append({"section": _current_section, "label": label, "passed": True, "detail": detail})
    print(f"  {PASS}  {label}" + (f"  {detail}" if detail else ""))
    return True


def fail(label: str, detail: str = "") -> bool:
    _report.append({"section": _current_section, "label": label, "passed": False, "detail": detail})
    print(f"  {FAIL}  {label}" + (f"  {detail}" if detail else ""))
    return False


def warn(label: str, detail: str = "") -> None:
    _report.append({"section": _current_section, "label": label, "passed": None, "detail": detail})
    print(f"  {WARN}  {label}" + (f"  {detail}" if detail else ""))


def check(label: str, passed: bool, detail: str = "") -> bool:
    return ok(label, detail) if passed else fail(label, detail)


def section(title: str) -> None:
    global _current_section
    _current_section = title
    print(f"\n{BOLD}{title}{RESET}")


# ── Helpers ──────────────────────────────────────────────────────────────────

def is_hex256(s: str) -> bool:
    """Return True iff s is a 64-character lowercase hex string (256-bit hash)."""
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def build_evidence_message(
    sequence: int,
    prev_stream_hex: str,
    stream_hex: str,
    state_hex: str,
    session_id_hex: str,
) -> bytes:
    """
    Build the 161-byte message the enclave signs (spec §3.1 + §3.2 snapshot mode).

      Magic        ( 4)  b"VARE"
      FormatVer    ( 1)  0x01
      Sequence     ( 8)  u64 little-endian
      PrevL1Hash   (32)  H_stream at the previous evidence emission
      L1Hash       (32)  H_stream at this emission
      L2Hash       (32)  terminal state digest
      PayloadLen   ( 4)  u32 LE; 0 in snapshot mode
      SHA-256("")  (32)  SHA-256(b"") — snapshot mode placeholder
      SessionID    (16)  binds the signature to this session

    Total: 4+1+8+32+32+32+4+32+16 = 161 bytes
    """
    return (
        b"VARE"
        + bytes([0x01])
        + struct.pack("<Q", sequence)
        + bytes.fromhex(prev_stream_hex)
        + bytes.fromhex(stream_hex)
        + bytes.fromhex(state_hex)
        + struct.pack("<I", 0)
        + hashlib.sha256(b"").digest()
        + bytes.fromhex(session_id_hex)
    )


# ── Main verification ────────────────────────────────────────────────────────

def main(json_mode: bool = False) -> bool:
    global _USE_COLOR, PASS, FAIL, WARN, BOLD, RESET

    if json_mode:
        _USE_COLOR = False
        PASS = FAIL = WARN = BOLD = RESET = ""

    print(f"{BOLD}VAR Evidence Verifier{RESET}")
    print(f"Gateway : {GATEWAY}")

    all_ok = True

    # ── 1. Connectivity ────────────────────────────────────────────────────
    section("1. Connectivity")
    health = _get("/health")
    all_ok &= check("Gateway reachable and healthy", health.get("status") == "healthy")

    # ── 2. Fetch all payloads ──────────────────────────────────────────────
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

    # Show the session anchor early so humans can compare out-of-band.
    if session_id_hex:
        print(f"Session : {session_id_hex}")

    # ── 3. Bundle header fields ────────────────────────────────────────────
    section("2. Bundle header  (GET /session)")
    all_ok &= check("magic == VARB",   magic == "VARB",   f"got {magic!r}")
    all_ok &= check("version == 01",   version == "01",   f"got {version!r}")
    all_ok &= check("session_id present",
                    bool(session_id_hex),
                    f"{session_id_hex[:16]}…" if session_id_hex else "missing")
    all_ok &= check("bootstrap_nonce present",
                    bool(bootstrap_nonce_hex),
                    f"{bootstrap_nonce_hex[:16]}…" if bootstrap_nonce_hex else "missing")

    # ── 4. Bootstrap nonce integrity ───────────────────────────────────────
    section("3. Bootstrap nonce integrity  (spec §1.2)")
    print(f"   Recomputing SHA-256(attestation_doc ‖ session_id) independently…")
    try:
        doc_bytes = bytes.fromhex(doc_hex)
    except ValueError as exc:
        all_ok &= fail("Bootstrap nonce decode", f"attestation doc is not valid hex: {exc}")
        doc_bytes = None

    try:
        session_id_bytes = bytes.fromhex(session_id_hex)
    except ValueError as exc:
        all_ok &= fail("Bootstrap nonce decode", f"session_id is not valid hex: {exc}")
        session_id_bytes = None

    if doc_bytes is not None and session_id_bytes is not None:
        recomputed = hashlib.sha256(doc_bytes + session_id_bytes).hexdigest()
        nonce_ok   = recomputed == bootstrap_nonce_hex
        detail = (
            f"{bootstrap_nonce_hex[:24]}…"
            if nonce_ok
            else f"expected {recomputed[:16]}… got {bootstrap_nonce_hex[:16]}…"
        )
        all_ok &= check("SHA-256(doc ‖ session_id) == bootstrap_nonce", nonce_ok, detail)

    # ── 5. L1 stream hash + sequence ──────────────────────────────────────
    section("4. L1 stream hash  (PTY byte-stream chain, spec §2.1)")
    all_ok &= check("prev_stream present",
                    bool(prev_stream_hex),
                    f"{prev_stream_hex[:24]}…" if prev_stream_hex else "missing")
    all_ok &= check("prev_stream well-formed", is_hex256(prev_stream_hex),
                    f"{prev_stream_hex[:24]}…" if prev_stream_hex else "")
    all_ok &= check("stream present",
                    bool(stream_hex),
                    f"{stream_hex[:24]}…" if stream_hex else "missing")
    all_ok &= check("stream well-formed hex", is_hex256(stream_hex),
                    f"{stream_hex[:24]}…" if stream_hex else "")
    if stream_hex and stream_hex == bootstrap_nonce_hex:
        warn("stream == bootstrap nonce — no LOG entries recorded yet in this session")
    elif stream_hex:
        ok("stream differs from nonce — at least one LOG entry has been recorded")
    all_ok &= check("Sequence number present",
                    sequence is not None,
                    f"seq={sequence}" if sequence is not None else "missing")

    # ── 6. L2 state hash ──────────────────────────────────────────────────
    section("5. L2 state hash  (terminal visual state, spec §2.2)")
    all_ok &= check("Present",         bool(state_hex), "missing" if not state_hex else "")
    all_ok &= check("Well-formed hex", is_hex256(state_hex),
                    f"{state_hex[:24]}…" if state_hex else "")

    # ── 7. Ed25519 signature ───────────────────────────────────────────────
    section("6. Ed25519 signature  (spec §3.1 + §3.2 snapshot mode)")
    if sig_hex == "MOCK_SIG":
        warn("Signature is MOCK_SIG — gateway is running without real signing")
    elif not sig_hex:
        all_ok &= fail("Signature present", "missing")
    elif len(sig_hex) != 128:
        all_ok &= fail("Signature length", f"expected 128 hex chars, got {len(sig_hex)}")
    elif not HAS_CRYPTOGRAPHY:
        warn("cryptography package not installed — skipping Ed25519 verification",
             "run: pip install cryptography")
        ok("Signature present and well-formed", f"{sig_hex[:32]}…")
    else:
        try:
            pk_bytes  = bytes.fromhex(pk_hex)
            sig_bytes = bytes.fromhex(sig_hex)
            msg = build_evidence_message(
                sequence=sequence if sequence is not None else 0,
                prev_stream_hex=prev_stream_hex,
                stream_hex=stream_hex,
                state_hex=state_hex,
                session_id_hex=session_id_hex,
            )
            if len(msg) != 161:
                all_ok &= fail(
                    "Signature message construction",
                    f"expected 161 bytes, got {len(msg)} — likely a missing hash field",
                )
            else:
                pub_key = Ed25519PublicKey.from_public_bytes(pk_bytes)
                pub_key.verify(sig_bytes, msg)
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

    # ── 8. Attestation document ────────────────────────────────────────────
    section("7. Attestation document  (GET /attestation)")
    all_ok &= check("PCR0 present",
                    bool(pcr0_hex),
                    f"{pcr0_hex[:16]}…" if pcr0_hex else "missing")
    all_ok &= check("Public key present",
                    bool(pk_hex),
                    f"{pk_hex[:16]}…" if pk_hex else "missing")
    all_ok &= check("Doc present",
                    bool(doc_hex),
                    f"{len(doc_hex)//2} bytes" if doc_hex else "missing")

    is_sim = pcr0_hex == "aa" * 48
    if is_sim:
        warn("PCR0 is 0xAA…AA — simulation mode, not real Nitro hardware")
        warn("COSE_Sign1 validation skipped (doc is a mock, not a real NSM attestation)")

    # ── 9. COSE_Sign1 validation (real hardware only) ──────────────────────
    section("8. COSE_Sign1 attestation validation  (spec §4, real hardware only)")
    if is_sim:
        warn("Skipped — simulation mode detected (PCR0 == 0xAA…AA)")
    elif not doc_bytes:
        all_ok &= fail("Skipped — attestation doc missing or unparseable")
    elif not HAS_COSE:
        warn("cbor2 or cryptography not installed — skipping COSE_Sign1 validation",
             "run: pip install cbor2 cryptography")
    else:
        cose_ok, cose_detail, cose_payload = _verify_nitro_cose(doc_bytes)
        if cose_ok:
            ok("COSE_Sign1 structure parsed", cose_detail)
            ok("Cert chain valid (each cert signed by next)")
            ok("Root cert matches AWS Nitro root CA",
               "verify at aws-nitro-enclaves.amazonaws.com")
            ok("COSE_Sign1 ECDSA P-384 signature valid")
            # Cross-check PCR0 from the verified doc payload against gateway-reported value
            if cose_payload is not None:
                pcrs = cose_payload.get("pcrs") or {}
                pcr0_from_doc = pcrs.get(0)
                if pcr0_from_doc is not None:
                    pcr0_doc_hex = pcr0_from_doc.hex() if isinstance(pcr0_from_doc, bytes) else ""
                    all_ok &= check(
                        "PCR0 from doc matches gateway-reported PCR0",
                        pcr0_doc_hex == pcr0_hex,
                        f"{pcr0_doc_hex[:16]}…" if pcr0_doc_hex == pcr0_hex
                        else f"doc={pcr0_doc_hex[:16]}… gw={pcr0_hex[:16]}…",
                    )
        else:
            all_ok &= fail("COSE_Sign1 validation", cose_detail)

    # ── 10. Summary ────────────────────────────────────────────────────────
    print()
    print("─" * 60)
    if all_ok:
        print(f"{PASS} All verifiable checks passed.")
        if not json_mode:
            print()
            print("   The bootstrap nonce is cryptographically bound to the")
            print("   attestation document and session ID.  Every LOG entry")
            print("   extends the L1 chain from that anchor.  The Ed25519")
            print("   signature ties the current L1+L2 state to the enclave's")
            print("   attested public key.  On real Nitro hardware the COSE_Sign1")
            print("   attestation doc is verified against the AWS root CA,")
            print("   closing the chain of trust from silicon to evidence.")
    else:
        print(f"{FAIL} One or more checks FAILED.")

    if json_mode:
        print()
        print(json.dumps({
            "result": "pass" if all_ok else "fail",
            "gateway": GATEWAY,
            "session_id": session_id_hex,
            "checks": _report,
        }, indent=2))

    return all_ok


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify a VAR evidence bundle produced by the HTTP gateway.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="emit a machine-readable JSON summary to stdout (suppresses colour)",
    )
    args = parser.parse_args()

    passed = main(json_mode=args.json)
    sys.exit(0 if passed else 1)
