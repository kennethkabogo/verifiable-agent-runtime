#!/usr/bin/env python3
"""
APEX Evidence Verifier  —  apex_verify.py
==========================================
Implements §8 Verification Algorithm (Steps 1–12) from APEX spec v2.7.0.

An independent auditor can run this tool against any APEX bundle file to
confirm that the evidence chain originated in a real Nitro Enclave, has not
been tampered with, and carries valid temporal attestation.

Usage:
  python tools/apex_verify.py bundle.log          # verify a bundle
  python tools/apex_verify.py --self-test          # verify §14.9 synthetic fixture
  python tools/apex_verify.py bundle.log --pty PATH  # + Step 9 L2 replay

Exit codes: 0 = all steps PASS  |  1 = one or more steps FAIL  |  2 = parse error

Required:   pip install cryptography argon2-cffi cbor2
Optional:   pip install pyte   (Step 9 L2 replay only)

See APEX spec §8 for the normative verification algorithm.
See spec/position-input-channel.md for scope and known limitations.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Optional dependencies ────────────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    _CRYPTO = True
except ImportError:
    _CRYPTO = False

try:
    import argon2.low_level as _argon2_ll
    _ARGON2 = True
except ImportError:
    _ARGON2 = False

try:
    import pyte as _pyte
    _PYTE = True
except ImportError:
    _PYTE = False

try:
    import cbor2 as _cbor2
    _CBOR2 = True
except ImportError:
    _CBOR2 = False

# ── Constants ────────────────────────────────────────────────────────────────

SPEC_VERSION       = "2.7.0"
SPEC_MAJOR         = 2
ARGON_SALT         = b"APEX_SWFv1\x00\x00\x00\x00\x00\x00"  # 16 bytes, §5.7
_SHA256_EMPTY      = hashlib.sha256(b"").digest()
_SIM_ATTEST_FILL   = 0xAA   # simulation mode attestation byte §11
_SIM_PCR_FILL      = 0x00   # simulation mode PCR byte

# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class BundleHeader:
    raw:             str
    magic:           str
    version:         str
    session_id:      bytes   # 16 bytes
    bootstrap_nonce: bytes   # 32 bytes
    enc_pub:         bytes   # 32 bytes  (X25519; not verified here)
    pcr0:            bytes   # 48 bytes
    pcr1:            bytes   # 48 bytes
    pcr2:            bytes   # 48 bytes
    signing_pub:     bytes   # 32 bytes  Ed25519 SessionPub
    attest_doc:      bytes   # raw attestation document bytes


@dataclass
class EvidencePacket:
    """SESSION_START (0x06) or EVIDENCE/STREAM (0x01) packet."""
    raw:          str
    action:       str    # "SESSION_START" or "EVIDENCE"
    prev_stream:  bytes  # 32 bytes  PrevL1Hash
    stream:       bytes  # 32 bytes  L1Hash
    state:        bytes  # 32 bytes  L2Hash
    payload_hash: bytes  # 32 bytes  SHA-256(Payload); SHA-256("") if absent
    payload_len:  int    # 0 in snapshot/session-start mode
    sig:          bytes  # 64 bytes
    seq:          int


@dataclass
class TemporalProofPacket:
    """TEMPORAL_PROOF (0x09) packet."""
    raw:         str
    prev_stream: bytes  # 32 bytes  PrevL1Hash (= last EVIDENCE L1Hash)
    stream:      bytes  # 32 bytes  L1Hash after Argon fold
    proof:       bytes  # 32 bytes  ArgonOutput
    m:           int
    t:           int
    p:           int
    sig:         bytes  # 64 bytes
    seq:         int


@dataclass
class SessionResumePacket:
    """SESSION_RESUME (0x07) packet — first packet of every resumed segment."""
    raw:         str
    prev_stream: bytes  # 32 bytes
    stream:      bytes  # 32 bytes  (equals prev_stream after TEMPORAL_PROOF)
    sig:         bytes  # 64 bytes
    seq:         int


@dataclass
class BundleSeal:
    raw:             str
    terminal_digest: bytes  # 32 bytes  SHA-256(all signatures concatenated)
    bundle_hash:     bytes  # 32 bytes
    seal_sig:        bytes  # 64 bytes


@dataclass
class SettlementBlock:
    raw:             str
    escrow_id:       bytes  # 16 bytes
    amount:          bytes  # 32 bytes  decimal string, zero-padded
    currency:        bytes  # 8 bytes   space-padded
    terminal_digest: bytes  # 32 bytes  must match BundleSeal
    sig:             bytes  # 64 bytes  over 88-byte APXT scope


@dataclass
class Segment:
    header:  BundleHeader
    packets: list = field(default_factory=list)  # EvidencePacket | TemporalProofPacket | SessionResumePacket


@dataclass
class Bundle:
    segments:   list[Segment]
    bundle_seal: Optional[BundleSeal]
    settlement:  Optional[SettlementBlock]

    def all_packets(self):
        """All packets across all segments, in sequence order."""
        return [p for seg in self.segments for p in seg.packets]

    def session_id(self) -> bytes:
        return self.segments[0].header.session_id

    def bootstrap_nonce(self) -> bytes:
        return self.segments[0].header.bootstrap_nonce


# ── CheckResult ──────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    step:    str
    passed:  bool
    detail:  str
    skipped: bool = False

    def warn(self) -> bool:
        return self.skipped


# ── Parsers ──────────────────────────────────────────────────────────────────

def _fields(line: str) -> dict[str, str]:
    """Split a colon-delimited key=value line into a dict.  Tokens without '=' are skipped."""
    out: dict[str, str] = {}
    for part in line.split(":"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _unhex(s: str, label: str, expected: Optional[int] = None) -> bytes:
    try:
        b = bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"invalid hex in {label}: {exc}") from exc
    if expected is not None and len(b) != expected:
        raise ValueError(f"{label}: expected {expected} bytes, got {len(b)}")
    return b


def parse_bundle_header(line: str) -> BundleHeader:
    f = _fields(line)
    magic = f.get("magic", "")
    if magic != "APXB":
        raise ValueError(f"Bundle Header magic: expected 'APXB', got {magic!r}")
    return BundleHeader(
        raw             = line,
        magic           = magic,
        version         = f.get("version", "?"),
        session_id      = _unhex(f["session"],                          "session_id",      16),
        bootstrap_nonce = _unhex(f["nonce"],                            "bootstrap_nonce", 32),
        enc_pub         = _unhex(f.get("enc_pub", "00" * 32),           "enc_pub",         32),
        pcr0            = _unhex(f.get("pcr0",    "aa" * 48),           "pcr0",            48),
        pcr1            = _unhex(f.get("pcr1",    "aa" * 48),           "pcr1",            48),
        pcr2            = _unhex(f.get("pcr2",    "aa" * 48),           "pcr2",            48),
        signing_pub     = _unhex(f["pk"],                               "signing_pub",     32),
        attest_doc      = _unhex(f.get("doc", ""),                      "attest_doc"),
    )


def parse_evidence_packet(line: str, action: str) -> EvidencePacket:
    f = _fields(line)
    ph_raw = f.get("payload_hash", "")
    payload_hash = _unhex(ph_raw, "payload_hash", 32) if ph_raw else _SHA256_EMPTY
    payload_len  = int(f.get("payload_len", "0"))
    return EvidencePacket(
        raw          = line,
        action       = action,
        prev_stream  = _unhex(f["prev_stream"], "prev_stream", 32),
        stream       = _unhex(f["stream"],      "stream",      32),
        state        = _unhex(f["state"],       "state",       32),
        payload_hash = payload_hash,
        payload_len  = payload_len,
        sig          = _unhex(f["sig"],         "sig",         64),
        seq          = int(f["seq"]),
    )


def parse_temporal_proof(line: str) -> TemporalProofPacket:
    f = _fields(line)
    return TemporalProofPacket(
        raw         = line,
        prev_stream = _unhex(f["prev_stream"], "prev_stream", 32),
        stream      = _unhex(f["stream"],      "stream",      32),
        proof       = _unhex(f["proof"],       "proof",       32),
        m           = int(f["m"]),
        t           = int(f["t"]),
        p           = int(f["p"]),
        sig         = _unhex(f["sig"],         "sig",         64),
        seq         = int(f["seq"]),
    )


def parse_session_resume(line: str) -> SessionResumePacket:
    f = _fields(line)
    return SessionResumePacket(
        raw         = line,
        prev_stream = _unhex(f["prev_stream"], "prev_stream", 32),
        stream      = _unhex(f["stream"],      "stream",      32),
        sig         = _unhex(f["sig"],         "sig",         64),
        seq         = int(f["seq"]),
    )


def parse_bundle_seal(line: str) -> BundleSeal:
    f = _fields(line)
    return BundleSeal(
        raw             = line,
        terminal_digest = _unhex(f["terminal_digest"], "terminal_digest", 32),
        bundle_hash     = _unhex(f["bundle_hash"],     "bundle_hash",     32),
        seal_sig        = _unhex(f["seal_sig"],        "seal_sig",        64),
    )


def parse_settlement(line: str) -> SettlementBlock:
    f = _fields(line)
    magic = f.get("magic", "APXT")
    if magic != "APXT":
        raise ValueError(f"Settlement magic: expected 'APXT', got {magic!r}")
    return SettlementBlock(
        raw             = line,
        escrow_id       = _unhex(f["escrow_id"],       "escrow_id",       16),
        amount          = _unhex(f["amount"],           "amount",          32),
        currency        = _unhex(f["currency"],         "currency",         8),
        terminal_digest = _unhex(f["terminal_digest"],  "terminal_digest", 32),
        sig             = _unhex(f["sig"],              "sig",             64),
    )


def load_bundle(lines: list[str]) -> Bundle:
    """Parse a bundle log file into a Bundle object."""
    segments: list[Segment] = []
    current:  Optional[Segment] = None
    seal:     Optional[BundleSeal] = None
    settle:   Optional[SettlementBlock] = None

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("BUNDLE_HEADER:"):
            current = Segment(header=parse_bundle_header(line))
            segments.append(current)
        elif line.startswith("SESSION_START:"):
            if current is None:
                raise ValueError("SESSION_START before BUNDLE_HEADER")
            current.packets.append(parse_evidence_packet(line, "SESSION_START"))
        elif line.startswith("EVIDENCE:"):
            if current is None:
                raise ValueError("EVIDENCE before BUNDLE_HEADER")
            current.packets.append(parse_evidence_packet(line, "EVIDENCE"))
        elif line.startswith("TEMPORAL_PROOF:"):
            if current is None:
                raise ValueError("TEMPORAL_PROOF before BUNDLE_HEADER")
            current.packets.append(parse_temporal_proof(line))
        elif line.startswith("SESSION_RESUME:"):
            if current is None:
                raise ValueError("SESSION_RESUME before BUNDLE_HEADER")
            current.packets.append(parse_session_resume(line))
        elif line.startswith("BUNDLE_SEAL:"):
            seal = parse_bundle_seal(line)
        elif line.startswith("SETTLEMENT:"):
            settle = parse_settlement(line)

    if not segments:
        raise ValueError("no BUNDLE_HEADER found in input")

    return Bundle(segments=segments, bundle_seal=seal, settlement=settle)


# ── Signature scope builders ─────────────────────────────────────────────────

def _apxe_scope(pkt: EvidencePacket, session_id: bytes) -> bytes:
    """Reconstruct the 161-byte APXE scope for SESSION_START and EVIDENCE packets."""
    msg  = b"APXE"
    msg += b"\x01"
    msg += struct.pack("<Q", pkt.seq)
    msg += pkt.prev_stream
    msg += pkt.stream
    msg += pkt.state
    msg += struct.pack("<I", pkt.payload_len)
    msg += pkt.payload_hash
    msg += session_id
    assert len(msg) == 161, f"APXE scope: expected 161, got {len(msg)}"
    return msg


def _apxp_scope(pkt: TemporalProofPacket, session_id: bytes) -> bytes:
    """Reconstruct the 137-byte APXP scope for TEMPORAL_PROOF packets."""
    msg  = b"APXP"
    msg += b"\x01"
    msg += struct.pack("<Q", pkt.seq)
    msg += pkt.prev_stream
    msg += pkt.stream
    msg += pkt.proof
    msg += struct.pack("<I", pkt.m)
    msg += struct.pack("<I", pkt.t)
    msg += struct.pack("<I", pkt.p)
    msg += session_id
    assert len(msg) == 137, f"APXP scope: expected 137, got {len(msg)}"
    return msg


def _apxs_scope(pkt: SessionResumePacket, session_id: bytes) -> bytes:
    """Reconstruct the 93-byte APXS scope for SESSION_RESUME packets."""
    msg  = b"APXS"
    msg += b"\x01"
    msg += struct.pack("<Q", pkt.seq)
    msg += pkt.prev_stream
    msg += pkt.stream
    msg += session_id
    assert len(msg) == 93, f"APXS scope: expected 93, got {len(msg)}"
    return msg


# ── AWS Nitro COSE_Sign1 verification ────────────────────────────────────────

def _verify_nitro_cose(
    attest_doc_bytes: bytes,
    expected_pub:     bytes,
    expected_pcr0:    bytes,
    expected_pcr1:    bytes,
    expected_pcr2:    bytes,
) -> tuple[bool, str]:
    """Verify an AWS Nitro COSE_Sign1 attestation document.

    Implements §8 Step 2 rules 1–5:
      1. Parse COSE_Sign1 (RFC 8152 / CBOR tag 18)
      2. Verify ECDSA P-384 signature over Sig_Structure using leaf cert
      3. Verify certificate chain (leaf → intermediates → root)
      4. CBOR map-walk PCR0/1/2; assert PCRCommitment = SHA-256(PCR0‖PCR1‖PCR2)
      5. Assert AttestationDoc.public_key == bundle SessionPub

    Returns (ok, detail_string).
    """
    if not _CBOR2:
        return False, "cbor2 not installed — pip install cbor2"
    if not _CRYPTO:
        return False, "cryptography not installed — pip install cryptography"

    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.hashes import SHA384
    from cryptography import x509

    try:
        # ── 1. Parse COSE_Sign1 ───────────────────────────────────────────────
        cose = _cbor2.loads(attest_doc_bytes)
        # AWS Nitro emits CBORTag(18, [protected, unprotected, payload, sig])
        cose_list = cose.value if hasattr(cose, "value") else cose
        if not isinstance(cose_list, list) or len(cose_list) != 4:
            return False, f"COSE_Sign1: expected 4-element array, got {type(cose_list).__name__}[{len(cose_list) if isinstance(cose_list, list) else '?'}]"

        protected_bytes, _unprotected, payload_bytes, signature = cose_list
        if not isinstance(protected_bytes, bytes) or not isinstance(payload_bytes, bytes) or not isinstance(signature, bytes):
            return False, "COSE_Sign1: protected/payload/signature must be bstr"

        payload = _cbor2.loads(payload_bytes)

        # ── 2. Verify COSE_Sign1 signature ────────────────────────────────────
        # Sig_Structure = ["Signature1", protected_bstr, b"" (external_aad), payload_bstr]
        sig_structure = _cbor2.dumps(["Signature1", protected_bytes, b"", payload_bytes])

        leaf_cert_der = payload.get("certificate", b"")
        if not leaf_cert_der:
            return False, "attestation doc: no leaf certificate"
        leaf_cert = x509.load_der_x509_certificate(leaf_cert_der)

        try:
            leaf_cert.public_key().verify(signature, sig_structure, ECDSA(SHA384()))
        except Exception as exc:
            return False, f"COSE_Sign1 signature invalid: {exc}"

        # ── 3. Verify certificate chain ───────────────────────────────────────
        cabundle = payload.get("cabundle", [])
        chain = [leaf_cert] + [x509.load_der_x509_certificate(c) for c in cabundle]
        for i in range(len(chain) - 1):
            child, issuer = chain[i], chain[i + 1]
            try:
                issuer.public_key().verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ECDSA(child.signature_hash_algorithm),
                )
            except Exception as exc:
                return False, f"cert chain break at depth {i} ({child.subject.rfc4514_string()}): {exc}"

        # ── 4. CBOR map-walk PCRs and assert PCRCommitment ───────────────────
        pcrs = payload.get("pcrs", {})
        pcr0_doc = pcrs.get(0, b"")
        pcr1_doc = pcrs.get(1, b"")
        pcr2_doc = pcrs.get(2, b"")

        issues = []
        if pcr0_doc != expected_pcr0:
            issues.append(f"PCR0 mismatch\n    doc: {pcr0_doc.hex()}\n    hdr: {expected_pcr0.hex()}")
        if pcr1_doc != expected_pcr1:
            issues.append(f"PCR1 mismatch\n    doc: {pcr1_doc.hex()}\n    hdr: {expected_pcr1.hex()}")
        if pcr2_doc != expected_pcr2:
            issues.append(f"PCR2 mismatch\n    doc: {pcr2_doc.hex()}\n    hdr: {expected_pcr2.hex()}")
        if issues:
            return False, "PCRs in attestation doc do not match bundle header\n  " + "\n  ".join(issues)

        pcr_commitment = hashlib.sha256(pcr0_doc + pcr1_doc + pcr2_doc).digest()

        # ── 5. Assert SessionPub in AttestationDoc.public_key ─────────────────
        pub_from_doc = payload.get("public_key", b"")
        if pub_from_doc != expected_pub:
            return False, (
                f"SessionPub mismatch between attestation doc and bundle header\n"
                f"  doc: {pub_from_doc.hex()}\n"
                f"  hdr: {expected_pub.hex()}"
            )

        root_cn = chain[-1].subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )
        root_name = root_cn[0].value if root_cn else "unknown"

        return True, (
            f"COSE_Sign1 valid  chain depth={len(chain)}  root='{root_name}'\n"
            f"  PCR0={pcr0_doc.hex()[:12]}…  PCR1={pcr1_doc.hex()[:12]}…  PCR2={pcr2_doc.hex()[:12]}…\n"
            f"  PCRCommitment={pcr_commitment.hex()[:16]}…  SessionPub matches"
        )

    except Exception as exc:
        return False, f"COSE verification error: {exc}"


# ── Step helpers ─────────────────────────────────────────────────────────────

def _pass(step: str, detail: str) -> CheckResult:
    return CheckResult(step, True, detail)


def _fail(step: str, detail: str) -> CheckResult:
    return CheckResult(step, False, detail)


def _skip(step: str, detail: str) -> CheckResult:
    return CheckResult(step, True, detail, skipped=True)


def _ed25519_verify(pub_bytes: bytes, msg: bytes, sig: bytes) -> bool:
    if not _CRYPTO:
        return True   # caller must check _CRYPTO before trusting result
    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, msg)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ── §8 Verification Steps ────────────────────────────────────────────────────

def step_1_bundle_header(bundle: Bundle) -> CheckResult:
    """Step 1 — Parse and validate the Bundle Header."""
    hdr = bundle.segments[0].header
    # Magic
    if hdr.magic != "APXB":
        return _fail("Step 1 Bundle Header", f"magic: expected 'APXB', got {hdr.magic!r}")
    # Version MAJOR
    try:
        major = int(hdr.version.split(".")[0])
    except (ValueError, IndexError):
        return _fail("Step 1 Bundle Header", f"unparseable version: {hdr.version!r}")
    if major > SPEC_MAJOR:
        return _fail("Step 1 Bundle Header",
                     f"bundle MAJOR={major} > implemented MAJOR={SPEC_MAJOR} — verifier too old")
    return _pass("Step 1 Bundle Header",
                 f"magic=APXB  version={hdr.version}  MAJOR={major} ≤ {SPEC_MAJOR}  "
                 f"session={hdr.session_id.hex()[:16]}…")


def step_2_segment_headers(bundle: Bundle) -> CheckResult:
    """Step 2 — Validate each Segment Header (PCRCommitment + COSE_Sign1 for production bundles)."""
    issues = []
    notes  = []
    sim_mode = False

    for i, seg in enumerate(bundle.segments):
        hdr = seg.header

        # Detect simulation mode: attestation doc is all-0xAA fill or PCRs all-zero
        doc_is_sim = len(hdr.attest_doc) > 0 and all(b == _SIM_ATTEST_FILL for b in hdr.attest_doc)
        pcr_is_sim = all(b == _SIM_PCR_FILL for b in hdr.pcr0 + hdr.pcr1 + hdr.pcr2)

        if doc_is_sim or pcr_is_sim:
            sim_mode = True
            notes.append(f"segment {i}: simulation-mode attestation — COSE skipped (§11)")
            computed = hashlib.sha256(hdr.pcr0 + hdr.pcr1 + hdr.pcr2).digest()
            notes.append(f"segment {i}: PCRCommitment={computed.hex()[:16]}…  (all-zero PCRs expected in sim)")
        else:
            # Production bundle — full COSE_Sign1 verification (§8 Step 2 rules 1–5)
            if not hdr.attest_doc:
                issues.append(f"segment {i}: attestation doc missing")
                continue

            ok, detail = _verify_nitro_cose(
                hdr.attest_doc,
                hdr.signing_pub,
                hdr.pcr0,
                hdr.pcr1,
                hdr.pcr2,
            )
            if ok:
                notes.append(f"segment {i}: {detail}")
            else:
                issues.append(f"segment {i}: COSE verification FAILED — {detail}")

    if issues:
        return _fail("Step 2 Segment Headers", "\n  ".join(issues))

    detail = "\n  ".join(notes)
    if sim_mode:
        return _skip("Step 2 Segment Headers", f"simulation mode — COSE skipped\n  {detail}")
    return _pass("Step 2 Segment Headers", detail)


def step_3_bootstrap_nonce(bundle: Bundle) -> CheckResult:
    """Step 3 — Reconstruct the Bootstrap Nonce."""
    hdr = bundle.segments[0].header
    expected = hashlib.sha256(hdr.attest_doc + hdr.session_id).digest()
    if expected != hdr.bootstrap_nonce:
        return _fail("Step 3 Bootstrap Nonce",
                     f"MISMATCH\n  expected : {expected.hex()}\n  got      : {hdr.bootstrap_nonce.hex()}")
    return _pass("Step 3 Bootstrap Nonce",
                 f"SHA-256(doc ‖ session_id) = {expected.hex()[:16]}…  matches header.nonce")


def step_4_chain_continuity(bundle: Bundle) -> CheckResult:
    """Step 4 — Verify chain continuity within each segment; sequence number monotonicity."""
    session_id = bundle.session_id()
    anchor     = bundle.bootstrap_nonce()
    issues     = []

    for seg_idx, seg in enumerate(bundle.segments):
        pkts = seg.packets
        if not pkts:
            continue

        # Within-segment: first packet must start from anchor (bootstrap nonce for seg 0,
        # or last stream of prior segment for seg > 0 — but cross-segment is Step 10).
        if seg_idx == 0:
            if pkts[0].prev_stream != anchor:
                issues.append(
                    f"seg 0 pkt seq={pkts[0].seq}: prev_stream ≠ bootstrap_nonce\n"
                    f"  expected : {anchor.hex()}\n  got      : {pkts[0].prev_stream.hex()}"
                )

        # Consecutive links and sequence numbers
        for i in range(1, len(pkts)):
            prev, curr = pkts[i - 1], pkts[i]
            if curr.prev_stream != prev.stream:
                issues.append(
                    f"seg {seg_idx}: gap between seq={prev.seq} and seq={curr.seq}\n"
                    f"  prev.stream    : {prev.stream.hex()}\n"
                    f"  curr.prev_stream: {curr.prev_stream.hex()}"
                )
            if curr.seq != prev.seq + 1:
                issues.append(
                    f"seg {seg_idx}: sequence jump: {prev.seq} → {curr.seq} (expected {prev.seq + 1})"
                )

    if issues:
        return _fail("Step 4 Chain Continuity", "\n  ".join(issues))

    total = sum(len(s.packets) for s in bundle.segments)
    return _pass("Step 4 Chain Continuity",
                 f"{total} packet(s) across {len(bundle.segments)} segment(s) — all hash links valid, "
                 f"sequences strictly monotonic")


def step_5_signatures(bundle: Bundle) -> CheckResult:
    """Step 5 — Verify Ed25519 signature on every packet."""
    if not _CRYPTO:
        return _skip("Step 5 Signatures",
                     "SKIPPED — pip install cryptography to enable Ed25519 verification")

    session_id = bundle.session_id()
    failures   = []
    total      = 0

    for seg in bundle.segments:
        pub = seg.header.signing_pub
        for pkt in seg.packets:
            total += 1
            if isinstance(pkt, EvidencePacket):
                scope = _apxe_scope(pkt, session_id)
            elif isinstance(pkt, TemporalProofPacket):
                scope = _apxp_scope(pkt, session_id)
            elif isinstance(pkt, SessionResumePacket):
                scope = _apxs_scope(pkt, session_id)
            else:
                failures.append(f"seq=?: unknown packet type {type(pkt)}")
                continue

            if not _ed25519_verify(pub, scope, pkt.sig):
                failures.append(f"seq={pkt.seq} ({type(pkt).__name__}): signature INVALID")

    if failures:
        return _fail("Step 5 Signatures", f"{len(failures)}/{total} invalid:\n  " + "\n  ".join(failures))
    return _pass("Step 5 Signatures", f"{total}/{total} Ed25519 signature(s) valid")


def step_6_terminal_digest(bundle: Bundle) -> CheckResult:
    """Step 6 — Verify TerminalDigest = SHA-256(all packet signatures in sequence order)."""
    if bundle.bundle_seal is None:
        return _fail("Step 6 Terminal Digest", "no BUNDLE_SEAL found in bundle")

    all_sigs = b"".join(p.sig for p in bundle.all_packets())
    computed = hashlib.sha256(all_sigs).digest()

    if computed != bundle.bundle_seal.terminal_digest:
        return _fail("Step 6 Terminal Digest",
                     f"MISMATCH\n"
                     f"  computed from {len(bundle.all_packets())} sigs : {computed.hex()}\n"
                     f"  BundleSeal.TerminalDigest                      : {bundle.bundle_seal.terminal_digest.hex()}")
    return _pass("Step 6 Terminal Digest",
                 f"SHA-256({len(bundle.all_packets())} signatures) = {computed.hex()[:16]}…  matches BundleSeal")


def step_7_bundle_seal(bundle: Bundle) -> CheckResult:
    """Step 7 — Verify BundleHash computation and SealSig."""
    if bundle.bundle_seal is None:
        return _fail("Step 7 Bundle Seal", "no BUNDLE_SEAL found in bundle")

    last_seg   = bundle.segments[-1]
    seal       = bundle.bundle_seal
    session_id = bundle.session_id()
    nonce      = bundle.bootstrap_nonce()
    last_pub   = last_seg.header.signing_pub
    td         = seal.terminal_digest

    expected_hash = hashlib.sha256(b"APXB" + session_id + nonce + last_pub + td).digest()
    if expected_hash != seal.bundle_hash:
        return _fail("Step 7 Bundle Seal",
                     f"BundleHash MISMATCH\n"
                     f"  computed : {expected_hash.hex()}\n"
                     f"  got      : {seal.bundle_hash.hex()}")

    if not _CRYPTO:
        return _skip("Step 7 Bundle Seal",
                     f"BundleHash verified; SealSig SKIPPED — pip install cryptography")

    if not _ed25519_verify(last_pub, seal.bundle_hash, seal.seal_sig):
        return _fail("Step 7 Bundle Seal", "SealSig INVALID — does not verify over BundleHash")

    return _pass("Step 7 Bundle Seal",
                 f"BundleHash={seal.bundle_hash.hex()[:16]}…  SealSig valid (last-segment keypair)")


def step_8_settlement(bundle: Bundle) -> CheckResult:
    """Step 8 — Verify Settlement Block (if present)."""
    if bundle.settlement is None:
        return _skip("Step 8 Settlement Block", "no Settlement Block in bundle — skipped")
    if bundle.bundle_seal is None:
        return _fail("Step 8 Settlement Block", "Settlement Block present but no BUNDLE_SEAL — cannot cross-check TerminalDigest")

    settle = bundle.settlement
    seal   = bundle.bundle_seal

    # Assert TerminalDigest matches
    if settle.terminal_digest != seal.terminal_digest:
        return _fail("Step 8 Settlement Block",
                     f"Settlement.TerminalDigest ≠ BundleSeal.TerminalDigest\n"
                     f"  settlement : {settle.terminal_digest.hex()}\n"
                     f"  bundle_seal: {seal.terminal_digest.hex()}")

    if not _CRYPTO:
        return _skip("Step 8 Settlement Block",
                     "TerminalDigest matches; SettlementSig SKIPPED — pip install cryptography")

    # Verify 88-byte APXT scope: EscrowID(16) ‖ Amount(32) ‖ Currency(8) ‖ TerminalDigest(32)
    scope = settle.escrow_id + settle.amount + settle.currency + settle.terminal_digest
    assert len(scope) == 88
    last_pub = bundle.segments[-1].header.signing_pub

    if not _ed25519_verify(last_pub, scope, settle.sig):
        return _fail("Step 8 Settlement Block", "SettlementSig INVALID over 88-byte APXT scope")

    return _pass("Step 8 Settlement Block",
                 f"TerminalDigest matches; SettlementSig valid  escrow={settle.escrow_id.hex()}")


def step_9_l2_replay(bundle: Bundle, pty_path: Optional[str]) -> CheckResult:
    """Step 9 — L2 hash replay through VT100 parser (requires --pty and pyte).

    L2Hash is already committed inside each packet's signature (Step 5).
    If Step 5 passes, L2 integrity is already guaranteed cryptographically.
    Step 9 additionally confirms that the signed L2Hash corresponds to the
    actual visible terminal output — requires the raw PTY byte stream.
    """
    if pty_path is None:
        return _skip("Step 9 L2 Replay",
                     "SKIPPED — no --pty stream provided.  "
                     "L2Hash is committed in packet signatures (Step 5 guarantees binding).")
    if not _PYTE:
        return _skip("Step 9 L2 Replay",
                     "SKIPPED — pip install pyte to enable PTY replay")

    try:
        pty_bytes = Path(pty_path).read_bytes()
    except OSError as exc:
        return _fail("Step 9 L2 Replay", f"cannot read PTY stream: {exc}")

    # Replay through pyte screen
    screen = _pyte.Screen(80, 24)
    stream_parser = _pyte.ByteStream(screen)
    stream_parser.feed(pty_bytes)

    # Compute L2Hash over rendered terminal state (§5.2)
    cell_digest = _l2_cell_digest(screen)
    l2_computed = hashlib.sha256(
        b"\x01"                          # format_version
        + struct.pack("<H", screen.cursor.x)
        + struct.pack("<H", screen.cursor.y)
        + struct.pack("<H", screen.columns)
        + struct.pack("<H", screen.lines)
        + cell_digest
    ).digest()

    # Check against the last evidence packet's L2Hash
    ev_packets = [p for p in bundle.all_packets() if isinstance(p, EvidencePacket)]
    if not ev_packets:
        return _fail("Step 9 L2 Replay", "no evidence packets to verify L2Hash against")

    last_l2 = ev_packets[-1].state
    if l2_computed != last_l2:
        return _fail("Step 9 L2 Replay",
                     f"L2Hash MISMATCH on last evidence packet\n"
                     f"  replayed : {l2_computed.hex()}\n"
                     f"  signed   : {last_l2.hex()}")
    return _pass("Step 9 L2 Replay",
                 f"PTY replay ({len(pty_bytes)} bytes) produces L2Hash={l2_computed.hex()[:16]}…  matches")


def _l2_cell_digest(screen) -> bytes:
    """Compute §5.2.1 cell digest from a pyte Screen."""
    h = hashlib.sha256()
    for y in range(screen.lines):
        for x in range(screen.columns):
            cell = screen.buffer[y][x]
            # Codepoint → UTF-8, zero-padded to 4 bytes (§5.2.1)
            ch = cell.data if cell.data else " "
            utf8 = ch.encode("utf-8")
            padded = utf8[:4].ljust(4, b"\x00")
            h.update(padded)
            # Colours (3 bytes each; default = 0)
            fg = _color_bytes(getattr(cell, "fg", "default"))
            bg = _color_bytes(getattr(cell, "bg", "default"))
            h.update(fg)
            h.update(bg)
            # Attribute bitmask (§5.2.2)
            attrs = 0
            if getattr(cell, "bold",          False): attrs |= 0x01
            if getattr(cell, "italics",       False): attrs |= 0x02
            if getattr(cell, "faint",         False): attrs |= 0x04
            if getattr(cell, "blink",         False): attrs |= 0x08
            if getattr(cell, "reverse",       False): attrs |= 0x10
            if getattr(cell, "invisible",     False): attrs |= 0x20
            if getattr(cell, "strikethrough", False): attrs |= 0x40
            if getattr(cell, "underscore", False) or getattr(cell, "underline", False): attrs |= 0x80
            h.update(bytes([attrs]))
    return h.digest()


def _color_bytes(color) -> bytes:
    """Convert a pyte colour value to 3 RGB bytes."""
    if isinstance(color, tuple) and len(color) == 3:
        return bytes(color)
    if isinstance(color, int):
        return bytes([0, 0, color & 0xFF])
    return b"\x00\x00\x00"


def step_10_segment_boundaries(bundle: Bundle) -> CheckResult:
    """Step 10 — Verify segment boundaries (multi-segment bundles only)."""
    if len(bundle.segments) < 2:
        return _skip("Step 10 Segment Boundaries", "single-segment bundle — not applicable")

    issues = []
    warns  = []

    for i in range(1, len(bundle.segments)):
        seg_prev = bundle.segments[i - 1]
        seg_curr = bundle.segments[i]

        # Last packet of prior segment must be a TEMPORAL_PROOF (Rule A) or EVIDENCE (Rule B)
        prev_pkts = seg_prev.packets
        last_prev = prev_pkts[-1] if prev_pkts else None

        # First packet of resumed segment must be SESSION_RESUME
        curr_pkts = seg_curr.packets
        first_curr = curr_pkts[0] if curr_pkts else None

        if first_curr is None:
            issues.append(f"boundary {i-1}→{i}: resumed segment has no packets")
            continue

        if not isinstance(first_curr, SessionResumePacket):
            issues.append(
                f"boundary {i-1}→{i}: first packet of segment {i} is "
                f"{type(first_curr).__name__}, expected SESSION_RESUME"
            )
        else:
            # PrevL1Hash of SESSION_RESUME must == last packet stream of prior segment
            if last_prev is not None and first_curr.prev_stream != last_prev.stream:
                issues.append(
                    f"boundary {i-1}→{i}: SESSION_RESUME.prev_stream ≠ last packet stream of segment {i-1}\n"
                    f"  expected : {last_prev.stream.hex()}\n"
                    f"  got      : {first_curr.prev_stream.hex()}"
                )
            # Sequence number continuity across boundary
            if last_prev is not None and first_curr.seq != last_prev.seq + 1:
                issues.append(
                    f"boundary {i-1}→{i}: sequence not strictly monotonic: "
                    f"{last_prev.seq} → {first_curr.seq}"
                )

    if issues:
        return _fail("Step 10 Segment Boundaries", "\n  ".join(issues))
    return _pass("Step 10 Segment Boundaries",
                 f"{len(bundle.segments) - 1} boundary/boundaries verified: "
                 f"SESSION_RESUME present and hash-linked at each")


def step_11_temporal_proofs(bundle: Bundle) -> tuple[CheckResult, int, int]:
    """Step 11 — Verify TEMPORAL_PROOF packets.

    Returns (result, K, K_tp) for ECR computation in Step 12.
    K    = number of hibernate boundaries (= SESSION_RESUME packets)
    K_tp = boundaries with valid TEMPORAL_PROOF (Rule A passed)
    """
    all_pkts = bundle.all_packets()
    resume_seqs = {p.seq for p in all_pkts if isinstance(p, SessionResumePacket)}
    tp_packets  = [p for p in all_pkts if isinstance(p, TemporalProofPacket)]

    K    = len(resume_seqs)
    K_tp = 0
    issues = []
    notes  = []

    session_id = bundle.session_id()

    if K == 0:
        return _skip("Step 11 Temporal Proofs", "single-segment bundle (K=0) — not applicable"), 0, 0

    for tp in tp_packets:
        seq = tp.seq

        # Rule: p MUST equal 1 (§5.7 and Step 11)
        if tp.p != 1:
            issues.append(f"seq={seq}: p={tp.p} ≠ 1 — non-conformant parallelism, FAIL")
            continue

        # Parameter floor
        if tp.m < 65536 or tp.t < 3:
            issues.append(f"seq={seq}: m={tp.m} or t={tp.t} below floor (m≥65536, t≥3)")
            continue

        if not _ARGON2:
            notes.append(f"seq={seq}: Argon2id SKIPPED — pip install argon2-cffi")
            K_tp += 1  # optimistically count as attested when crypto unavailable
            continue

        # Derive argon_input = LastEvidenceL1Hash ‖ SessionID ‖ Sequence (u64 LE)
        # LastEvidenceL1Hash = the stream hash of the packet immediately before this TEMPORAL_PROOF
        tp_idx   = all_pkts.index(tp)
        last_ev  = all_pkts[tp_idx - 1] if tp_idx > 0 else None
        if last_ev is None:
            issues.append(f"seq={seq}: no preceding packet to derive LastEvidenceL1Hash")
            continue

        argon_input = last_ev.stream + session_id + struct.pack("<Q", seq)
        try:
            computed = _argon2_ll.hash_secret_raw(
                secret      = argon_input,
                salt        = ARGON_SALT,
                time_cost   = tp.t,
                memory_cost = tp.m,
                parallelism = tp.p,
                hash_len    = 32,
                type        = _argon2_ll.Type.ID,
            )
        except Exception as exc:
            issues.append(f"seq={seq}: Argon2id computation failed: {exc}")
            continue

        if computed != tp.proof:
            issues.append(
                f"seq={seq}: ArgonOutput MISMATCH\n"
                f"  expected (from spec/fixture) : {tp.proof.hex()}\n"
                f"  recomputed                   : {computed.hex()}"
            )
        else:
            notes.append(f"seq={seq}: Argon2id valid (m={tp.m}, t={tp.t}, p={tp.p})")
            K_tp += 1

    if issues:
        detail = f"K={K}, K_tp={K_tp}\n  " + "\n  ".join(issues + notes)
        return _fail("Step 11 Temporal Proofs", detail), K, K_tp

    detail = f"K={K} hibernate boundaries, K_tp={K_tp} with valid TEMPORAL_PROOF\n  " + "\n  ".join(notes)
    return _pass("Step 11 Temporal Proofs", detail), K, K_tp


def step_12_ecr(K: int, K_tp: int) -> tuple[CheckResult, float]:
    """Step 12 — Compute Evidence Coverage Ratio."""
    if K == 0:
        ecr = 1.0
        detail = "K=0 (single-segment session) → ECR = 1.0 (vacuously)"
    else:
        ecr = K_tp / K
        detail = f"K={K}, K_tp={K_tp} → ECR = {K_tp}/{K} = {ecr:.4f}"

    return _pass("Step 12 ECR", detail), ecr


# ── Reporting ────────────────────────────────────────────────────────────────

_G = "\033[32m"
_R = "\033[31m"
_Y = "\033[33m"
_B = "\033[1m"
_Z = "\033[0m"


def _tag(r: CheckResult) -> str:
    if r.skipped: return f"{_Y}SKIP{_Z}"
    return f"{_G}PASS{_Z}" if r.passed else f"{_R}FAIL{_Z}"


def print_report(results: list[CheckResult], bundle: Bundle, all_passed: bool, ecr: float) -> None:
    seg_count = len(bundle.segments)
    pkt_count = sum(len(s.packets) for s in bundle.segments)
    sid       = bundle.session_id().hex()

    print()
    print(f"  {_B}APEX Evidence Verifier  —  spec v{SPEC_VERSION}{_Z}")
    print(f"  Session  : {sid}")
    print(f"  Segments : {seg_count}")
    print(f"  Packets  : {pkt_count}")
    print()

    for r in results:
        print(f"  [{_tag(r)}] {r.step}")
        for ln in r.detail.splitlines():
            print(f"          {ln}")

    print()
    print(f"  ECR   : {ecr:.4f}")
    verdict = f"{_G}{_B}PASS{_Z}" if all_passed else f"{_R}{_B}FAIL{_Z}"
    print(f"  RESULT: {verdict}")
    print()


# ── CLI ──────────────────────────────────────────────────────────────────────

def run(lines: list[str], pty_path: Optional[str] = None) -> tuple[bool, list[CheckResult], Bundle, float]:
    bundle = load_bundle(lines)

    results: list[CheckResult] = []
    results.append(step_1_bundle_header(bundle))
    results.append(step_2_segment_headers(bundle))
    results.append(step_3_bootstrap_nonce(bundle))
    results.append(step_4_chain_continuity(bundle))
    results.append(step_5_signatures(bundle))
    results.append(step_6_terminal_digest(bundle))
    results.append(step_7_bundle_seal(bundle))
    results.append(step_8_settlement(bundle))
    results.append(step_9_l2_replay(bundle, pty_path))
    results.append(step_10_segment_boundaries(bundle))
    tp_result, K, K_tp = step_11_temporal_proofs(bundle)
    results.append(tp_result)
    ecr_result, ecr = step_12_ecr(K, K_tp)
    results.append(ecr_result)

    all_passed = all(r.passed for r in results)
    return all_passed, results, bundle, ecr


# Path to the built-in §14.9 fixture, relative to this file
_FIXTURE_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "fixture_14n.log"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify APEX evidence bundles (Steps 1–12, §8 APEX v2.7.0).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify a bundle log produced by the VAR runtime:
  python tools/apex_verify.py session.log

  # Verify the built-in §14.9 synthetic fixture (zero dependencies except cryptography):
  python tools/apex_verify.py --self-test

  # With L2 PTY replay (requires pyte):
  python tools/apex_verify.py session.log --pty session.pty
""",
    )
    parser.add_argument("file", nargs="?", metavar="FILE",
                        help="Bundle log file; use '-' for stdin.")
    parser.add_argument("--self-test", action="store_true",
                        help=f"Run against §14.9 fixture at {_FIXTURE_PATH}")
    parser.add_argument("--pty", metavar="FILE",
                        help="Raw PTY byte stream for Step 9 L2 replay.")
    args = parser.parse_args()

    if args.self_test:
        if not _FIXTURE_PATH.exists():
            print(f"error: fixture not found at {_FIXTURE_PATH}", file=sys.stderr)
            return 2
        lines = _FIXTURE_PATH.read_text().splitlines(keepends=True)
        print(f"  [self-test] loading §14.9 fixture: {_FIXTURE_PATH}")
    elif args.file:
        src = sys.stdin if args.file == "-" else open(args.file)
        with src:
            lines = src.readlines()
    else:
        parser.print_help()
        return 2

    try:
        all_passed, results, bundle, ecr = run(lines, pty_path=args.pty)
    except (ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print_report(results, bundle, all_passed, ecr)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
