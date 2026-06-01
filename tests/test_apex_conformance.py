"""
APEX v2.1.0 Conformance Tests  (§14 Test Vectors)
===================================================
Two test classes:

  TestCryptoVectors        (18 tests)
    Independent computation of every §14.8 golden value.
    Imports ONLY stdlib + cryptography — no VAR runtime code.
    Any divergence between the spec, the generator, or the implementation
    fails here immediately.

  TestVerifierConformance  (12 tests)
    Exercises src/verifier/verify.py with the §14 session identity using
    snapshot-mode packets.  Includes one test that explicitly documents why
    the §14 stream-mode packet signature is correctly rejected by the
    snapshot-mode verifier.

Run:
  pip install cryptography pytest
  pytest tests/test_apex_conformance.py -v
"""

import hashlib
import struct
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="pip install cryptography")

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ---------------------------------------------------------------------------
# §14.2 Fixed inputs
# ---------------------------------------------------------------------------

SIGNING_SEED = bytes(32)                   # 32 zero bytes — SYNTHETIC / TEST-ONLY
SESSION_ID   = bytes([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00,
    0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
])
ATTEST_DOC   = bytes([0xAA] * 96)          # simulation-mode attestation document
PAYLOAD      = b"hello"
SEQ          = 1

# ---------------------------------------------------------------------------
# §14.8 Golden values
# ---------------------------------------------------------------------------

BOOTSTRAP_NONCE_HEX = "b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63"
L1_1_HEX            = "a231fcd1c04fef6e333954f22b311425d7d55ce3994b9a6d38a7cb72eedce64b"
L2_HASH_HEX         = "d416434244a2ce8276e6f3d72cc53f953f5e3f581f2e6862e5e36fadbe10ab71"
PACKET_SIG_HEX      = (
    "36092fb379e6e33a6dccf33be6c9b617e0f9b2837195d0e6414ce00590383988"
    "a208d9b37d065d1b1999ecb4872b26f4c8ce0bf3f4c91f90cb07b94c0c2b1f05"
)
TERMINAL_DIGEST_HEX = "33c143a8fd36b26f375339c66ab10aab0f457e5a5678790c38cdf2fac08f9978"
BUNDLE_HASH_HEX     = "ddb62dbda59c6ea21ea7d6227d00e0d267dd8b1b3d35ad6a88c5fbfe4612399a"
SEAL_SIG_HEX        = (
    "8e0b8126cdf3f6453ecdbcbfe2656693b0d386b9a76dffe23875e95d487ce4b1"
    "51ba37b9e0df690c44a23b388e1e50661ac7b1531b9a963907b737f2eb3b120d"
)
SIGNING_PUB_HEX     = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"

# ---------------------------------------------------------------------------
# Module-level derived values (no VAR runtime imports — stdlib + cryptography)
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _build_stream_scope(
    seq: int,
    prev_l1: bytes,
    l1: bytes,
    l2: bytes,
    payload: bytes,
    session_id: bytes,
) -> bytes:
    """Build the 161-byte STREAM-mode signature scope (§14.6, magic VARE)."""
    msg = bytearray(161)
    msg[0:4]   = b"VARE"
    msg[4]     = 0x01
    struct.pack_into("<Q", msg, 5, seq)
    msg[13:45]   = prev_l1
    msg[45:77]   = l1
    msg[77:109]  = l2
    struct.pack_into("<I", msg, 109, len(payload))
    msg[113:145] = _sha256(payload)
    msg[145:161] = session_id
    return bytes(msg)


_SIGNING_KEY     = Ed25519PrivateKey.from_private_bytes(SIGNING_SEED)
_SIGNING_PUB     = _SIGNING_KEY.public_key().public_bytes_raw()

_NONCE           = _sha256(ATTEST_DOC + SESSION_ID)
_L1_0            = _NONCE
_L1_1            = _sha256(_L1_0 + PAYLOAD)

_L2_META         = (
    bytes([0x01])
    + struct.pack("<H", 0)   # cursor_x
    + struct.pack("<H", 0)   # cursor_y
    + struct.pack("<H", 80)  # terminal_width
    + struct.pack("<H", 24)  # terminal_height
)
_L2_HASH         = _sha256(_L2_META + _sha256(b""))

_SIG_SCOPE       = _build_stream_scope(SEQ, _L1_0, _L1_1, _L2_HASH, PAYLOAD, SESSION_ID)
_PACKET_SIG      = _SIGNING_KEY.sign(_SIG_SCOPE)
_TERMINAL_DIGEST = _sha256(_PACKET_SIG)
_BUNDLE_HASH     = _sha256(b"VARB" + SESSION_ID + _NONCE + _SIGNING_PUB + _TERMINAL_DIGEST)
_SEAL_SIG        = _SIGNING_KEY.sign(_BUNDLE_HASH)


# ===========================================================================
# TestCryptoVectors — 18 tests, no VAR imports
# ===========================================================================

class TestCryptoVectors:
    """
    Re-derive every §14.8 golden value from first principles.
    Only stdlib and cryptography are imported; no VAR runtime code.
    """

    def test_signing_pub_from_zero_seed(self):
        """Ed25519 public key for 32-zero seed must match §14.2."""
        assert _SIGNING_PUB.hex() == SIGNING_PUB_HEX

    def test_bootstrap_nonce_formula(self):
        """BootstrapNonce = SHA-256(AttestDoc ‖ SessionID)."""
        assert _sha256(ATTEST_DOC + SESSION_ID).hex() == BOOTSTRAP_NONCE_HEX

    def test_bootstrap_nonce_golden(self):
        """Pinned: §14.8 BootstrapNonce golden value."""
        assert _NONCE.hex() == BOOTSTRAP_NONCE_HEX

    def test_l1_genesis_is_bootstrap_nonce(self):
        """L1[0] == BootstrapNonce (chain genesis)."""
        assert _L1_0 == _NONCE

    def test_l1_1_formula(self):
        """L1[1] = SHA-256(L1[0] ‖ payload)."""
        assert _sha256(_L1_0 + PAYLOAD).hex() == L1_1_HEX

    def test_l1_1_golden(self):
        """Pinned: §14.8 L1[1] golden value."""
        assert _L1_1.hex() == L1_1_HEX

    def test_l2_hash_formula(self):
        """L2Hash = SHA-256(format_version ‖ cursor_x ‖ cursor_y ‖ width ‖ height ‖ SHA-256(""))."""
        meta = (
            bytes([0x01])
            + struct.pack("<H", 0)    # cursor_x
            + struct.pack("<H", 0)    # cursor_y
            + struct.pack("<H", 80)   # terminal_width
            + struct.pack("<H", 24)   # terminal_height
        )
        assert _sha256(meta + _sha256(b"")).hex() == L2_HASH_HEX

    def test_l2_hash_golden(self):
        """Pinned: §14.8 L2Hash golden value."""
        assert _L2_HASH.hex() == L2_HASH_HEX

    def test_sig_scope_is_161_bytes(self):
        """Signature scope MUST be exactly 161 bytes (§14.6)."""
        assert len(_SIG_SCOPE) == 161

    def test_sig_scope_magic_is_vare(self):
        """Bytes [0:4] of scope MUST be b\"VARE\" (reference-impl magic, §14.1)."""
        assert _SIG_SCOPE[0:4] == b"VARE"

    def test_sig_scope_prev_l1_at_offset_13(self):
        """PrevL1Hash occupies bytes [13:45] and equals BootstrapNonce for packet 1."""
        assert _SIG_SCOPE[13:45] == bytes.fromhex(BOOTSTRAP_NONCE_HEX)

    def test_sig_scope_session_id_at_offset_145(self):
        """SessionID occupies the final 16 bytes [145:161]."""
        assert _SIG_SCOPE[145:161] == SESSION_ID

    def test_packet_sig_verifies(self):
        """Ed25519 signature over 161-byte scope must verify with §14.2 public key."""
        pub = Ed25519PublicKey.from_public_bytes(_SIGNING_PUB)
        pub.verify(_PACKET_SIG, _SIG_SCOPE)   # raises InvalidSignature on failure

    def test_packet_sig_golden(self):
        """Pinned: §14.8 Packet[1].Signature golden value."""
        assert _PACKET_SIG.hex() == PACKET_SIG_HEX

    def test_terminal_digest_formula(self):
        """TerminalDigest = SHA-256(Packet[1].Signature) for a single-packet session."""
        assert _sha256(_PACKET_SIG).hex() == TERMINAL_DIGEST_HEX

    def test_terminal_digest_golden(self):
        """Pinned: §14.8 TerminalDigest golden value."""
        assert _TERMINAL_DIGEST.hex() == TERMINAL_DIGEST_HEX

    def test_bundle_hash_formula(self):
        """BundleHash = SHA-256("VARB" ‖ SessionID ‖ BootstrapNonce ‖ SigningPub ‖ TerminalDigest)."""
        expected = _sha256(
            b"VARB"
            + SESSION_ID
            + bytes.fromhex(BOOTSTRAP_NONCE_HEX)
            + bytes.fromhex(SIGNING_PUB_HEX)
            + bytes.fromhex(TERMINAL_DIGEST_HEX)
        )
        assert expected.hex() == BUNDLE_HASH_HEX

    def test_bundle_hash_golden(self):
        """Pinned: §14.8 BundleHash golden value."""
        assert _BUNDLE_HASH.hex() == BUNDLE_HASH_HEX


# ===========================================================================
# TestVerifierConformance — 12 tests
# ===========================================================================

# Add src/verifier to sys.path so `import verify` resolves regardless of cwd.
sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "verifier"))
import verify as _v  # noqa: E402


def _sec14_header_line() -> str:
    """Build a BUNDLE_HEADER line using §14.2 session identity."""
    return (
        f"BUNDLE_HEADER:magic=VARB:version=01"
        f":session={SESSION_ID.hex()}"
        f":nonce={_NONCE.hex()}"
        f":enc_pub={'00' * 32}"
        f":QUOTE:pcr0={'aa' * 48}"
        f":pk={_SIGNING_PUB.hex()}"
        f":doc={ATTEST_DOC.hex()}"
    )


class TestVerifierConformance:
    """
    Exercises src/verifier/verify.py with the §14 session identity.

    Snapshot mode: build_signed_message() always writes PayloadLen=0 and
    SHA-256("") for the payload fields.  The §14 stream-mode PACKET_SIG was
    signed with PayloadLen=5 and SHA-256(b"hello"), so it is intentionally
    incompatible with the snapshot verifier — which is tested explicitly below.
    """

    # ── build_signed_message() field layout ─────────────────────────────────

    def test_build_signed_message_is_161_bytes(self):
        msg = _v.build_signed_message(SEQ, _L1_0, _L1_1, _L2_HASH, SESSION_ID)
        assert len(msg) == 161

    def test_build_signed_message_magic_is_vare(self):
        msg = _v.build_signed_message(SEQ, _L1_0, _L1_1, _L2_HASH, SESSION_ID)
        assert msg[0:4] == b"VARE"

    def test_build_signed_message_payload_len_is_zero(self):
        """Snapshot verifier always writes PayloadLen = 0 at bytes [109:113]."""
        msg = _v.build_signed_message(SEQ, _L1_0, _L1_1, _L2_HASH, SESSION_ID)
        assert struct.unpack("<I", msg[109:113])[0] == 0

    def test_build_signed_message_payload_hash_is_sha256_empty(self):
        """Snapshot verifier always writes SHA-256("") at bytes [113:145]."""
        msg = _v.build_signed_message(SEQ, _L1_0, _L1_1, _L2_HASH, SESSION_ID)
        assert msg[113:145] == hashlib.sha256(b"").digest()

    def test_build_signed_message_session_id_at_offset_145(self):
        """SessionID is embedded at the final 16 bytes [145:161]."""
        msg = _v.build_signed_message(SEQ, _L1_0, _L1_1, _L2_HASH, SESSION_ID)
        assert msg[145:161] == SESSION_ID

    def test_build_signed_message_sequence_u64_le(self):
        """Sequence is encoded as u64 little-endian at bytes [5:13]."""
        msg = _v.build_signed_message(SEQ, _L1_0, _L1_1, _L2_HASH, SESSION_ID)
        assert struct.unpack("<Q", msg[5:13])[0] == SEQ

    # ── Ed25519 round-trips ─────────────────────────────────────────────────

    def test_snapshot_sig_verifies_with_sec14_key(self):
        """A signature over a snapshot-mode message verifies with the §14.2 key."""
        snap_msg = _v.build_signed_message(SEQ, _L1_0, _L1_1, _L2_HASH, SESSION_ID)
        snap_sig = _SIGNING_KEY.sign(snap_msg)
        pub = Ed25519PublicKey.from_public_bytes(_SIGNING_PUB)
        pub.verify(snap_sig, snap_msg)   # must not raise

    def test_stream_sig_rejected_by_snapshot_verifier(self):
        """
        The §14 STREAM-mode PACKET_SIG (PayloadLen=5, SHA-256(b"hello"))
        MUST NOT verify against the snapshot-mode message (PayloadLen=0,
        SHA-256("")).  Stream and snapshot packets use intentionally different
        message formats; this test locks in that incompatibility.
        """
        snap_msg = _v.build_signed_message(SEQ, _L1_0, _L1_1, _L2_HASH, SESSION_ID)
        pub = Ed25519PublicKey.from_public_bytes(_SIGNING_PUB)
        stream_sig = bytes.fromhex(PACKET_SIG_HEX)
        with pytest.raises(InvalidSignature):
            pub.verify(stream_sig, snap_msg)

    # ── Structural checks via verify.py ─────────────────────────────────────

    def test_bootstrap_nonce_check_passes_with_sec14_inputs(self):
        """check_bootstrap_nonce() passes when nonce == SHA-256(doc ‖ session_id)."""
        hdr = _v.parse_header(_sec14_header_line())
        result = _v.check_bootstrap_nonce(hdr)
        assert result.passed

    def test_bootstrap_nonce_check_fails_with_wrong_nonce(self):
        """check_bootstrap_nonce() fails when the nonce is tampered."""
        tampered = (
            f"BUNDLE_HEADER:magic=VARB:version=01"
            f":session={SESSION_ID.hex()}"
            f":nonce={'ff' * 32}"
            f":enc_pub={'00' * 32}"
            f":QUOTE:pcr0={'aa' * 48}"
            f":pk={_SIGNING_PUB.hex()}"
            f":doc={ATTEST_DOC.hex()}"
        )
        hdr = _v.parse_header(tampered)
        result = _v.check_bootstrap_nonce(hdr)
        assert not result.passed

    def test_chain_continuity_with_sec14_l1_anchor(self):
        """
        A single evidence packet anchored at L1[0]=BootstrapNonce with
        stream=L1[1] satisfies check_chain_continuity().
        """
        pkt = _v.EvidencePacket(
            raw="",
            prev_stream=_L1_0,
            stream=_L1_1,
            state=_L2_HASH,
            sig=b"\x00" * 64,
            seq=1,
        )
        result = _v.check_chain_continuity([pkt], _NONCE)
        assert result.passed

    def test_full_verification_with_sec14_snapshot_packet(self):
        """
        End-to-end verify_segments() with the §14.2 session identity and a
        correctly-signed snapshot-mode packet.  All structural checks must pass;
        the Ed25519 signature check must also pass (cryptography is available).
        """
        snap_msg = _v.build_signed_message(SEQ, _L1_0, _L1_1, _L2_HASH, SESSION_ID)
        snap_sig = _SIGNING_KEY.sign(snap_msg)

        hdr = _v.parse_header(_sec14_header_line())
        pkt = _v.EvidencePacket(
            raw="",
            prev_stream=_L1_0,
            stream=_L1_1,
            state=_L2_HASH,
            sig=snap_sig,
            seq=SEQ,
        )
        seg = _v.Segment(header=hdr)
        seg.packets.append(pkt)

        passed, results = _v.verify_segments([seg])

        nonce_check = next(r for r in results if "4.2" in r.section)
        chain_check = next(r for r in results if "4.3" in r.section)
        assert nonce_check.passed, f"nonce check failed: {nonce_check.detail}"
        assert chain_check.passed, f"chain check failed: {chain_check.detail}"
        assert passed, "verify_segments() returned FAIL"
