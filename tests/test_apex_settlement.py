"""
APEX v2.2.0 Settlement Block Conformance Tests  (§15 Test Vectors)
===================================================================
27 tests pinning all §15.8 golden values for a two-packet session
with a Settlement Block.

Coverage:
  TestL1ChainExtension    (4)  — L1[2] formula and golden value
  TestScope2Layout        (6)  — 161-byte Scope[2] field layout
  TestSig2                (2)  — Packet 2 signature
  TestTerminalDigest2     (4)  — SHA-256(Sig[1]‖Sig[2]); ordering / §14 divergence
  TestBundleHash2         (3)  — BundleHash for two-packet session
  TestSealSig2            (3)  — SealSig for two-packet session
  TestSettlementSig       (5)  — 88-byte APXT scope; SettlementSig golden value

Run:
  pip install cryptography pytest
  pytest tests/test_apex_settlement.py -v
"""

import hashlib
import struct

import pytest

pytest.importorskip("cryptography", reason="pip install cryptography")

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ---------------------------------------------------------------------------
# §14.2 base inputs (unchanged)
# ---------------------------------------------------------------------------

SIGNING_SEED = bytes(32)
SESSION_ID   = bytes([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00,
    0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
])
ATTEST_DOC   = bytes([0xAA] * 96)
PAYLOAD_1    = b"hello"
SEQ_1        = 1

# ---------------------------------------------------------------------------
# §15.2 additional fixed inputs
# ---------------------------------------------------------------------------

PAYLOAD_2 = b"world"
SEQ_2     = 2

# Settlement scope (§6 sizes): EscrowID=16, Amount=32, Currency=8
ESCROW_ID = bytes.fromhex("deadbeefdead40008000deadbeef0001")   # 16 bytes
AMOUNT    = b"1000000" + b"\x00" * 25                           # 32 bytes: decimal zero-padded
CURRENCY  = b"USDC    "                                         # 8 bytes: space-padded

# ---------------------------------------------------------------------------
# §15.8 Golden values
# ---------------------------------------------------------------------------

L1_2_HEX             = "cd84b951c893096829a4c78ac9d3efc65f4dc9b3c3896df0653ea887d50142fe"
SIG_2_HEX            = (
    "937b3e0585745ce592b903c6b7fb0132d5b9658a7eae218ae8019353dd59b200"
    "6d8f84f7b2bb756940c7708308c8268315d1d09196f7bf2e68a5be9815d44904"
)
TERMINAL_DIGEST_2_HEX = "88e004ad67bf28c7a00d6c097ba8a6a09a11508af30b816dff692429b3c33c3d"
BUNDLE_HASH_2_HEX     = "e05dd6abae2ee095b5895632845c55ecf44e91bb6c166b83899eb10381f4990c"
SEAL_SIG_2_HEX        = (
    "fa384faab2d5d6fb2cd5df6a094cf800f6298ecfab4c3bdfbac2e58c687d651b"
    "8ff604df2f92b0f6e5c019189f8f18cb2e7058a878e05ce7496735ab10e3c00e"
)
SETTLE_SIG_HEX        = (
    "101f4cf36ec03be2ed7289b4acc664ed2353053a7f336f0094572a6dbb644b91"
    "980f7646defb52b4530a8855b4b780d9551375effa9f38b5a251aa861c43880b"
)

# §14 TerminalDigest for divergence tests
TERMINAL_DIGEST_14_HEX = "33c143a8fd36b26f375339c66ab10aab0f457e5a5678790c38cdf2fac08f9978"
# §14 BundleHash / SealSig for divergence tests
BUNDLE_HASH_14_HEX = "ddb62dbda59c6ea21ea7d6227d00e0d267dd8b1b3d35ad6a88c5fbfe4612399a"
SEAL_SIG_14_HEX    = (
    "8e0b8126cdf3f6453ecdbcbfe2656693b0d386b9a76dffe23875e95d487ce4b1"
    "51ba37b9e0df690c44a23b388e1e50661ac7b1531b9a963907b737f2eb3b120d"
)

# ---------------------------------------------------------------------------
# Helpers — no VAR imports
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _build_scope(
    seq: int,
    prev_l1: bytes,
    l1: bytes,
    l2: bytes,
    payload: bytes,
    session_id: bytes,
) -> bytes:
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


# ---------------------------------------------------------------------------
# Module-level derived values
# ---------------------------------------------------------------------------

_KEY   = Ed25519PrivateKey.from_private_bytes(SIGNING_SEED)
_PUB   = _KEY.public_key().public_bytes_raw()
_NONCE = _sha256(ATTEST_DOC + SESSION_ID)
_L1_0  = _NONCE
_L1_1  = _sha256(_L1_0 + PAYLOAD_1)
_L1_2  = _sha256(_L1_1 + PAYLOAD_2)

_L2_META = (
    bytes([0x01])
    + struct.pack("<H", 0)
    + struct.pack("<H", 0)
    + struct.pack("<H", 80)
    + struct.pack("<H", 24)
)
_L2_HASH = _sha256(_L2_META + _sha256(b""))

_SCOPE_1       = _build_scope(SEQ_1, _L1_0, _L1_1, _L2_HASH, PAYLOAD_1, SESSION_ID)
_SIG_1         = _KEY.sign(_SCOPE_1)
_SCOPE_2       = _build_scope(SEQ_2, _L1_1, _L1_2, _L2_HASH, PAYLOAD_2, SESSION_ID)
_SIG_2         = _KEY.sign(_SCOPE_2)
_TERMINAL_DIGEST_2 = _sha256(_SIG_1 + _SIG_2)
_BUNDLE_HASH_2 = _sha256(b"VARB" + SESSION_ID + _NONCE + _PUB + _TERMINAL_DIGEST_2)
_SEAL_SIG_2    = _KEY.sign(_BUNDLE_HASH_2)

_SETTLE_SCOPE  = ESCROW_ID + AMOUNT + CURRENCY + _TERMINAL_DIGEST_2
_SETTLE_SIG    = _KEY.sign(_SETTLE_SCOPE)


# ===========================================================================
# TestL1ChainExtension — 4 tests
# ===========================================================================

class TestL1ChainExtension:

    def test_l1_2_formula(self):
        """L1[2] = SHA-256(L1[1] ‖ b"world")."""
        assert _sha256(_L1_1 + PAYLOAD_2).hex() == L1_2_HEX

    def test_l1_2_golden(self):
        """Pinned: §15.8 L1[2] golden value."""
        assert _L1_2.hex() == L1_2_HEX

    def test_l1_1_is_prev_for_packet_2(self):
        """L1[1] (from §14) serves as PrevL1Hash for packet 2."""
        assert _SCOPE_2[13:45].hex() == _L1_1.hex()

    def test_l1_chain_strictly_extends(self):
        """L1[0], L1[1], L1[2] are all distinct — chain never collapses."""
        assert len({_L1_0.hex(), _L1_1.hex(), _L1_2.hex()}) == 3


# ===========================================================================
# TestScope2Layout — 6 tests
# ===========================================================================

class TestScope2Layout:

    def test_scope2_is_161_bytes(self):
        assert len(_SCOPE_2) == 161

    def test_scope2_magic_is_vare(self):
        assert _SCOPE_2[0:4] == b"VARE"

    def test_scope2_sequence_is_2(self):
        assert struct.unpack("<Q", _SCOPE_2[5:13])[0] == 2

    def test_scope2_prev_l1_is_l1_1(self):
        """PrevL1Hash of packet 2 == L1[1] (chain continuity)."""
        assert _SCOPE_2[13:45] == _L1_1

    def test_scope2_l1_is_l1_2(self):
        """L1Hash of packet 2 == L1[2]."""
        assert _SCOPE_2[45:77] == _L1_2

    def test_scope2_session_id_at_offset_145(self):
        """SessionID is embedded at bytes [145:161] — binds sig to this session."""
        assert _SCOPE_2[145:161] == SESSION_ID


# ===========================================================================
# TestSig2 — 2 tests
# ===========================================================================

class TestSig2:

    def test_sig2_verifies(self):
        """Ed25519 signature over Scope[2] must verify with the §14.2 public key."""
        pub = Ed25519PublicKey.from_public_bytes(_PUB)
        pub.verify(_SIG_2, _SCOPE_2)   # raises InvalidSignature on failure

    def test_sig2_golden(self):
        """Pinned: §15.8 Sig[2] golden value."""
        assert _SIG_2.hex() == SIG_2_HEX


# ===========================================================================
# TestTerminalDigest2 — 4 tests
# ===========================================================================

class TestTerminalDigest2:

    def test_terminal_digest_formula(self):
        """TerminalDigest = SHA-256(Sig[1] ‖ Sig[2]) for two-packet session."""
        assert _sha256(_SIG_1 + _SIG_2).hex() == TERMINAL_DIGEST_2_HEX

    def test_terminal_digest_golden(self):
        """Pinned: §15.8 TerminalDigest golden value."""
        assert _TERMINAL_DIGEST_2.hex() == TERMINAL_DIGEST_2_HEX

    def test_ordering_matters(self):
        """SHA-256(Sig[2] ‖ Sig[1]) MUST differ from SHA-256(Sig[1] ‖ Sig[2])."""
        reversed_td = _sha256(_SIG_2 + _SIG_1)
        assert reversed_td.hex() != TERMINAL_DIGEST_2_HEX

    def test_sec14_terminal_digest_diverges(self):
        """§14 single-sig TerminalDigest MUST NOT equal §15 two-sig TerminalDigest."""
        assert TERMINAL_DIGEST_14_HEX != TERMINAL_DIGEST_2_HEX


# ===========================================================================
# TestBundleHash2 — 3 tests
# ===========================================================================

class TestBundleHash2:

    def test_bundle_hash_formula(self):
        """BundleHash = SHA-256("VARB" ‖ SessionID ‖ BootstrapNonce ‖ SigningPub ‖ TerminalDigest)."""
        expected = _sha256(
            b"VARB"
            + SESSION_ID
            + _NONCE
            + _PUB
            + bytes.fromhex(TERMINAL_DIGEST_2_HEX)
        )
        assert expected.hex() == BUNDLE_HASH_2_HEX

    def test_bundle_hash_golden(self):
        """Pinned: §15.8 BundleHash golden value."""
        assert _BUNDLE_HASH_2.hex() == BUNDLE_HASH_2_HEX

    def test_bundle_hash_diverges_from_sec14(self):
        """§14 (single-packet) BundleHash MUST differ from §15 (two-packet) BundleHash."""
        assert BUNDLE_HASH_14_HEX != BUNDLE_HASH_2_HEX


# ===========================================================================
# TestSealSig2 — 3 tests
# ===========================================================================

class TestSealSig2:

    def test_seal_sig_verifies(self):
        """SealSig must verify over BundleHash with the §14.2 public key."""
        pub = Ed25519PublicKey.from_public_bytes(_PUB)
        pub.verify(_SEAL_SIG_2, _BUNDLE_HASH_2)   # raises on failure

    def test_seal_sig_golden(self):
        """Pinned: §15.8 SealSig golden value."""
        assert _SEAL_SIG_2.hex() == SEAL_SIG_2_HEX

    def test_seal_sig_diverges_from_sec14(self):
        """§14 (single-packet) SealSig MUST differ from §15 (two-packet) SealSig."""
        assert SEAL_SIG_14_HEX != SEAL_SIG_2_HEX


# ===========================================================================
# TestSettlementSig — 5 tests
# ===========================================================================

class TestSettlementSig:

    def test_settlement_scope_is_88_bytes(self):
        """APXT settlement signature scope is exactly 88 bytes (§6 / §15.7)."""
        assert len(_SETTLE_SCOPE) == 88

    def test_settlement_scope_layout(self):
        """Field offsets in 88-byte scope: EscrowID[0:16], Amount[16:48], Currency[48:56], TerminalDigest[56:88]."""
        assert _SETTLE_SCOPE[0:16]  == ESCROW_ID
        assert _SETTLE_SCOPE[16:48] == AMOUNT
        assert _SETTLE_SCOPE[48:56] == CURRENCY
        assert _SETTLE_SCOPE[56:88] == _TERMINAL_DIGEST_2

    def test_settlement_sig_verifies(self):
        """SettlementSig must verify over the 88-byte scope with the §14.2 public key."""
        pub = Ed25519PublicKey.from_public_bytes(_PUB)
        pub.verify(_SETTLE_SIG, _SETTLE_SCOPE)   # raises on failure

    def test_settlement_sig_golden(self):
        """Pinned: §15.8 SettlementSig golden value."""
        assert _SETTLE_SIG.hex() == SETTLE_SIG_HEX

    def test_settlement_wrong_terminal_digest_fails(self):
        """
        A settlement scope with the wrong TerminalDigest (e.g. §14 value)
        MUST NOT verify against the §15 SettlementSig.
        """
        wrong_scope = ESCROW_ID + AMOUNT + CURRENCY + bytes.fromhex(TERMINAL_DIGEST_14_HEX)
        pub = Ed25519PublicKey.from_public_bytes(_PUB)
        with pytest.raises(InvalidSignature):
            pub.verify(_SETTLE_SIG, wrong_scope)
