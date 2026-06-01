#!/usr/bin/env python3
"""
APEX v2.1.0 Test Vector Generator
==================================
Generates fully-deterministic test vectors for the APEX specification.

All values are synthetic / for test use only.
Run with: python3 tools/gen_test_vectors.py

Output is a Markdown block suitable for pasting directly into spec/APEX.md §14.
"""

import hashlib
import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ── Helpers ────────────────────────────────────────────────────────────────────

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hex_block(data: bytes, indent: int = 0) -> str:
    """Format bytes as grouped hex (16 per line)."""
    pad = " " * indent
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        line = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"{pad}{line}")
    return "\n".join(lines)

def label_row(offset: int, size: int, field: str, value: bytes) -> str:
    hex_val = value.hex()
    return f"| {offset:5d} | {size:5d} | {field:<30s} | `{hex_val}` |"

# ── Fixed test inputs ───────────────────────────────────────────────────────────

# Ed25519 seed: 32 zero bytes — NEVER use in production
SIGNING_SEED = bytes(32)
# Note: cryptography lib takes private key as seed directly
SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(SIGNING_SEED)
SIGNING_PUB = SIGNING_KEY.public_key().public_bytes_raw()

# PCR values: 48 zero bytes each (synthetic — simulation mode)
PCR0 = bytes(48)
PCR1 = bytes(48)
PCR2 = bytes(48)
PCR_COMMITMENT = sha256(PCR0 + PCR1 + PCR2)

# SessionID: UUID v4 canonical — first non-null test UUID
# Bytes: 00000000-0000-4000-8000-000000000001
SESSION_ID = bytes([0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x40, 0x00,
                    0x80, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01])

# AgentID: SHA-256 of the string "TEST_AGENT" (placeholder)
AGENT_ID = sha256(b"TEST_AGENT")

# AttestationDoc: 96 bytes of 0xAA (simulation mode per §11)
ATTEST_DOC = bytes([0xAA] * 96)

# BundleID: fixed test UUID
BUNDLE_ID = bytes([0xDE, 0xAD, 0xBE, 0xEF,
                   0xDE, 0xAD, 0x40, 0x00,
                   0x80, 0x00, 0xDE, 0xAD,
                   0xBE, 0xEF, 0x00, 0x01])

# CreatedAt: fixed timestamp (2025-01-01 00:00:00 UTC in nanoseconds)
CREATED_AT = 1735689600_000_000_000  # nanoseconds

# Payload: 5 ASCII bytes
PAYLOAD = b"hello"

# Sequence number for the single packet
SEQ = 1

# ── Derivations ─────────────────────────────────────────────────────────────────

# Bootstrap Nonce (spec §3.1)
# BootstrapNonce = SHA-256(AttestationDoc ‖ SessionID)
BOOTSTRAP_NONCE = sha256(ATTEST_DOC + SESSION_ID)

# L1 chain
# L1[0] = BootstrapNonce  (initial state)
L1_0 = BOOTSTRAP_NONCE
# L1[1] = SHA-256(L1[0] ‖ payload)
L1_1 = sha256(L1_0 + PAYLOAD)

# L2 Hash: minimal terminal state
# FormatVer=0x01, cursor_x=0, cursor_y=0, width=80, height=24, cell_digest=SHA-256("")
L2_META = (
    bytes([0x01])                   # format_version
    + struct.pack("<H", 0)          # cursor_x
    + struct.pack("<H", 0)          # cursor_y
    + struct.pack("<H", 80)         # terminal_width
    + struct.pack("<H", 24)         # terminal_height
)
L2_CELL_DIGEST = sha256(b"")        # empty cell grid
L2_HASH = sha256(L2_META + L2_CELL_DIGEST)

# SHA-256(Payload)
PAYLOAD_HASH = sha256(PAYLOAD)

# ── Signature scope (161 bytes, matching VAR reference implementation) ──────────
#
# NOTE: The VAR reference implementation (src/runtime/shell.zig) uses:
#   - Magic "VARE" (0x56 0x41 0x52 0x45) instead of the spec's "APXE"
#   - 161-byte scope omitting the ActionType byte
# These test vectors match the reference implementation exactly.
# See §14.1 note for details.

def build_sig_scope() -> bytes:
    msg = bytearray(161)
    pos = 0

    # Magic "VARE"
    msg[pos:pos+4] = b"VARE"
    pos += 4

    # FormatVer = 0x01
    msg[pos] = 0x01
    pos += 1

    # Sequence (u64 LE)
    struct.pack_into("<Q", msg, pos, SEQ)
    pos += 8

    # PrevL1Hash = L1[0] = BootstrapNonce
    msg[pos:pos+32] = L1_0
    pos += 32

    # L1Hash = L1[1]
    msg[pos:pos+32] = L1_1
    pos += 32

    # L2Hash
    msg[pos:pos+32] = L2_HASH
    pos += 32

    # PayloadLen (u32 LE) — NOTE: the reference impl always writes 0 in snapshot mode.
    # For the test vector we write the actual payload length to match a full STREAM packet.
    struct.pack_into("<I", msg, pos, len(PAYLOAD))
    pos += 4

    # SHA-256(Payload)
    msg[pos:pos+32] = PAYLOAD_HASH
    pos += 32

    # SessionID
    msg[pos:pos+16] = SESSION_ID
    pos += 16

    assert pos == 161, f"expected 161, got {pos}"
    return bytes(msg)

SIG_SCOPE = build_sig_scope()

# Ed25519 signature
PACKET_SIG = SIGNING_KEY.sign(SIG_SCOPE)

# ── Bundle Seal ──────────────────────────────────────────────────────────────────

# TerminalDigest = SHA-256(Packet[1].Signature)  (single-packet session)
TERMINAL_DIGEST = sha256(PACKET_SIG)

# BundleHash (VAR reference implementation formula):
# SHA-256("VARB" ‖ session_id ‖ bootstrap_nonce ‖ signing_pub ‖ TerminalDigest)
BUNDLE_HASH = sha256(b"VARB" + SESSION_ID + BOOTSTRAP_NONCE + SIGNING_PUB + TERMINAL_DIGEST)

# SealSig = Ed25519(keypair, BundleHash)
SEAL_SIG = SIGNING_KEY.sign(BUNDLE_HASH)

# ── Render output ─────────────────────────────────────────────────────────────────

def render_scope_table(scope: bytes) -> str:
    """Render the 161-byte scope as a byte-by-byte annotated table."""
    rows = []
    rows.append("| Offset | Size | Field | Value |")
    rows.append("|-------:|-----:|:------|:------|")

    def add_row(offset, size, field, value):
        rows.append(f"| {offset} | {size} | {field} | `{value.hex()}` |")

    offset = 0
    add_row(0,   4,  'Magic (`"VARE"`)',         scope[0:4])
    add_row(4,   1,  'FormatVer',                scope[4:5])
    add_row(5,   8,  'Sequence (u64 LE = 1)',    scope[5:13])
    add_row(13,  32, 'PrevL1Hash (= BootstrapNonce)', scope[13:45])
    add_row(45,  32, 'L1Hash',                   scope[45:77])
    add_row(77,  32, 'L2Hash',                   scope[77:109])
    add_row(109, 4,  'PayloadLen (u32 LE = 5)',  scope[109:113])
    add_row(113, 32, 'SHA-256(Payload)',          scope[113:145])
    add_row(145, 16, 'SessionID',                scope[145:161])
    rows.append(f"| **161** | | **total** | |")

    return "\n".join(rows)


def render_hex_block(data: bytes, cols: int = 16) -> str:
    lines = []
    for i in range(0, len(data), cols):
        chunk = data[i:i+cols]
        lines.append("  " + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(lines)


def main():
    out = []

    out.append("## 14. Test Vectors")
    out.append("")
    out.append("### §14.1 Scope and Notation")
    out.append("")
    out.append("The following test vectors give a fully-worked single-packet session using")
    out.append("known synthetic inputs. A third-party implementer who can reproduce every")
    out.append("value independently has confirmed correct byte layout, correct endianness,")
    out.append("and correct hash chaining without running VAR.")
    out.append("")
    out.append("**Notation**")
    out.append("")
    out.append("- `‖` denotes byte concatenation.")
    out.append("- All hex strings are lowercase, no spaces, unless formatted as byte blocks.")
    out.append("- `u64 LE` / `u32 LE` = little-endian unsigned integer.")
    out.append("- Values labelled **SYNTHETIC / TEST-ONLY** MUST NOT appear in production bundles.")
    out.append("")
    out.append("> **Implementation note.** The VAR reference implementation")
    out.append("> (`src/runtime/shell.zig`) uses magic bytes `VARE` (0x56 0x41 0x52 0x45)")
    out.append("> and a **161-byte** signature scope (ActionType byte omitted).")
    out.append("> These test vectors match that behaviour. A future APEX 3.0 revision")
    out.append("> will unify the magic bytes across all packet types under the `APX*` prefix.")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §14.2 Fixed Inputs")
    out.append("")
    out.append("#### Ed25519 Signing Keypair (SYNTHETIC / TEST-ONLY)")
    out.append("")
    out.append("| Field | Value |")
    out.append("|:------|:------|")
    out.append(f"| Seed (32 bytes) | `{SIGNING_SEED.hex()}` |")
    out.append(f"| Public key (32 bytes) | `{SIGNING_PUB.hex()}` |")
    out.append("")
    out.append("#### Platform Configuration Registers (SYNTHETIC — all-zero simulation)")
    out.append("")
    out.append("| Register | Value (48 bytes) |")
    out.append("|:---------|:-----------------|")
    out.append(f"| PCR0 | `{'00' * 48}` |")
    out.append(f"| PCR1 | `{'00' * 48}` |")
    out.append(f"| PCR2 | `{'00' * 48}` |")
    out.append(f"| PCRCommitment | `{PCR_COMMITMENT.hex()}` |")
    out.append("")
    out.append("#### Session Identity")
    out.append("")
    out.append("| Field | Value |")
    out.append("|:------|:------|")
    out.append(f"| SessionID (16 bytes) | `{SESSION_ID.hex()}` |")
    out.append(f"| BundleID (16 bytes) | `{BUNDLE_ID.hex()}` |")
    out.append(f"| AgentID (32 bytes) | `{AGENT_ID.hex()}` |")
    out.append(f"| CreatedAt (u64 LE ns) | `{struct.pack('<Q', CREATED_AT).hex()}` = {CREATED_AT} ns |")
    out.append("")
    out.append("#### Attestation Document (SYNTHETIC — simulation mode §11)")
    out.append("")
    out.append("96 bytes of `0xaa`, representing the placeholder attestation used in")
    out.append("simulation mode when Nitro hardware is absent:")
    out.append("")
    out.append("```")
    out.append(render_hex_block(ATTEST_DOC))
    out.append("```")
    out.append("")
    out.append("#### Packet Payload")
    out.append("")
    out.append("| Field | Value |")
    out.append("|:------|:------|")
    out.append(f"| Payload bytes | `{PAYLOAD.hex()}` (`{PAYLOAD.decode()}`) |")
    out.append(f"| PayloadLen | {len(PAYLOAD)} |")
    out.append(f"| ActionType | `01` (STREAM) |")
    out.append(f"| Sequence | 1 |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §14.3 Bootstrap Nonce")
    out.append("")
    out.append("```")
    out.append("BootstrapNonce = SHA-256(AttestationDoc ‖ SessionID)")
    out.append("```")
    out.append("")
    out.append("| Input | Bytes | Hex |")
    out.append("|:------|------:|:----|")
    out.append(f"| AttestationDoc | 96 | `{ATTEST_DOC[:8].hex()}…` (96 × 0xaa) |")
    out.append(f"| SessionID | 16 | `{SESSION_ID.hex()}` |")
    out.append(f"| **BootstrapNonce** | **32** | `{BOOTSTRAP_NONCE.hex()}` |")
    out.append("")
    out.append("> **L1 chain genesis:** `L1[0] = BootstrapNonce`")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §14.4 L1 Hash After One Packet")
    out.append("")
    out.append("```")
    out.append("L1[1] = SHA-256(L1[0] ‖ payload)")
    out.append("      = SHA-256(BootstrapNonce ‖ b\"hello\")")
    out.append("```")
    out.append("")
    out.append("| Field | Value |")
    out.append("|:------|:------|")
    out.append(f"| L1[0] = BootstrapNonce | `{L1_0.hex()}` |")
    out.append(f"| Payload (`hello`) | `{PAYLOAD.hex()}` |")
    out.append(f"| **L1[1]** | **`{L1_1.hex()}`** |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §14.5 L2 State Hash")
    out.append("")
    out.append("Computed over a minimal terminal state (80 × 24, cursor at origin, empty cell grid):")
    out.append("")
    out.append("```")
    out.append("L2 = SHA-256(format_version ‖ cursor_x ‖ cursor_y ‖ width ‖ height ‖ cell_digest)")
    out.append("```")
    out.append("")
    out.append("| Component | Size | Value |")
    out.append("|:----------|-----:|:------|")
    out.append(f"| format_version (u8) | 1 | `01` |")
    out.append(f"| cursor_x (u16 LE) | 2 | `0000` |")
    out.append(f"| cursor_y (u16 LE) | 2 | `0000` |")
    out.append(f"| terminal_width (u16 LE = 80) | 2 | `{struct.pack('<H', 80).hex()}` |")
    out.append(f"| terminal_height (u16 LE = 24) | 2 | `{struct.pack('<H', 24).hex()}` |")
    out.append(f"| cell_digest = SHA-256(`\"\"`) | 32 | `{sha256(b'').hex()}` |")
    out.append(f"| **L2Hash** | **32** | **`{L2_HASH.hex()}`** |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §14.6 Evidence Packet — 161-byte Signature Scope")
    out.append("")
    out.append("The enclave signs this fixed-length 161-byte message:")
    out.append("")
    out.append(render_scope_table(SIG_SCOPE))
    out.append("")
    out.append("Full scope (161 bytes):")
    out.append("")
    out.append("```")
    out.append(render_hex_block(SIG_SCOPE))
    out.append("```")
    out.append("")
    out.append("#### Packet Signature")
    out.append("")
    out.append("```")
    out.append("Signature = Ed25519_Sign(signing_key, scope_161)")
    out.append("```")
    out.append("")
    out.append(f"| Field | Value |")
    out.append(f"|:------|:------|")
    out.append(f"| Signature (64 bytes) | `{PACKET_SIG.hex()}` |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §14.7 Terminal Digest and Bundle Seal")
    out.append("")
    out.append("Single-packet session; TerminalDigest covers exactly one signature.")
    out.append("")
    out.append("```")
    out.append("TerminalDigest = SHA-256(Packet[1].Signature)")
    out.append("BundleHash     = SHA-256(\"VARB\" ‖ SessionID ‖ BootstrapNonce ‖ SigningPub ‖ TerminalDigest)")
    out.append("SealSig        = Ed25519_Sign(signing_key, BundleHash)")
    out.append("```")
    out.append("")
    out.append("| Field | Value |")
    out.append("|:------|:------|")
    out.append(f"| Packet[1].Signature | `{PACKET_SIG.hex()}` |")
    out.append(f"| **TerminalDigest** | **`{TERMINAL_DIGEST.hex()}`** |")
    out.append(f"| `\"VARB\"` prefix | `56415242` |")
    out.append(f"| SessionID | `{SESSION_ID.hex()}` |")
    out.append(f"| BootstrapNonce | `{BOOTSTRAP_NONCE.hex()}` |")
    out.append(f"| SigningPub | `{SIGNING_PUB.hex()}` |")
    out.append(f"| **BundleHash** | **`{BUNDLE_HASH.hex()}`** |")
    out.append(f"| **SealSig** | **`{SEAL_SIG.hex()}`** |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §14.8 Summary")
    out.append("")
    out.append("A compliant implementation MUST produce these exact values given the inputs in §14.2:")
    out.append("")
    out.append("| Value | Expected |")
    out.append("|:------|:---------|")
    out.append(f"| BootstrapNonce | `{BOOTSTRAP_NONCE.hex()}` |")
    out.append(f"| L1[1] | `{L1_1.hex()}` |")
    out.append(f"| L2Hash | `{L2_HASH.hex()}` |")
    out.append(f"| Packet[1].Signature | `{PACKET_SIG.hex()}` |")
    out.append(f"| TerminalDigest | `{TERMINAL_DIGEST.hex()}` |")
    out.append(f"| BundleHash | `{BUNDLE_HASH.hex()}` |")
    out.append(f"| SealSig | `{SEAL_SIG.hex()}` |")
    out.append("")

    # ── §15: Settlement Block Test Vectors ────────────────────────────────────

    # Additional fixed inputs (§15.2)
    PAYLOAD_2 = b"world"
    SEQ_2     = 2

    # Settlement scope sizes per §6: EscrowID=16, Amount=32, Currency=8
    ESCROW_ID = bytes.fromhex("deadbeefdead40008000deadbeef0001")
    AMOUNT    = b"1000000" + b"\x00" * 25   # 32 bytes decimal zero-padded
    CURRENCY  = b"USDC    "                  # 8 bytes space-padded

    # L1 chain extension
    L1_2 = sha256(L1_1 + PAYLOAD_2)

    # Scope[2] — 161-byte STREAM mode for packet 2
    def build_scope2() -> bytes:
        msg = bytearray(161)
        msg[0:4] = b"VARE"
        msg[4] = 0x01
        struct.pack_into("<Q", msg, 5, SEQ_2)
        msg[13:45]  = L1_1
        msg[45:77]  = L1_2
        msg[77:109] = L2_HASH
        struct.pack_into("<I", msg, 109, len(PAYLOAD_2))
        msg[113:145] = sha256(PAYLOAD_2)
        msg[145:161] = SESSION_ID
        assert len(msg) == 161
        return bytes(msg)

    SIG_SCOPE_2  = build_scope2()
    PACKET_SIG_2 = SIGNING_KEY.sign(SIG_SCOPE_2)

    # Two-packet TerminalDigest: SHA-256(Sig[1] ‖ Sig[2])
    TERMINAL_DIGEST_2 = sha256(PACKET_SIG + PACKET_SIG_2)

    # BundleHash and SealSig for two-packet session
    BUNDLE_HASH_2 = sha256(b"VARB" + SESSION_ID + BOOTSTRAP_NONCE + SIGNING_PUB + TERMINAL_DIGEST_2)
    SEAL_SIG_2    = SIGNING_KEY.sign(BUNDLE_HASH_2)

    # Settlement scope: EscrowID(16) | Amount(32) | Currency(8) | TerminalDigest(32) = 88 bytes
    SETTLE_SCOPE = ESCROW_ID + AMOUNT + CURRENCY + TERMINAL_DIGEST_2
    assert len(SETTLE_SCOPE) == 88
    SETTLE_SIG = SIGNING_KEY.sign(SETTLE_SCOPE)

    out.append("---")
    out.append("")
    out.append("## 15. Settlement Block Test Vectors")
    out.append("")
    out.append("### §15.1 Scope")
    out.append("")
    out.append("§15 extends the §14 session by one additional evidence packet and a")
    out.append("Settlement Block, verifying TerminalDigest over multiple signatures")
    out.append("and the 88-byte APXT settlement signature scope.")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §15.2 Additional Fixed Inputs")
    out.append("")
    out.append("#### Second Packet")
    out.append("")
    out.append("| Field | Value |")
    out.append("|:------|:------|")
    out.append(f"| Payload bytes | `{PAYLOAD_2.hex()}` (`{PAYLOAD_2.decode()}`) |")
    out.append(f"| PayloadLen | {len(PAYLOAD_2)} |")
    out.append(f"| ActionType | `01` (STREAM) |")
    out.append(f"| Sequence | {SEQ_2} |")
    out.append("")
    out.append("#### Settlement Inputs (SYNTHETIC / TEST-ONLY)")
    out.append("")
    out.append("| Field | Size | Value |")
    out.append("|:------|-----:|:------|")
    out.append(f"| EscrowID | 16 | `{ESCROW_ID.hex()}` |")
    out.append(f"| Amount (decimal, zero-padded) | 32 | `{AMOUNT.hex()}` |")
    out.append(f"| Currency (space-padded) | 8 | `{CURRENCY.hex()}` (`\"USDC    \"`) |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §15.3 L1 Chain Extension")
    out.append("")
    out.append("```")
    out.append("L1[2] = SHA-256(L1[1] ‖ b\"world\")")
    out.append("```")
    out.append("")
    out.append("| Field | Value |")
    out.append("|:------|:------|")
    out.append(f"| L1[1] (from §14) | `{L1_1.hex()}` |")
    out.append(f"| Payload (`world`) | `{PAYLOAD_2.hex()}` |")
    out.append(f"| **L1[2]** | **`{L1_2.hex()}`** |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §15.4 Scope[2] — 161-byte Signature Scope for Packet 2")
    out.append("")
    out.append(render_scope_table(SIG_SCOPE_2))
    out.append("")
    out.append("Full scope (161 bytes):")
    out.append("")
    out.append("```")
    out.append(render_hex_block(SIG_SCOPE_2))
    out.append("```")
    out.append("")
    out.append("#### Packet 2 Signature")
    out.append("")
    out.append(f"| Field | Value |")
    out.append(f"|:------|:------|")
    out.append(f"| Sig[2] (64 bytes) | `{PACKET_SIG_2.hex()}` |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §15.5 Terminal Digest — Two-Packet Session")
    out.append("")
    out.append("```")
    out.append("TerminalDigest = SHA-256(Sig[1] ‖ Sig[2])")
    out.append("```")
    out.append("")
    out.append("| Field | Value |")
    out.append("|:------|:------|")
    out.append(f"| Sig[1] (from §14) | `{PACKET_SIG.hex()}` |")
    out.append(f"| Sig[2] | `{PACKET_SIG_2.hex()}` |")
    out.append(f"| **TerminalDigest** | **`{TERMINAL_DIGEST_2.hex()}`** |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §15.6 Bundle Seal — Two-Packet Session")
    out.append("")
    out.append("| Field | Value |")
    out.append("|:------|:------|")
    out.append(f"| **BundleHash** | **`{BUNDLE_HASH_2.hex()}`** |")
    out.append(f"| **SealSig** | **`{SEAL_SIG_2.hex()}`** |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §15.7 Settlement Block — APXT Signature Scope")
    out.append("")
    out.append("| Offset | Size | Field | Value |")
    out.append("|-------:|-----:|:------|:------|")
    out.append(f"| 0 | 16 | EscrowID | `{ESCROW_ID.hex()}` |")
    out.append(f"| 16 | 32 | Amount (decimal, zero-padded) | `{AMOUNT.hex()}` |")
    out.append(f"| 48 | 8 | Currency (space-padded) | `{CURRENCY.hex()}` |")
    out.append(f"| 56 | 32 | TerminalDigest | `{TERMINAL_DIGEST_2.hex()}` |")
    out.append(f"| **88** | | **total** | |")
    out.append("")
    out.append(f"| Field | Value |")
    out.append(f"|:------|:------|")
    out.append(f"| **SettlementSig** | **`{SETTLE_SIG.hex()}`** |")
    out.append("")
    out.append("---")
    out.append("")
    out.append("### §15.8 Summary")
    out.append("")
    out.append("A compliant implementation MUST produce these exact values given the §14.2")
    out.append("inputs plus the §15.2 additional inputs:")
    out.append("")
    out.append("| Value | Expected |")
    out.append("|:------|:---------|")
    out.append(f"| L1[2] | `{L1_2.hex()}` |")
    out.append(f"| Sig[2] | `{PACKET_SIG_2.hex()}` |")
    out.append(f"| TerminalDigest | `{TERMINAL_DIGEST_2.hex()}` |")
    out.append(f"| BundleHash | `{BUNDLE_HASH_2.hex()}` |")
    out.append(f"| SealSig | `{SEAL_SIG_2.hex()}` |")
    out.append(f"| SettlementSig | `{SETTLE_SIG.hex()}` |")
    out.append("")

    # Print to stdout
    print("\n".join(out))

    # Sanity-check sizes — §14
    assert len(BOOTSTRAP_NONCE) == 32
    assert len(L1_1) == 32
    assert len(L2_HASH) == 32
    assert len(PACKET_SIG) == 64
    assert len(TERMINAL_DIGEST) == 32
    assert len(BUNDLE_HASH) == 32
    assert len(SEAL_SIG) == 64
    assert len(SIG_SCOPE) == 161
    # Sanity-check sizes — §15
    assert len(L1_2) == 32
    assert len(PACKET_SIG_2) == 64
    assert len(TERMINAL_DIGEST_2) == 32
    assert len(BUNDLE_HASH_2) == 32
    assert len(SEAL_SIG_2) == 64
    assert len(SETTLE_SIG) == 64
    assert len(SETTLE_SCOPE) == 88
    assert len(SIG_SCOPE_2) == 161
    print(
        f"<!-- Generated by tools/gen_test_vectors.py — "
        f"§14 ({len(SIG_SCOPE)}-byte scope) and §15 ({len(SETTLE_SCOPE)}-byte settlement scope) assertions pass -->",
        file=__import__("sys").stderr,
    )

if __name__ == "__main__":
    main()
