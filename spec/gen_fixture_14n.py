#!/usr/bin/env python3
"""
Computes §14.N two-segment session test vectors for APEX.md.

Fixture shape:
  SESSION_START[1] → EVIDENCE[2] → TEMPORAL_PROOF[3]
  → SESSION_RESUME[4] → SETTLEMENT_FINAL[5]

Packet specs implemented here:
  SESSION_START  (0x06): 161-byte "APXE" scope, empty payload
  EVIDENCE       (0x01): 161-byte "APXE" scope, payload = "hello"
  TEMPORAL_PROOF (0x09): 137-byte "APXP" scope, Argon2id SWF
  SESSION_RESUME (0x07):  93-byte "APXS" scope, no payload/L2
  SETTLEMENT_FINAL(0x05): §6 APXT settlement block (TerminalDigest over sigs 1-4)

Segment 1 uses keypair A (seed = 0x00 * 32).
Segment 2 uses keypair B (seed = 0x01 * 32).
All other inputs from §14.2.
"""

import hashlib
import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import argon2

# ── Fixed §14.2 inputs ────────────────────────────────────────────────────────

SEED_A = bytes(32)                                            # 0x00 * 32
SEED_B = bytes([0x01] * 32)                                   # 0x01 * 32
SESSION_ID = bytes.fromhex("00000000000040008000000000000001")
BUNDLE_ID  = bytes.fromhex("deadbeefdead40008000deadbeef0001")
ATTEST_DOC = bytes([0xAA] * 96)

# Settlement inputs (same as §15)
ESCROW_ID = BUNDLE_ID
AMOUNT    = b"1000000" + bytes(25)                            # 7 ASCII + 25 NUL = 32 bytes
CURRENCY  = b"USDC    "                                       # 8 bytes space-padded

# Argon2id constants from shell.zig §5.7
ARGON_SALT = b"APEX_SWFv1\x00\x00\x00\x00\x00\x00"         # 16 bytes
ARGON_M = 65536
ARGON_T = 3
ARGON_P = 1

# ── Helpers ───────────────────────────────────────────────────────────────────

def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()

def hex_(b):
    return b.hex()

def fmt_bytes(b, width=16):
    rows = []
    for i in range(0, len(b), width):
        rows.append("  " + " ".join(f"{x:02x}" for x in b[i:i+width]))
    return "\n".join(rows)

# ── Keypairs ──────────────────────────────────────────────────────────────────

kp_a = Ed25519PrivateKey.from_private_bytes(SEED_A)
pub_a = kp_a.public_key().public_bytes_raw()

kp_b = Ed25519PrivateKey.from_private_bytes(SEED_B)
pub_b = kp_b.public_key().public_bytes_raw()

# ── Bootstrap nonce ───────────────────────────────────────────────────────────

bootstrap_nonce = sha256(ATTEST_DOC, SESSION_ID)
L1 = [bootstrap_nonce]  # L1[0] = BootstrapNonce

# ── Scope builders ────────────────────────────────────────────────────────────

SHA256_EMPTY = sha256(b"")

def scope_vare(seq, prev_l1, l1, l2, payload_bytes):
    """161-byte APXE scope for SESSION_START and EVIDENCE packets."""
    payload_hash = sha256(payload_bytes) if payload_bytes else SHA256_EMPTY
    payload_len  = len(payload_bytes)
    msg  = b"APXE"
    msg += b"\x01"                                    # FormatVer
    msg += struct.pack("<Q", seq)                     # Sequence u64 LE
    msg += prev_l1                                    # PrevL1Hash
    msg += l1                                         # L1Hash
    msg += l2                                         # L2Hash
    msg += struct.pack("<I", payload_len)             # PayloadLen u32 LE
    msg += payload_hash                               # SHA-256(Payload)
    msg += SESSION_ID                                 # SessionID
    assert len(msg) == 161, f"APXE scope length {len(msg)}"
    return msg

def scope_apxp(seq, prev_l1, l1, argon_out):
    """137-byte APXP scope for TEMPORAL_PROOF."""
    msg  = b"APXP"
    msg += b"\x01"
    msg += struct.pack("<Q", seq)
    msg += prev_l1
    msg += l1
    msg += argon_out
    msg += struct.pack("<I", ARGON_M)
    msg += struct.pack("<I", ARGON_T)
    msg += struct.pack("<I", ARGON_P)
    msg += SESSION_ID
    assert len(msg) == 137, f"APXP scope length {len(msg)}"
    return msg

def scope_vars(seq, prev_l1, l1):
    """93-byte APXS scope for SESSION_RESUME."""
    msg  = b"APXS"
    msg += b"\x01"
    msg += struct.pack("<Q", seq)
    msg += prev_l1
    msg += l1
    msg += SESSION_ID
    assert len(msg) == 93, f"APXS scope length {len(msg)}"
    return msg

# ── L2 state hash (same as §14: 80×24 terminal, empty cell grid) ──────────────

def compute_l2():
    cell_digest = sha256(b"")   # SHA-256("") — empty cell grid
    msg  = b"\x01"              # format_version
    msg += struct.pack("<H", 0)   # cursor_x
    msg += struct.pack("<H", 0)   # cursor_y
    msg += struct.pack("<H", 80)  # width
    msg += struct.pack("<H", 24)  # height
    msg += cell_digest
    return sha256(msg)

L2 = compute_l2()

# ── Packet 1: SESSION_START (seq=1, keypair A, payload="") ────────────────────

payload_start = b""
L1.append(sha256(L1[0], payload_start))   # L1[1]
scope1 = scope_vare(1, L1[0], L1[1], L2, payload_start)
sig1   = kp_a.sign(scope1)

# ── Packet 2: EVIDENCE (seq=2, keypair A, payload="hello") ────────────────────

payload_ev = b"hello"
L1.append(sha256(L1[1], payload_ev))      # L1[2]
scope2 = scope_vare(2, L1[1], L1[2], L2, payload_ev)
sig2   = kp_a.sign(scope2)

# ── Packet 3: TEMPORAL_PROOF (seq=3, keypair A) ───────────────────────────────
# argon_input = LastEvidenceL1Hash (L1[2]) ‖ SessionID ‖ Sequence (u64 LE)

argon_input = L1[2] + SESSION_ID + struct.pack("<Q", 3)  # 56 bytes
argon_out   = argon2.low_level.hash_secret_raw(
    secret=argon_input,
    salt=ARGON_SALT,
    time_cost=ARGON_T,
    memory_cost=ARGON_M,
    parallelism=ARGON_P,
    hash_len=32,
    type=argon2.low_level.Type.ID,
)

# PrevL1Hash for TEMPORAL_PROOF = prev_stream_hash = L1[2] (after EVIDENCE commit)
prev_tp = L1[2]
L1.append(sha256(L1[2], argon_out))       # L1[3]
scope3  = scope_apxp(3, prev_tp, L1[3], argon_out)
sig3    = kp_a.sign(scope3)

# TemporalProofHash = SHA-256(wire_line) — we'll note this separately
tp_line = (
    f"TEMPORAL_PROOF:prev_stream={hex_(prev_tp)}:stream={hex_(L1[3])}"
    f":proof={hex_(argon_out)}:m={ARGON_M}:t={ARGON_T}:p={ARGON_P}"
    f":sig={hex_(sig3)}:seq=3"
)
tp_hash = sha256(tp_line.encode())

# ── Packet 4: SESSION_RESUME (seq=4, keypair B) ───────────────────────────────
# At resume: stream_hash = prev_stream_hash = L1[3] (restored from sealed state)
# PrevL1Hash = L1[3], L1Hash = L1[3]  (equal — TEMPORAL_PROOF left both equal)

scope4 = scope_vars(4, L1[3], L1[3])
sig4   = kp_b.sign(scope4)

# SESSION_RESUME does NOT advance the L1 chain.

# ── TerminalDigest (over sigs 1-4) ────────────────────────────────────────────

terminal_digest = sha256(sig1, sig2, sig3, sig4)

# ── Bundle Seal ───────────────────────────────────────────────────────────────
# BundleHash uses keypair B's public key (segment 2 is the final segment)

bundle_hash = sha256(b"APXB", SESSION_ID, bootstrap_nonce, pub_b, terminal_digest)
seal_sig    = kp_b.sign(bundle_hash)

# ── SETTLEMENT_FINAL (seq=5 is ordinal, not a chain sequence) ─────────────────
# Settlement block §6: EscrowID ‖ Amount ‖ Currency ‖ TerminalDigest
# Signed by keypair B (current segment keypair)

settle_scope = ESCROW_ID + AMOUNT + CURRENCY + terminal_digest
assert len(settle_scope) == 88
settle_sig   = kp_b.sign(settle_scope)

# ── PCRCommitment (all-zero PCRs, same as §14) ───────────────────────────────

pcr0 = pcr1 = pcr2 = bytes(48)
pcr_commitment = sha256(pcr0, pcr1, pcr2)

# ── Output ────────────────────────────────────────────────────────────────────

print("=" * 72)
print("§14.N COMPUTED FIXTURE VALUES")
print("=" * 72)
print()

print(f"Bootstrap nonce:    {hex_(bootstrap_nonce)}")
print(f"L2Hash (state):     {hex_(L2)}")
print()
print(f"L1[0] = BootstrapNonce:   {hex_(L1[0])}")
print(f"L1[1] = SHA-256(L1[0]‖''):  {hex_(L1[1])}")
print(f"L1[2] = SHA-256(L1[1]‖'hello'): {hex_(L1[2])}")
print(f"L1[3] = SHA-256(L1[2]‖argon_out): {hex_(L1[3])}")
print()

print("-- Keypair A (seed = 0x00 * 32) --")
print(f"  Seed:   {hex_(SEED_A)}")
print(f"  Pubkey: {hex_(pub_a)}")
print()
print("-- Keypair B (seed = 0x01 * 32) --")
print(f"  Seed:   {hex_(SEED_B)}")
print(f"  Pubkey: {hex_(pub_b)}")
print()

print("-- Packet 1: SESSION_START[1] (seq=1, keypair A, payload='') --")
print(f"  PrevL1Hash: {hex_(L1[0])}")
print(f"  L1Hash:     {hex_(L1[1])}")
print(f"  L2Hash:     {hex_(L2)}")
print(f"  PayloadLen: 0")
print(f"  SHA-256(''):  {hex_(SHA256_EMPTY)}")
print(f"  Scope (161 bytes):")
print(fmt_bytes(scope1))
print(f"  Signature:  {hex_(sig1)}")
print()

print("-- Packet 2: EVIDENCE[2] (seq=2, keypair A, payload='hello') --")
print(f"  PrevL1Hash: {hex_(L1[1])}")
print(f"  L1Hash:     {hex_(L1[2])}")
print(f"  L2Hash:     {hex_(L2)}")
print(f"  PayloadLen: 5")
print(f"  SHA-256('hello'): {hex_(sha256(b'hello'))}")
print(f"  Scope (161 bytes):")
print(fmt_bytes(scope2))
print(f"  Signature:  {hex_(sig2)}")
print()

print("-- Packet 3: TEMPORAL_PROOF[3] (seq=3, keypair A) --")
print(f"  argon_input (56 bytes) = L1[2] ‖ SessionID ‖ seq=3:")
print(f"    {hex_(argon_input)}")
print(f"  ArgonOutput: {hex_(argon_out)}")
print(f"  PrevL1Hash:  {hex_(prev_tp)}")
print(f"  L1Hash:      {hex_(L1[3])}")
print(f"  m={ARGON_M}, t={ARGON_T}, p={ARGON_P}")
print(f"  Scope (137 bytes):")
print(fmt_bytes(scope3))
print(f"  Signature:   {hex_(sig3)}")
print(f"  Wire line:   {tp_line}")
print(f"  TemporalProofHash (SHA-256 of wire line): {hex_(tp_hash)}")
print()

print("-- Packet 4: SESSION_RESUME[4] (seq=4, keypair B) --")
print(f"  PrevL1Hash: {hex_(L1[3])}")
print(f"  L1Hash:     {hex_(L1[3])}  (same; TEMPORAL_PROOF left both equal)")
print(f"  Scope (93 bytes):")
print(fmt_bytes(scope4))
print(f"  Signature:  {hex_(sig4)}")
print()

print("-- Terminal Digest (covers sigs 1-4) --")
print(f"  SHA-256(Sig[1] ‖ Sig[2] ‖ Sig[3] ‖ Sig[4])")
print(f"  TerminalDigest: {hex_(terminal_digest)}")
print()

print("-- Bundle Seal (signed by keypair B) --")
print(f"  BundleHash = SHA-256('APXB' ‖ SessionID ‖ BootstrapNonce ‖ PubB ‖ TerminalDigest)")
print(f"  BundleHash: {hex_(bundle_hash)}")
print(f"  SealSig:    {hex_(seal_sig)}")
print()

print("-- SETTLEMENT_FINAL[5] (APXT block, signed by keypair B) --")
print(f"  EscrowID:      {hex_(ESCROW_ID)}")
print(f"  Amount (32):   {hex_(AMOUNT)}")
print(f"  Currency (8):  {hex_(CURRENCY)}")
print(f"  TerminalDigest: {hex_(terminal_digest)}")
print(f"  Settle scope (88 bytes):")
print(fmt_bytes(settle_scope))
print(f"  SettlementSig: {hex_(settle_sig)}")
print()

print("-- PCR Commitment (all-zero PCRs) --")
print(f"  PCRCommitment: {hex_(pcr_commitment)}")
print()

print("=" * 72)
print("SUMMARY TABLE")
print("=" * 72)
vals = [
    ("BootstrapNonce",    hex_(bootstrap_nonce)),
    ("L1[1]",            hex_(L1[1])),
    ("L1[2]",            hex_(L1[2])),
    ("L1[3]",            hex_(L1[3])),
    ("L2Hash",           hex_(L2)),
    ("ArgonInput (hex)", hex_(argon_input)),
    ("ArgonOutput",      hex_(argon_out)),
    ("TemporalProofHash", hex_(tp_hash)),
    ("Sig[1] SESSION_START", hex_(sig1)),
    ("Sig[2] EVIDENCE",  hex_(sig2)),
    ("Sig[3] TEMPORAL_PROOF", hex_(sig3)),
    ("Sig[4] SESSION_RESUME", hex_(sig4)),
    ("TerminalDigest",   hex_(terminal_digest)),
    ("BundleHash",       hex_(bundle_hash)),
    ("SealSig",          hex_(seal_sig)),
    ("SettlementSig",    hex_(settle_sig)),
]
for name, val in vals:
    print(f"  {name:<30} {val}")
