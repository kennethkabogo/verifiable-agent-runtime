#!/usr/bin/env python3
"""
APEX v2.10.0 JSON Test Fixture Generator
=========================================
Produces spec/fixtures/apex_v2_10_0.json — a machine-readable contract
between the VAR reference implementation and any cross-repo verifier (e.g.
Finfiti's varVerifier.ts).

Run with:
    python3 tools/gen_test_fixture.py

All inputs are deterministic (32-zero Ed25519 seed, fixed session IDs, fixed
payloads). The output is committed; CI on either side can assert against it
without re-running the generator.

THESE VALUES ARE SYNTHETIC / TEST-ONLY. Never use in production.
"""

import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ── Fixed inputs ─────────────────────────────────────────────────────────────

SIGNING_SEED = bytes(32)
SIGNING_KEY  = Ed25519PrivateKey.from_private_bytes(SIGNING_SEED)
SIGNING_PUB  = SIGNING_KEY.public_key().public_bytes_raw()

SESSION_ID = bytes([0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x40, 0x00,
                    0x80, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01])

BUNDLE_ID = bytes([0xDE, 0xAD, 0xBE, 0xEF,
                   0xDE, 0xAD, 0x40, 0x00,
                   0x80, 0x00, 0xDE, 0xAD,
                   0xBE, 0xEF, 0x00, 0x01])

AGENT_ID   = sha256(b"TEST_AGENT")
ATTEST_DOC = bytes([0xAA] * 96)
CREATED_AT = 1735689600_000_000_000  # 2025-01-01T00:00:00Z ns
PAYLOAD_1  = b"hello"
PAYLOAD_2  = b"world"

# ── Derivations ───────────────────────────────────────────────────────────────

BOOTSTRAP_NONCE = sha256(ATTEST_DOC + SESSION_ID)

L1_0 = BOOTSTRAP_NONCE
L1_1 = sha256(L1_0 + PAYLOAD_1)
L1_2 = sha256(L1_1 + PAYLOAD_2)

L2_META = (
    bytes([0x01])
    + struct.pack("<H", 0)
    + struct.pack("<H", 0)
    + struct.pack("<H", 80)
    + struct.pack("<H", 24)
)
L2_HASH = sha256(L2_META + sha256(b""))

# ── Signature scopes (161 bytes each, VARE magic = VARB bundle) ───────────────

def build_scope(seq: int, prev_l1: bytes, l1: bytes, payload: bytes) -> bytes:
    msg = bytearray(161)
    msg[0:4] = b"VARE"
    msg[4] = 0x01
    struct.pack_into("<Q", msg, 5, seq)
    msg[13:45]  = prev_l1
    msg[45:77]  = l1
    msg[77:109] = L2_HASH
    struct.pack_into("<I", msg, 109, len(payload))
    msg[113:145] = sha256(payload)
    msg[145:161] = SESSION_ID
    assert len(msg) == 161
    return bytes(msg)

SCOPE_1 = build_scope(1, L1_0, L1_1, PAYLOAD_1)
SCOPE_2 = build_scope(2, L1_1, L1_2, PAYLOAD_2)

SIG_1 = SIGNING_KEY.sign(SCOPE_1)
SIG_2 = SIGNING_KEY.sign(SCOPE_2)

# ── Bundle Seal (single-packet, §14) ─────────────────────────────────────────

POLICY_HASH     = bytes(32)  # zero-filled = unconstrained
TERMINAL_DIGEST_1 = sha256(SIG_1)
BUNDLE_HASH_1   = sha256(b"VARB" + SESSION_ID + BOOTSTRAP_NONCE + SIGNING_PUB + TERMINAL_DIGEST_1 + POLICY_HASH)
SEAL_SIG_1      = SIGNING_KEY.sign(BUNDLE_HASH_1)

# ── Bundle Seal (two-packet, §15) ─────────────────────────────────────────────

TERMINAL_DIGEST_2 = sha256(SIG_1 + SIG_2)
BUNDLE_HASH_2     = sha256(b"VARB" + SESSION_ID + BOOTSTRAP_NONCE + SIGNING_PUB + TERMINAL_DIGEST_2 + POLICY_HASH)
SEAL_SIG_2        = SIGNING_KEY.sign(BUNDLE_HASH_2)

# ── Settlement scope (88 bytes, §15) ─────────────────────────────────────────

ESCROW_ID      = bytes.fromhex("deadbeefdead40008000deadbeef0001")
AMOUNT_BYTES   = b"1000000" + b"\x00" * 25   # 32 bytes decimal zero-padded
CURRENCY_BYTES = b"USDC    "                  # 8 bytes space-padded
SETTLE_SCOPE   = ESCROW_ID + AMOUNT_BYTES + CURRENCY_BYTES + TERMINAL_DIGEST_2
assert len(SETTLE_SCOPE) == 88
SETTLE_SIG     = SIGNING_KEY.sign(SETTLE_SCOPE)

# ── Serialize ─────────────────────────────────────────────────────────────────

fixture = {
    "_note": "SYNTHETIC / TEST-ONLY — DO NOT USE IN PRODUCTION",
    "spec_version": "2.10.0",
    "bundle_magic": "VARB",
    "scope_magic":  "VARE",

    "inputs": {
        "signing_seed_hex":    SIGNING_SEED.hex(),
        "signing_pub_hex":     SIGNING_PUB.hex(),
        "session_id_hex":      SESSION_ID.hex(),
        "bundle_id_hex":       BUNDLE_ID.hex(),
        "agent_id_hex":        AGENT_ID.hex(),
        "attest_doc_hex":      ATTEST_DOC.hex(),
        "created_at_ns":       CREATED_AT,
        "payload_1_hex":       PAYLOAD_1.hex(),
        "payload_2_hex":       PAYLOAD_2.hex(),
        "policy_hash_hex":     POLICY_HASH.hex(),
    },

    "derivations": {
        "bootstrap_nonce_hex": BOOTSTRAP_NONCE.hex(),
        "l1_0_hex":            L1_0.hex(),
        "l1_1_hex":            L1_1.hex(),
        "l1_2_hex":            L1_2.hex(),
        "l2_hash_hex":         L2_HASH.hex(),
    },

    "section_14": {
        "_note": "Single-packet session (§14)",
        "packet_1": {
            "sequence":          1,
            "prev_l1_hash_hex":  L1_0.hex(),
            "l1_hash_hex":       L1_1.hex(),
            "payload_len":       len(PAYLOAD_1),
            "payload_hash_hex":  sha256(PAYLOAD_1).hex(),
            "scope_161_hex":     SCOPE_1.hex(),
            "signature_hex":     SIG_1.hex(),
        },
        "bundle_seal": {
            "terminal_digest_hex": TERMINAL_DIGEST_1.hex(),
            "policy_hash_hex":     POLICY_HASH.hex(),
            "bundle_hash_hex":     BUNDLE_HASH_1.hex(),
            "seal_sig_hex":        SEAL_SIG_1.hex(),
        },
    },

    "section_15": {
        "_note": "Two-packet session with settlement (§15)",
        "packet_1": {
            "sequence":         1,
            "prev_l1_hash_hex": L1_0.hex(),
            "l1_hash_hex":      L1_1.hex(),
            "payload_len":      len(PAYLOAD_1),
            "payload_hash_hex": sha256(PAYLOAD_1).hex(),
            "scope_161_hex":    SCOPE_1.hex(),
            "signature_hex":    SIG_1.hex(),
        },
        "packet_2": {
            "sequence":         2,
            "prev_l1_hash_hex": L1_1.hex(),
            "l1_hash_hex":      L1_2.hex(),
            "payload_len":      len(PAYLOAD_2),
            "payload_hash_hex": sha256(PAYLOAD_2).hex(),
            "scope_161_hex":    SCOPE_2.hex(),
            "signature_hex":    SIG_2.hex(),
        },
        "bundle_seal": {
            "terminal_digest_hex": TERMINAL_DIGEST_2.hex(),
            "policy_hash_hex":     POLICY_HASH.hex(),
            "bundle_hash_hex":     BUNDLE_HASH_2.hex(),
            "seal_sig_hex":        SEAL_SIG_2.hex(),
        },
        "settlement": {
            "escrow_id_hex":       ESCROW_ID.hex(),
            "amount_hex":          AMOUNT_BYTES.hex(),
            "currency_hex":        CURRENCY_BYTES.hex(),
            "terminal_digest_hex": TERMINAL_DIGEST_2.hex(),
            "scope_88_hex":        SETTLE_SCOPE.hex(),
            "settlement_sig_hex":  SETTLE_SIG.hex(),
        },
    },
}

out_path = Path(__file__).parent.parent / "spec" / "fixtures" / "apex_v2_10_0.json"
out_path.parent.mkdir(exist_ok=True)
out_path.write_text(json.dumps(fixture, indent=2) + "\n")
print(f"wrote {out_path}")
