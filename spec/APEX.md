# APEX — Attested Proof of EXecution
## Specification v2.0.0

**Status:** Draft  
**Authors:** Kenneth Kabogo  
**Repository:** https://github.com/kennethkabogo/verifiable-agent-runtime  
**Canonical URL:** https://kennethkabogo.github.io/apex-spec  

---

## Abstract

APEX defines a cryptographic wire format and verification protocol for producing tamper-evident, hardware-rooted proofs of AI agent execution. An APEX-compliant runtime produces an **Evidence Bundle** — a structured, signed record binding the agent's identity, actions, and outputs to a silicon-level measurement that any third party can verify independently, without trusting the operator or the host.

APEX is designed to be runtime-agnostic. The reference implementation is VAR (Verifiable Agent Runtime). Any runtime that produces APEX-compliant bundles can interoperate with APEX-compliant verifiers and settlement systems.

---

## Terminology

| Term | Definition |
|:---|:---|
| **Enclave** | A Trusted Execution Environment (TEE) running the agent. Reference: AWS Nitro Enclave. |
| **Host** | The parent instance operating the enclave. Treated as untrusted. |
| **Operator** | The entity running the enclave. Treated as untrusted by the verifier. |
| **Auditor** | Any third party performing independent verification of an Evidence Bundle. |
| **PCR** | Platform Configuration Register — a hardware measurement of the enclave image. |
| **Session** | A single continuous agent execution, identified by a UUID v4. |
| **Segment** | A contiguous slice of a session bounded by a single attestation quote. Sessions may span multiple segments across hibernate/resume cycles. |
| **Bootstrap Nonce** | The initial state of the L1 hash chain, derived from hardware attestation. |
| **L1 Hash** | The running SHA-256 hash of the raw PTY byte stream. |
| **L2 Hash** | The SHA-256 hash of the rendered terminal state at evidence emission time. |
| **Settlement System** | A system (e.g. Finfiti) that gates fund release on a valid APEX attestation. |
| **APEX-compliant** | A runtime or verifier that fully implements this specification. |

---

## 1. Design Principles

1. **Hardware root of trust.** The only enforcement mechanism that survives a fully compromised host is a hardware boundary. APEX is anchored to PCR measurements, not software policy.

2. **Operator untrusted.** An APEX verifier MUST NOT require trust in the operator to complete verification. All cryptographic material necessary for verification is embedded in the bundle or published by the hardware vendor.

3. **No gaps tolerated.** Any gap in the evidence chain — missing output, reordered packets, or a broken hash link — MUST cause verification to fail. Partial verification is not defined.

4. **Settlement is a first-class primitive.** APEX bundles may include a Settlement Block. A settlement system that consumes APEX bundles MUST gate fund release on a verified terminal digest. No valid attestation means no payout.

5. **Implementer portability.** The spec is implementation-agnostic. A QVAC agent, a coding agent, or an infrastructure agent can all produce APEX-compliant bundles provided they run inside a supported TEE and implement this wire format.

6. **Versioning is strict.** Verifiers MUST reject bundles with a higher MAJOR version than they implement. Verifiers MUST accept bundles with a higher MINOR version (unknown fields ignored). PATCH increments carry no byte-level change.

---

## 2. Bundle Structure

An APEX Evidence Bundle consists of five blocks, in order:

```
[ Bundle Header   ]  — session identity and hardware attestation
[ Segment Header  ]  — per-segment attestation quote and signing key
[ Evidence Chain  ]  — ordered, signed, hash-linked evidence packets
[ Settlement Block]  — optional; payment authorisation gated on attestation
[ Bundle Seal     ]  — terminal digest and bundle-level signature
```

---

## 3. Bundle Header

Emitted once per session at session start.

| Field | Type | Description |
|:---|:---|:---|
| Magic | `[4]u8` | `"APXB"` (`0x41 0x50 0x58 0x42`) |
| SpecVersion | `[5]u8` | ASCII semver, e.g. `"2.0.0"` |
| BundleID | `[16]u8` | UUID v4 — globally unique per bundle |
| SessionID | `[16]u8` | UUID v4 — identifies the session across segments |
| AgentID | `[32]u8` | SHA-256 of the enclave image file (EIF or equivalent) |
| CreatedAt | `u64` LE | Nanoseconds since Unix epoch (UTC) |
| BootstrapNonce | `[32]u8` | `SHA-256(AttestationDoc ‖ SessionID)` — anchors the L1 chain |

### 3.1 Bootstrap Nonce

The Bootstrap Nonce is the genesis state of the L1 hash chain. It MUST be derived inside the enclave as:

```
BootstrapNonce = SHA-256(AttestationDoc ‖ SessionID)
```

This binds the initial chain state to a specific hardware attestation and a specific session UUID. An auditor who independently recomputes this value confirms that the chain originated inside the correct enclave.

---

## 4. Segment Header

Emitted once per session segment. A session with no hibernate/resume cycles has exactly one segment.

| Field | Type | Description |
|:---|:---|:---|
| Magic | `[4]u8` | `"APXS"` (`0x41 0x50 0x58 0x53`) |
| SegmentIndex | `u32` LE | 0-based. First segment = 0. |
| AttestationLen | `u32` LE | Byte length of the Attestation Document |
| AttestationDoc | `[AttestationLen]u8` | Hardware-signed COSE_Sign1 from the TEE |
| SessionPub | `[32]u8` | Ed25519 public key generated fresh inside the enclave for this segment |
| PCR0 | `[48]u8` | Enclave image measurement extracted from AttestationDoc |
| PCR1 | `[48]u8` | Kernel + bootstrap measurement |
| PCR2 | `[48]u8` | Application measurement |
| PCRCommitment | `[32]u8` | `SHA-256(PCR0 ‖ PCR1 ‖ PCR2)` |

The SessionPub MUST be embedded in the AttestationDoc `public_key` field, proving it was generated inside the enclave.

The Ed25519 signing keypair is NOT persisted across hibernate/resume. Each segment generates a fresh keypair.

---

## 5. Evidence Chain

### 5.1 L1 Stream Hash

The L1 hash is a sequential digest of the raw PTY byte stream:

```
L1[0] = BootstrapNonce
L1[n] = SHA-256(L1[n-1] ‖ data_chunk[n])
```

A verifier detects gaps or reordering by asserting `Packet[n].PrevL1Hash == Packet[n-1].L1Hash`.

### 5.2 L2 State Hash

The L2 hash captures the rendered terminal state at evidence emission time:

```
L2 = SHA-256(
    format_version  ‖   // u8, current: 0x01
    cursor_x        ‖   // u16 LE
    cursor_y        ‖   // u16 LE
    terminal_width  ‖   // u16 LE
    terminal_height ‖   // u16 LE
    cell_digest         // §5.2.1
)
```

#### 5.2.1 Cell Digest

Computed in row-major (top-to-bottom, left-to-right) order. For each cell:

```
cell_bytes =
    codepoint_utf8_padded   // UTF-8 encoded into zero-padded [4]u8; all codepoints
                             // in grapheme cluster included in sequence
    fg_color_rgb            // R, G, B (3 bytes)
    bg_color_rgb            // R, G, B (3 bytes)
    attrs_u8                // 1-byte attribute bitmask (§5.2.2)
```

Each cell contributes exactly 11 bytes per codepoint. Multi-codepoint grapheme clusters MUST include all codepoints in sequence; implementers MUST NOT hash only the first codepoint.

#### 5.2.2 Attribute Bitmask

| Bit | Attribute |
|:---|:---|
| 0 | Bold |
| 1 | Italic |
| 2 | Faint |
| 3 | Blink |
| 4 | Reverse |
| 5 | Invisible |
| 6 | Strikethrough |
| 7 | Underline |

### 5.3 Evidence Packet

| Field | Type | Description |
|:---|:---|:---|
| Magic | `[4]u8` | `"APXE"` (`0x41 0x50 0x58 0x45`) |
| FormatVer | `u8` | Packet format version. Current: `0x01` |
| Sequence | `u64` LE | Monotonically increasing, starting at 1. No gaps permitted. |
| PrevL1Hash | `[32]u8` | `L1[n-1]` — enables gap detection |
| L1Hash | `[32]u8` | `L1[n]` |
| L2Hash | `[32]u8` | Terminal state at emission time |
| ActionType | `u8` | See §5.4 |
| PayloadLen | `u32` LE | Byte length of payload (0 in snapshot mode) |
| Payload | `[PayloadLen]u8` | Raw terminal data (empty in snapshot mode) |
| Signature | `[64]u8` | Ed25519 over 162-byte message — §5.5 |

### 5.4 Action Types

Unknown action types MUST cause verification to fail. Implementers MUST NOT silently ignore unknown values.

| Value | Name | Description |
|:---|:---|:---|
| `0x01` | STREAM | PTY byte stream chunk |
| `0x02` | EXEC | Subprocess execution record |
| `0x03` | SECRET_ACCESS | Secret provisioned to the agent |
| `0x04` | SETTLEMENT_INIT | Settlement escrow opened |
| `0x05` | SETTLEMENT_FINAL | Settlement escrow released or rejected |
| `0x06` | SESSION_START | First packet of a session |
| `0x07` | SESSION_RESUME | First packet of a resumed segment |
| `0x08` | SNAPSHOT | Snapshot-mode emission (no payload) |

### 5.5 Signature Scope

The enclave signs a fixed-length 162-byte message:

| Offset | Size | Field |
|---:|---:|:---|
| 0 | 4 | Magic `"APXE"` |
| 4 | 1 | FormatVer |
| 5 | 8 | Sequence (u64 LE) |
| 13 | 32 | PrevL1Hash |
| 45 | 32 | L1Hash |
| 77 | 32 | L2Hash |
| 109 | 1 | ActionType |
| 110 | 4 | PayloadLen (u32 LE) |
| 114 | 32 | SHA-256(Payload); `SHA-256(b"")` in snapshot mode |
| 146 | 16 | SessionID |
| **162** | | **total** |

```
Signature = Ed25519_Sign(segment_secret_key, msg_162)
```

### 5.6 Execution Records

For `EXEC` packets, the payload carries a structured execution record:

| Field | Type | Description |
|:---|:---|:---|
| CmdLen | `u16` LE | Byte length of command string |
| Cmd | `[CmdLen]u8` | Space-joined command line |
| StdoutHash | `[32]u8` | `SHA-256(stdout_bytes)` |
| StderrHash | `[32]u8` | `SHA-256(stderr_bytes)` |
| ExitCode | `u8` | Process exit code (signal → 128 + signum) |
| Seq | `u64` LE | Sequence counter at execution time |

Execution records are append-only within a session. Implementers MUST NOT remove or reorder entries. stdout bytes MUST be folded into the L1 chain:

```
L1[n] = SHA-256(L1[n-1] ‖ stdout_bytes)
```

stderr is captured and hashed but NOT committed to the L1 chain.

---

## 6. Settlement Block (Optional)

A Settlement Block MAY be appended after the Evidence Chain. A settlement system MUST NOT release funds without a verified Settlement Block whose `TerminalDigest` matches the verified Evidence Chain.

| Field | Type | Description |
|:---|:---|:---|
| Magic | `[4]u8` | `"APXT"` (`0x41 0x50 0x58 0x54`) |
| EscrowID | `[16]u8` | UUID v4 |
| Amount | `[32]u8` | Decimal string, zero-padded. No floating point. |
| Currency | `[8]u8` | ISO 4217 or `"USDT    "` (space-padded to 8 bytes) |
| Recipient | `[64]u8` | Opaque identifier, zero-padded |
| Condition | `u8` | `0x01` = attestation_valid_and_terminal_digest_confirmed |
| TerminalDigest | `[32]u8` | Must match Bundle Seal terminal digest |
| SettlementSig | `[64]u8` | Ed25519 over (EscrowID ‖ Amount ‖ Currency ‖ TerminalDigest) |

---

## 7. Bundle Seal

Emitted once, after the final Evidence Packet (and Settlement Block if present).

| Field | Type | Description |
|:---|:---|:---|
| Magic | `[4]u8` | `"APXZ"` (`0x41 0x50 0x58 0x5A`) |
| TerminalDigest | `[32]u8` | SHA-256 of all Packet Signatures in sequence order |
| BundleHash | `[32]u8` | SHA-256 of (BundleHeader ‖ all SegmentHeaders ‖ TerminalDigest) |
| SealSig | `[64]u8` | Ed25519(last_segment_secret_key, BundleHash) |

---

## 8. Verification Algorithm (Normative)

An APEX verifier MUST perform all steps in order. Failure at any step MUST abort with an error. Partial verification is not defined.

### Step 1 — Parse and validate the Bundle Header
- Assert Magic == `"APXB"`
- Assert SpecVersion MAJOR <= implemented MAJOR
- Assert BundleID is a valid UUID v4

### Step 2 — Validate each Segment Header
For each segment:
1. Parse AttestationDoc as COSE_Sign1 (RFC 8152)
2. Verify COSE signature using the TEE vendor root CA
3. Extract PCR0, PCR1, PCR2 via **CBOR map walk** (NOT byte scan)
4. Assert `PCRCommitment == SHA-256(PCR0 ‖ PCR1 ‖ PCR2)`
5. Assert SessionPub is present in AttestationDoc `public_key` field

### Step 3 — Reconstruct the Bootstrap Nonce
```
expected = SHA-256(Segment[0].AttestationDoc ‖ SessionID)
assert expected == BundleHeader.BootstrapNonce
```

### Step 4 — Verify chain continuity
```
assert Packet[1].PrevL1Hash == BundleHeader.BootstrapNonce
for n in 2..N:
    assert Packet[n].PrevL1Hash == Packet[n-1].L1Hash
    assert Packet[n].Sequence == Packet[n-1].Sequence + 1
```

### Step 5 — Verify each packet signature
For each packet:
1. Identify the segment whose index covers this packet's sequence number
2. Reconstruct the 162-byte message (§5.5)
3. `Ed25519_Verify(segment.SessionPub, msg_162, Packet[n].Signature)`
4. Assert ActionType is a known value (§5.4)

### Step 6 — Verify the Terminal Digest
```
assert BundleSeal.TerminalDigest == SHA-256(concat(Packet[1..N].Signature))
```

### Step 7 — Verify the Bundle Seal
```
assert BundleSeal.BundleHash == SHA-256(BundleHeader ‖ all SegmentHeaders ‖ BundleSeal.TerminalDigest)
Ed25519_Verify(last_segment.SessionPub, BundleSeal.BundleHash, BundleSeal.SealSig)
```

### Step 8 — Verify Settlement Block (if present)
```
assert Settlement.TerminalDigest == BundleSeal.TerminalDigest
Ed25519_Verify(last_segment.SessionPub, EscrowID ‖ Amount ‖ Currency ‖ TerminalDigest, Settlement.SettlementSig)
```

### Step 9 — L2 Verification (Optional)
Replay the PTY stream through a VT-compatible parser, compute L2 over the resulting grid (§5.2), and assert it matches each packet's L2Hash. This confirms the signed terminal state corresponds to the actual visible output.

---

## 9. Hibernate / Resume Protocol

Sessions may span multiple enclave lifecycles. Each resume creates a new segment with a fresh keypair.

```
Agent → Enclave   RESUME:<hex_sealed_blob>
Enclave → Agent   BUNDLE_HEADER:…:session=<orig_session_id>:nonce=<orig_bootstrap_nonce>
Enclave → Agent   READY
Enclave → Agent   RESUMED:session=<orig_session_id>:seq=<last_seq+1>
```

A verifier processing a resumed session MUST:
1. Accept that SessionPub changes across segments for the same SessionID
2. Verify each segment's signatures against that segment's SessionPub
3. Assert `Packet[1].PrevL1Hash` of the resumed segment equals the last L1Hash of the preceding segment

---

## 10. Sealed State

Sealed state allows session continuity across enclave restarts. The sealed blob format:

```
[ sealed_dek_len : 4 bytes  ]  u32 LE
[ sealed_dek     : N bytes  ]  KMS ciphertext of AES-256 DEK
[ nonce          : 12 bytes ]  AES-GCM nonce
[ tag            : 16 bytes ]  AES-GCM authentication tag
[ ciphertext     : M bytes  ]  AES-256-GCM of serialised state
```

The Ed25519 signing keypair MUST NOT be persisted in the sealed state. Each resumed segment generates a fresh keypair bound to a new attestation quote.

---

## 11. Simulation Mode

When TEE hardware is absent (e.g. development environments), an APEX-compliant runtime MAY operate in simulation mode:

- AttestationDoc is a 96-byte placeholder (`0xAA`-filled)
- PCR0 = `0xAA…AA` (48 bytes)
- All hash chain and signature operations remain identical

Simulation-mode bundles MUST be clearly marked. An APEX verifier MUST reject simulation-mode bundles when hardware attestation is required (e.g. prior to settlement).

---

## 12. Security Considerations

| Threat | Mitigation |
|:---|:---|
| Binary swap on host | PCR0 measurement binds the running image; a swapped binary changes PCR0 and fails Step 2 |
| Log tampering by host | L1 hash chain is hardware-signed; any gap or alteration breaks chain continuity in Step 4 |
| Cross-session replay | SessionID is included in every packet signature scope (Step 5) |
| False PCR extraction | CBOR map walk (Step 2) prevents byte-scan false matches across map entries |
| Key persistence attack | Ed25519 keypair is not persisted across hibernate/resume (§10) |
| Settlement detachment | TerminalDigest is bound in both the Bundle Seal and Settlement Block signatures (Step 8) |
| Short CBOR slice | Verifiers MUST bounds-check all CBOR bstr reads; a truncated document MUST fail, not yield a short slice |
| ECDSA signature truncation | Settlement signatures MUST be validated for correct length before r/s extraction |

---

## 13. Version History

| Version | Changes |
|:---|:---|
| 2.0.0 | APEX spec. New magic bytes, named action types, Settlement Block, Bundle Seal, strict unknown-type rejection, grapheme cluster correction |
| 1.5 | VAR evidence_spec: CBOR map walk for PCR extraction, CBOR bounds check, session_pub_cert |
| 1.4 | executions array replaces last_exec; cover-up attack prevention |
| 1.3 | EXEC command, stdout commitment to L1, stderr hash |
| 1.2 | SessionID in signature scope, snapshot mode, sealed state, KMS recipient flow |
| 1.1 | Initial public draft |

---

## 14. Conformance

An implementation is **APEX-compliant** if it:

1. Produces bundles that pass all Steps 1–8 of the verification algorithm (§8)
2. Rejects unknown ActionType values rather than passing them through
3. Performs CBOR map walk (not byte scan) for PCR extraction
4. Does not persist the Ed25519 signing keypair across hibernate/resume cycles
5. Gates settlement on a verified TerminalDigest

A verifier is **APEX-compliant** if it implements all Steps 1–8 and correctly handles multi-segment sessions.

---

*APEX is an open specification. Third-party implementations are encouraged. The reference implementation is VAR: https://github.com/kennethkabogo/verifiable-agent-runtime*
