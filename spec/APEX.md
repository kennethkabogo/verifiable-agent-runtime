# APEX — Attested Proof of EXecution
## Specification v2.7.0

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
| ActionType | `u8` | See §5.4. Validated by verifier but not included in signature scope. |
| PayloadLen | `u32` LE | Byte length of payload (0 in snapshot mode) |
| Payload | `[PayloadLen]u8` | Raw terminal data (empty in snapshot mode) |
| Signature | `[64]u8` | Ed25519 over 161-byte message — §5.5 |

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
| `0x09` | TEMPORAL_PROOF | Sequential work function proof at a hibernate boundary |

### 5.5 Signature Scope

The enclave signs a fixed-length 161-byte message. ActionType is a packet field (§5.3) but is NOT included in the signed scope — it is validated by the verifier as a parsing step (§8 Step 5).

| Offset | Size | Field |
|---:|---:|:---|
| 0 | 4 | Magic `"APXE"` |
| 4 | 1 | FormatVer |
| 5 | 8 | Sequence (u64 LE) |
| 13 | 32 | PrevL1Hash |
| 45 | 32 | L1Hash |
| 77 | 32 | L2Hash |
| 109 | 4 | PayloadLen (u32 LE) |
| 113 | 32 | SHA-256(Payload); `SHA-256(b"")` in snapshot mode |
| 145 | 16 | SessionID |
| **161** | | **total** |

```
Signature = Ed25519_Sign(segment_secret_key, msg_161)
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

### 5.7 TEMPORAL_PROOF Packet Payload

A `TEMPORAL_PROOF` packet (`0x09`) carries an Argon2id sequential work function output
that bounds the elapsed wall-clock time at each hibernate boundary.

| Field | Type | Description |
| :--- | :--- | :--- |
| ArgonOutput | `[32]u8` | Argon2id output over `LastEvidenceL1Hash ‖ SessionID ‖ Sequence` |
| m | `u32` LE | Argon2id memory parameter (KiB). MUST be ≥ 65536. |
| t | `u32` LE | Argon2id time parameter (iterations). MUST be ≥ 3. |
| p | `u8` | Argon2id parallelism. MUST equal 1. Values ≠ 1 are non-conformant and MUST be rejected. |

**Argon2id input derivation.** The verifier derives the Argon2id input from chain state — it
is not stored in the packet:

```
argon_input = LastEvidenceL1Hash ‖ SessionID ‖ Sequence (u64 LE)
```

where `LastEvidenceL1Hash` is the L1Hash of the immediately preceding EVIDENCE packet and
`Sequence` is the sequence number of the TEMPORAL_PROOF packet itself.

**Parameter floor rationale.** `m ≥ 65536` and `t ≥ 3` match the RFC 9106 interactive
profile minimum. `p = 1` is fixed (not a floor) because parallelism defeats the sequential
property: the temporal proof is only meaningful if the computation cannot be accelerated by
adding cores. A TEMPORAL_PROOF with `p ≠ 1` MUST be rejected by the verifier at Step 11.

**Performance note.** Implementers SHOULD benchmark Argon2id at the floor parameters
(`m=65536, t=3, p=1`) inside their TEE platform before finalising deployment params.
On AWS Nitro Enclave c5.xlarge vCPUs (2 vCPU, 512 MiB), measured latency at the floor
is **~240 ms** (mean 239.81 ms, p50 241.22 ms, p95 247.09 ms; n=7 runs inside a
production-mode enclave with real NSM attestation enabled). Downstream integrators SHOULD
treat 250 ms as the practical upper bound per checkpoint on this hardware class.
If measured latency significantly exceeds 250 ms at the floor on a given TEE platform,
the Argon2id params MAY be adjusted downward toward an implementation-specific minimum,
but such bundles MUST be flagged as non-standard-floor in a future registry extension.

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
| BundleHash | `[32]u8` | SHA-256(`"APXB"` ‖ SessionID ‖ BootstrapNonce ‖ SessionPub ‖ TerminalDigest) |
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

For multi-segment bundles, apply this check within each segment independently. Cross-segment continuity is verified in Step 10.

### Step 5 — Verify each packet signature
For each packet:
1. Identify the segment whose index covers this packet's sequence number
2. Reconstruct the 161-byte message (§5.5)
3. `Ed25519_Verify(segment.SessionPub, msg_161, Packet[n].Signature)`
4. Assert ActionType is a known value (§5.4) — field validation, not part of signed scope

### Step 6 — Verify the Terminal Digest
```
assert BundleSeal.TerminalDigest == SHA-256(concat(Packet[1..N].Signature))
```

### Step 7 — Verify the Bundle Seal
```
assert BundleSeal.BundleHash == SHA-256("APXB" ‖ SessionID ‖ BootstrapNonce ‖ SessionPub ‖ BundleSeal.TerminalDigest)
Ed25519_Verify(last_segment.SessionPub, BundleSeal.BundleHash, BundleSeal.SealSig)
```

### Step 8 — Verify Settlement Block (if present)
```
assert Settlement.TerminalDigest == BundleSeal.TerminalDigest
Ed25519_Verify(last_segment.SessionPub, EscrowID ‖ Amount ‖ Currency ‖ TerminalDigest, Settlement.SettlementSig)
```

### Step 9 — L2 Verification (Optional)
Replay the PTY stream through a VT-compatible parser, compute L2 over the resulting grid (§5.2), and assert it matches each packet's L2Hash. This confirms the signed terminal state corresponds to the actual visible output.

### Step 10 — Verify segment boundaries (multi-segment bundles only)
If the bundle contains more than one segment, for each boundary between segment N and segment N+1:

1. Assert the first packet of segment N+1 has ActionType == SESSION_RESUME (`0x07`). Do not infer segment boundaries from timing gaps alone.
2. Assert `first_packet(segment[N+1]).PrevL1Hash == last_evidence_packet(segment[N]).L1Hash`.
3. Assert sequence numbers are strictly monotonically increasing across the boundary: `first_packet(segment[N+1]).Sequence == last_packet(segment[N]).Sequence + 1`. No reset is permitted.
4. WARN if the timestamp gap between `last_packet(segment[N])` and `first_packet(segment[N+1])` exceeds the configured threshold (implementation default: 3600 seconds). Do not FAIL — a crash recovery gap is expected and legitimate. The WARN surfaces the gap for audit without invalidating an otherwise intact chain.

### Step 11 — Verify TEMPORAL_PROOF packets at segment boundaries (multi-segment bundles only)

For each boundary between segment N and segment N+1, let `tp_seq = last_evidence_packet(segment[N]).Sequence + 1`.

**Rule A — TEMPORAL_PROOF present at `tp_seq`:**

1. Assert `packet[tp_seq].ActionType == TEMPORAL_PROOF` (`0x09`).
2. Assert `packet[tp_seq].p == 1`. If `p ≠ 1`, FAIL — non-conformant parallelism.
3. Assert `packet[tp_seq].m ≥ 65536` and `packet[tp_seq].t ≥ 3`. If below floor, FAIL.
4. Derive `argon_input = last_evidence_packet(segment[N]).L1Hash ‖ SessionID ‖ tp_seq (u64 LE)`.
5. Re-run `Argon2id(argon_input, m=packet[tp_seq].m, t=packet[tp_seq].t, p=1)`.
6. Assert the output matches `packet[tp_seq].ArgonOutput`. If not, FAIL.
7. If the sealed state for this boundary includes `TemporalProofHash`:
   - Assert `TemporalProofHash == SHA-256(full wire bytes of packet[tp_seq])`. If not, FAIL.
8. If the sealed state does NOT include `TemporalProofHash`:
   - FAIL — the sealed state claims no temporal proof exists, but one is present in the chain.

**Rule B — no TEMPORAL_PROOF at `tp_seq`:**

1. If the sealed state includes `TemporalProofHash`: FAIL — hash references a proof that is not in the chain.
2. If the sealed state does NOT include `TemporalProofHash`: the hibernate boundary is temporally unattested. Continue verification; WARN with `TEMPORALLY_UNATTESTED`.
3. For sessions containing a `SETTLEMENT_INIT` packet (`0x04`): treat Rule B as a FAIL rather than a WARN. Settlement verifiers MUST require temporal attestation at all hibernate boundaries.

### Step 12 — Compute the Evidence Coverage Ratio (ECR)

The ECR is a summary metric reporting what fraction of a session's hibernate boundaries are temporally attested by a valid TEMPORAL_PROOF. It is a verifier output, not a wire field.

**A verifier MUST NOT compute or report ECR until Steps 1–7 (including BundleSeal verification) are complete.** Partial or unverified bundles MUST NOT be scored.

#### Definitions

| Symbol | Meaning |
| :--- | :--- |
| K | Number of hibernate boundaries in the bundle. Equal to the number of SESSION_RESUME packets. Single-segment sessions have K = 0. |
| K_tp | Number of boundaries where Step 11 Rule A passed (TEMPORAL_PROOF present and valid). |

#### Computation

1. If K = 0 (single-segment session): ECR = 1.0. No hibernate gaps exist to be unattested.
2. If K > 0: `ECR = K_tp / K`, a real number in [0.0, 1.0].

#### Interpretation

| ECR | Meaning |
| :--- | :--- |
| 1.0 | All hibernate gaps have a valid TEMPORAL_PROOF. Every gap is bounded below by the Argon2id sequential work function (≥ 240 ms at the floor on the reference platform — §5.7). |
| (0, 1) | Mixed attestation. `K_tp` boundaries are attested; `K − K_tp` are not. |
| 0.0 | No hibernate boundaries have temporal attestation. |

#### Settlement interaction

A conformant settlement system MUST require ECR = 1.0 before releasing funds. This is the formal expression of the constraint already enforced per-boundary in Step 11 Rule B.3: if any boundary triggered Rule B.3 (settlement FAIL), the bundle cannot have reached Step 12 with a Settlement Block intact. ECR = 1.0 is therefore a necessary, verifiable precondition.

---

## 9. Hibernate / Resume Protocol

Sessions may span multiple enclave lifecycles. Each resume creates a new segment with a fresh keypair.

### 9.1 Planned Hibernate / Resume

```
Agent → Enclave   RESUME:<hex_sealed_blob>
Enclave → Agent   BUNDLE_HEADER:…:session=<orig_session_id>:nonce=<orig_bootstrap_nonce>
Enclave → Agent   READY
Enclave → Agent   RESUMED:session=<orig_session_id>:seq=<last_seq+1>
```

### 9.2 Crash Recovery (Unclean Exit)

An unclean exit (OOM kill, SIGKILL, hardware reset) may occur at any point during a session. To guarantee a recoverable chain, the enclave writes a sealed checkpoint after each EVIDENCE emission (§10.3) — before returning acknowledgment to the agent. No separate crash-handling path is required; the same `RESUME` flow applies.

**In-flight data policy.** Log lines accumulated since the last EVIDENCE emission and not yet included in an EVIDENCE packet are not included in the sealed checkpoint and are not recoverable. The resumed segment begins from the last committed EVIDENCE packet. Verifiers MUST NOT expect continuity at sub-EVIDENCE granularity across a segment boundary.

### 9.3 Session Resume First Packet

The first packet of every resumed segment MUST have ActionType == SESSION_RESUME (`0x07`). This provides an explicit boundary marker; verifiers MUST NOT infer segment boundaries from timing gaps alone.

### 9.4 Verifier Requirements for Multi-Segment Sessions

A verifier processing a resumed session MUST:

1. Accept that SessionPub changes across segments for the same SessionID.
2. Verify each segment's signatures against that segment's SessionPub.
3. Apply Step 10 at each segment boundary (§8 Step 10).
4. Apply Step 11 at each segment boundary (§8 Step 11).

### 9.5 TEMPORAL_PROOF Emission at Hibernate Boundaries

The enclave MUST emit a `TEMPORAL_PROOF` packet (`0x09`) immediately before writing the
sealed checkpoint at each hibernate boundary. The packet occupies sequence `LastSeq + 1`
(the position immediately after the last committed EVIDENCE packet and immediately before
the sealed checkpoint write). The SESSION_RESUME packet of the next segment MUST have
`PrevL1Hash == L1Hash(TEMPORAL_PROOF[LastSeq+1])` — the temporal proof is a normal link
in the chain; no additional anchoring is required.

**Emission order (normative):**

```
EVIDENCE[N]          emit and sign
TEMPORAL_PROOF[N+1]  emit and sign (Argon2id over L1Hash[N] ‖ SessionID ‖ N+1)
sealed checkpoint    write (sealed payload includes TemporalProofHash referencing TEMPORAL_PROOF[N+1])
[process hibernates]
SESSION_RESUME[N+2]  PrevL1Hash = L1Hash(TEMPORAL_PROOF[N+1])
```

The sealed checkpoint write MUST NOT precede the TEMPORAL_PROOF emission. A crash
between EVIDENCE[N] and TEMPORAL_PROOF[N+1] leaves the checkpoint from the prior cycle
(EVIDENCE[N-1]) as the recoverable state; the TEMPORAL_PROOF for the N cycle is not
recoverable and the N cycle hibernate is treated as temporally unattested on RESUME.

**Crash recovery within the hibernate window.** Two narrow crash windows require
explicit handling:

*Window 1: crash between Argon2id completion and TEMPORAL_PROOF emission.*
The Argon2id output was computed but the packet was never signed or sent. On restart,
the enclave MUST re-derive and re-emit from the prior sealed checkpoint (EVIDENCE[N-1]).
The Argon2id output is fully deterministic: given the same `LastEvidenceL1Hash ‖
SessionID ‖ Sequence` inputs and the same params, the output is identical. No
intermediate Argon2id state need be persisted. The re-emitted packet is byte-for-byte
identical to the packet that would have been emitted on the first attempt; the chain
position is the same; no duplicate is produced. Implementations MUST NOT buffer or
cache the Argon2id output across a crash boundary — re-derivation is the correct
and safe path.

*Window 2: crash between TEMPORAL_PROOF emission and sealed checkpoint write.*
The TEMPORAL_PROOF packet is in the chain but the sealed checkpoint was not written (or
was written incompletely). On restart, the prior sealed checkpoint (EVIDENCE[N-1]) is
the recoverable state. The TEMPORAL_PROOF[N+1] packet is already in the bundle's
evidence chain, but the sealed state has no `TemporalProofHash` referencing it. This
hibernate boundary is treated as temporally unattested on RESUME (Rule B of Step 11).
This is correct: the sealed checkpoint that would have bound the temporal proof was
never durably written, so the temporal attestation claim for that boundary cannot be
made. The chain remains valid; the gap is surfaced as `TEMPORALLY_UNATTESTED`.

---

## 10. Sealed State

### 10.1 Blob Format

```
[ sealed_dek_len : 4 bytes  ]  u32 LE
[ sealed_dek     : N bytes  ]  KMS ciphertext of AES-256 DEK
[ nonce          : 12 bytes ]  AES-GCM nonce
[ tag            : 16 bytes ]  AES-GCM authentication tag
[ ciphertext     : M bytes  ]  AES-256-GCM of serialised payload (§10.2)
```

### 10.2 Sealed Payload

The plaintext inside the AES-GCM ciphertext contains the minimum state required to resume the evidence chain:

| Field | Type | Description |
| :--- | :--- | :--- |
| SessionID | `[36]u8` | UUID of the original session |
| BootstrapNonce | `[32]u8` | Original nonce from segment 0; replayed in `BUNDLE_HEADER` on resume |
| SegmentIndex | `u32` LE | Index of the next segment to be created on resume |
| LastSeq | `u64` LE | Sequence number of the last committed EVIDENCE packet |
| LastEvidenceL1Hash | `[32]u8` | L1Hash of the last committed EVIDENCE packet; becomes `PrevL1Hash` of the first packet in the resumed segment |
| TemporalProofHash | `[32]u8` (optional) | SHA-256 of the full wire bytes of the `TEMPORAL_PROOF` packet at sequence `LastSeq+1`. Present if and only if the enclave emitted a conformant `TEMPORAL_PROOF` packet before this checkpoint. |

The Ed25519 signing keypair MUST NOT be included in the sealed payload. Each resumed segment generates a fresh keypair bound to a new attestation quote.

**`SegmentIndex` is an audit convenience field, not a security verification input.** A verifier MUST NOT rely on `SegmentIndex` alone to establish ordering or detect gaps; the L1 hash chain (`LastEvidenceL1Hash` → `PrevL1Hash` of the first resumed packet) and `seq` are the normative ordering mechanism. `SegmentIndex` allows human audit tooling to label and count segments without traversing the full hash chain. A conformant verifier MUST accept a sealed payload whose `SegmentIndex` is monotonically increasing across checkpoints but MAY treat a non-monotonic value as a warning rather than a hard rejection, since the hash chain is sufficient to detect any actual evidence-ordering attack.

### 10.3 Checkpoint Timing

The enclave MUST write a sealed checkpoint synchronously after each successful EVIDENCE emission, before returning acknowledgment to the agent. A crash between two evidence windows loses at most the in-flight window opened since the last checkpoint.

The TERMINATE path SHOULD write a final checkpoint in the same format. No separate terminal-seal format is defined.

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
| Input-channel attestation (known gap) | APEX attests the output side of process attestation — what the agent produced. Input-channel attestation (verifying that inputs were not synthetically replayed) is out of scope for v2.x and is a known gap for adversarial input replay on owned hardware. |
| Stale sealed-state replay under partition | An attacker forces a crash during a network partition (S_D→S_F in the session lifecycle), then replays a stale sealed checkpoint on RESUME. The KMS will unseal it (the PCR measurement is valid). Mitigation: the `TEMPORAL_PROOF` packet (`0x09`) at each hibernate boundary bounds the replay window to the Argon2id wall-clock cost — an attacker cannot replay a stale checkpoint faster than the memory-hard function allows. **Conformance caveat:** mitigation requires `p = 1` enforcement at Step 11. A non-conformant implementation that accepts `p > 1` reduces the sequential work bound proportionally. Full KMS-layer anti-replay (rejecting any RESUME whose sealed sequence number was already seen) remains a defence-in-depth complement and a v3.x candidate. |

---

## 13. Post-Quantum Migration Path

### 13.1 Exposure

APEX uses Ed25519 (Curve25519) at three points:

| Surface | Usage | Forgery consequence |
| :--- | :--- | :--- |
| Evidence packet signatures | Signs the 161-byte scope per packet | Fabricated audit trail |
| BundleSeal signature | Signs BundleHash over TerminalDigest | False proof of clean termination |
| SettlementSig | Signs 88-byte APXT scope | **Redirected funds** |

Ed25519 is an elliptic curve scheme. Shor's algorithm breaks the elliptic curve discrete
logarithm problem on a sufficiently capable quantum computer; the curve choice (Curve25519
vs secp256k1) does not affect this exposure.

**What is already quantum-resistant:**

The L1/L2 hash chain, TerminalDigest, BundleHash, and bootstrap nonce are all SHA-256.
SHA-256 provides approximately 128 bits of quantum security under Grover's algorithm —
adequate at current projections. The protocol skeleton survives post-quantum migration intact;
only the three signature surfaces above require replacement.

### 13.2 Migration Target

| Scheme | Standard | Notes |
| :--- | :--- | :--- |
| ML-DSA | NIST FIPS 204 (2024) | Primary candidate. Lattice-based; NIST-standardized. |
| SPHINCS+ | NIST FIPS 205 (2024) | Hash-based alternative. No lattice assumption dependency; larger signatures (~8–50 KB). |

The signed scope format changes in width, not structure. The 161-byte evidence packet scope,
88-byte APXT settlement scope, and 32-byte BundleHash input remain structurally unchanged;
only the signature bytes appended to each grow. A MAJOR version bump (v3.0.0) handles the
transition cleanly — v2.x and v3.x bundles are distinguishable by the version field in the
Bundle Header.

Hybrid signatures (Ed25519 + ML-DSA in parallel, both required to verify) are the
recommended transitional approach: they provide backward compatibility for v2.x verifiers
while hardening against quantum adversaries before full migration is complete.

### 13.3 Migration Priority

Replace in this order:

1. **SettlementSig** — financial forgery risk. An attacker who breaks the session keypair can
   redirect an in-flight settlement. This is the highest-value target and the first surface
   to harden.
2. **BundleSeal signature** — proof-of-termination forgery risk. A forged BundleSeal breaks
   the clean-termination guarantee that `POST /terminate` relies on.
3. **Evidence packet signatures** — audit trail forgery risk. Lower urgency because the L1
   hash chain itself is quantum-resistant; a forged packet signature alone does not let an
   attacker alter the hash chain without detection.

### 13.4 Timeline Guidance

NIST, Google, and Cloudflare have each named 2029 as the target completion date for
post-quantum migration. The US government (NSA/NIST) currently specifies 2035 as the
deadline for retiring quantum-vulnerable cryptography in federal use; this date is widely
regarded as a floor, not a ceiling.

APEX implementations targeting regulated environments or long-lived settlement records
SHOULD begin planning SettlementSig migration no later than 2028 to allow adequate
verification tooling and key infrastructure lead time.

---

## 14. Test Vectors

### §14.1 Scope and Notation

The following test vectors give a fully-worked single-packet session using
known synthetic inputs. A third-party implementer who can reproduce every
value independently has confirmed correct byte layout, correct endianness,
and correct hash chaining without running VAR.

**§14.9 — Two-segment session with TEMPORAL_PROOF.** See §14.9 for the
fully-worked two-segment fixture covering `TEMPORAL_PROOF` (`0x09`),
`SESSION_RESUME` (`0x07`), `TemporalProofHash`, and the multi-segment
bundle seal.  The fixture shape is:

```text
SESSION_START[1] → EVIDENCE[2] → TEMPORAL_PROOF[3] → SESSION_RESUME[4] → SETTLEMENT_FINAL[5]
```

#### Notation

- `‖` denotes byte concatenation.
- All hex strings are lowercase, no spaces, unless formatted as byte blocks.
- `u64 LE` / `u32 LE` = little-endian unsigned integer.
- Values labelled **SYNTHETIC / TEST-ONLY** MUST NOT appear in production bundles.

> **Implementation note.** The VAR reference implementation
> (`src/runtime/shell.zig`) uses a **161-byte** signature scope (ActionType byte omitted).
> All magic bytes now use the `APX*` prefix (`APXE`, `APXB`, `APXS`, `APXP`).

---

### §14.2 Fixed Inputs

#### Ed25519 Signing Keypair (SYNTHETIC / TEST-ONLY)

| Field | Value |
|:------|:------|
| Seed (32 bytes) | `0000000000000000000000000000000000000000000000000000000000000000` |
| Public key (32 bytes) | `3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29` |

#### Platform Configuration Registers (SYNTHETIC — all-zero simulation)

| Register | Value (48 bytes) |
|:---------|:-----------------|
| PCR0 | `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` |
| PCR1 | `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` |
| PCR2 | `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` |
| PCRCommitment | `81c611f35bff79491538b2f7cf201c7597a661a5c549633541c62bdc8af1613f` |

#### Session Identity

| Field | Value |
|:------|:------|
| SessionID (16 bytes) | `00000000000040008000000000000001` |
| BundleID (16 bytes) | `deadbeefdead40008000deadbeef0001` |
| AgentID (32 bytes) | `3f89a1b22305afcc23f99eeb2310bf4b1a1398aac586b5cd102feab8ebb90aa9` |
| CreatedAt (u64 LE ns) | `000057c07e681618` = 1735689600000000000 ns |

#### Attestation Document (SYNTHETIC — simulation mode §11)

96 bytes of `0xaa`, representing the placeholder attestation used in
simulation mode when Nitro hardware is absent:

```
  aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
  aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
  aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
  aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
  aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
  aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
```

#### Packet Payload

| Field | Value |
|:------|:------|
| Payload bytes | `68656c6c6f` (`hello`) |
| PayloadLen | 5 |
| ActionType | `01` (STREAM) |
| Sequence | 1 |

---

### §14.3 Bootstrap Nonce

```
BootstrapNonce = SHA-256(AttestationDoc ‖ SessionID)
```

| Input | Bytes | Hex |
|:------|------:|:----|
| AttestationDoc | 96 | `aaaaaaaaaaaaaaaa…` (96 × 0xaa) |
| SessionID | 16 | `00000000000040008000000000000001` |
| **BootstrapNonce** | **32** | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |

> **L1 chain genesis:** `L1[0] = BootstrapNonce`

---

### §14.4 L1 Hash After One Packet

```
L1[1] = SHA-256(L1[0] ‖ payload)
      = SHA-256(BootstrapNonce ‖ b"hello")
```

| Field | Value |
|:------|:------|
| L1[0] = BootstrapNonce | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |
| Payload (`hello`) | `68656c6c6f` |
| **L1[1]** | **`a231fcd1c04fef6e333954f22b311425d7d55ce3994b9a6d38a7cb72eedce64b`** |

---

### §14.5 L2 State Hash

Computed over a minimal terminal state (80 × 24, cursor at origin, empty cell grid):

```
L2 = SHA-256(format_version ‖ cursor_x ‖ cursor_y ‖ width ‖ height ‖ cell_digest)
```

| Component | Size | Value |
|:----------|-----:|:------|
| format_version (u8) | 1 | `01` |
| cursor_x (u16 LE) | 2 | `0000` |
| cursor_y (u16 LE) | 2 | `0000` |
| terminal_width (u16 LE = 80) | 2 | `5000` |
| terminal_height (u16 LE = 24) | 2 | `1800` |
| cell_digest = SHA-256(`""`) | 32 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| **L2Hash** | **32** | **`d416434244a2ce8276e6f3d72cc53f953f5e3f581f2e6862e5e36fadbe10ab71`** |

---

### §14.6 Evidence Packet — 161-byte Signature Scope

The enclave signs this fixed-length 161-byte message:

| Offset | Size | Field | Value |
|-------:|-----:|:------|:------|
| 0 | 4 | Magic (`"APXE"`) | `41505845` |
| 4 | 1 | FormatVer | `01` |
| 5 | 8 | Sequence (u64 LE = 1) | `0100000000000000` |
| 13 | 32 | PrevL1Hash (= BootstrapNonce) | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |
| 45 | 32 | L1Hash | `a231fcd1c04fef6e333954f22b311425d7d55ce3994b9a6d38a7cb72eedce64b` |
| 77 | 32 | L2Hash | `d416434244a2ce8276e6f3d72cc53f953f5e3f581f2e6862e5e36fadbe10ab71` |
| 109 | 4 | PayloadLen (u32 LE = 5) | `05000000` |
| 113 | 32 | SHA-256(Payload) | `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` |
| 145 | 16 | SessionID | `00000000000040008000000000000001` |
| **161** | | **total** | |

Full scope (161 bytes):

```
  41 50 58 45 01 01 00 00 00 00 00 00 00 b7 51 e7
  86 08 6c 23 13 51 23 cf 48 6a d4 63 34 9f eb e3
  08 f9 c5 4c 58 c0 44 78 a4 53 af 0e 63 a2 31 fc
  d1 c0 4f ef 6e 33 39 54 f2 2b 31 14 25 d7 d5 5c
  e3 99 4b 9a 6d 38 a7 cb 72 ee dc e6 4b d4 16 43
  42 44 a2 ce 82 76 e6 f3 d7 2c c5 3f 95 3f 5e 3f
  58 1f 2e 68 62 e5 e3 6f ad be 10 ab 71 05 00 00
  00 2c f2 4d ba 5f b0 a3 0e 26 e8 3b 2a c5 b9 e2
  9e 1b 16 1e 5c 1f a7 42 5e 73 04 33 62 93 8b 98
  24 00 00 00 00 00 00 40 00 80 00 00 00 00 00 00
  01
```

#### Packet Signature

```
Signature = Ed25519_Sign(signing_key, scope_161)
```

| Field | Value |
|:------|:------|
| Signature (64 bytes) | `aacb74fddf9bd1c4d759a600e080f1fb3798793dfa18adb701236c823c487dddf86a08920340f62d3b4f1e0e64873f36be633a1fa44bf2659ef3b4680d6c2200` |

---

### §14.7 Terminal Digest and Bundle Seal

Single-packet session; TerminalDigest covers exactly one signature.

```
TerminalDigest = SHA-256(Packet[1].Signature)
BundleHash     = SHA-256("APXB" ‖ SessionID ‖ BootstrapNonce ‖ SigningPub ‖ TerminalDigest)
SealSig        = Ed25519_Sign(signing_key, BundleHash)
```

| Field | Value |
|:------|:------|
| Packet[1].Signature | `aacb74fddf9bd1c4d759a600e080f1fb3798793dfa18adb701236c823c487dddf86a08920340f62d3b4f1e0e64873f36be633a1fa44bf2659ef3b4680d6c2200` |
| **TerminalDigest** | **`e413a0e508a058ecd6238aa23176fc3624c85be8d5cb559f3b8b3e0ea5897258`** |
| `"APXB"` prefix | `41505842` |
| SessionID | `00000000000040008000000000000001` |
| BootstrapNonce | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |
| SigningPub | `3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29` |
| **BundleHash** | **`a8de27e18199d9f823f7de3ddc4c3acb93a8380fccfe3ab4b0224d1850aa649b`** |
| **SealSig** | **`78c98301f221dde4cc569a9ddffeceaba60080491437c27aad94ca9efd2ae288d055b4e7ed26880ea978bdf485ab393dafbe79c2a32f874a0f7b71c1b8029806`** |

---

### §14.8 Summary

A compliant implementation MUST produce these exact values given the inputs in §14.2:

| Value | Expected |
|:------|:---------|
| BootstrapNonce | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |
| L1[1] | `a231fcd1c04fef6e333954f22b311425d7d55ce3994b9a6d38a7cb72eedce64b` |
| L2Hash | `d416434244a2ce8276e6f3d72cc53f953f5e3f581f2e6862e5e36fadbe10ab71` |
| Packet[1].Signature | `aacb74fddf9bd1c4d759a600e080f1fb3798793dfa18adb701236c823c487dddf86a08920340f62d3b4f1e0e64873f36be633a1fa44bf2659ef3b4680d6c2200` |
| TerminalDigest | `e413a0e508a058ecd6238aa23176fc3624c85be8d5cb559f3b8b3e0ea5897258` |
| BundleHash | `a8de27e18199d9f823f7de3ddc4c3acb93a8380fccfe3ab4b0224d1850aa649b` |
| SealSig | `78c98301f221dde4cc569a9ddffeceaba60080491437c27aad94ca9efd2ae288d055b4e7ed26880ea978bdf485ab393dafbe79c2a32f874a0f7b71c1b8029806` |

---

## §14.9 Two-Segment Session — TEMPORAL_PROOF and SESSION_RESUME

### §14.9.1 Scope

This section extends §14 with a minimal two-segment session exercising:

- `SESSION_START` (0x06) — first packet, empty payload
- `TEMPORAL_PROOF` (0x09) — 137-byte APXP scope, Argon2id SWF
- `SESSION_RESUME` (0x07) — 93-byte APXS scope, segment-2 keypair
- Multi-segment `TerminalDigest` and `BundleHash`
- `SETTLEMENT_FINAL` block (`APXT`) over the four-packet digest

Segment 1 uses **Keypair A** (seed = `0x00 × 32`).
Segment 2 uses **Keypair B** (seed = `0x01 × 32`) — fresh per-segment
keypair; Keypair A is not persisted across the hibernate boundary.

All §14.2 fixed inputs (SessionID, BundleID, AttestationDoc,
L2Hash) carry over unchanged.

---

### §14.9.2 Additional Fixed Inputs

#### Ed25519 Keypair B (Segment 2 — SYNTHETIC / TEST-ONLY)

| Field | Value |
|:------|:------|
| Seed (32 bytes) | `0101010101010101010101010101010101010101010101010101010101010101` |
| Public key (32 bytes) | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

---

### §14.9.3 L1 Chain — Five Steps

```
L1[0] = BootstrapNonce
L1[1] = SHA-256(L1[0] ‖ b"")        — SESSION_START (empty payload)
L1[2] = SHA-256(L1[1] ‖ b"hello")   — EVIDENCE
L1[3] = SHA-256(L1[2] ‖ ArgonOutput) — TEMPORAL_PROOF
         L1[3] = prev_stream_hash = stream_hash at SESSION_RESUME time
```

| Hash | Value |
|:-----|:------|
| L1[0] (BootstrapNonce) | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |
| L1[1] | `e45c897ebe0fe84f41fb3fedda6b69e8e01c99dfc23eb58bb4433069a600a16c` |
| L1[2] | `68b39da0213eb4ef7acc7082a689fddf3cd75b315124f789b1543036c6e82a8f` |
| L1[3] | `f972ac032fff65740dee0be839b86c5528161c393ce298f9cc4e9611f406ba1f` |

---

### §14.9.4 Packet 1 — SESSION_START

ActionType `0x06`. Payload is empty (`PayloadLen = 0`). Uses the standard
161-byte APXE scope (§5.5) with `SHA-256(b"")` in the payload-hash field.

| Offset | Size | Field | Value |
|-------:|-----:|:------|:------|
| 0 | 4 | Magic (`"APXE"`) | `41505845` |
| 4 | 1 | FormatVer | `01` |
| 5 | 8 | Sequence (u64 LE = 1) | `0100000000000000` |
| 13 | 32 | PrevL1Hash (= BootstrapNonce) | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |
| 45 | 32 | L1Hash (= L1[1]) | `e45c897ebe0fe84f41fb3fedda6b69e8e01c99dfc23eb58bb4433069a600a16c` |
| 77 | 32 | L2Hash | `d416434244a2ce8276e6f3d72cc53f953f5e3f581f2e6862e5e36fadbe10ab71` |
| 109 | 4 | PayloadLen (u32 LE = 0) | `00000000` |
| 113 | 32 | SHA-256(b"") | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 145 | 16 | SessionID | `00000000000040008000000000000001` |
| **161** | | **total** | |

Full scope (161 bytes):

```
  41 50 58 45 01 01 00 00 00 00 00 00 00 b7 51 e7
  86 08 6c 23 13 51 23 cf 48 6a d4 63 34 9f eb e3
  08 f9 c5 4c 58 c0 44 78 a4 53 af 0e 63 e4 5c 89
  7e be 0f e8 4f 41 fb 3f ed da 6b 69 e8 e0 1c 99
  df c2 3e b5 8b b4 43 30 69 a6 00 a1 6c d4 16 43
  42 44 a2 ce 82 76 e6 f3 d7 2c c5 3f 95 3f 5e 3f
  58 1f 2e 68 62 e5 e3 6f ad be 10 ab 71 00 00 00
  00 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9
  24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8
  55 00 00 00 00 00 00 40 00 80 00 00 00 00 00 00
  01
```

| Field | Value |
|:------|:------|
| **Sig[1]** | **`99fddb38d80c8fc9497bd174b1890bda8c6f443962eb2073055ff91a11c96a5526fa07dc6bb50bf6aa9f56e7b189f01d7be8390c6b4aef75c66ee897b419bc0f`** |

---

### §14.9.5 Packet 2 — EVIDENCE

ActionType `0x01` (STREAM). Payload `"hello"` (5 bytes). Same 161-byte
APXE scope as §14.6 but with updated PrevL1Hash and L1Hash.

| Offset | Size | Field | Value |
|-------:|-----:|:------|:------|
| 0 | 4 | Magic (`"APXE"`) | `41505845` |
| 4 | 1 | FormatVer | `01` |
| 5 | 8 | Sequence (u64 LE = 2) | `0200000000000000` |
| 13 | 32 | PrevL1Hash (= L1[1]) | `e45c897ebe0fe84f41fb3fedda6b69e8e01c99dfc23eb58bb4433069a600a16c` |
| 45 | 32 | L1Hash (= L1[2]) | `68b39da0213eb4ef7acc7082a689fddf3cd75b315124f789b1543036c6e82a8f` |
| 77 | 32 | L2Hash | `d416434244a2ce8276e6f3d72cc53f953f5e3f581f2e6862e5e36fadbe10ab71` |
| 109 | 4 | PayloadLen (u32 LE = 5) | `05000000` |
| 113 | 32 | SHA-256(`"hello"`) | `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` |
| 145 | 16 | SessionID | `00000000000040008000000000000001` |
| **161** | | **total** | |

Full scope (161 bytes):

```
  41 50 58 45 01 02 00 00 00 00 00 00 00 e4 5c 89
  7e be 0f e8 4f 41 fb 3f ed da 6b 69 e8 e0 1c 99
  df c2 3e b5 8b b4 43 30 69 a6 00 a1 6c 68 b3 9d
  a0 21 3e b4 ef 7a cc 70 82 a6 89 fd df 3c d7 5b
  31 51 24 f7 89 b1 54 30 36 c6 e8 2a 8f d4 16 43
  42 44 a2 ce 82 76 e6 f3 d7 2c c5 3f 95 3f 5e 3f
  58 1f 2e 68 62 e5 e3 6f ad be 10 ab 71 05 00 00
  00 2c f2 4d ba 5f b0 a3 0e 26 e8 3b 2a c5 b9 e2
  9e 1b 16 1e 5c 1f a7 42 5e 73 04 33 62 93 8b 98
  24 00 00 00 00 00 00 40 00 80 00 00 00 00 00 00
  01
```

| Field | Value |
|:------|:------|
| **Sig[2]** | **`7e6f6c36ada44432f630198ee95d17640bd7799551af965a69c63fc88e00aa3ee12e1a39ce02d21a5f1380a032b99a09fcd8fd37dcfa06cd6defd90e38638e04`** |

---

### §14.9.6 Packet 3 — TEMPORAL_PROOF

ActionType `0x09`. Emitted at the hibernate boundary, immediately before
the sealed checkpoint (§9.5). Uses a 137-byte **APXP** scope — distinct
from the APXE scope to prevent cross-packet signature confusion.

**Argon2id input derivation** (56 bytes):

```
argon_input = LastEvidenceL1Hash ‖ SessionID ‖ Sequence (u64 LE)
            = L1[2] ‖ SessionID ‖ 0x0300000000000000
```

| Component | Bytes | Value |
|:----------|------:|:------|
| L1[2] (LastEvidenceL1Hash) | 32 | `68b39da0213eb4ef7acc7082a689fddf3cd75b315124f789b1543036c6e82a8f` |
| SessionID | 16 | `00000000000040008000000000000001` |
| Sequence (u64 LE = 3) | 8 | `0300000000000000` |
| **argon_input (56 bytes)** | | `68b39da0213eb4ef7acc7082a689fddf3cd75b315124f789b1543036c6e82a8f` `000000000000400080000000000000010300000000000000` |

**Argon2id parameters:** m=65536, t=3, p=1, salt=`APEX_SWFv1\x00\x00\x00\x00\x00\x00` (16 bytes)

| Field | Value |
|:------|:------|
| **ArgonOutput (32 bytes)** | **`32a4a37d9f56d5027485b38fc65e5865698cab7379d56b6c4f44763dfd2e5f3f`** |

**L1 chain advance:**

```
L1[3] = SHA-256(L1[2] ‖ ArgonOutput)
      = SHA-256(68b39da0... ‖ 32a4a37d...)
      = f972ac032fff65740dee0be839b86c5528161c393ce298f9cc4e9611f406ba1f
```

**TEMPORAL_PROOF signature scope (137 bytes, APXP magic):**

| Offset | Size | Field | Value |
|-------:|-----:|:------|:------|
| 0 | 4 | Magic (`"APXP"`) | `41505850` |
| 4 | 1 | FormatVer | `01` |
| 5 | 8 | Sequence (u64 LE = 3) | `0300000000000000` |
| 13 | 32 | PrevL1Hash (= L1[2]) | `68b39da0213eb4ef7acc7082a689fddf3cd75b315124f789b1543036c6e82a8f` |
| 45 | 32 | L1Hash (= L1[3]) | `f972ac032fff65740dee0be839b86c5528161c393ce298f9cc4e9611f406ba1f` |
| 77 | 32 | ArgonOutput | `32a4a37d9f56d5027485b38fc65e5865698cab7379d56b6c4f44763dfd2e5f3f` |
| 109 | 4 | m (u32 LE = 65536) | `00000100` |
| 113 | 4 | t (u32 LE = 3) | `03000000` |
| 117 | 4 | p (u32 LE = 1) | `01000000` |
| 121 | 16 | SessionID | `00000000000040008000000000000001` |
| **137** | | **total** | |

Full scope (137 bytes):

```
  41 50 58 50 01 03 00 00 00 00 00 00 00 68 b3 9d
  a0 21 3e b4 ef 7a cc 70 82 a6 89 fd df 3c d7 5b
  31 51 24 f7 89 b1 54 30 36 c6 e8 2a 8f f9 72 ac
  03 2f ff 65 74 0d ee 0b e8 39 b8 6c 55 28 16 1c
  39 3c e2 98 f9 cc 4e 96 11 f4 06 ba 1f 32 a4 a3
  7d 9f 56 d5 02 74 85 b3 8f c6 5e 58 65 69 8c ab
  73 79 d5 6b 6c 4f 44 76 3d fd 2e 5f 3f 00 00 01
  00 03 00 00 00 01 00 00 00 00 00 00 00 00 00 40
  00 80 00 00 00 00 00 00 01
```

| Field | Value |
|:------|:------|
| **Sig[3]** | **`61cd5040de303e9a595faae5a431a386220d61d09f1b22d3beef915bbf90d15b8cf506fb908bda94f3fbe476991a6ab876efde08fb6bf1efaa067c976d12b305`** |

**Wire line and TemporalProofHash:**

The full wire-format line emitted by the runtime and stored in `sig_log`:

```
TEMPORAL_PROOF:prev_stream=68b39da0213eb4ef7acc7082a689fddf3cd75b315124f789b1543036c6e82a8f:stream=f972ac032fff65740dee0be839b86c5528161c393ce298f9cc4e9611f406ba1f:proof=32a4a37d9f56d5027485b38fc65e5865698cab7379d56b6c4f44763dfd2e5f3f:m=65536:t=3:p=1:sig=61cd5040de303e9a595faae5a431a386220d61d09f1b22d3beef915bbf90d15b8cf506fb908bda94f3fbe476991a6ab876efde08fb6bf1efaa067c976d12b305:seq=3
```

```
TemporalProofHash = SHA-256(wire_line_bytes)
                 = 4c1931a50e49569bfaf6f55e01e919ce73666d4c55cadc23b3cba340a1ecf90f
```

This value is stored in the sealed payload `TemporalProofHash` field (§10.2).

---

### §14.9.7 Packet 4 — SESSION_RESUME

ActionType `0x07`. First packet of segment 2. Signed with **Keypair B**.

At the start of segment 2, the sealed payload is restored: both `stream_hash`
and `prev_stream_hash` equal `L1[3]` (TEMPORAL_PROOF left them identical).
Therefore `PrevL1Hash == L1Hash == L1[3]` in this packet.

**SESSION_RESUME signature scope (93 bytes, APXS magic):**

| Offset | Size | Field | Value |
|-------:|-----:|:------|:------|
| 0 | 4 | Magic (`"APXS"`) | `41505853` |
| 4 | 1 | FormatVer | `01` |
| 5 | 8 | Sequence (u64 LE = 4) | `0400000000000000` |
| 13 | 32 | PrevL1Hash (= L1[3]) | `f972ac032fff65740dee0be839b86c5528161c393ce298f9cc4e9611f406ba1f` |
| 45 | 32 | L1Hash (= L1[3]) | `f972ac032fff65740dee0be839b86c5528161c393ce298f9cc4e9611f406ba1f` |
| 77 | 16 | SessionID | `00000000000040008000000000000001` |
| **93** | | **total** | |

Full scope (93 bytes):

```
  41 50 58 53 01 04 00 00 00 00 00 00 00 f9 72 ac
  03 2f ff 65 74 0d ee 0b e8 39 b8 6c 55 28 16 1c
  39 3c e2 98 f9 cc 4e 96 11 f4 06 ba 1f f9 72 ac
  03 2f ff 65 74 0d ee 0b e8 39 b8 6c 55 28 16 1c
  39 3c e2 98 f9 cc 4e 96 11 f4 06 ba 1f 00 00 00
  00 00 00 40 00 80 00 00 00 00 00 00 01
```

| Field | Value |
|:------|:------|
| **Sig[4]** | **`53fd25c6e94c31e7c991c4f1e0183fa285c587b8f451ba205d19fae2d16e2944b68e2a47bdfda7a250b7a970d39f61f730707a157031f9e500811bbfdc5aeb06`** |

---

### §14.9.8 Terminal Digest — Four-Packet Two-Segment Session

```
TerminalDigest = SHA-256(Sig[1] ‖ Sig[2] ‖ Sig[3] ‖ Sig[4])
```

> **Order is binding.** Concatenation is in ascending sequence order. Any
> permutation produces a different digest and MUST be rejected.

| Field | Value |
|:------|:------|
| Sig[1] (SESSION_START) | `99fddb38d80c8fc9497bd174b1890bda8c6f443962eb2073055ff91a11c96a5526fa07dc6bb50bf6aa9f56e7b189f01d7be8390c6b4aef75c66ee897b419bc0f` |
| Sig[2] (EVIDENCE) | `7e6f6c36ada44432f630198ee95d17640bd7799551af965a69c63fc88e00aa3ee12e1a39ce02d21a5f1380a032b99a09fcd8fd37dcfa06cd6defd90e38638e04` |
| Sig[3] (TEMPORAL_PROOF) | `61cd5040de303e9a595faae5a431a386220d61d09f1b22d3beef915bbf90d15b8cf506fb908bda94f3fbe476991a6ab876efde08fb6bf1efaa067c976d12b305` |
| Sig[4] (SESSION_RESUME) | `53fd25c6e94c31e7c991c4f1e0183fa285c587b8f451ba205d19fae2d16e2944b68e2a47bdfda7a250b7a970d39f61f730707a157031f9e500811bbfdc5aeb06` |
| **TerminalDigest** | **`25d82d7967728c23910c9c29a49b7be3076df3ea57565365eb048197c2d58a22`** |

---

### §14.9.9 Bundle Seal — Two-Segment Session

The bundle seal uses **Keypair B** (the final segment's keypair) and the
final segment's public key (`PubB`) in the BundleHash computation.

```
BundleHash = SHA-256("APXB" ‖ SessionID ‖ BootstrapNonce ‖ PubB ‖ TerminalDigest)
SealSig    = Ed25519_Sign(keypair_B, BundleHash)
```

| Field | Value |
|:------|:------|
| `"APXB"` prefix | `41505842` |
| SessionID | `00000000000040008000000000000001` |
| BootstrapNonce | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |
| PubB (segment-2 public key) | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| TerminalDigest | `25d82d7967728c23910c9c29a49b7be3076df3ea57565365eb048197c2d58a22` |
| **BundleHash** | **`a73c9d4c36dd5ab879d00020a2d9f3ffec3bff628eb27fff14c284cc1477e85f`** |
| **SealSig** | **`5117b5ef8503d0b70982d9d517064881ae540e337953ad5240071928157c4c89ce11e4a95d88865ca044e939b01999cd70d2d05c757701180ece1b64e9c04206`** |

---

### §14.9.10 Settlement Block — APXT Signature Scope

The 88-byte settlement scope uses the same structure as §15.7 but over the
four-packet `TerminalDigest`. Signed by **Keypair B**.

| Offset | Size | Field | Value |
|-------:|-----:|:------|:------|
| 0 | 16 | EscrowID | `deadbeefdead40008000deadbeef0001` |
| 16 | 32 | Amount (decimal, zero-padded) | `3130303030303000000000000000000000000000000000000000000000000000` |
| 48 | 8 | Currency (space-padded) | `5553444320202020` |
| 56 | 32 | TerminalDigest | `25d82d7967728c23910c9c29a49b7be3076df3ea57565365eb048197c2d58a22` |
| **88** | | **total** | |

```
SettlementSig = Ed25519_Sign(keypair_B, settle_scope_88)
```

| Field | Value |
|:------|:------|
| **SettlementSig** | **`6af786709d6ca0b0f6c68224d05c3e6a524aa774612f2afb612c5a74d58e5d2c7c569e05ae13629f44d586ef330c715a79a91c2b7e4f17d7fdff3bb82361bb0b`** |

---

### §14.9.11 Summary

A compliant implementation MUST produce these exact values given the §14.2
inputs and the §14.9.2 additional inputs:

| Value | Expected |
|:------|:---------|
| L1[1] (after SESSION_START) | `e45c897ebe0fe84f41fb3fedda6b69e8e01c99dfc23eb58bb4433069a600a16c` |
| L1[2] (after EVIDENCE) | `68b39da0213eb4ef7acc7082a689fddf3cd75b315124f789b1543036c6e82a8f` |
| ArgonOutput | `32a4a37d9f56d5027485b38fc65e5865698cab7379d56b6c4f44763dfd2e5f3f` |
| L1[3] (after TEMPORAL_PROOF) | `f972ac032fff65740dee0be839b86c5528161c393ce298f9cc4e9611f406ba1f` |
| TemporalProofHash | `4c1931a50e49569bfaf6f55e01e919ce73666d4c55cadc23b3cba340a1ecf90f` |
| Sig[1] SESSION_START | `99fddb38d80c8fc9497bd174b1890bda8c6f443962eb2073055ff91a11c96a5526fa07dc6bb50bf6aa9f56e7b189f01d7be8390c6b4aef75c66ee897b419bc0f` |
| Sig[2] EVIDENCE | `7e6f6c36ada44432f630198ee95d17640bd7799551af965a69c63fc88e00aa3ee12e1a39ce02d21a5f1380a032b99a09fcd8fd37dcfa06cd6defd90e38638e04` |
| Sig[3] TEMPORAL_PROOF | `61cd5040de303e9a595faae5a431a386220d61d09f1b22d3beef915bbf90d15b8cf506fb908bda94f3fbe476991a6ab876efde08fb6bf1efaa067c976d12b305` |
| Sig[4] SESSION_RESUME | `53fd25c6e94c31e7c991c4f1e0183fa285c587b8f451ba205d19fae2d16e2944b68e2a47bdfda7a250b7a970d39f61f730707a157031f9e500811bbfdc5aeb06` |
| TerminalDigest | `25d82d7967728c23910c9c29a49b7be3076df3ea57565365eb048197c2d58a22` |
| BundleHash | `a73c9d4c36dd5ab879d00020a2d9f3ffec3bff628eb27fff14c284cc1477e85f` |
| SealSig | `5117b5ef8503d0b70982d9d517064881ae540e337953ad5240071928157c4c89ce11e4a95d88865ca044e939b01999cd70d2d05c757701180ece1b64e9c04206` |
| SettlementSig | `6af786709d6ca0b0f6c68224d05c3e6a524aa774612f2afb612c5a74d58e5d2c7c569e05ae13629f44d586ef330c715a79a91c2b7e4f17d7fdff3bb82361bb0b` |

---

### §14.9.12 ECR Computation

Applying Step 12 to the §14.9 bundle:

| Symbol | Value | Derivation |
| :--- | :--- | :--- |
| K | 1 | One SESSION_RESUME packet (Seq = 4) → one hibernate boundary |
| K_tp | 1 | Step 11 Rule A passes at Seq = 3 (TEMPORAL_PROOF present and valid) |
| **ECR** | **1.0** | K_tp / K = 1 / 1 |

For reference: the §14 base fixture is a single-segment session (K = 0), so ECR = **1.0** vacuously.

A hypothetical two-segment bundle identical to §14.9 but with the TEMPORAL_PROOF packet absent (Rule B path) would yield K = 1, K_tp = 0, ECR = **0.0**, and the settlement step would FAIL per Rule B.3.

---

## 15. Settlement Block Test Vectors

### §15.1 Scope

§15 extends the §14 session by one additional evidence packet and a Settlement
Block.  The two-packet session verifies:

- TerminalDigest computation over **multiple** concatenated signatures
- Scope[2] byte layout for a packet with sequence > 1
- Settlement signature scope (88 bytes: `EscrowID ‖ Amount ‖ Currency ‖
  TerminalDigest`)

All §14.2 fixed inputs carry over unchanged.

---

### §15.2 Additional Fixed Inputs

#### Second Packet

| Field | Value |
|:------|:------|
| Payload bytes | `776f726c64` (`world`) |
| PayloadLen | 5 |
| ActionType | `01` (STREAM) |
| Sequence | 2 |

#### Settlement Block Inputs (SYNTHETIC / TEST-ONLY)

The settlement signature scope sizes match §6: EscrowID=16 bytes, Amount=32
bytes (decimal string zero-padded), Currency=8 bytes (space-padded).

| Field | Size | Value |
|:------|-----:|:------|
| EscrowID | 16 | `deadbeefdead40008000deadbeef0001` (BundleID from §14.2) |
| Amount | 32 | `31303030303030000000000000000000` `00000000000000000000000000000000` (ASCII `"1000000"`, zero-padded) |
| Currency | 8 | `5553444320202020` (ASCII `"USDC    "`, space-padded) |

---

### §15.3 L1 Chain Extension

```
L1[2] = SHA-256(L1[1] ‖ b"world")
```

| Field | Value |
|:------|:------|
| L1[1] (from §14) | `a231fcd1c04fef6e333954f22b311425d7d55ce3994b9a6d38a7cb72eedce64b` |
| Payload (`world`) | `776f726c64` |
| **L1[2]** | **`cd84b951c893096829a4c78ac9d3efc65f4dc9b3c3896df0653ea887d50142fe`** |

---

### §15.4 Scope[2] — 161-byte Signature Scope for Packet 2

| Offset | Size | Field | Value |
|-------:|-----:|:------|:------|
| 0 | 4 | Magic (`"APXE"`) | `41505845` |
| 4 | 1 | FormatVer | `01` |
| 5 | 8 | Sequence (u64 LE = 2) | `0200000000000000` |
| 13 | 32 | PrevL1Hash (= L1[1]) | `a231fcd1c04fef6e333954f22b311425d7d55ce3994b9a6d38a7cb72eedce64b` |
| 45 | 32 | L1Hash (= L1[2]) | `cd84b951c893096829a4c78ac9d3efc65f4dc9b3c3896df0653ea887d50142fe` |
| 77 | 32 | L2Hash (same as §14) | `d416434244a2ce8276e6f3d72cc53f953f5e3f581f2e6862e5e36fadbe10ab71` |
| 109 | 4 | PayloadLen (u32 LE = 5) | `05000000` |
| 113 | 32 | SHA-256(Payload) | `486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7` |
| 145 | 16 | SessionID | `00000000000040008000000000000001` |
| **161** | | **total** | |

Full scope (161 bytes):

```
  41 50 58 45 01 02 00 00 00 00 00 00 00 a2 31 fc
  d1 c0 4f ef 6e 33 39 54 f2 2b 31 14 25 d7 d5 5c
  e3 99 4b 9a 6d 38 a7 cb 72 ee dc e6 4b cd 84 b9
  51 c8 93 09 68 29 a4 c7 8a c9 d3 ef c6 5f 4d c9
  b3 c3 89 6d f0 65 3e a8 87 d5 01 42 fe d4 16 43
  42 44 a2 ce 82 76 e6 f3 d7 2c c5 3f 95 3f 5e 3f
  58 1f 2e 68 62 e5 e3 6f ad be 10 ab 71 05 00 00
  00 48 6e a4 62 24 d1 bb 4f b6 80 f3 4f 7c 9a d9
  6a 8f 24 ec 88 be 73 ea 8e 5a 6c 65 26 0e 9c b8
  a7 00 00 00 00 00 00 40 00 80 00 00 00 00 00 00
  01
```

#### Packet 2 Signature

```
Sig[2] = Ed25519_Sign(signing_key, Scope[2])
```

| Field | Value |
|:------|:------|
| Sig[2] (64 bytes) | `1a5cefd8b7b320d582e6d763187b05b1ec499108f1d8d7357bc24a5c7b5e17982d460e8a6c7990e4458812f9ece7d2e18a3608b9a48d09b52b2f8fab47fcb402` |

---

### §15.5 Terminal Digest — Two-Packet Session

TerminalDigest covers all packet signatures in sequence order by concatenation.

```
TerminalDigest = SHA-256(Sig[1] ‖ Sig[2])
```

> **Order is binding.** `SHA-256(Sig[2] ‖ Sig[1])` produces a different digest
> and MUST be rejected.

| Field | Value |
|:------|:------|
| Sig[1] (from §14) | `aacb74fddf9bd1c4d759a600e080f1fb3798793dfa18adb701236c823c487dddf86a08920340f62d3b4f1e0e64873f36be633a1fa44bf2659ef3b4680d6c2200` |
| Sig[2] | `1a5cefd8b7b320d582e6d763187b05b1ec499108f1d8d7357bc24a5c7b5e17982d460e8a6c7990e4458812f9ece7d2e18a3608b9a48d09b52b2f8fab47fcb402` |
| **TerminalDigest** | **`b4d8cd5d6a7ecbe3ce8898bf111031fa70b3fd5426f9119cfa114d374236cc85`** |

The §14 single-packet TerminalDigest (`e413a0e5…`) MUST NOT match this value.

---

### §15.6 Bundle Seal — Two-Packet Session

```
BundleHash = SHA-256("APXB" ‖ SessionID ‖ BootstrapNonce ‖ SigningPub ‖ TerminalDigest)
SealSig    = Ed25519_Sign(signing_key, BundleHash)
```

| Field | Value |
|:------|:------|
| **BundleHash** | **`eda0949b09a795f5b0f8974079252e32210f5d9c21e30d9939842d7edfded5e7`** |
| **SealSig** | **`7a56c7866c0c20a74aafbd3dd675d299292bdebbad195067f8d362df2e149f3ca893808b4bd88ffb33eeb09d152e45132f839d5658dc56ec10b5aa3afb89e10c`** |

---

### §15.7 Settlement Block — APXT Signature Scope

The 88-byte settlement signature scope (`APXT`) is formed by concatenating four
fields in order, matching the Settlement Block wire format (§6):

| Offset | Size | Field | Value |
|-------:|-----:|:------|:------|
| 0 | 16 | EscrowID | `deadbeefdead40008000deadbeef0001` |
| 16 | 32 | Amount (decimal, zero-padded) | `3130303030303000000000000000000000000000000000000000000000000000` |
| 48 | 8 | Currency (space-padded) | `5553444320202020` |
| 56 | 32 | TerminalDigest | `b4d8cd5d6a7ecbe3ce8898bf111031fa70b3fd5426f9119cfa114d374236cc85` |
| **88** | | **total** | |

```
SettlementSig = Ed25519_Sign(signing_key, settle_scope_88)
```

| Field | Value |
|:------|:------|
| **SettlementSig** | **`e105775ff46ee34b88165415dd2bcb131b5ca0a7b9ff08644aef3103f646bb6d7a2b44e389e57caa07ad187c4b49ed898bdc1e376216ca271959c9b9dfe21a09`** |

---

### §15.8 Summary

A compliant implementation MUST produce these exact values given the §14.2
inputs plus the §15.2 additional inputs:

| Value | Expected |
|:------|:---------|
| L1[2] | `cd84b951c893096829a4c78ac9d3efc65f4dc9b3c3896df0653ea887d50142fe` |
| Sig[2] | `1a5cefd8b7b320d582e6d763187b05b1ec499108f1d8d7357bc24a5c7b5e17982d460e8a6c7990e4458812f9ece7d2e18a3608b9a48d09b52b2f8fab47fcb402` |
| TerminalDigest | `b4d8cd5d6a7ecbe3ce8898bf111031fa70b3fd5426f9119cfa114d374236cc85` |
| BundleHash | `eda0949b09a795f5b0f8974079252e32210f5d9c21e30d9939842d7edfded5e7` |
| SealSig | `7a56c7866c0c20a74aafbd3dd675d299292bdebbad195067f8d362df2e149f3ca893808b4bd88ffb33eeb09d152e45132f839d5658dc56ec10b5aa3afb89e10c` |
| SettlementSig | `e105775ff46ee34b88165415dd2bcb131b5ca0a7b9ff08644aef3103f646bb6d7a2b44e389e57caa07ad187c4b49ed898bdc1e376216ca271959c9b9dfe21a09` |

---

## 16. Version History

| Version | Changes |
|:---|:---|
| 2.7.0 | §8 Step 12 added: Evidence Coverage Ratio (ECR) — verifier-computed metric reporting the fraction of hibernate boundaries with a valid TEMPORAL_PROOF; MUST NOT be reported before BundleSeal verification; ECR = K_tp / K (K = 0 → 1.0); settlement precondition formalized; §14.9.12 ECR test vector (K=1, K_tp=1, ECR=1.0); §17 Conformance updated to Steps 1–12 |
| 2.6.1 | TEMPORAL_PROOF (0x09) signature scope magic renamed VART→APXP; all §14.9 fixture vectors updated (Sig[3], TemporalProofHash, TerminalDigest, BundleHash, SealSig, SettlementSig); gen_fixture_14n.py updated to APXP; shell.zig scope comment updated |
| 2.5.0 | §14.9 two-segment session test vectors added: SESSION_START (0x06) 161-byte APXE scope, TEMPORAL_PROOF (0x09) 137-byte APXP scope with Argon2id SWF, SESSION_RESUME (0x07) 93-byte APXS scope, four-packet TerminalDigest, two-keypair bundle seal; gen_fixture_14n.py generation script; §14.1 "Planned" stub replaced with §14.9 reference |
| 2.4.1 | §5.7 performance note updated with measured Argon2id latency on AWS Nitro c5.xlarge: ~240 ms (mean 239.81 ms, p50 241.22 ms, p95 247.09 ms) at floor params m=65536 t=3 p=1; 250 ms practical upper bound documented; §14 TEMPORAL_PROOF fixture note updated (benchmark settled, fixture unblocked) |
| 2.4.0 | ActionType `0x09 TEMPORAL_PROOF` added (§5.4); §5.7 TEMPORAL_PROOF packet payload schema (ArgonOutput, m, t, p); normative parameter floor m≥65536, t≥3, p=1 fixed; §9.5 TEMPORAL_PROOF emission ordering at hibernate boundaries; §10.2 sealed payload extended with optional `TemporalProofHash`; §8 Step 11 checkpoint-local verifier rules (Rule A/B, settlement escalation); §12 stale sealed-state replay moved from known gap to mitigated with conformance caveat; §17 Conformance updated |
| 2.3.0 | §9 Hibernate/Resume expanded to four subsections covering crash recovery (§9.2), SESSION_RESUME first-packet requirement (§9.3), and verifier rules (§9.4); §10 Sealed State expanded with sealed payload field table (§10.2) and checkpoint timing (§10.3); §8 Step 10 added for multi-segment boundary verification; §17 Conformance updated; input-channel attestation gap documented in §12 |
| 2.2.0 | §15 Settlement Block Test Vectors — two-packet session, TerminalDigest over multiple signatures, 88-byte APXT settlement signature scope; §13 roadmap marked complete |
| 2.1.0 | §14 Test Vectors — fully-worked single-packet session with known synthetic inputs |
| 2.0.0 | APEX spec. New magic bytes, named action types, Settlement Block, Bundle Seal, strict unknown-type rejection, grapheme cluster correction |
| 1.5 | VAR evidence_spec: CBOR map walk for PCR extraction, CBOR bounds check, session_pub_cert |
| 1.4 | executions array replaces last_exec; cover-up attack prevention |
| 1.3 | EXEC command, stdout commitment to L1, stderr hash |
| 1.2 | SessionID in signature scope, snapshot mode, sealed state, KMS recipient flow |
| 1.1 | Initial public draft |

---

## 17. Conformance

An implementation is **APEX-compliant** if it:

1. Produces bundles that pass all Steps 1–12 of the verification algorithm (§8)
2. Rejects unknown ActionType values rather than passing them through
3. Performs CBOR map walk (not byte scan) for PCR extraction
4. Does not persist the Ed25519 signing keypair across hibernate/resume cycles
5. Gates settlement on a verified TerminalDigest
6. Writes a sealed checkpoint after each EVIDENCE emission (§10.3) and emits SESSION_RESUME as the first packet of every resumed segment (§9.3)
7. Emits a `TEMPORAL_PROOF` packet (`0x09`) immediately before each sealed checkpoint write at hibernate boundaries, with `p = 1`, `m ≥ 65536`, and `t ≥ 3` (§9.5)
8. Includes `TemporalProofHash` in the sealed payload whenever a conformant `TEMPORAL_PROOF` was emitted for that checkpoint (§10.2)

A verifier is **APEX-compliant** if it implements all Steps 1–12 and correctly handles multi-segment sessions per §9.4 and §9.5.

---

*APEX is an open specification. Third-party implementations are encouraged. The reference implementation is VAR: https://github.com/kennethkabogo/verifiable-agent-runtime*
