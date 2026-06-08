# APEX — Attested Proof of EXecution
## Specification v2.3.0

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
| Magic | `[4]u8` | `"VARE"` (`0x56 0x41 0x52 0x45`) |
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

### 5.5 Signature Scope

The enclave signs a fixed-length 161-byte message. ActionType is a packet field (§5.3) but is NOT included in the signed scope — it is validated by the verifier as a parsing step (§8 Step 5).

| Offset | Size | Field |
|---:|---:|:---|
| 0 | 4 | Magic `"VARE"` |
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
| BundleHash | `[32]u8` | SHA-256(`"VARB"` ‖ SessionID ‖ BootstrapNonce ‖ SessionPub ‖ TerminalDigest) |
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
assert BundleSeal.BundleHash == SHA-256("VARB" ‖ SessionID ‖ BootstrapNonce ‖ SessionPub ‖ BundleSeal.TerminalDigest)
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

The Ed25519 signing keypair MUST NOT be included in the sealed payload. Each resumed segment generates a fresh keypair bound to a new attestation quote.

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
| Stale sealed-state replay under partition (known gap) | If an attacker forces a crash during a network partition (S_D→S_F in the session lifecycle), a stale sealed checkpoint from before the partition may be presented on RESUME. The KMS will unseal it (the PCR measurement is valid), and the chain will resume from stale state — silently dropping evidence emitted after the last checkpoint but before the partition. APEX v2.3.0 does not mitigate this. A full mitigation requires the KMS or a trusted counter service to reject any RESUME whose sealed sequence number was already seen (anti-replay on the checkpoint nonce). Known gap for v2.x. |

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

#### Notation

- `‖` denotes byte concatenation.
- All hex strings are lowercase, no spaces, unless formatted as byte blocks.
- `u64 LE` / `u32 LE` = little-endian unsigned integer.
- Values labelled **SYNTHETIC / TEST-ONLY** MUST NOT appear in production bundles.

> **Implementation note.** The VAR reference implementation
> (`src/runtime/shell.zig`) uses magic bytes `VARE` (0x56 0x41 0x52 0x45)
> and a **161-byte** signature scope (ActionType byte omitted).
> These test vectors match that behaviour. A future APEX 3.0 revision
> will unify the magic bytes across all packet types under the `APX*` prefix.

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
| 0 | 4 | Magic (`"VARE"`) | `56415245` |
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
  56 41 52 45 01 01 00 00 00 00 00 00 00 b7 51 e7
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
| Signature (64 bytes) | `36092fb379e6e33a6dccf33be6c9b617e0f9b2837195d0e6414ce00590383988a208d9b37d065d1b1999ecb4872b26f4c8ce0bf3f4c91f90cb07b94c0c2b1f05` |

---

### §14.7 Terminal Digest and Bundle Seal

Single-packet session; TerminalDigest covers exactly one signature.

```
TerminalDigest = SHA-256(Packet[1].Signature)
BundleHash     = SHA-256("VARB" ‖ SessionID ‖ BootstrapNonce ‖ SigningPub ‖ TerminalDigest)
SealSig        = Ed25519_Sign(signing_key, BundleHash)
```

| Field | Value |
|:------|:------|
| Packet[1].Signature | `36092fb379e6e33a6dccf33be6c9b617e0f9b2837195d0e6414ce00590383988a208d9b37d065d1b1999ecb4872b26f4c8ce0bf3f4c91f90cb07b94c0c2b1f05` |
| **TerminalDigest** | **`33c143a8fd36b26f375339c66ab10aab0f457e5a5678790c38cdf2fac08f9978`** |
| `"VARB"` prefix | `56415242` |
| SessionID | `00000000000040008000000000000001` |
| BootstrapNonce | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |
| SigningPub | `3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29` |
| **BundleHash** | **`ddb62dbda59c6ea21ea7d6227d00e0d267dd8b1b3d35ad6a88c5fbfe4612399a`** |
| **SealSig** | **`8e0b8126cdf3f6453ecdbcbfe2656693b0d386b9a76dffe23875e95d487ce4b151ba37b9e0df690c44a23b388e1e50661ac7b1531b9a963907b737f2eb3b120d`** |

---

### §14.8 Summary

A compliant implementation MUST produce these exact values given the inputs in §14.2:

| Value | Expected |
|:------|:---------|
| BootstrapNonce | `b751e786086c23135123cf486ad463349febe308f9c54c58c04478a453af0e63` |
| L1[1] | `a231fcd1c04fef6e333954f22b311425d7d55ce3994b9a6d38a7cb72eedce64b` |
| L2Hash | `d416434244a2ce8276e6f3d72cc53f953f5e3f581f2e6862e5e36fadbe10ab71` |
| Packet[1].Signature | `36092fb379e6e33a6dccf33be6c9b617e0f9b2837195d0e6414ce00590383988a208d9b37d065d1b1999ecb4872b26f4c8ce0bf3f4c91f90cb07b94c0c2b1f05` |
| TerminalDigest | `33c143a8fd36b26f375339c66ab10aab0f457e5a5678790c38cdf2fac08f9978` |
| BundleHash | `ddb62dbda59c6ea21ea7d6227d00e0d267dd8b1b3d35ad6a88c5fbfe4612399a` |
| SealSig | `8e0b8126cdf3f6453ecdbcbfe2656693b0d386b9a76dffe23875e95d487ce4b151ba37b9e0df690c44a23b388e1e50661ac7b1531b9a963907b737f2eb3b120d` |

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
| 0 | 4 | Magic (`"VARE"`) | `56415245` |
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
  56 41 52 45 01 02 00 00 00 00 00 00 00 a2 31 fc
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
| Sig[2] (64 bytes) | `937b3e0585745ce592b903c6b7fb0132d5b9658a7eae218ae8019353dd59b2006d8f84f7b2bb756940c7708308c8268315d1d09196f7bf2e68a5be9815d44904` |

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
| Sig[1] (from §14) | `36092fb379e6e33a6dccf33be6c9b617e0f9b2837195d0e6414ce00590383988a208d9b37d065d1b1999ecb4872b26f4c8ce0bf3f4c91f90cb07b94c0c2b1f05` |
| Sig[2] | `937b3e0585745ce592b903c6b7fb0132d5b9658a7eae218ae8019353dd59b2006d8f84f7b2bb756940c7708308c8268315d1d09196f7bf2e68a5be9815d44904` |
| **TerminalDigest** | **`88e004ad67bf28c7a00d6c097ba8a6a09a11508af30b816dff692429b3c33c3d`** |

The §14 single-packet TerminalDigest (`33c143a8…`) MUST NOT match this value.

---

### §15.6 Bundle Seal — Two-Packet Session

```
BundleHash = SHA-256("VARB" ‖ SessionID ‖ BootstrapNonce ‖ SigningPub ‖ TerminalDigest)
SealSig    = Ed25519_Sign(signing_key, BundleHash)
```

| Field | Value |
|:------|:------|
| **BundleHash** | **`e05dd6abae2ee095b5895632845c55ecf44e91bb6c166b83899eb10381f4990c`** |
| **SealSig** | **`fa384faab2d5d6fb2cd5df6a094cf800f6298ecfab4c3bdfbac2e58c687d651b8ff604df2f92b0f6e5c019189f8f18cb2e7058a878e05ce7496735ab10e3c00e`** |

---

### §15.7 Settlement Block — APXT Signature Scope

The 88-byte settlement signature scope (`APXT`) is formed by concatenating four
fields in order, matching the Settlement Block wire format (§6):

| Offset | Size | Field | Value |
|-------:|-----:|:------|:------|
| 0 | 16 | EscrowID | `deadbeefdead40008000deadbeef0001` |
| 16 | 32 | Amount (decimal, zero-padded) | `3130303030303000000000000000000000000000000000000000000000000000` |
| 48 | 8 | Currency (space-padded) | `5553444320202020` |
| 56 | 32 | TerminalDigest | `88e004ad67bf28c7a00d6c097ba8a6a09a11508af30b816dff692429b3c33c3d` |
| **88** | | **total** | |

```
SettlementSig = Ed25519_Sign(signing_key, settle_scope_88)
```

| Field | Value |
|:------|:------|
| **SettlementSig** | **`101f4cf36ec03be2ed7289b4acc664ed2353053a7f336f0094572a6dbb644b91980f7646defb52b4530a8855b4b780d9551375effa9f38b5a251aa861c43880b`** |

---

### §15.8 Summary

A compliant implementation MUST produce these exact values given the §14.2
inputs plus the §15.2 additional inputs:

| Value | Expected |
|:------|:---------|
| L1[2] | `cd84b951c893096829a4c78ac9d3efc65f4dc9b3c3896df0653ea887d50142fe` |
| Sig[2] | `937b3e0585745ce592b903c6b7fb0132d5b9658a7eae218ae8019353dd59b2006d8f84f7b2bb756940c7708308c8268315d1d09196f7bf2e68a5be9815d44904` |
| TerminalDigest | `88e004ad67bf28c7a00d6c097ba8a6a09a11508af30b816dff692429b3c33c3d` |
| BundleHash | `e05dd6abae2ee095b5895632845c55ecf44e91bb6c166b83899eb10381f4990c` |
| SealSig | `fa384faab2d5d6fb2cd5df6a094cf800f6298ecfab4c3bdfbac2e58c687d651b8ff604df2f92b0f6e5c019189f8f18cb2e7058a878e05ce7496735ab10e3c00e` |
| SettlementSig | `101f4cf36ec03be2ed7289b4acc664ed2353053a7f336f0094572a6dbb644b91980f7646defb52b4530a8855b4b780d9551375effa9f38b5a251aa861c43880b` |

---

## 16. Version History

| Version | Changes |
|:---|:---|
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

1. Produces bundles that pass all Steps 1–10 of the verification algorithm (§8)
2. Rejects unknown ActionType values rather than passing them through
3. Performs CBOR map walk (not byte scan) for PCR extraction
4. Does not persist the Ed25519 signing keypair across hibernate/resume cycles
5. Gates settlement on a verified TerminalDigest
6. Writes a sealed checkpoint after each EVIDENCE emission (§10.3) and emits SESSION_RESUME as the first packet of every resumed segment (§9.3)

A verifier is **APEX-compliant** if it implements all Steps 1–10 and correctly handles multi-segment sessions per §9.4.

---

*APEX is an open specification. Third-party implementations are encouraged. The reference implementation is VAR: https://github.com/kennethkabogo/verifiable-agent-runtime*
