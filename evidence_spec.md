# Specification: VAR Evidence Bundle (v1.4)

This document is the formal technical contract between the **VAR Enclave**
and the **Auditor Client**.  It defines the cryptographic wire formats,
hashing logic, signature scope, and verification requirements for the
Verifiable Agent Runtime.

**Changelog**
- v1.4 — §2.3.3: replace `last_exec` (singular) with `executions` (ordered
         array).  Every command run during the session is appended to the log;
         nothing is ever discarded.  Fixes the "cover-up" attack where a
         malicious command followed by a benign one would erase the evidence.
         HTTP Sidecar path (`POST /exec` + `GET /evidence`) now documented as
         the language-agnostic interface for co-located skills.
- v1.3 — Add §2.3 Structured Execution (EXEC command, `last_exec` evidence
         field, stdout/stderr hash commitment to L1 chain).
- v1.2 — Add SessionID to §3.1 signature scope (matches implementation).
         Add §3.2 Snapshot Mode.  Add §5 Sealed State.  Add §6 KMS
         Recipient Flow.  Expand §4 with attestation validation steps.
         Rename `TEE_Sign` → `Ed25519_Sign`.
- v1.1 — Initial public draft.

---

## 1. Session Lifecycle

### 1.1 Bundle Header

Every VAR session begins with a one-time **Bundle Header**.  It provides
the root of trust and the initial parameters for all subsequent verification.

| Field | Type | Description |
| :--- | :--- | :--- |
| **Magic** | `[4]u8` | Constant `"VARB"` (`0x56 0x41 0x52 0x42`) |
| **Version** | `u8` | Bundle format version.  Current: `0x01` |
| **Session ID** | `[16]u8` | Unique UUID v4 for this session |
| **Bootstrap Nonce** | `[32]u8` | `SHA-256(AttestationDoc ‖ SessionID)` — see §1.2 |
| **Attestation Len** | `u32` LE | Byte length of the Attestation Document |
| **Attestation Doc** | `[AttestationLen]u8` | Hardware-signed COSE\_Sign1 document from the NSM |

### 1.2 Bootstrap Nonce

The hash chain is **anchored to the session** by the Bootstrap Nonce,
derived once inside the enclave as:

```
H_stream[0] = SHA-256(AttestationDoc ‖ SessionID)
```

This binds the initial chain state to a specific hardware attestation and a
specific session UUID.  An auditor who independently recomputes this value
can confirm that the chain they are verifying originated inside the correct
enclave.

---

## 2. Hashing Logic

### 2.1 L1 Stream Hash

The L1 hash is a **sequential digest of the raw PTY byte stream**.  Each
chunk of output from the agent process extends the chain:

```
H_stream[n] = SHA-256(H_stream[n-1] ‖ data_chunk[n])
```

- `H_stream[0]` is the Bootstrap Nonce (§1.2).
- An auditor can detect **gaps or reordering** by checking
  `Packet[n].PrevL1Hash == Packet[n-1].L1Hash`.

### 2.2 L2 State Hash

The L2 hash captures the **visual terminal state** at the moment evidence is
emitted.  It is computed over the full rendered grid:

```
H_state = SHA-256(
    format_version  ‖   // u8, current: 0x01
    cursor_x        ‖   // u16 LE
    cursor_y        ‖   // u16 LE
    terminal_width  ‖   // u16 LE
    terminal_height ‖   // u16 LE
    cell_digest         // see §2.2.1
)
```

#### 2.2.1 Cell Digest Serialization

The `cell_digest` MUST be computed using a **row-major (top-to-bottom,
left-to-right)** traversal of the terminal buffer.  For each cell:

```
cell_bytes =
    codepoint_utf8  // UTF-8 encoded into a zero-initialised [4]u8,
                    // left-aligned; unused bytes remain 0x00
    fg_color_rgb    // R, G, B (3 bytes)
    bg_color_rgb    // R, G, B (3 bytes)
    attrs_u8        // 1-byte attribute bitmask (see §2.2.2)
```

Each cell contributes exactly 11 bytes.  The concatenation of all cells'
bytes is hashed in-order as the `cell_digest` input.

#### 2.2.2 Attribute Bitmask (`attrs_u8`)

| Bit | Attribute |
| :--- | :--- |
| 0 | Bold |
| 1 | Italic |
| 2 | Faint |
| 3 | Blink |
| 4 | Reverse (Inverse) |
| 5 | Invisible |
| 6 | Strikethrough |
| 7 | Underline |

### 2.3 Structured Execution (EXEC)

When an agent invokes the `EXEC` command (vsock) or `POST /exec` (HTTP), the
enclave runs the requested subprocess and records a structured execution result
alongside the normal L1/L2 hashing.

#### 2.3.1 stdout Commitment

stdout bytes are folded into the L1 chain exactly as `logOutput` would:

```
H_stream[n] = SHA-256(H_stream[n-1] ‖ stdout_bytes)
```

A verifier can therefore confirm that a specific stdout was produced by
computing `SHA-256(stdout_bytes)` and checking it is consistent with the
observed L1 chain delta between two consecutive evidence packets.

#### 2.3.2 stderr Handling

stderr bytes are captured and hashed (`SHA-256(stderr_bytes)`) but are
**not** committed to the L1 chain.  stderr is diagnostic output that does not
form part of the verifiable execution record.

#### 2.3.3 `executions` Evidence Field

Every evidence bundle carries an **ordered array** of all subprocess
executions that occurred during the session up to that point:

```json
{
  "executions": [
    {
      "cmd":         "uname -a",
      "stdout_hash": "<hex64>",
      "stderr_hash": "<hex64>",
      "exit_code":   0,
      "seq":         1
    },
    {
      "cmd":         "date -u",
      "stdout_hash": "<hex64>",
      "stderr_hash": "<hex64>",
      "exit_code":   0,
      "seq":         1
    }
  ]
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| **cmd** | `string` | Space-joined command line, e.g. `"ls -la /tmp"` |
| **stdout_hash** | `hex[64]` | `SHA-256(stdout_bytes)` |
| **stderr_hash** | `hex[64]` | `SHA-256(stderr_bytes)` |
| **exit_code** | `u8` | Process exit code (signal → 128 + signum) |
| **seq** | `u64` | Value of `sequence` counter at execution time |

`executions` is `[]` (empty array) before any `EXEC` call in the session.
Entries are **append-only**: commands are never removed or reordered.

> **Security note — "cover-up" attack prevention**
>
> The v1.3 `last_exec` field could be exploited by an agent that ran a
> malicious command and then immediately followed it with a benign one
> (e.g. `whoami`), erasing the evidence.  The `executions` array closes
> this gap: the enclave accumulates all invocations for the session lifetime.

#### 2.3.4 Verification

To verify the full execution history in v1.4:

1. Obtain the signed evidence bundle for the session.
2. For each entry `E[i]` in `executions` (in order), confirm that the L1
   chain advanced correctly:
   `L1[after_i] == SHA-256(L1[before_i] ‖ E[i].stdout_bytes)`.
3. Confirm `SHA-256(E[i].stdout_bytes) == E[i].stdout_hash` for each entry.
4. The `exit_code` and `stderr_hash` are informational and are not covered
   by the Ed25519 signature; they are auditable but not cryptographically
   enforced in v1.4.

---

## 3. Evidence Packet Format

Evidence is emitted as a sequence of signed packets.

| Field | Type | Description |
| :--- | :--- | :--- |
| **Magic** | `[4]u8` | Constant `"VARE"` (`0x56 0x41 0x52 0x45`) |
| **Format Ver** | `u8` | Packet format version.  Current: `0x01` |
| **Sequence** | `u64` LE | Monotonically increasing index, starting at 1 |
| **Prev L1 Hash** | `[32]u8` | `H_stream[n-1]` — enables gap detection |
| **L1 Hash** | `[32]u8` | `H_stream[n]` |
| **L2 Hash** | `[32]u8` | `H_state` at emission time |
| **Payload Len** | `u32` LE | Byte length of the raw terminal payload (0 in snapshot mode — §3.2) |
| **Payload** | `[PayloadLen]u8` | Raw terminal data bytes (empty in snapshot mode) |
| **Signature** | `[64]u8` | Ed25519 signature over the 161-byte message — §3.1 |

### 3.1 Signature Scope

The enclave signs a fixed-length 161-byte message constructed as follows:

| Offset | Size | Field | Value |
| ---: | ---: | :--- | :--- |
| 0 | 4 | Magic | `b"VARE"` |
| 4 | 1 | FormatVer | `0x01` |
| 5 | 8 | Sequence | `u64` little-endian |
| 13 | 32 | PrevL1Hash | `H_stream[n-1]` |
| 45 | 32 | L1Hash | `H_stream[n]` |
| 77 | 32 | L2Hash | `H_state` |
| 109 | 4 | PayloadLen | `u32` LE; `0` in snapshot mode |
| 113 | 32 | SHA-256(Payload) | `SHA-256(Payload)`; `SHA-256(b"")` in snapshot mode |
| 145 | 16 | SessionID | Session UUID — binds the signature to this session |
| **161** | — | **total** | |

The signature is computed with the enclave's ephemeral Ed25519 keypair
(generated fresh at session start; public key embedded in the Attestation Doc):

```
Signature = Ed25519_Sign(secret_key, msg_161)
```

The SessionID field (offset 145) prevents cross-session replay: a valid
signature from session A cannot be replayed as evidence for session B.

### 3.2 Snapshot Mode

The VAR HTTP gateway operates in **snapshot mode**: the full PTY stream is
captured in the L1 chain rather than attached as discrete payload bytes to
each packet.  In snapshot mode:

- `PayloadLen = 0`
- `SHA-256(Payload) = SHA-256(b"")` =
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

An auditor verifying a snapshot-mode packet MUST use `SHA-256(b"")` in the
161-byte message regardless of any payload bytes transmitted out-of-band.

---

## 4. Verification Requirements

The Auditor Client MUST perform the following steps in order.

### 4.1 Anchor Trust — Validate the Attestation Document

1. Parse the Attestation Doc as a COSE\_Sign1 structure (RFC 8152).
2. Verify the COSE signature using the **Nitro root CA certificate** (published
   by AWS at `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`).
3. Extract the `PCR0` field from the attested document and compare it against the
   expected SHA-384 measurement of the enclave image.
4. Extract the **public key** embedded in the `public_key` field of the attested
   document.  This is the Ed25519 public key that signed the evidence packets.

> **Simulation mode**: When `/dev/nsm` is absent, the enclave produces a
> 96-byte placeholder doc (`0xAA`-filled) and `PCR0 = 0xAA…AA`.  Evidence from
> simulation mode provides hash-chain integrity but no hardware attestation.

### 4.2 Reconstruct the Bootstrap Nonce

Independently recompute:

```
expected_nonce = SHA-256(AttestationDoc ‖ SessionID)
```

Assert `expected_nonce == bundle_header.BootstrapNonce`.  A mismatch means
the nonce was not derived from the presented attestation and session.

### 4.3 Check Chain Continuity

For each consecutive pair of packets `(n-1, n)`:

```
assert Packet[n].PrevL1Hash == Packet[n-1].L1Hash
```

`Packet[1].PrevL1Hash` MUST equal the Bootstrap Nonce.  Any gap indicates
that output was produced but not included in the evidence stream.

### 4.4 Verify Each Signature

For each packet, reconstruct the 161-byte message (§3.1) and verify:

```
Ed25519_Verify(public_key, msg_161, Packet[n].Signature)
```

A valid signature proves that the enclave holding the attested private key
produced this exact combination of (Sequence, PrevL1Hash, L1Hash, L2Hash,
PayloadLen, SessionID).

### 4.5 Replay Terminal State (Optional — L2 Verification)

Feed the raw Payload bytes (or the cumulative PTY stream reconstructed from
the L1 chain) into a VT-compatible parser (e.g., `ghostty-vt`) and compute
`H_state` over the resulting grid (§2.2).  Assert the computed hash matches
`Packet[n].L2Hash`.

This step confirms that the signed terminal state corresponds to the actual
visible output, not a hash of different content.

---

## 5. Sealed State (Hibernate / Resume)

To survive an enclave restart without losing session continuity, the runtime
can **seal** (hibernate) the in-memory state and **unseal** (resume) it on
the next boot.

### 5.1 Sealed Blob Wire Format

```
[sealed_dek_len : 4 bytes]   u32 LE — byte length of the wrapped DEK
[sealed_dek     : N bytes]   KMS ciphertext of the AES-256 DEK
[nonce          : 12 bytes]  AES-GCM nonce
[tag            : 16 bytes]  AES-GCM authentication tag
[ciphertext     : M bytes]   AES-256-GCM encryption of the serialised state
```

The serialised state includes: SessionID, L1 stream hash, previous stream hash,
sequence number, Ed25519 secret key, and vault entries.

### 5.2 DEK Wrapping — KMS Recipient Flow

The AES-256 DEK is wrapped by AWS KMS using the Nitro **recipient flow** so
the host-side proxy never receives the plaintext DEK:

1. The enclave generates an ephemeral RSA-2048 keypair per unseal.
2. The RSA public key (SubjectPublicKeyInfo DER) is embedded in the NSM
   attestation document (`public_key` field).
3. `kms:Decrypt` is called with `Recipient.AttestationDocument` set to the
   NSM-signed document.  KMS verifies the document's NSM signature, trusts the
   embedded RSA public key, and returns `CiphertextForRecipient` instead of
   `Plaintext`.
4. `CiphertextForRecipient` is a 256-byte RSAES-OAEP-SHA-256 block.  The
   enclave decrypts it with the ephemeral RSA private key to recover the 32-byte
   DEK.  The proxy sees only RSA-wrapped ciphertext.

The KMS CMK key policy MUST include a `kms:RecipientAttestation:PCR0`
condition restricting decryption to enclaves with the correct image hash.

---

## 6. KMS Recipient Flow — Security Properties

| Property | Guarantee |
| :--- | :--- |
| **Host isolation** | The host-side vsock proxy never receives the plaintext DEK; it forwards RSA-wrapped ciphertext it cannot decrypt. |
| **Ephemeral key** | The RSA keypair is generated fresh per unseal and discarded immediately after; no long-lived RSA material exists. |
| **Attestation binding** | KMS verifies the NSM signature before wrapping, ensuring only an enclave with the correct PCR0 can receive the DEK. |
| **Session binding** | The Ed25519 keypair restored from the sealed state allows the resumed session to continue signing evidence with the same public key that was attested at session start. |
