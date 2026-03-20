# Specification: VAR Evidence Bundle (v1.1)

This document defines the cryptographic wire format and hashing logic for the Verifiable Agent Runtime (VAR). It serves as the formal technical contract between the VAR Enclave and the Auditor Client.

## 1. Session Lifecycle

### 1.1 Bundle Header

A VAR session evidence file/stream begins with a one-time Bundle Header. This provides the root of trust and initial parameters for the auditor.

| Field | Type | Description |
| :--- | :--- | :--- |
| **Magic** | `[4]u8` | Constant `0x56415242` ("VARB") |
| **Version** | `u8` | Bundle format version (Current: `0x01`). |
| **Session ID** | `[16]u8` | Unique UUID v4 for the session. |
| **Bootstrap Nonce** | `[32]u8` | `SHA-256(attestation_doc || session_id)`. |
| **Attestation Len** | `u32` | Length of the Attestation Document. |
| **Attestation Doc** | `[]u8` | The hardware-signed Attestation Quote. |

### 1.2 Bootstrap Nonce

The hash chain is anchored to the specific session by the **Bootstrap Nonce**, derived inside the enclave as:
`H_stream[0] = SHA-256(AttestationDoc || SessionID)`

## 2. Hashing Logic

### 2.1 Stream Hash (L1)

The stream hash (L1) provides a sequential digest of the raw PTY byte stream.

```text
H_stream[n] = SHA-256(H_stream[n-1] || data_chunk[n])
```

### 2.2 State Hash (L2)

The state hash (L2) captures the visual representation of the terminal at the end of the current packet.

```text
H_state = SHA-256(
    format_version ||
    cursor_x || cursor_y ||
    terminal_width || terminal_height ||
    cell_digest
)
```

#### 2.2.1 Cell Digest Serialization

The `cell_digest` MUST be calculated using a **Top-to-Bottom, Left-to-Right** (Row-Major) traversal of the terminal buffer.

For each cell in the grid:
```text
digest_input += cell.codepoint_utf8     // UTF-8 encoded into a zero-initialized [4]u8 (left-aligned, not UTF-32)
digest_input += cell.fg_color_rgb       // R, G, B (3 bytes)
digest_input += cell.bg_color_rgb       // R, G, B (3 bytes)
digest_input += cell.attrs_u8           // 1 byte bitmask
```

#### 2.2.2 Attribute Bitmask (attrs_u8)

The 8-bit attribute mask is defined as follows:
- **Bit 0**: Bold
- **Bit 1**: Italic
- **Bit 2**: Faint
- **Bit 3**: Blink
- **Bit 4**: Reverse (Inverse)
- **Bit 5**: Invisible
- **Bit 6**: Strikethrough
- **Bit 7**: Underline

## 3. Evidence Packet Format

Evidence is emitted as a sequence of signed packets.

| Field | Type | Description |
| :--- | :--- | :--- |
| **Magic** | `u32` | Constant `0x56415245` ("VARE") |
| **Format Ver** | `u8` | Packet format version (Current: `0x01`). |
| **Sequence** | `u64` | Monotonically increasing index (starts at 1). |
| **Prev L1 Hash** | `[32]u8` | `H_stream[n-1]`. Used for gap detection. |
| **L1 Hash** | `[32]u8` | `H_stream[n]`. |
| **L2 Hash** | `[32]u8` | `H_state`. |
| **Payload Len** | `u32` | Length of raw terminal data. |
| **Payload** | `[]u8` | The raw terminal data bytes. |
| **Signature** | `[64]u8` | TEE-identity signature (see 3.1). |

### 3.1 Signature Scope

To ensure payload integrity, the signature covers the header fields and a hash of the payload:

`Signature = TEE_Sign(Magic || FormatVer || Sequence || PrevL1Hash || L1Hash || L2Hash || PayloadLen || SHA-256(Payload))`

## 4. Verification Requirements

The Auditor Client MUST:
1. **Anchor Trust**: Validate the Attestation Doc and extract the TEE's Public Key.
2. **Reconstruct Nonce**: Verify the Bootstrap Nonce matches the Attestation Doc and Session ID.
3. **Check Continuity**: Ensure `Packet[n].PrevL1Hash == Packet[n-1].L1Hash`.
4. **Replay & Compare**: Feed the Payload into a compliant VT parser (e.g., ghostty-vt) and assert that the resulting UI state matches the signed **L2 Hash**.
