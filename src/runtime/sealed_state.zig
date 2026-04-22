/// sealed_state.zig — Hibernate/resume support for the Verifiable Agent Runtime.
///
/// Problem: every enclave restart wipes the in-memory vault, hash chain, and
/// signing keypair, breaking session continuity.
///
/// Solution: "sealing" — the enclave serializes its runtime state, encrypts it
/// with AES-256-GCM using a random Data Encryption Key (DEK), then wraps the DEK
/// so that only an enclave running the same binary can unwrap it.
///
/// DEK wrapping strategy:
///   Simulation (no /dev/nsm): XOR with a fixed mock wrapping key.
///     Intent: exercises the full pipeline without real hardware.
///     Security: none — dev/test only.
///   Production (real Nitro):  kms:Encrypt (seal) / kms:Decrypt (unseal) via a
///     host-side vsock proxy (CID 2, port VAR_KMS_PROXY_PORT, default 8443).
///     The CMK key policy restricts kms:Decrypt to enclaves whose PCR0 matches
///     the known-good image.  Set VAR_KMS_KEY_ARN to the CMK ARN before launch.
///     Unseal uses the Nitro recipient flow (kmsDecryptWithRecipient): an
///     ephemeral RSA-2048 keypair is generated per-unseal, the public key is
///     bound into the NSM attestation document, and KMS returns the DEK RSA-
///     wrapped rather than in plaintext — the proxy never sees the DEK.
///
/// Sealed blob wire format (binary, then hex-encoded for the line protocol):
///   [sealed_dek_len : 4 bytes]   u32 LE — byte length of the wrapped key
///   [sealed_dek     : N bytes]   wrapped AES-256 key (32 bytes in sim; KMS ciphertext in prod)
///   [nonce          : 12 bytes]  AES-GCM nonce
///   [tag            : 16 bytes]  AES-GCM authentication tag
///   [ciphertext     : M bytes]   AES-256-GCM ciphertext of the serialized state
///
/// Serialized plaintext format (version 0x02):
///   [magic           : 4 ]  "VARS"
///   [version         : 1 ]  0x02
///   [session_id      : 16]  UUID v4
///   [stream_hash     : 32]  current L1 hash chain tip (spec §2.1)
///   [prev_hash       : 32]  L1 hash at last evidence emission
///   [sequence        : 8 ]  u64 LE — next sequence number on resume
///   [bootstrap_nonce : 32]  SHA-256(AttestationDoc || SessionID) — chain anchor
///   [vault_count     : 4 ]  u32 LE
///   [exec_count      : 4 ]  u32 LE
///   per vault entry:
///     [key_len    : 2 ]  u16 LE
///     [key        : key_len]
///     [val_len    : 2 ]  u16 LE
///     [val        : val_len]
///   per exec entry:
///     [cmd_len    : 2 ]  u16 LE
///     [cmd        : cmd_len]
///     [stdout_hash: 32]
///     [stderr_hash: 32]
///     [exit_code  : 1 ]
///     [seq        : 8 ]  u64 LE
///
/// The Ed25519 signing keypair is NOT persisted.  Each resumed session segment
/// generates a fresh keypair whose public key is bound into the new attestation
/// quote.  Verifiers must accept different public keys for different session
/// segments of the same SessionID.
///
/// Note on terminal state (L2): the VerifiableTerminal grid is NOT persisted.
/// On resume the grid starts empty.  The L1 stream_hash already encodes the
/// complete output history, so the evidence chain remains intact; the L2 state
/// hash in subsequent bundles will simply reflect a fresh terminal.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const SecureVault = @import("vault.zig").SecureVault;
const shell = @import("shell.zig");
const SecureLogger = shell.SecureLogger;
const ExecRecord = shell.ExecRecord;
const VsockHandler = @import("vsock.zig").VsockHandler;

// ---------------------------------------------------------------------------
// Wire-format constants
// ---------------------------------------------------------------------------

const MAGIC = [4]u8{ 'V', 'A', 'R', 'S' };
const FORMAT_VERSION: u8 = 0x02;

/// Minimum plaintext size: magic(4) + version(1) + session_id(16) +
/// stream_hash(32) + prev_hash(32) + sequence(8) + bootstrap_nonce(32) +
/// vault_count(4) + exec_count(4) = 133
const MIN_PLAINTEXT: usize = 133;

/// Minimum and maximum byte lengths for the wrapped DEK field.
/// Simulation (XOR): exactly 32 bytes.
/// Production (KMS): ciphertext varies by key type; cap at 1 KiB to prevent OOM.
const MIN_SEALED_DEK_LEN: usize = 32;
const MAX_SEALED_DEK_LEN: usize = 1024;

/// Minimum sealed blob size: sealed_dek_len(4) + min_sealed_dek(32) + nonce(12) + tag(16) = 64
const MIN_BLOB: usize = 4 + MIN_SEALED_DEK_LEN + 12 + 16;

// ---------------------------------------------------------------------------
// Captured runtime state
// ---------------------------------------------------------------------------

/// All mutable runtime state required to resume a hibernated session.
/// Produced by capture(); consumed by restoreVault() / restoreLogger().
/// Must be freed via deinit() when done.
pub const CapturedState = struct {
    allocator: std.mem.Allocator,
    session_id: [16]u8,
    stream_hash: [32]u8,
    prev_stream_hash: [32]u8,
    sequence: u64,
    /// Bootstrap nonce anchoring the L1 chain to the original session attestation.
    /// Preserved so the resumed session's BUNDLE_HEADER carries the same nonce,
    /// allowing an auditor to verify chain continuity across the hibernate boundary.
    bootstrap_nonce: [32]u8,
    vault_entries: []VaultEntry,
    exec_entries: []ExecEntry,

    pub const VaultEntry = struct {
        key: []const u8,
        value: []const u8,
    };

    /// Flat snapshot of an execution record for serialization.
    /// Mirrors ExecRecord but owned by the CapturedState allocator.
    pub const ExecEntry = struct {
        cmd: []u8,
        stdout_hash: [32]u8,
        stderr_hash: [32]u8,
        exit_code: u8,
        seq: u64,
    };

    pub fn deinit(self: *CapturedState) void {
        for (self.vault_entries) |e| {
            std.crypto.secureZero(u8, @constCast(e.key));
            std.crypto.secureZero(u8, @constCast(e.value));
            self.allocator.free(e.key);
            self.allocator.free(e.value);
        }
        self.allocator.free(self.vault_entries);
        for (self.exec_entries) |e| {
            std.crypto.secureZero(u8, e.cmd);
            self.allocator.free(e.cmd);
        }
        self.allocator.free(self.exec_entries);
    }
};

// ---------------------------------------------------------------------------
// Capture and restore
// ---------------------------------------------------------------------------

/// Snapshot all mutable runtime state from vault and logger.
/// Logger state (scalars + exec entries) is captured under a single mutex
/// acquisition for consistency.  Vault state is captured under a separate
/// acquisition — the two locks are never held simultaneously to prevent
/// deadlocks with concurrent callers.
/// Caller must call CapturedState.deinit() when done.
pub fn capture(
    allocator: std.mem.Allocator,
    vault: *SecureVault,
    logger: *SecureLogger,
) !CapturedState {
    // Snapshot all logger scalar fields and exec entries under a single mutex
    // acquisition so the captured state is internally consistent.  The previous
    // approach used five separate lock/unlock cycles for scalar fields, allowing
    // concurrent runAndLog or getEvidenceBundleJson calls to modify stream_hash,
    // sequence, or executions between reads — producing a snapshot where fields
    // belong to different points in time.
    var session_id: [16]u8 = undefined;
    var stream_hash: [32]u8 = undefined;
    var prev_stream_hash: [32]u8 = undefined;
    var sequence: u64 = 0;
    var bootstrap_nonce: [32]u8 = undefined;

    const exec_entries = blk: {
        logger.mutex.lock();
        defer logger.mutex.unlock();

        session_id       = logger.session_id;
        stream_hash      = logger.stream_hash;
        prev_stream_hash = logger.prev_stream_hash;
        sequence         = logger.sequence;
        bootstrap_nonce  = logger.bootstrap_nonce;
        const n = logger.executions.items.len;
        const buf = try allocator.alloc(CapturedState.ExecEntry, n);
        var init_count: usize = 0;
        errdefer {
            for (buf[0..init_count]) |e| allocator.free(e.cmd);
            allocator.free(buf);
        }
        for (logger.executions.items, 0..) |rec, i| {
            buf[i] = .{
                .cmd = try allocator.dupe(u8, rec.cmd),
                .stdout_hash = rec.stdout_hash,
                .stderr_hash = rec.stderr_hash,
                .exit_code = rec.exit_code,
                .seq = rec.seq,
            };
            init_count = i + 1;
        }
        break :blk buf;
    };
    errdefer {
        for (exec_entries) |e| {
            std.crypto.secureZero(u8, e.cmd);
            allocator.free(e.cmd);
        }
        allocator.free(exec_entries);
    }

    // Snapshot vault entries.
    const vault_entries = blk: {
        vault.mutex.lock();
        defer vault.mutex.unlock();

        const n = vault.secrets.count();
        const buf = try allocator.alloc(CapturedState.VaultEntry, n);
        errdefer allocator.free(buf);

        var it = vault.secrets.iterator();
        var i: usize = 0;
        while (it.next()) |kv| : (i += 1) {
            const k = try allocator.dupe(u8, kv.key_ptr.*);
            errdefer allocator.free(k);
            const v = try allocator.dupe(u8, kv.value_ptr.*);
            buf[i] = .{ .key = k, .value = v };
        }
        break :blk buf;
    };

    return CapturedState{
        .allocator = allocator,
        .session_id = session_id,
        .stream_hash = stream_hash,
        .prev_stream_hash = prev_stream_hash,
        .sequence = sequence,
        .bootstrap_nonce = bootstrap_nonce,
        .vault_entries = vault_entries,
        .exec_entries = exec_entries,
    };
}

/// Restore vault from a previously captured state.
/// All existing vault entries are wiped and replaced.
pub fn restoreVault(state: *const CapturedState, vault: *SecureVault) !void {
    vault.mutex.lock();
    defer vault.mutex.unlock();

    // Wipe and free all existing entries before repopulating.
    var it = vault.secrets.iterator();
    while (it.next()) |entry| {
        std.crypto.secureZero(u8, @constCast(entry.key_ptr.*));
        std.crypto.secureZero(u8, @constCast(entry.value_ptr.*));
        vault.allocator.free(entry.key_ptr.*);
        vault.allocator.free(entry.value_ptr.*);
    }
    vault.secrets.clearRetainingCapacity();

    for (state.vault_entries) |e| {
        const k = try vault.allocator.dupe(u8, e.key);
        errdefer vault.allocator.free(k);
        const v = try vault.allocator.dupe(u8, e.value);
        errdefer vault.allocator.free(v);
        try vault.secrets.put(k, v);
    }
}

/// Restore logger hash-chain state from a previously captured state.
/// The signing keypair is NOT restored — each resumed session segment generates
/// a fresh keypair bound to a new attestation quote (see module doc comment).
/// The VerifiableTerminal grid is reset to empty — see module doc comment.
pub fn restoreLogger(state: *const CapturedState, logger: *SecureLogger) !void {
    logger.mutex.lock();
    defer logger.mutex.unlock();

    logger.session_id = state.session_id;
    logger.stream_hash = state.stream_hash;
    logger.prev_stream_hash = state.prev_stream_hash;
    logger.sequence = state.sequence;
    logger.bootstrap_nonce = state.bootstrap_nonce;

    // Restore the ordered execution audit log.
    // The logger was freshly created at startup, so executions will be empty;
    // we clear it anyway for safety.
    for (logger.executions.items) |rec| rec.deinit(logger.allocator);
    logger.executions.clearRetainingCapacity();

    for (state.exec_entries) |e| {
        const cmd = try logger.allocator.dupe(u8, e.cmd);
        errdefer logger.allocator.free(cmd);
        try logger.executions.append(logger.allocator, ExecRecord{
            .cmd = cmd,
            .stdout_hash = e.stdout_hash,
            .stderr_hash = e.stderr_hash,
            .exit_code = e.exit_code,
            .seq = e.seq,
        });
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

fn serialize(allocator: std.mem.Allocator, state: *const CapturedState) ![]u8 {
    // Pre-compute total size.
    var size: usize = MIN_PLAINTEXT;
    for (state.vault_entries) |e| {
        size += 2 + e.key.len + 2 + e.value.len;
    }
    for (state.exec_entries) |e| {
        size += 2 + e.cmd.len + 32 + 32 + 1 + 8;
    }

    const buf = try allocator.alloc(u8, size);
    var pos: usize = 0;

    @memcpy(buf[pos..][0..4], &MAGIC);                                pos += 4;
    buf[pos] = FORMAT_VERSION;                                         pos += 1;
    @memcpy(buf[pos..][0..16], &state.session_id);                    pos += 16;
    @memcpy(buf[pos..][0..32], &state.stream_hash);                   pos += 32;
    @memcpy(buf[pos..][0..32], &state.prev_stream_hash);              pos += 32;
    std.mem.writeInt(u64, buf[pos..][0..8], state.sequence, .little);  pos += 8;
    @memcpy(buf[pos..][0..32], &state.bootstrap_nonce);               pos += 32;

    std.mem.writeInt(u32, buf[pos..][0..4], @intCast(state.vault_entries.len), .little);
    pos += 4;
    std.mem.writeInt(u32, buf[pos..][0..4], @intCast(state.exec_entries.len), .little);
    pos += 4;

    for (state.vault_entries) |e| {
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(e.key.len), .little);   pos += 2;
        @memcpy(buf[pos..][0..e.key.len], e.key);                                 pos += e.key.len;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(e.value.len), .little); pos += 2;
        @memcpy(buf[pos..][0..e.value.len], e.value);                             pos += e.value.len;
    }

    for (state.exec_entries) |e| {
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(e.cmd.len), .little);   pos += 2;
        @memcpy(buf[pos..][0..e.cmd.len], e.cmd);                                 pos += e.cmd.len;
        @memcpy(buf[pos..][0..32], &e.stdout_hash);                               pos += 32;
        @memcpy(buf[pos..][0..32], &e.stderr_hash);                               pos += 32;
        buf[pos] = e.exit_code;                                                    pos += 1;
        std.mem.writeInt(u64, buf[pos..][0..8], e.seq, .little);                  pos += 8;
    }

    std.debug.assert(pos == size);
    return buf;
}

fn deserialize(allocator: std.mem.Allocator, buf: []const u8) !CapturedState {
    if (buf.len < MIN_PLAINTEXT) return error.TruncatedState;

    var pos: usize = 0;

    if (!std.mem.eql(u8, buf[pos..][0..4], &MAGIC)) return error.InvalidMagic;
    pos += 4;
    if (buf[pos] != FORMAT_VERSION) return error.UnsupportedVersion;
    pos += 1;

    var session_id: [16]u8 = undefined;
    @memcpy(&session_id, buf[pos..][0..16]);
    pos += 16;

    var stream_hash: [32]u8 = undefined;
    @memcpy(&stream_hash, buf[pos..][0..32]);
    pos += 32;

    var prev_stream_hash: [32]u8 = undefined;
    @memcpy(&prev_stream_hash, buf[pos..][0..32]);
    pos += 32;

    const sequence = std.mem.readInt(u64, buf[pos..][0..8], .little);
    pos += 8;

    var bootstrap_nonce: [32]u8 = undefined;
    @memcpy(&bootstrap_nonce, buf[pos..][0..32]);
    pos += 32;

    const vault_count = std.mem.readInt(u32, buf[pos..][0..4], .little);
    pos += 4;
    const exec_count = std.mem.readInt(u32, buf[pos..][0..4], .little);
    pos += 4;

    // Cap counts to prevent OOM from a corrupt blob.
    if (vault_count > 4096) return error.VaultCountTooLarge;
    if (exec_count > 65536) return error.ExecCountTooLarge;

    const vault_entries = try allocator.alloc(CapturedState.VaultEntry, vault_count);
    var vault_init: usize = 0;
    errdefer {
        for (vault_entries[0..vault_init]) |e| {
            allocator.free(e.key);
            allocator.free(e.value);
        }
        allocator.free(vault_entries);
    }

    for (0..vault_count) |i| {
        if (pos + 2 > buf.len) return error.TruncatedState;
        const key_len = std.mem.readInt(u16, buf[pos..][0..2], .little);
        pos += 2;
        if (pos + key_len > buf.len) return error.TruncatedState;
        const key = try allocator.dupe(u8, buf[pos..][0..key_len]);
        pos += key_len;

        if (pos + 2 > buf.len) { allocator.free(key); return error.TruncatedState; }
        const val_len = std.mem.readInt(u16, buf[pos..][0..2], .little);
        pos += 2;
        if (pos + val_len > buf.len) { allocator.free(key); return error.TruncatedState; }
        const value = try allocator.dupe(u8, buf[pos..][0..val_len]);
        pos += val_len;

        vault_entries[i] = .{ .key = key, .value = value };
        vault_init = i + 1;
    }

    const exec_entries = try allocator.alloc(CapturedState.ExecEntry, exec_count);
    var exec_init: usize = 0;
    errdefer {
        for (exec_entries[0..exec_init]) |e| allocator.free(e.cmd);
        allocator.free(exec_entries);
    }

    for (0..exec_count) |i| {
        if (pos + 2 > buf.len) return error.TruncatedState;
        const cmd_len = std.mem.readInt(u16, buf[pos..][0..2], .little);
        pos += 2;
        if (pos + cmd_len > buf.len) return error.TruncatedState;
        const cmd = try allocator.dupe(u8, buf[pos..][0..cmd_len]);
        pos += cmd_len;

        if (pos + 32 + 32 + 1 + 8 > buf.len) { allocator.free(cmd); return error.TruncatedState; }
        var stdout_hash: [32]u8 = undefined;
        @memcpy(&stdout_hash, buf[pos..][0..32]); pos += 32;
        var stderr_hash: [32]u8 = undefined;
        @memcpy(&stderr_hash, buf[pos..][0..32]); pos += 32;
        const exit_code = buf[pos]; pos += 1;
        const seq = std.mem.readInt(u64, buf[pos..][0..8], .little); pos += 8;

        exec_entries[i] = .{
            .cmd = cmd,
            .stdout_hash = stdout_hash,
            .stderr_hash = stderr_hash,
            .exit_code = exit_code,
            .seq = seq,
        };
        exec_init = i + 1;
    }

    return CapturedState{
        .allocator = allocator,
        .session_id = session_id,
        .stream_hash = stream_hash,
        .prev_stream_hash = prev_stream_hash,
        .sequence = sequence,
        .bootstrap_nonce = bootstrap_nonce,
        .vault_entries = vault_entries,
        .exec_entries = exec_entries,
    };
}

// ---------------------------------------------------------------------------
// DEK wrapping
// ---------------------------------------------------------------------------

/// Simulation-only mock wrapping key.  The ASCII value spells "var-mock-wrap-key-dev-only-not-p"
/// to make its purpose obvious in a hex dump.  Never used on real Nitro hardware.
const MOCK_WRAP_KEY = [32]u8{
    'v', 'a', 'r', '-', 'm', 'o', 'c', 'k',
    '-', 'w', 'r', 'a', 'p', '-', 'k', 'e',
    'y', '-', 'd', 'e', 'v', '-', 'o', 'n',
    'l', 'y', '-', 'n', 'o', 't', '-', 'p',
};

/// Default vsock port where the host-side KMS forwarding proxy listens.
/// Override with the VAR_KMS_PROXY_PORT environment variable.
const KMS_PROXY_PORT_DEFAULT: u16 = 8443;

fn hasNsmDevice() bool {
    const f = std.fs.openFileAbsolute("/dev/nsm", .{ .mode = .read_write }) catch return false;
    f.close();
    return true;
}

// ---------------------------------------------------------------------------
// KMS helpers (production path)
//
// The enclave has no direct internet access.  The host-side VAR proxy bridges
// vsock → HTTPS to kms.<region>.amazonaws.com and signs requests with the EC2
// instance role credentials (IAM role attached to the parent instance).
//
// Seal flow:   enclave  →  proxy  →  kms:Encrypt  →  KMS ciphertext returned
// Unseal flow: enclave  →  proxy  →  kms:Decrypt (with Recipient field)
//              KMS returns CiphertextForRecipient (RSA-OAEP-SHA256 wrapped DEK)
//              Enclave RSA-unwraps with ephemeral private key → plaintext DEK
//              The proxy never sees plaintext key material.
//
// Key policy on the CMK restricts kms:Decrypt to callers presenting a valid
// Nitro attestation document whose PCR0 matches the known-good enclave image:
//
//   "Condition": {
//     "StringEqualsIgnoreCase": {
//       "kms:RecipientAttestation:PCR0": "<sha384_hex_of_enclave_image>"
//     }
//   }
// ---------------------------------------------------------------------------

/// Extracts a JSON string value for `key` from a flat JSON object.
/// Returns a heap-allocated copy; caller must free.  Returns null on any error.
fn jsonExtractString(allocator: std.mem.Allocator, json: []const u8, key: []const u8) !?[]u8 {
    var search_buf: [128]u8 = undefined;
    const pattern = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{key}) catch return null;
    const key_pos = std.mem.indexOf(u8, json, pattern) orelse return null;
    var rest = json[key_pos + pattern.len ..];
    rest = std.mem.trimLeft(u8, rest, " \t\r\n");
    if (rest.len == 0 or rest[0] != ':') return null;
    rest = std.mem.trimLeft(u8, rest[1..], " \t\r\n");
    if (rest.len == 0 or rest[0] != '"') return null;
    rest = rest[1..]; // skip opening quote
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    return try allocator.dupe(u8, rest[0..end]);
}

/// Posts a JSON body to the KMS proxy and returns the raw response body.
/// Caller owns the returned slice.
fn kmsHttpPost(
    allocator: std.mem.Allocator,
    proxy_port: u16,
    action: []const u8,
    body: []const u8,
) ![]u8 {
    var conn = try VsockHandler.connect(allocator, VsockHandler.VMADDR_CID_HOST, proxy_port);
    defer conn.close();

    const request = try std.fmt.allocPrint(
        allocator,
        "POST / HTTP/1.0\r\n" ++
            "Content-Type: application/x-amz-json-1.1\r\n" ++
            "X-Amz-Target: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n" ++
            "{s}",
        .{ action, body.len, body },
    );
    defer allocator.free(request);

    _ = try conn.send(request);

    // Read the full response (proxy closes the connection after sending).
    var resp_buf = try allocator.alloc(u8, 32768);
    defer allocator.free(resp_buf);
    var total: usize = 0;
    while (total < resp_buf.len) {
        const n = conn.receive(resp_buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }

    // Check HTTP status (must be 2xx).
    if (total < 12) return error.KmsEmptyResponse;
    if (!std.mem.startsWith(u8, resp_buf[0..total], "HTTP/1.") or resp_buf[9] != '2')
        return error.KmsRequestFailed;

    // Locate and return the response body (after the blank header line).
    const sep = std.mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n") orelse
        return error.KmsInvalidResponse;
    return try allocator.dupe(u8, resp_buf[sep + 4 .. total]);
}

/// Calls kms:Encrypt and returns the KMS ciphertext blob.
/// Caller owns the returned slice.
fn kmsEncrypt(
    allocator: std.mem.Allocator,
    key_arn: []const u8,
    proxy_port: u16,
    plaintext: []const u8,
) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const b64_pt_len = enc.calcSize(plaintext.len);
    const b64_pt_buf = try allocator.alloc(u8, b64_pt_len);
    defer allocator.free(b64_pt_buf);
    const b64_pt = enc.encode(b64_pt_buf, plaintext);

    const req_body = try std.fmt.allocPrint(
        allocator,
        "{{\"KeyId\":\"{s}\",\"Plaintext\":\"{s}\"}}",
        .{ key_arn, b64_pt },
    );
    defer allocator.free(req_body);

    const resp_body = try kmsHttpPost(allocator, proxy_port, "TrentService.Encrypt", req_body);
    defer allocator.free(resp_body);

    const b64_ct = (try jsonExtractString(allocator, resp_body, "CiphertextBlob")) orelse
        return error.KmsNoCiphertextBlob;
    defer allocator.free(b64_ct);

    const dec = std.base64.standard.Decoder;
    const ct_len = try dec.calcSizeForSlice(b64_ct);
    const ct = try allocator.alloc(u8, ct_len);
    try dec.decode(ct, b64_ct);
    return ct;
}

/// Calls kms:Decrypt and returns the 32-byte plaintext DEK.
fn kmsDecrypt(
    allocator: std.mem.Allocator,
    proxy_port: u16,
    ciphertext_blob: []const u8,
) ![32]u8 {
    const enc = std.base64.standard.Encoder;
    const b64_ct_len = enc.calcSize(ciphertext_blob.len);
    const b64_ct_buf = try allocator.alloc(u8, b64_ct_len);
    defer allocator.free(b64_ct_buf);
    const b64_ct = enc.encode(b64_ct_buf, ciphertext_blob);

    const req_body = try std.fmt.allocPrint(
        allocator,
        "{{\"CiphertextBlob\":\"{s}\"}}",
        .{b64_ct},
    );
    defer allocator.free(req_body);

    const resp_body = try kmsHttpPost(allocator, proxy_port, "TrentService.Decrypt", req_body);
    defer allocator.free(resp_body);

    const b64_pt = (try jsonExtractString(allocator, resp_body, "Plaintext")) orelse
        return error.KmsNoPlaintext;
    defer allocator.free(b64_pt);

    const dec = std.base64.standard.Decoder;
    const pt_len = try dec.calcSizeForSlice(b64_pt);
    if (pt_len != 32) return error.KmsUnexpectedPlaintextLength;
    var dek: [32]u8 = undefined;
    try dec.decode(&dek, b64_pt);
    return dek;
}

/// Returns the KMS proxy port from the environment, or the default.
fn kmsProxyPort() u16 {
    const s = std.posix.getenv("VAR_KMS_PROXY_PORT") orelse return KMS_PROXY_PORT_DEFAULT;
    return std.fmt.parseInt(u16, s, 10) catch KMS_PROXY_PORT_DEFAULT;
}

/// Wraps (seals) a 32-byte AES-256 DEK.
/// On real Nitro hardware: calls kms:Encrypt via the host proxy.
/// In simulation: XOR with the mock wrapping key (dev/test only, no security).
/// Caller owns the returned slice.
fn sealDek(allocator: std.mem.Allocator, dek: [32]u8) ![]u8 {
    if (hasNsmDevice()) {
        const key_arn = std.posix.getenv("VAR_KMS_KEY_ARN") orelse return error.KmsKeyArnNotSet;
        return kmsEncrypt(allocator, key_arn, kmsProxyPort(), &dek);
    }
    // Simulation: one-time-pad style XOR with the mock wrapping key.
    const out = try allocator.alloc(u8, 32);
    for (dek, 0..) |b, i| out[i] = b ^ MOCK_WRAP_KEY[i];
    return out;
}

/// Calls kms:Decrypt using the Nitro recipient flow so the proxy never sees
/// the plaintext DEK.
///
/// Steps:
///   1. Generate an ephemeral RSA-2048 keypair (fresh per unseal).
///   2. Request an NSM attestation document with the RSA public key (SPKI DER)
///      embedded — NSM signs it, binding the key to the enclave's PCR values.
///   3. POST TrentService.Decrypt with a Recipient field:
///        { "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
///          "AttestationDocument": "<base64(nsm_doc)>" }
///      KMS verifies the NSM signature, trusts the embedded public key, and
///      returns CiphertextForRecipient instead of Plaintext.
///   4. Base64-decode CiphertextForRecipient (256-byte RSA-2048 block).
///   5. RSA-OAEP-SHA256 decrypt with the ephemeral private key → 32-byte DEK.
fn kmsDecryptWithRecipient(
    allocator: std.mem.Allocator,
    proxy_port: u16,
    ciphertext_blob: []const u8,
) ![32]u8 {
    const nsm = @import("nsm.zig");
    const rsa = @import("rsa_recipient.zig");

    // 1. Ephemeral RSA-2048 keypair — private key never leaves the enclave.
    var kp = try rsa.generateKeyPair(allocator);
    defer kp.deinit(allocator);

    // 2. NSM attestation doc with RSA public key (SPKI DER) bound in.
    const attest_doc = try nsm.getAttestationDoc(allocator, null, kp.pub_key_der);
    defer allocator.free(attest_doc);

    // 3. Build the kms:Decrypt request body.
    const enc = std.base64.standard.Encoder;

    const b64_ct_len = enc.calcSize(ciphertext_blob.len);
    const b64_ct_buf = try allocator.alloc(u8, b64_ct_len);
    defer allocator.free(b64_ct_buf);
    const b64_ct = enc.encode(b64_ct_buf, ciphertext_blob);

    const b64_doc_len = enc.calcSize(attest_doc.len);
    const b64_doc_buf = try allocator.alloc(u8, b64_doc_len);
    defer allocator.free(b64_doc_buf);
    const b64_doc = enc.encode(b64_doc_buf, attest_doc);

    const req_body = try std.fmt.allocPrint(
        allocator,
        "{{\"CiphertextBlob\":\"{s}\"," ++
            "\"Recipient\":{{\"KeyEncryptionAlgorithm\":\"RSAES_OAEP_SHA_256\"," ++
            "\"AttestationDocument\":\"{s}\"}}}}",
        .{ b64_ct, b64_doc },
    );
    defer allocator.free(req_body);

    const resp_body = try kmsHttpPost(allocator, proxy_port, "TrentService.Decrypt", req_body);
    defer allocator.free(resp_body);

    // 4. Extract CiphertextForRecipient (256-byte RSA-2048 block, base64-encoded).
    const b64_wrapped = (try jsonExtractString(allocator, resp_body, "CiphertextForRecipient")) orelse
        return error.KmsNoCiphertextForRecipient;
    defer allocator.free(b64_wrapped);

    const dec = std.base64.standard.Decoder;
    const wrapped_len = try dec.calcSizeForSlice(b64_wrapped);
    if (wrapped_len != 256) return error.KmsUnexpectedWrappedDekLength;
    var wrapped: [256]u8 = undefined;
    try dec.decode(&wrapped, b64_wrapped);
    defer std.crypto.secureZero(u8, &wrapped);

    // 5. RSA-OAEP-SHA256 unwrap → 32-byte plaintext DEK.
    return rsa.unwrapDek(&kp, &wrapped);
}

/// Unwraps a sealed DEK produced by sealDek().
/// On real Nitro hardware: uses the recipient flow (kmsDecryptWithRecipient)
/// so the proxy never receives the plaintext DEK.
/// In simulation: XOR with the mock wrapping key.
fn unsealDek(allocator: std.mem.Allocator, sealed: []const u8) ![32]u8 {
    if (hasNsmDevice()) {
        return kmsDecryptWithRecipient(allocator, kmsProxyPort(), sealed);
    }
    if (sealed.len != 32) return error.InvalidSealedDekLength;
    var dek: [32]u8 = undefined;
    for (sealed, 0..) |b, i| dek[i] = b ^ MOCK_WRAP_KEY[i];
    return dek;
}

// ---------------------------------------------------------------------------
// Public seal / unseal
// ---------------------------------------------------------------------------

/// Encrypts and seals CapturedState into an opaque binary blob.
/// Caller owns the returned slice (free with allocator.free).
pub fn seal(allocator: std.mem.Allocator, state: *const CapturedState) ![]u8 {
    const plaintext = try serialize(allocator, state);
    defer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }

    var dek: [Aes256Gcm.key_length]u8 = undefined;
    var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&dek);
    std.crypto.random.bytes(&nonce);
    defer std.crypto.secureZero(u8, &dek);

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(ciphertext);
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    Aes256Gcm.encrypt(ciphertext, &tag, plaintext, "", nonce, dek);

    const sealed_dek = try sealDek(allocator, dek);
    defer allocator.free(sealed_dek);

    // Layout: sealed_dek_len(4) || sealed_dek(N) || nonce(12) || tag(16) || ciphertext(M)
    const blob = try allocator.alloc(u8, 4 + sealed_dek.len + 12 + 16 + ciphertext.len);
    var pos: usize = 0;
    std.mem.writeInt(u32, blob[pos..][0..4], @intCast(sealed_dek.len), .little); pos += 4;
    @memcpy(blob[pos..][0..sealed_dek.len], sealed_dek);                          pos += sealed_dek.len;
    @memcpy(blob[pos..][0..12], &nonce);                                           pos += 12;
    @memcpy(blob[pos..][0..16], &tag);                                             pos += 16;
    @memcpy(blob[pos..][0..ciphertext.len], ciphertext);

    return blob;
}

/// Decrypts and deserializes a blob produced by seal().
/// Caller owns the returned CapturedState (call deinit when done).
pub fn unseal(allocator: std.mem.Allocator, blob: []const u8) !CapturedState {
    if (blob.len < MIN_BLOB) return error.BlobTooShort;

    var pos: usize = 0;
    const sealed_dek_len = std.mem.readInt(u32, blob[pos..][0..4], .little); pos += 4;
    if (sealed_dek_len < MIN_SEALED_DEK_LEN) return error.SealedDekTooShort;
    if (sealed_dek_len > MAX_SEALED_DEK_LEN) return error.SealedDekTooLarge;
    if (pos + sealed_dek_len + 12 + 16 > blob.len) return error.BlobTooShort;
    const sealed_dek = blob[pos..][0..sealed_dek_len]; pos += sealed_dek_len;
    const nonce      = blob[pos..][0..12];              pos += 12;
    const tag        = blob[pos..][0..16];              pos += 16;
    const ciphertext = blob[pos..];

    const dek = try unsealDek(allocator, sealed_dek);
    defer std.crypto.secureZero(u8, @constCast(&dek));

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    defer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }

    Aes256Gcm.decrypt(plaintext, ciphertext, tag.*, "", nonce.*, dek) catch
        return error.DecryptionFailed;

    return deserialize(allocator, plaintext);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "seal/unseal round-trip: empty vault and exec entries" {
    const allocator = std.testing.allocator;

    var nonce: [32]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    var sid: [16]u8 = undefined;
    std.crypto.random.bytes(&sid);
    var stream: [32]u8 = undefined;
    std.crypto.random.bytes(&stream);

    const state = CapturedState{
        .allocator = allocator,
        .session_id = sid,
        .stream_hash = stream,
        .prev_stream_hash = nonce,
        .sequence = 42,
        .bootstrap_nonce = nonce,
        .vault_entries = &.{},
        .exec_entries = &.{},
    };

    const blob = try seal(allocator, &state);
    defer allocator.free(blob);

    var restored = try unseal(allocator, blob);
    defer restored.deinit();

    try std.testing.expectEqual(state.sequence, restored.sequence);
    try std.testing.expectEqual(state.session_id, restored.session_id);
    try std.testing.expectEqual(state.bootstrap_nonce, restored.bootstrap_nonce);
    try std.testing.expectEqual(state.stream_hash, restored.stream_hash);
    try std.testing.expectEqual(state.prev_stream_hash, restored.prev_stream_hash);
    try std.testing.expectEqual(@as(usize, 0), restored.vault_entries.len);
    try std.testing.expectEqual(@as(usize, 0), restored.exec_entries.len);
}

test "seal/unseal round-trip: exec entries are preserved" {
    const allocator = std.testing.allocator;

    var nonce: [32]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    var sid: [16]u8 = undefined;
    std.crypto.random.bytes(&sid);

    var stdout_hash: [32]u8 = undefined;
    std.crypto.random.bytes(&stdout_hash);
    var stderr_hash: [32]u8 = undefined;
    std.crypto.random.bytes(&stderr_hash);

    const exec_entries = [_]CapturedState.ExecEntry{
        .{
            .cmd = @constCast("uname -a"),
            .stdout_hash = stdout_hash,
            .stderr_hash = stderr_hash,
            .exit_code = 0,
            .seq = 1,
        },
        .{
            .cmd = @constCast("date -u"),
            .stdout_hash = [_]u8{0xAB} ** 32,
            .stderr_hash = [_]u8{0xCD} ** 32,
            .exit_code = 0,
            .seq = 1,
        },
    };

    const state = CapturedState{
        .allocator = allocator,
        .session_id = sid,
        .stream_hash = nonce,
        .prev_stream_hash = nonce,
        .sequence = 7,
        .bootstrap_nonce = nonce,
        .vault_entries = &.{},
        .exec_entries = @constCast(&exec_entries),
    };

    const blob = try seal(allocator, &state);
    defer allocator.free(blob);

    var restored = try unseal(allocator, blob);
    defer restored.deinit();

    try std.testing.expectEqual(@as(usize, 2), restored.exec_entries.len);
    try std.testing.expectEqualStrings("uname -a", restored.exec_entries[0].cmd);
    try std.testing.expectEqual(@as(u8, 0), restored.exec_entries[0].exit_code);
    try std.testing.expectEqual(@as(u64, 1), restored.exec_entries[0].seq);
    try std.testing.expectEqual(stdout_hash, restored.exec_entries[0].stdout_hash);
    try std.testing.expectEqualStrings("date -u", restored.exec_entries[1].cmd);
    try std.testing.expectEqual([_]u8{0xAB} ** 32, restored.exec_entries[1].stdout_hash);
    try std.testing.expectEqual([_]u8{0xCD} ** 32, restored.exec_entries[1].stderr_hash);
}

test "seal/unseal round-trip: bootstrap_nonce is preserved" {
    const allocator = std.testing.allocator;

    var nonce: [32]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    var sid: [16]u8 = undefined;
    std.crypto.random.bytes(&sid);

    const state = CapturedState{
        .allocator = allocator,
        .session_id = sid,
        .stream_hash = [_]u8{0x11} ** 32,
        .prev_stream_hash = [_]u8{0x22} ** 32,
        .sequence = 99,
        .bootstrap_nonce = nonce,
        .vault_entries = &.{},
        .exec_entries = &.{},
    };

    const blob = try seal(allocator, &state);
    defer allocator.free(blob);

    var restored = try unseal(allocator, blob);
    defer restored.deinit();

    try std.testing.expectEqual(nonce, restored.bootstrap_nonce);
    try std.testing.expectEqual([_]u8{0x11} ** 32, restored.stream_hash);
    try std.testing.expectEqual([_]u8{0x22} ** 32, restored.prev_stream_hash);
    try std.testing.expectEqual(@as(u64, 99), restored.sequence);
}
