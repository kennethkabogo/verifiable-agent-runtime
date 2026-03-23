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
///   Production (real Nitro):  TODO — replace sealDek/unsealDek bodies with an
///     AWS KMS GenerateDataKey + Decrypt call conditioned on a Nitro attestation
///     document.  The KMS key policy restricts decryption to enclaves whose PCR0
///     matches the known-good enclave image, so the DEK is unrecoverable by the
///     host or any other binary.
///
/// Sealed blob wire format (binary, then hex-encoded for the line protocol):
///   [sealed_dek  : 32 bytes]   wrapped AES-256 key
///   [nonce       : 12 bytes]   AES-GCM nonce
///   [tag         : 16 bytes]   AES-GCM authentication tag
///   [ciphertext  : N bytes]    AES-256-GCM ciphertext of the serialized state
///
/// Serialized plaintext format:
///   [magic        : 4 ]  "VARS"
///   [version      : 1 ]  0x01
///   [session_id   : 16]  UUID v4
///   [stream_hash  : 32]  current L1 hash chain tip (spec §2.1)
///   [prev_hash    : 32]  L1 hash at last evidence emission
///   [sequence     : 8 ]  u64 LE — next sequence number on resume
///   [ed25519_seed : 32]  first 32 bytes of the secret key; keypair is re-derived
///   [vault_count  : 4 ]  u32 LE
///   per vault entry:
///     [key_len    : 2 ]  u16 LE
///     [key        : key_len]
///     [val_len    : 2 ]  u16 LE
///     [val        : val_len]
///
/// Note on terminal state (L2): the VerifiableTerminal grid is NOT persisted.
/// On resume the grid starts empty.  The L1 stream_hash already encodes the
/// complete output history, so the evidence chain remains intact; the L2 state
/// hash in subsequent bundles will simply reflect a fresh terminal.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const SecureVault = @import("vault.zig").SecureVault;
const SecureLogger = @import("shell.zig").SecureLogger;

// ---------------------------------------------------------------------------
// Wire-format constants
// ---------------------------------------------------------------------------

const MAGIC = [4]u8{ 'V', 'A', 'R', 'S' };
const FORMAT_VERSION: u8 = 0x01;

/// Minimum plaintext size: magic(4) + version(1) + session_id(16) +
/// stream_hash(32) + prev_hash(32) + sequence(8) + seed(32) + vault_count(4) = 129
const MIN_PLAINTEXT: usize = 129;

/// Minimum sealed blob size: sealed_dek(32) + nonce(12) + tag(16) = 60
const MIN_BLOB: usize = 60;

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
    /// First 32 bytes of the Ed25519 secret key (the seed).
    /// The keypair is deterministically re-derived from this on restore.
    ed25519_seed: [32]u8,
    vault_entries: []Entry,

    pub const Entry = struct {
        key: []const u8,
        value: []const u8,
    };

    pub fn deinit(self: *CapturedState) void {
        for (self.vault_entries) |e| {
            std.crypto.utils.secureZero(u8, @constCast(e.key));
            std.crypto.utils.secureZero(u8, @constCast(e.value));
            self.allocator.free(e.key);
            self.allocator.free(e.value);
        }
        self.allocator.free(self.vault_entries);
        std.crypto.utils.secureZero(u8, &self.ed25519_seed);
    }
};

// ---------------------------------------------------------------------------
// Capture and restore
// ---------------------------------------------------------------------------

/// Snapshot all mutable runtime state from vault and logger.
/// Locks each mutex independently to avoid lock-order deadlocks.
/// Caller must call CapturedState.deinit() when done.
pub fn capture(
    allocator: std.mem.Allocator,
    vault: *SecureVault,
    logger: *SecureLogger,
) !CapturedState {
    // Snapshot logger fields first (cheap, no allocation).
    const session_id = blk: {
        logger.mutex.lock();
        defer logger.mutex.unlock();
        break :blk logger.session_id;
    };
    const stream_hash = blk: {
        logger.mutex.lock();
        defer logger.mutex.unlock();
        break :blk logger.stream_hash;
    };
    const prev_stream_hash = blk: {
        logger.mutex.lock();
        defer logger.mutex.unlock();
        break :blk logger.prev_stream_hash;
    };
    const sequence = blk: {
        logger.mutex.lock();
        defer logger.mutex.unlock();
        break :blk logger.sequence;
    };
    const ed25519_seed = blk: {
        logger.mutex.lock();
        defer logger.mutex.unlock();
        // The first 32 bytes of the 64-byte secret key are the RFC 8032 seed.
        const sk_bytes = logger.keypair.secret_key.toBytes();
        var seed: [32]u8 = undefined;
        @memcpy(&seed, sk_bytes[0..32]);
        break :blk seed;
    };

    // Snapshot vault entries.
    const entries = blk: {
        vault.mutex.lock();
        defer vault.mutex.unlock();

        const n = vault.secrets.count();
        const buf = try allocator.alloc(CapturedState.Entry, n);
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
        .ed25519_seed = ed25519_seed,
        .vault_entries = entries,
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
        std.crypto.utils.secureZero(u8, @constCast(entry.key_ptr.*));
        std.crypto.utils.secureZero(u8, @constCast(entry.value_ptr.*));
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

/// Restore logger hash-chain and signing keypair from a previously captured state.
/// The VerifiableTerminal grid is reset to empty — see module doc comment.
pub fn restoreLogger(state: *const CapturedState, logger: *SecureLogger) !void {
    logger.mutex.lock();
    defer logger.mutex.unlock();

    logger.session_id = state.session_id;
    logger.stream_hash = state.stream_hash;
    logger.prev_stream_hash = state.prev_stream_hash;
    logger.sequence = state.sequence;

    // Re-derive the Ed25519 keypair from the stored seed.
    logger.keypair = try Ed25519.KeyPair.generate(state.ed25519_seed);
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

    const buf = try allocator.alloc(u8, size);
    var pos: usize = 0;

    @memcpy(buf[pos..][0..4], &MAGIC);                               pos += 4;
    buf[pos] = FORMAT_VERSION;                                        pos += 1;
    @memcpy(buf[pos..][0..16], &state.session_id);                   pos += 16;
    @memcpy(buf[pos..][0..32], &state.stream_hash);                  pos += 32;
    @memcpy(buf[pos..][0..32], &state.prev_stream_hash);             pos += 32;
    std.mem.writeInt(u64, buf[pos..][0..8], state.sequence, .little); pos += 8;
    @memcpy(buf[pos..][0..32], &state.ed25519_seed);                 pos += 32;

    std.mem.writeInt(u32, buf[pos..][0..4], @intCast(state.vault_entries.len), .little);
    pos += 4;

    for (state.vault_entries) |e| {
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(e.key.len), .little);   pos += 2;
        @memcpy(buf[pos..][0..e.key.len], e.key);                                pos += e.key.len;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(e.value.len), .little); pos += 2;
        @memcpy(buf[pos..][0..e.value.len], e.value);                            pos += e.value.len;
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

    var ed25519_seed: [32]u8 = undefined;
    @memcpy(&ed25519_seed, buf[pos..][0..32]);
    pos += 32;

    const vault_count = std.mem.readInt(u32, buf[pos..][0..4], .little);
    pos += 4;

    // Cap vault_count to prevent OOM from a corrupt blob.
    if (vault_count > 4096) return error.VaultCountTooLarge;

    const entries = try allocator.alloc(CapturedState.Entry, vault_count);
    var entries_init: usize = 0;
    errdefer {
        for (entries[0..entries_init]) |e| {
            allocator.free(e.key);
            allocator.free(e.value);
        }
        allocator.free(entries);
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

        entries[i] = .{ .key = key, .value = value };
        entries_init = i + 1;
    }

    return CapturedState{
        .allocator = allocator,
        .session_id = session_id,
        .stream_hash = stream_hash,
        .prev_stream_hash = prev_stream_hash,
        .sequence = sequence,
        .ed25519_seed = ed25519_seed,
        .vault_entries = entries,
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

fn hasNsmDevice() bool {
    const f = std.fs.openFileAbsolute("/dev/nsm", .{ .mode = .read_write }) catch return false;
    f.close();
    return true;
}

/// Wraps (seals) a 32-byte AES-256 DEK.
/// Caller owns the returned 32-byte slice.
fn sealDek(allocator: std.mem.Allocator, dek: [32]u8) ![]u8 {
    const out = try allocator.alloc(u8, 32);
    if (hasNsmDevice()) {
        // TODO(production): call AWS KMS GenerateDataKey conditioned on a fresh
        // Nitro attestation document so only enclaves with PCR0 = this image can
        // unwrap.  Replace the memcpy below with the KMS response ciphertext.
        @memcpy(out, &dek);
    } else {
        // Simulation: one-time-pad style XOR with the mock wrapping key.
        for (dek, 0..) |b, i| out[i] = b ^ MOCK_WRAP_KEY[i];
    }
    return out;
}

/// Unwraps a sealed DEK produced by sealDek().
fn unsealDek(sealed: []const u8) ![32]u8 {
    if (sealed.len != 32) return error.InvalidSealedDekLength;
    var dek: [32]u8 = undefined;
    if (hasNsmDevice()) {
        // TODO(production): call AWS KMS Decrypt with the current attestation doc.
        @memcpy(&dek, sealed);
    } else {
        for (sealed, 0..) |b, i| dek[i] = b ^ MOCK_WRAP_KEY[i];
    }
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
        std.crypto.utils.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }

    var dek: [Aes256Gcm.key_length]u8 = undefined;
    var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&dek);
    std.crypto.random.bytes(&nonce);
    defer std.crypto.utils.secureZero(u8, &dek);

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(ciphertext);
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    Aes256Gcm.encrypt(ciphertext, &tag, plaintext, "", nonce, dek);

    const sealed_dek = try sealDek(allocator, dek);
    defer allocator.free(sealed_dek);

    // Layout: sealed_dek(32) || nonce(12) || tag(16) || ciphertext(N)
    const blob = try allocator.alloc(u8, 32 + 12 + 16 + ciphertext.len);
    var pos: usize = 0;
    @memcpy(blob[pos..][0..32], sealed_dek);                 pos += 32;
    @memcpy(blob[pos..][0..12], &nonce);                     pos += 12;
    @memcpy(blob[pos..][0..16], &tag);                       pos += 16;
    @memcpy(blob[pos..][0..ciphertext.len], ciphertext);

    return blob;
}

/// Decrypts and deserializes a blob produced by seal().
/// Caller owns the returned CapturedState (call deinit when done).
pub fn unseal(allocator: std.mem.Allocator, blob: []const u8) !CapturedState {
    if (blob.len < MIN_BLOB) return error.BlobTooShort;

    var pos: usize = 0;
    const sealed_dek = blob[pos..][0..32]; pos += 32;
    const nonce      = blob[pos..][0..12]; pos += 12;
    const tag        = blob[pos..][0..16]; pos += 16;
    const ciphertext = blob[pos..];

    const dek = try unsealDek(sealed_dek);
    defer std.crypto.utils.secureZero(u8, @constCast(&dek));

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    defer {
        std.crypto.utils.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }

    Aes256Gcm.decrypt(plaintext, ciphertext, tag.*, "", nonce.*, dek) catch
        return error.DecryptionFailed;

    return deserialize(allocator, plaintext);
}
