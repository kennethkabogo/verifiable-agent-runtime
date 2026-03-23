const std = @import("std");
const VerifiableTerminal = @import("vt.zig").VerifiableTerminal;
const Ed25519 = std.crypto.sign.Ed25519;

/// SecureLogger handles the PTY master logic and provides a verifiable hash chain
/// of both the terminal stream and the reconstructed terminal state.
pub const SecureLogger = struct {
    allocator: std.mem.Allocator,
    /// Current L1 stream hash — H_stream[n] (spec §2.1).
    stream_hash: [32]u8,
    /// L1 hash captured at the previous evidence emission — H_stream[n-1].
    /// Used as PrevL1Hash in each signed packet so auditors can detect gaps
    /// (spec §3, §4 continuity check).  Initialized to the bootstrap nonce
    /// so the very first packet has a well-defined predecessor.
    prev_stream_hash: [32]u8,
    vt: VerifiableTerminal,
    mutex: std.Thread.Mutex = .{},
    /// Monotonically increasing counter incremented on every evidence emission.
    /// Included in the signed message so each bundle is unique even when the
    /// stream state has not changed, and a verifier can detect skipped packets.
    sequence: u64,
    /// Ephemeral Ed25519 keypair used to sign each evidence bundle.
    /// The corresponding public key is bound in the session's attestation quote.
    keypair: Ed25519.KeyPair,
    /// Session identifier included in every signature so a verifier can bind the
    /// signature to a specific session without trusting the gateway.
    session_id: [16]u8,

    /// init anchors the hash chain to the session.  The caller passes the
    /// pre-computed bootstrap_nonce (SHA-256(attestation_doc || session_id))
    /// from ProtocolHandler so the value is never computed more than once.
    ///
    ///   H_stream[0] = bootstrap_nonce   (spec §1.2)
    pub fn init(
        allocator: std.mem.Allocator,
        bootstrap_nonce: [32]u8,
        session_id: [16]u8,
        keypair: Ed25519.KeyPair,
    ) !SecureLogger {
        return SecureLogger{
            .allocator = allocator,
            .stream_hash = bootstrap_nonce,
            .prev_stream_hash = bootstrap_nonce,
            .vt = try VerifiableTerminal.init(allocator, 80, 24),
            .sequence = 0,
            .keypair = keypair,
            .session_id = session_id,
        };
    }

    pub fn deinit(self: *SecureLogger) void {
        self.vt.deinit();
    }

    fn hex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
        var result = try allocator.alloc(u8, bytes.len * 2);
        const chars = "0123456789abcdef";
        for (bytes, 0..) |b, i| {
            result[i * 2] = chars[b >> 4];
            result[i * 2 + 1] = chars[b & 0x0f];
        }
        return result;
    }

    /// Appends a new output chunk and advances the hash chain (spec §2.1):
    ///   H_stream[n] = SHA-256(H_stream[n-1] || data_chunk[n])
    pub fn logOutput(self: *SecureLogger, data: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.stream_hash);
        hasher.update(data);
        hasher.final(&self.stream_hash);

        self.vt.processInput(data);
    }

    /// Signs an evidence snapshot following spec §3.1.
    ///
    /// Message layout (161 bytes):
    ///   Magic        (4)   "VARE" = 0x56 0x41 0x52 0x45
    ///   FormatVer    (1)   0x01
    ///   Sequence     (8)   u64, little-endian
    ///   PrevL1Hash   (32)  H_stream at the previous evidence emission
    ///   L1Hash       (32)  H_stream at this emission
    ///   L2Hash       (32)  terminal state digest
    ///   PayloadLen   (4)   u32 LE; 0 in snapshot mode (no discrete payload bytes)
    ///   SHA-256(Pay) (32)  SHA-256("") in snapshot mode
    ///   SessionID    (16)  snapshot-mode extension — binds the sig to this session
    ///
    /// The HTTP gateway uses snapshot mode: there are no discrete payload bytes
    /// per evidence packet (the full PTY stream is captured in the L1 chain).
    /// PayloadLen is therefore 0 and SHA-256(Payload) is SHA-256("").
    fn signEvidence(
        self: *SecureLogger,
        prev_stream_hash: [32]u8,
        stream_hash: [32]u8,
        state_hash: [32]u8,
        sequence: u64,
    ) !Ed25519.Signature {
        // SHA-256("") — used as SHA-256(Payload) in snapshot mode.
        const empty_payload_hash = comptime blk: {
            var h: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash("", &h, .{});
            break :blk h;
        };

        var msg: [161]u8 = undefined;
        var pos: usize = 0;

        // Magic "VARE"
        @memcpy(msg[pos..][0..4], &[_]u8{ 0x56, 0x41, 0x52, 0x45 });
        pos += 4;
        // FormatVer
        msg[pos] = 0x01;
        pos += 1;
        // Sequence (u64 LE)
        std.mem.writeInt(u64, msg[pos..][0..8], sequence, .little);
        pos += 8;
        // PrevL1Hash
        @memcpy(msg[pos..][0..32], &prev_stream_hash);
        pos += 32;
        // L1Hash
        @memcpy(msg[pos..][0..32], &stream_hash);
        pos += 32;
        // L2Hash
        @memcpy(msg[pos..][0..32], &state_hash);
        pos += 32;
        // PayloadLen = 0 (snapshot mode, u32 LE)
        std.mem.writeInt(u32, msg[pos..][0..4], 0, .little);
        pos += 4;
        // SHA-256(Payload) = SHA-256("") (snapshot mode)
        @memcpy(msg[pos..][0..32], &empty_payload_hash);
        pos += 32;
        // SessionID (snapshot-mode extension)
        @memcpy(msg[pos..][0..16], &self.session_id);
        pos += 16;

        std.debug.assert(pos == 161);
        return self.keypair.sign(&msg, null);
    }

    /// Generates a signed bundle of the stream hash and the current terminal state.
    /// Returns an allocated string in the vsock line-protocol format.
    pub fn getEvidenceBundle(self: *SecureLogger) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Use next_seq as a local so sequence is only committed after the full
        // bundle is successfully constructed.  If any allocation below fails,
        // self.sequence and self.prev_stream_hash remain unchanged and the
        // caller can retry without creating a gap in the continuity chain.
        const next_seq = self.sequence + 1;
        const prev_hash = self.prev_stream_hash;
        const state_digest = self.vt.digestState();
        const sig = try self.signEvidence(prev_hash, self.stream_hash, state_digest, next_seq);
        const sig_bytes = sig.toBytes();

        const prev_h = try hex(self.allocator, &prev_hash);
        defer self.allocator.free(prev_h);
        const stream_h = try hex(self.allocator, &self.stream_hash);
        defer self.allocator.free(stream_h);
        const state_h = try hex(self.allocator, &state_digest);
        defer self.allocator.free(state_h);
        const sig_h = try hex(self.allocator, &sig_bytes);
        defer self.allocator.free(sig_h);

        const result = try std.fmt.allocPrint(self.allocator,
            "EVIDENCE:prev_stream={s}:stream={s}:state={s}:sig={s}:seq={d}",
            .{ prev_h, stream_h, state_h, sig_h, next_seq },
        );

        // Commit state only after the bundle is fully built.
        self.sequence = next_seq;
        self.prev_stream_hash = self.stream_hash;

        return result;
    }

    /// Returns the evidence bundle as a JSON object for the HTTP gateway.
    /// Caller must free the returned slice using `allocator`.
    pub fn getEvidenceBundleJson(self: *SecureLogger, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Same commit-last ordering as getEvidenceBundle: build the complete
        // JSON string before touching any persistent state so that an OOM
        // error leaves the continuity chain intact for a subsequent call.
        const next_seq = self.sequence + 1;
        const prev_hash = self.prev_stream_hash;
        const state_digest = self.vt.digestState();
        const sig = try self.signEvidence(prev_hash, self.stream_hash, state_digest, next_seq);
        const sig_bytes = sig.toBytes();

        const prev_h = try hex(allocator, &prev_hash);
        defer allocator.free(prev_h);
        const stream_h = try hex(allocator, &self.stream_hash);
        defer allocator.free(stream_h);
        const state_h = try hex(allocator, &state_digest);
        defer allocator.free(state_h);
        const sig_h = try hex(allocator, &sig_bytes);
        defer allocator.free(sig_h);

        const result = try std.fmt.allocPrint(allocator,
            \\{{"prev_stream":"{s}","stream":"{s}","state":"{s}","sig":"{s}","sequence":{d}}}
        , .{ prev_h, stream_h, state_h, sig_h, next_seq });

        // Commit state only after the bundle is fully built.
        self.sequence = next_seq;
        self.prev_stream_hash = self.stream_hash;

        return result;
    }
};
