const std = @import("std");
const VerifiableTerminal = @import("vt.zig").VerifiableTerminal;
const Ed25519 = std.crypto.sign.Ed25519;

/// SecureLogger handles the PTY master logic and provides a verifiable hash chain
/// of both the terminal stream and the reconstructed terminal state.
pub const SecureLogger = struct {
    allocator: std.mem.Allocator,
    stream_hash: [32]u8,
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

    /// Signs the current stream hash, state hash, session ID, and sequence
    /// number with the session keypair.
    ///
    /// Message layout (88 bytes):
    ///   stream_hash (32) || state_hash (32) || session_id (16) || sequence (8, LE)
    ///
    /// Including the sequence makes each bundle's signature unique even when
    /// the stream state hasn't changed, and lets a verifier detect replay or
    /// skipped packets.
    fn signEvidence(self: *SecureLogger, stream_hash: [32]u8, state_hash: [32]u8, sequence: u64) !Ed25519.Signature {
        var msg: [88]u8 = undefined;
        @memcpy(msg[0..32], &stream_hash);
        @memcpy(msg[32..64], &state_hash);
        @memcpy(msg[64..80], &self.session_id);
        std.mem.writeInt(u64, msg[80..88], sequence, .little);
        return self.keypair.sign(&msg, null);
    }

    /// Generates a signed bundle of the stream hash and the current terminal state.
    /// Returns an allocated string in the vsock line-protocol format.
    pub fn getEvidenceBundle(self: *SecureLogger) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.sequence += 1;
        const seq = self.sequence;

        const state_digest = self.vt.digestState();
        const sig = try self.signEvidence(self.stream_hash, state_digest, seq);
        const sig_bytes = sig.toBytes();

        const stream_h = try hex(self.allocator, &self.stream_hash);
        defer self.allocator.free(stream_h);
        const state_h = try hex(self.allocator, &state_digest);
        defer self.allocator.free(state_h);
        const sig_h = try hex(self.allocator, &sig_bytes);
        defer self.allocator.free(sig_h);

        return std.fmt.allocPrint(self.allocator, "EVIDENCE:stream={s}:state={s}:sig={s}:seq={d}", .{
            stream_h,
            state_h,
            sig_h,
            seq,
        });
    }

    /// Returns the evidence bundle as a JSON object for the HTTP gateway.
    /// Caller must free the returned slice using `allocator`.
    pub fn getEvidenceBundleJson(self: *SecureLogger, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.sequence += 1;
        const seq = self.sequence;

        const state_digest = self.vt.digestState();
        const sig = try self.signEvidence(self.stream_hash, state_digest, seq);
        const sig_bytes = sig.toBytes();

        const stream_h = try hex(allocator, &self.stream_hash);
        defer allocator.free(stream_h);
        const state_h = try hex(allocator, &state_digest);
        defer allocator.free(state_h);
        const sig_h = try hex(allocator, &sig_bytes);
        defer allocator.free(sig_h);

        return std.fmt.allocPrint(allocator,
            \\{{"stream":"{s}","state":"{s}","sig":"{s}","sequence":{d}}}
        , .{ stream_h, state_h, sig_h, seq });
    }
};
