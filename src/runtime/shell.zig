const std = @import("std");
const VerifiableTerminal = @import("vt.zig").VerifiableTerminal;

/// SecureLogger handles the PTY master logic and provides a verifiable hash chain
/// of both the terminal stream and the reconstructed terminal state.
pub const SecureLogger = struct {
    allocator: std.mem.Allocator,
    stream_hash: [32]u8,
    vt: VerifiableTerminal,

    /// init anchors the hash chain to the session by computing the Bootstrap Nonce
    /// as the initial stream hash value (spec §1.2):
    ///   H_stream[0] = SHA-256(AttestationDoc || SessionID)
    pub fn init(
        allocator: std.mem.Allocator,
        attestation_doc: []const u8,
        session_id: [16]u8,
    ) !SecureLogger {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(attestation_doc);
        hasher.update(&session_id);
        var bootstrap_nonce: [32]u8 = undefined;
        hasher.final(&bootstrap_nonce);

        return SecureLogger{
            .allocator = allocator,
            .stream_hash = bootstrap_nonce,
            .vt = try VerifiableTerminal.init(allocator, 80, 24),
        };
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
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.stream_hash);
        hasher.update(data);
        hasher.final(&self.stream_hash);

        self.vt.processInput(data);
    }

    /// Generates a signed bundle of the stream hash and the current terminal state.
    pub fn getEvidenceBundle(self: *SecureLogger) ![]u8 {
        const state_digest = self.vt.digestState();
        const stream_h = try hex(self.allocator, &self.stream_hash);
        defer self.allocator.free(stream_h);
        const state_h = try hex(self.allocator, &state_digest);
        defer self.allocator.free(state_h);

        return std.fmt.allocPrint(self.allocator, "EVIDENCE:stream={s}:state={s}:sig=MOCK_SIG", .{
            stream_h,
            state_h,
        });
    }
};
