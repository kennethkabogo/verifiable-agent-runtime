const std = @import("std");
const VerifiableTerminal = @import("vt.zig").VerifiableTerminal;

/// SecureLogger handles the PTY master logic and provides a verifiable hash chain 
/// of both the terminal stream and the reconstructed terminal state.
pub const SecureLogger = struct {
    allocator: std.mem.Allocator,
    stream_hash: [32]u8,
    vt: VerifiableTerminal,

    pub fn init(allocator: std.mem.Allocator) !SecureLogger {
        return SecureLogger{
            .allocator = allocator,
            .stream_hash = [_]u8{0} ** 32,
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

    /// Appends new output chunk and updates the hash chain.
    pub fn logOutput(self: *SecureLogger, data: []const u8) !void {
        // 1. Update Stream Hash (the raw byte chain)
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.stream_hash);
        hasher.update(data);
        hasher.final(&self.stream_hash);

        // 2. Update Terminal State Machine
        try self.vt.processInput(data);
    }

    /// Generates a signed bundle of the stream hash and the current terminal state.
    pub fn getEvidenceBundle(self: *SecureLogger) ![]u8 {
        const state_digest = try self.vt.digestState();
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
