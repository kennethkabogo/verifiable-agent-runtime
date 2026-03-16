const std = @import("std");

/// AttestationQuote represents a hardware-signed proof of the enclave's state.
pub const AttestationQuote = struct {
    pcr0: [32]u8,        // Binary Digest (SHA-256)
    public_key: [32]u8,  // Enclave's ephemeral public key
    signature: [64]u8,   // Mock Hardware Signature

    pub fn generate(public_key: [32]u8) !AttestationQuote {
        var pcr0: [32]u8 = undefined;
        @memset(&pcr0, 0xAA); 

        var signature: [64]u8 = undefined;
        @memset(&signature, 0x55); // Mock signature

        return AttestationQuote{
            .pcr0 = pcr0,
            .public_key = public_key,
            .signature = signature,
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

    pub fn serialize(self: AttestationQuote, allocator: std.mem.Allocator) ![]u8 {
        const pcr0_h = try hex(allocator, &self.pcr0);
        defer allocator.free(pcr0_h);
        const pk_h = try hex(allocator, &self.public_key);
        defer allocator.free(pk_h);
        const sig_h = try hex(allocator, &self.signature);
        defer allocator.free(sig_h);

        return try std.fmt.allocPrint(allocator, "QUOTE:pcr0={s}:pk={s}:sig={s}", .{
            pcr0_h,
            pk_h,
            sig_h,
        });
    }
};
