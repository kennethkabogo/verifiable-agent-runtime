const std = @import("std");
const nsm = @import("nsm.zig");

/// AttestationQuote represents a hardware-signed proof of the enclave's state.
/// On real Nitro hardware `doc` contains the CBOR-encoded COSE_Sign1 attestation
/// document returned by the NSM.  In simulation it holds a deterministic mock.
pub const AttestationQuote = struct {
    pcr0: [32]u8,       // Platform Configuration Register 0 (enclave image measurement)
    public_key: [32]u8, // Enclave's ephemeral public key bound into the attestation
    doc: []u8,          // Raw attestation document bytes (caller-allocated, owned)

    pub fn generate(allocator: std.mem.Allocator, public_key: [32]u8) !AttestationQuote {
        var pcr0: [32]u8 = undefined;
        @memset(&pcr0, 0xAA); // placeholder; real value comes from NSM PCR measurement

        // Pass the ephemeral public key so the NSM (or mock) can bind it into the doc.
        const doc = try nsm.getAttestationDoc(allocator, null, &public_key);

        return AttestationQuote{
            .pcr0 = pcr0,
            .public_key = public_key,
            .doc = doc,
        };
    }

    pub fn deinit(self: AttestationQuote, allocator: std.mem.Allocator) void {
        allocator.free(self.doc);
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

    /// Returns a human-readable representation suitable for logging / handshake display.
    pub fn serialize(self: AttestationQuote, allocator: std.mem.Allocator) ![]u8 {
        const pcr0_h = try hex(allocator, &self.pcr0);
        defer allocator.free(pcr0_h);
        const pk_h = try hex(allocator, &self.public_key);
        defer allocator.free(pk_h);
        const doc_h = try hex(allocator, self.doc);
        defer allocator.free(doc_h);

        return try std.fmt.allocPrint(allocator, "QUOTE:pcr0={s}:pk={s}:doc={s}", .{
            pcr0_h,
            pk_h,
            doc_h,
        });
    }
};
