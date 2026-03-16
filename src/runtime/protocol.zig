const std = @import("std");
const AttestationQuote = @import("attestation.zig").AttestationQuote;
const SecureVault = @import("vault.zig").SecureVault;

/// ProtocolHandler manages the secure handshake between the host and the enclave.
pub const ProtocolHandler = struct {
    allocator: std.mem.Allocator,
    vault: *SecureVault,

    pub fn init(allocator: std.mem.Allocator, vault: *SecureVault) ProtocolHandler {
        return ProtocolHandler{
            .allocator = allocator,
            .vault = vault,
        };
    }

    /// Step 1: Enclave prepares a 'Hello' packet with its attestation quote.
    pub fn prepareHandshake(self: *ProtocolHandler) ![]u8 {
        // Ephemeral session key for the enclave (mock)
        const pk = [_]u8{0x12} ** 32;
        const quote = try AttestationQuote.generate(pk);
        return try quote.serialize(self.allocator);
    }

    /// Step 2: Processes incoming encrypted secrets from the host.
    /// Format: "SECRET:<key>:<encrypted_val>"
    pub fn handleSecrets(self: *ProtocolHandler, packet: []const u8) !void {
        var it = std.mem.tokenizeScalar(u8, packet, ':');
        const prefix = it.next() orelse return error.InvalidPacket;
        if (!std.mem.eql(u8, prefix, "SECRET")) return;

        const key = it.next() orelse return error.InvalidKey;
        const secret = it.next() orelse return error.InvalidSecret;

        // In a real TEE, we would decrypt the secret using our private key here.
        // For simulation, we assume the host sent it in cleartext or we "auto-decrypt".
        try self.vault.store(key, secret);
    }
};
