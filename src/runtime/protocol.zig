const std = @import("std");
const AttestationQuote = @import("attestation.zig").AttestationQuote;
const SecureVault = @import("vault.zig").SecureVault;
const Ed25519 = std.crypto.sign.Ed25519;

/// ProtocolHandler manages the secure handshake between the host and the enclave.
pub const ProtocolHandler = struct {
    allocator: std.mem.Allocator,
    vault: *SecureVault,
    session_id: [16]u8,
    quote: AttestationQuote,
    /// Ephemeral Ed25519 signing keypair generated fresh for every session.
    /// The public key is bound into the attestation document so a verifier can
    /// confirm that any signature originated from inside this enclave instance.
    /// The private key never leaves the enclave process.
    keypair: Ed25519.KeyPair,

    /// init generates a UUID v4 session ID, an ephemeral Ed25519 keypair, and
    /// requests an attestation quote from the NSM (real hardware) or the mock
    /// fallback (simulation / CI).
    pub fn init(allocator: std.mem.Allocator, vault: *SecureVault) !ProtocolHandler {
        // UUID v4: 128 random bits with version/variant nibbles set per RFC 4122.
        var session_id: [16]u8 = undefined;
        std.crypto.random.bytes(&session_id);
        session_id[6] = (session_id[6] & 0x0f) | 0x40; // version = 4
        session_id[8] = (session_id[8] & 0x3f) | 0x80; // variant = 10xx

        // Generate a fresh ephemeral keypair.  The public key is bound into the
        // attestation quote so the NSM (or mock) can certify it.
        const keypair = try Ed25519.KeyPair.generate();
        const pk = keypair.public_key.toBytes();
        const quote = try AttestationQuote.generate(allocator, pk);

        return ProtocolHandler{
            .allocator = allocator,
            .vault = vault,
            .session_id = session_id,
            .quote = quote,
            .keypair = keypair,
        };
    }

    pub fn deinit(self: *ProtocolHandler) void {
        self.quote.deinit(self.allocator);
    }

    /// Step 1: Enclave emits a Bundle Header — the root-of-trust anchor for the session.
    ///
    /// Bundle Header fields (per spec §1.1):
    ///   Magic           "VARB"
    ///   Version         0x01
    ///   Session ID      UUID v4  (16 bytes)
    ///   Bootstrap Nonce SHA-256(AttestationDoc || SessionID)  (32 bytes)
    ///   Attestation Doc raw doc bytes
    pub fn prepareHandshake(self: *ProtocolHandler) ![]u8 {
        // Bootstrap Nonce = SHA-256(AttestationDoc || SessionID)
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(self.quote.doc);
        hasher.update(&self.session_id);
        var bootstrap_nonce: [32]u8 = undefined;
        hasher.final(&bootstrap_nonce);

        const sid_h = try hex(self.allocator, &self.session_id);
        defer self.allocator.free(sid_h);
        const nonce_h = try hex(self.allocator, &bootstrap_nonce);
        defer self.allocator.free(nonce_h);
        const quote_str = try self.quote.serialize(self.allocator);
        defer self.allocator.free(quote_str);

        return std.fmt.allocPrint(
            self.allocator,
            "BUNDLE_HEADER:magic=VARB:version=01:session={s}:nonce={s}:{s}",
            .{ sid_h, nonce_h, quote_str },
        );
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

    fn hex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
        var result = try allocator.alloc(u8, bytes.len * 2);
        const chars = "0123456789abcdef";
        for (bytes, 0..) |b, i| {
            result[i * 2] = chars[b >> 4];
            result[i * 2 + 1] = chars[b & 0x0f];
        }
        return result;
    }
};
