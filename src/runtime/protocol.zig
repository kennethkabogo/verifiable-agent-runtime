const std = @import("std");
const AttestationQuote = @import("attestation.zig").AttestationQuote;
const SecureVault = @import("vault.zig").SecureVault;
const Ed25519 = std.crypto.sign.Ed25519;

/// ProtocolHandler manages the secure handshake between the host and the enclave.
pub const ProtocolHandler = struct {
    allocator: std.mem.Allocator,
    vault: *SecureVault,
    session_id: [16]u8,
    /// Bootstrap Nonce = SHA-256(attestation_doc || session_id).
    /// Computed once in init() and reused by both the bundle header and the
    /// SecureLogger so there is a single authoritative value for the session.
    bootstrap_nonce: [32]u8,
    quote: AttestationQuote,
    /// Ephemeral Ed25519 signing keypair generated fresh for every session.
    /// The public key is bound into the attestation document so a verifier can
    /// confirm that any signature originated from inside this enclave instance.
    /// The private key never leaves the enclave process.
    keypair: Ed25519.KeyPair,

    /// init generates a UUID v4 session ID, an ephemeral Ed25519 keypair, and
    /// requests an attestation quote from the NSM (real hardware) or the mock
    /// fallback (simulation / CI).  The bootstrap nonce is computed here, once,
    /// so every downstream consumer uses the identical value.
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

        // Bootstrap Nonce = SHA-256(AttestationDoc || SessionID).
        // Computed once here so the logger, the bundle header, and the HTTP
        // gateway all share the same value rather than recomputing independently.
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(quote.doc);
        hasher.update(&session_id);
        var bootstrap_nonce: [32]u8 = undefined;
        hasher.final(&bootstrap_nonce);

        return ProtocolHandler{
            .allocator = allocator,
            .vault = vault,
            .session_id = session_id,
            .bootstrap_nonce = bootstrap_nonce,
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
        const sid_h = try hex(self.allocator, &self.session_id);
        defer self.allocator.free(sid_h);
        const nonce_h = try hex(self.allocator, &self.bootstrap_nonce);
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
    /// Format: "SECRET:<key>:<value>"
    ///
    /// The value may itself contain colons (e.g. URLs, base64, JWT tokens) so
    /// we only split on the first two delimiters and treat the remainder of the
    /// line as the value verbatim.
    pub fn handleSecrets(self: *ProtocolHandler, packet: []const u8) !void {
        const prefix_end = std.mem.indexOfScalar(u8, packet, ':') orelse return error.InvalidPacket;
        if (!std.mem.eql(u8, packet[0..prefix_end], "SECRET")) return;

        const rest = packet[prefix_end + 1 ..];
        const key_end = std.mem.indexOfScalar(u8, rest, ':') orelse return error.InvalidKey;
        const key = rest[0..key_end];
        const secret = rest[key_end + 1 ..];

        if (key.len == 0) return error.InvalidKey;
        if (secret.len == 0) return error.InvalidSecret;

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
