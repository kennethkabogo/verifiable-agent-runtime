const std = @import("std");
const AttestationQuote = @import("attestation.zig").AttestationQuote;
const SecureVault = @import("vault.zig").SecureVault;
const Ed25519 = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// Maximum byte length for a secret key name.
const MAX_SECRET_KEY_LEN: usize = 256;
/// Maximum byte length for a secret value — ample for JWTs, PEM private keys,
/// and Anthropic API keys, while preventing memory-exhaustion via the line protocol.
const MAX_SECRET_VALUE_LEN: usize = 8192;

/// HKDF info string that binds the derived key to this protocol version.
const HKDF_INFO = "VAR-secret-v1";

/// Minimum byte length of a base64-encoded ESECRET payload:
///   ephemeral_pub(32) + nonce(12) + tag(16) + at least 1 byte of ciphertext,
///   base64-encoded → ceil(61 / 3) * 4 = 84 bytes minimum.
const ESECRET_MIN_PAYLOAD_B64: usize = 84;

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
    /// Ephemeral X25519 keypair used for secret encryption.
    /// The public key is included in the bundle header so the host can encrypt
    /// secrets with ECDH → HKDF → AES-256-GCM before sending them over vsock.
    /// The private key never leaves the enclave process.
    enc_private: [32]u8,
    enc_public: [32]u8,

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

        // Generate a fresh ephemeral Ed25519 keypair.  The public key is bound
        // into the attestation quote so the NSM (or mock) can certify it.
        const keypair = Ed25519.KeyPair.generate();
        const pk = keypair.public_key.toBytes();
        // Pass session_id as the NSM nonce so the hardware witnesses this
        // specific session identity (silicon-enforced causal ordering).
        const quote = try AttestationQuote.generate(allocator, pk, session_id);

        // Generate a fresh ephemeral X25519 keypair for secret encryption.
        // The host encrypts each secret with the enclave's public key so that
        // only this enclave instance can decrypt it via ECDH + HKDF + AES-GCM.
        var enc_private: [32]u8 = undefined;
        std.crypto.random.bytes(&enc_private);
        const enc_public = try X25519.recoverPublicKey(enc_private);

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
            .enc_private = enc_private,
            .enc_public = enc_public,
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
    ///   enc_pub         X25519 public key (32 bytes, hex) for secret encryption
    ///   Attestation Doc raw doc bytes
    pub fn prepareHandshake(self: *ProtocolHandler) ![]u8 {
        const sid_h = try hex(self.allocator, &self.session_id);
        defer self.allocator.free(sid_h);
        const nonce_h = try hex(self.allocator, &self.bootstrap_nonce);
        defer self.allocator.free(nonce_h);
        const enc_pub_h = try hex(self.allocator, &self.enc_public);
        defer self.allocator.free(enc_pub_h);
        const quote_str = try self.quote.serialize(self.allocator);
        defer self.allocator.free(quote_str);

        return std.fmt.allocPrint(
            self.allocator,
            "BUNDLE_HEADER:magic=VARB:version=01:session={s}:nonce={s}:enc_pub={s}:{s}",
            .{ sid_h, nonce_h, enc_pub_h, quote_str },
        );
    }

    /// Step 2: Receives and stores a secret provisioned by the host.
    ///
    /// Two formats are accepted:
    ///
    ///   ESECRET:<key>:<b64>   — encrypted (production)
    ///     <b64> = base64( ephemeral_x25519_pub[32] | nonce[12] |
    ///                     AES-256-GCM(plaintext) | tag[16] )
    ///     Decrypted with ECDH(enc_private, ephemeral_pub) → HKDF-SHA256 → AES.
    ///
    ///   SECRET:<key>:<value>  — cleartext (simulation / CI only)
    ///     Stored directly; no decryption.  The host SHOULD use ESECRET whenever
    ///     enc_pub is present in the bundle header.
    ///
    /// The secret value field may contain colons (e.g. URLs, JWTs, base64), so
    /// we only split on the first two delimiters and treat the remainder verbatim.
    pub fn handleSecrets(self: *ProtocolHandler, packet: []const u8) !void {
        const colon1 = std.mem.indexOfScalar(u8, packet, ':') orelse return error.InvalidPacket;
        const verb = packet[0..colon1];
        const rest = packet[colon1 + 1 ..];
        const colon2 = std.mem.indexOfScalar(u8, rest, ':') orelse return error.InvalidKey;
        const key = rest[0..colon2];
        const payload = rest[colon2 + 1 ..];

        if (key.len == 0) return error.InvalidKey;
        if (key.len > MAX_SECRET_KEY_LEN) return error.KeyTooLong;

        if (std.mem.eql(u8, verb, "ESECRET")) {
            // ── Encrypted path ────────────────────────────────────────────
            if (payload.len < ESECRET_MIN_PAYLOAD_B64) return error.EsecretPayloadTooShort;

            // Decode base64 into a stack buffer.  Maximum decoded size:
            //   MAX_SECRET_VALUE_LEN + 32 (ephemeral pub) + 12 (nonce) + 16 (tag)
            const MAX_DECODED = MAX_SECRET_VALUE_LEN + 32 + 12 + 16;
            var decoded_buf: [MAX_DECODED]u8 = undefined;
            const b64 = std.base64.standard;
            const decoded_len = b64.Decoder.calcSizeForSlice(payload) catch
                return error.EsecretBase64Invalid;
            if (decoded_len > MAX_DECODED) return error.EsecretPayloadTooLong;
            b64.Decoder.decode(&decoded_buf, payload) catch
                return error.EsecretBase64Invalid;
            const decoded = decoded_buf[0..decoded_len];

            // Layout: ephemeral_pub[32] | nonce[12] | ciphertext+tag
            if (decoded.len < 32 + 12 + Aes256Gcm.tag_length + 1)
                return error.EsecretPayloadTooShort;

            const ephemeral_pub = decoded[0..32].*;
            const nonce = decoded[32..44].*;
            const ct_and_tag = decoded[44..];
            if (ct_and_tag.len < Aes256Gcm.tag_length) return error.EsecretPayloadTooShort;
            const ct = ct_and_tag[0 .. ct_and_tag.len - Aes256Gcm.tag_length];
            const tag = ct_and_tag[ct_and_tag.len - Aes256Gcm.tag_length ..][0..Aes256Gcm.tag_length].*;

            // ECDH: shared_secret = X25519(enc_private, ephemeral_pub)
            const shared = X25519.scalarmult(self.enc_private, ephemeral_pub) catch
                return error.EsecretEcdhFailed;

            // HKDF-SHA256: derive a 32-byte AES-256 key from the shared secret.
            const derived_key = HkdfSha256.extract("", &shared);
            var aes_key: [32]u8 = undefined;
            HkdfSha256.expand(&aes_key, HKDF_INFO, derived_key);

            // AES-256-GCM decrypt.
            var plaintext_buf: [MAX_SECRET_VALUE_LEN]u8 = undefined;
            if (ct.len > plaintext_buf.len) return error.EsecretPayloadTooLong;
            Aes256Gcm.decrypt(plaintext_buf[0..ct.len], ct, tag, "", nonce, aes_key) catch
                return error.EsecretDecryptFailed;
            const plaintext = plaintext_buf[0..ct.len];

            std.crypto.secureZero(u8, &aes_key);
            try self.vault.store(key, plaintext);
        } else if (std.mem.eql(u8, verb, "SECRET")) {
            // ── Cleartext path (simulation / CI) ─────────────────────────
            if (payload.len == 0) return error.InvalidSecret;
            if (payload.len > MAX_SECRET_VALUE_LEN) return error.SecretTooLong;
            try self.vault.store(key, payload);
        }
        // Unknown verb: silently ignore (forward-compatibility).
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

// ── Tests ──────────────────────────────────────────────────────────────────

/// Build a well-formed ESECRET packet encrypting `plaintext` with `enc_pub`.
/// Mirrors what agent.py's encrypt_secret() does on the host side.
fn buildEsecretPacket(
    allocator: std.mem.Allocator,
    key: []const u8,
    plaintext: []const u8,
    enc_pub: [32]u8,
) ![]u8 {
    var eph_priv: [32]u8 = undefined;
    std.crypto.random.bytes(&eph_priv);
    const eph_pub = try X25519.recoverPublicKey(eph_priv);
    const shared = try X25519.scalarmult(eph_priv, enc_pub);

    const prk = HkdfSha256.extract("", &shared);
    var aes_key: [32]u8 = undefined;
    HkdfSha256.expand(&aes_key, HKDF_INFO, prk);
    defer std.crypto.secureZero(u8, &aes_key);

    var nonce: [12]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    const ct_buf = try allocator.alloc(u8, plaintext.len + Aes256Gcm.tag_length);
    defer allocator.free(ct_buf);
    Aes256Gcm.encrypt(
        ct_buf[0..plaintext.len],
        ct_buf[plaintext.len..][0..Aes256Gcm.tag_length],
        plaintext,
        "",
        nonce,
        aes_key,
    );

    const raw = try allocator.alloc(u8, 32 + 12 + ct_buf.len);
    defer allocator.free(raw);
    @memcpy(raw[0..32], &eph_pub);
    @memcpy(raw[32..44], &nonce);
    @memcpy(raw[44..], ct_buf);

    const b64_len = std.base64.standard.Encoder.calcSize(raw.len);
    const b64_buf = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64_buf);
    _ = std.base64.standard.Encoder.encode(b64_buf, raw);

    return std.fmt.allocPrint(allocator, "ESECRET:{s}:{s}", .{ key, b64_buf });
}

test "handleSecrets: ESECRET decrypts and stores plaintext" {
    var vault = SecureVault.init(std.testing.allocator);
    defer vault.deinit();

    var proto = try ProtocolHandler.init(std.testing.allocator, &vault);
    defer proto.deinit();

    const plaintext = "sk-ant-test-secret-value-12345";
    const packet = try buildEsecretPacket(
        std.testing.allocator,
        "ANTHROPIC_API_KEY",
        plaintext,
        proto.enc_public,
    );
    defer std.testing.allocator.free(packet);

    try proto.handleSecrets(packet);

    const stored = vault.get("ANTHROPIC_API_KEY") orelse
        return error.SecretNotFound;
    try std.testing.expectEqualStrings(plaintext, stored);
}

test "handleSecrets: ESECRET with wrong key returns DecryptFailed" {
    var vault = SecureVault.init(std.testing.allocator);
    defer vault.deinit();

    var proto = try ProtocolHandler.init(std.testing.allocator, &vault);
    defer proto.deinit();

    // Build packet for a DIFFERENT enclave public key — decryption must fail.
    var wrong_pub: [32]u8 = undefined;
    std.crypto.random.bytes(&wrong_pub);
    const packet = try buildEsecretPacket(
        std.testing.allocator,
        "KEY",
        "secret",
        wrong_pub,
    );
    defer std.testing.allocator.free(packet);

    try std.testing.expectError(error.EsecretDecryptFailed, proto.handleSecrets(packet));
}

test "handleSecrets: cleartext SECRET still works (simulation path)" {
    var vault = SecureVault.init(std.testing.allocator);
    defer vault.deinit();

    var proto = try ProtocolHandler.init(std.testing.allocator, &vault);
    defer proto.deinit();

    try proto.handleSecrets("SECRET:MY_KEY:my-value");
    const stored = vault.get("MY_KEY") orelse return error.SecretNotFound;
    try std.testing.expectEqualStrings("my-value", stored);
}

test "handleSecrets: ESECRET short payload is rejected" {
    var vault = SecureVault.init(std.testing.allocator);
    defer vault.deinit();

    var proto = try ProtocolHandler.init(std.testing.allocator, &vault);
    defer proto.deinit();

    try std.testing.expectError(
        error.EsecretPayloadTooShort,
        proto.handleSecrets("ESECRET:KEY:aGVsbG8="),
    );
}

test "prepareHandshake includes enc_pub field" {
    var vault = SecureVault.init(std.testing.allocator);
    defer vault.deinit();

    var proto = try ProtocolHandler.init(std.testing.allocator, &vault);
    defer proto.deinit();

    const header = try proto.prepareHandshake();
    defer std.testing.allocator.free(header);

    try std.testing.expect(std.mem.indexOf(u8, header, "enc_pub=") != null);
    // enc_pub value is a 64-char hex string (32 bytes).
    const enc_pub_pos = std.mem.indexOf(u8, header, "enc_pub=").? + "enc_pub=".len;
    try std.testing.expect(header.len >= enc_pub_pos + 64);
}
