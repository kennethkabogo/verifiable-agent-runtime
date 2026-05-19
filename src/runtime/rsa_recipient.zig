/// rsa_recipient.zig — RSA-2048 ephemeral key generation and RSAES-OAEP-SHA256
/// unwrapping for the Nitro KMS recipient flow.
///
/// Threat closed: the host-side vsock proxy previously received the plaintext
/// DEK from kms:Decrypt.  With the recipient flow the enclave instead:
///   1. Generates an ephemeral RSA-2048 keypair (fresh per unseal).
///   2. Embeds the public key (SubjectPublicKeyInfo DER) in the NSM attestation
///      document — NSM signs it, binding the key to the enclave's PCR values.
///   3. Passes the attested document as Recipient.AttestationDocument in the
///      kms:Decrypt request.  KMS verifies the NSM signature, trusts the embedded
///      public key, and returns CiphertextForRecipient rather than Plaintext.
///   4. CiphertextForRecipient is the 256-byte RSA-2048 RSAES-OAEP-SHA256
///      ciphertext of the plaintext DEK.  Only the enclave (holding the ephemeral
///      private key) can recover it.  The proxy sees only ciphertext.
///
/// Requires: libcrypto (OpenSSL ≥ 1.1.1).
/// The Nitro enclave base image (Amazon Linux 2) ships openssl-libs; build.zig
/// links it with exe.linkSystemLibrary("crypto") + exe.linkLibC().

const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/x509.h");
});

/// Ephemeral RSA-2048 keypair for one unseal operation.
///
/// pub_key_der  — DER-encoded SubjectPublicKeyInfo (SPKI), passed to NSM as
///                the public_key field so it is bound into the attestation doc.
/// _pkey_int    — EVP_PKEY * stored as usize to keep cImport types out of
///                callers; cast back internally by generateKeyPair / unwrapDek.
///
/// Caller must call deinit() when done; private key material is wiped on free.
pub const RsaKeyPair = struct {
    pub_key_der: []u8,
    _pkey_int: usize,

    pub fn deinit(self: *RsaKeyPair, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.pub_key_der);
        allocator.free(self.pub_key_der);
        if (self._pkey_int != 0) {
            const pkey: *c.EVP_PKEY = @ptrFromInt(self._pkey_int);
            c.EVP_PKEY_free(pkey);
            self._pkey_int = 0;
        }
    }
};

/// Generate an ephemeral RSA-2048 keypair using the OpenSSL EVP keygen API.
/// Returns an RsaKeyPair; caller must call deinit() when done.
pub fn generateKeyPair(allocator: std.mem.Allocator) !RsaKeyPair {
    // Build a keygen context for RSA.
    const kctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse
        return error.EvpCtxAllocFailed;
    defer c.EVP_PKEY_CTX_free(kctx);

    if (c.EVP_PKEY_keygen_init(kctx) <= 0) return error.EvpKeygenInitFailed;
    if (c.EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0)
        return error.EvpKeygenBitsFailed;

    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen(kctx, &pkey) <= 0) return error.EvpKeygenFailed;
    // EVP_PKEY_free(null) is a no-op; errdefer safe even if pkey is somehow null.
    errdefer c.EVP_PKEY_free(pkey);

    // DER-encode the public key as SubjectPublicKeyInfo (SPKI / X.509 format).
    // i2d_PUBKEY(pkey, NULL) returns the required byte count without writing.
    const der_len_signed = c.i2d_PUBKEY(pkey, null);
    if (der_len_signed <= 0) return error.DerEncodeFailed;
    const der_len: usize = @intCast(der_len_signed);

    const owned_der = try allocator.alloc(u8, der_len);
    errdefer allocator.free(owned_der);

    // i2d_PUBKEY with a non-null **pp writes into *pp and advances *pp past the
    // encoded bytes.  The DER data lives in owned_der[0..der_len] regardless of
    // where der_ptr ends up after the call.
    var der_ptr: [*c]u8 = owned_der.ptr;
    if (c.i2d_PUBKEY(pkey, @ptrCast(&der_ptr)) != der_len_signed)
        return error.DerEncodeIncomplete;

    return RsaKeyPair{
        .pub_key_der = owned_der,
        ._pkey_int = @intFromPtr(pkey.?),
    };
}

/// Decrypt a CiphertextForRecipient blob and return the 32-byte plaintext DEK.
///
/// KMS returns CiphertextForRecipient as a 256-byte RSAES-OAEP-SHA256 block
/// (the RSA-2048 block size) encrypting the raw plaintext DEK bytes.
/// OAEP uses SHA-256 for both the hash and the MGF1 mask-generation function,
/// matching the KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256" field we send.
pub fn unwrapDek(key_pair: *const RsaKeyPair, ciphertext: []const u8) ![32]u8 {
    if (ciphertext.len != 256) return error.UnexpectedCiphertextLength;

    const pkey: *c.EVP_PKEY = @ptrFromInt(key_pair._pkey_int);

    const ctx = c.EVP_PKEY_CTX_new(pkey, null) orelse
        return error.EvpDecryptCtxFailed;
    defer c.EVP_PKEY_CTX_free(ctx);

    if (c.EVP_PKEY_decrypt_init(ctx) <= 0) return error.EvpDecryptInitFailed;
    if (c.EVP_PKEY_CTX_set_rsa_padding(ctx, c.RSA_PKCS1_OAEP_PADDING) <= 0)
        return error.EvpPaddingFailed;
    if (c.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, c.EVP_sha256()) <= 0)
        return error.EvpOaepMdFailed;
    if (c.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, c.EVP_sha256()) <= 0)
        return error.EvpMgfMdFailed;

    // First call with null output pointer to determine plaintext length.
    var out_len: usize = 0;
    if (c.EVP_PKEY_decrypt(ctx, null, &out_len, ciphertext.ptr, ciphertext.len) <= 0)
        return error.EvpDecryptSizeFailed;

    // The DEK must be exactly 32 bytes (AES-256).
    if (out_len != 32) return error.UnexpectedDekLength;

    var dek: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &dek);
    if (c.EVP_PKEY_decrypt(ctx, &dek, &out_len, ciphertext.ptr, ciphertext.len) <= 0)
        return error.EvpDecryptFailed;
    if (out_len != 32) return error.UnexpectedDekLength;

    return dek;
}
