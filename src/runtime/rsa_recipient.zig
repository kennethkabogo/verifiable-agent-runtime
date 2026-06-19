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
    @cInclude("openssl/cms.h");
    @cInclude("openssl/bio.h");
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

/// Decrypt a CiphertextForRecipient blob returned by AWS KMS Decrypt with Recipient.
///
/// AWS KMS does NOT return a raw 256-byte RSA-2048 ciphertext.  It returns a
/// DER-encoded CMS EnvelopedData structure (PKCS#7, ~467 bytes) that wraps the
/// RSA-OAEP-SHA256-encrypted DEK inside standard CMS headers.  This function
/// parses that structure with d2i_CMS_ContentInfo and decrypts it with
/// CMS_decrypt using the ephemeral private key.
///
/// Why CMS rather than raw RSA bytes: AWS KMS uses the CMS EnvelopedData
/// format (RFC 5652 §6) for the Recipient flow regardless of the
/// KeyEncryptionAlgorithm.  The ~155-byte overhead beyond the 256-byte RSA
/// block is the PKCS#7 OID, AlgorithmIdentifier, and RecipientInfo headers.
/// This is not documented clearly in the KMS API reference; the evidence is
/// the response body size (~778 bytes = ~155 JSON + ~623 base64 = ~467 binary)
/// and the leading 0x30 / 06 09 2a 86 48 86 f7 0d 01 07 06 DER bytes.
pub fn decryptCmsEnvelopedData(key_pair: *const RsaKeyPair, der: []const u8) ![32]u8 {
    const pkey: *c.EVP_PKEY = @ptrFromInt(key_pair._pkey_int);

    // d2i_CMS_ContentInfo advances der_ptr past consumed bytes; use a local copy.
    var der_ptr: [*c]const u8 = der.ptr;
    const cms = c.d2i_CMS_ContentInfo(null, &der_ptr, @intCast(der.len)) orelse
        return error.CmsParseFailed;
    defer c.CMS_ContentInfo_free(cms);

    const out_bio = c.BIO_new(c.BIO_s_mem()) orelse
        return error.BioAllocFailed;
    defer _ = c.BIO_free(out_bio);

    // pkey = ephemeral RSA private key; cert = NULL skips certificate lookup;
    // dcont = NULL because content is embedded; flags = 0.
    if (c.CMS_decrypt(cms, pkey, null, null, out_bio, 0) <= 0)
        return error.CmsDecryptFailed;

    var dek: [32]u8 = undefined;
    const n = c.BIO_read(out_bio, &dek, 32);
    if (n != 32) return error.UnexpectedDekLength;

    return dek;
}
