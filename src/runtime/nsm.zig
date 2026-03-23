const std = @import("std");

/// AWS Nitro Secure Module (NSM) driver.
///
/// On real Nitro hardware the NSM character device is at /dev/nsm and is
/// accessed via ioctl with CBOR-encoded request/response payloads.
///
/// When the device is absent (dev/CI/simulation) we fall back to a
/// deterministic mock so the rest of the attestation pipeline can be tested
/// without hardware.
const NSM_DEV_PATH = "/dev/nsm";

/// _IOWR(0x0A, 0, struct nsm_raw) where sizeof(struct nsm_raw) == 32.
/// Computed as: (3 << 30) | (0x0A << 8) | (0 << 0) | (32 << 16) = 0xC020_0A00
const NSM_IOCTL_REQUEST: u32 = 0xC020_0A00;

const NSM_REQUEST_MAX_SIZE: usize = 0x1000;
const NSM_RESPONSE_MAX_SIZE: usize = 0x3000;
/// Real Nitro attestation documents are 1–3 KiB (COSE_Sign1 + certificate chain).
/// 16 KiB is a generous upper bound that still prevents runaway heap allocation
/// from a crafted CBOR length field.
const MAX_DOC_LEN: usize = 0x4000;

/// Mirrors `struct nsm_iovec` from the Nitro kernel driver (include/uapi/linux/nsm.h).
/// addr/len describe a caller-owned buffer; _pad makes the C struct layout explicit.
const NsmIovec = extern struct {
    addr: u64,
    len: u32,
    _pad: u32 = 0,
};

/// Mirrors `struct nsm_raw` — the single ioctl argument for /dev/nsm.
/// sizeof == 32; passed by pointer to the ioctl syscall.
const NsmRaw = extern struct {
    request: NsmIovec,
    response: NsmIovec,
};

comptime {
    // Verify layout matches the kernel struct before any runtime use.
    std.debug.assert(@sizeOf(NsmRaw) == 32);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Request an attestation document from the NSM.
/// Returns the raw document bytes (caller owns the allocation).
/// Falls back to a deterministic mock when /dev/nsm is not present.
pub fn getAttestationDoc(
    allocator: std.mem.Allocator,
    nonce: ?[]const u8,
    public_key: ?[]const u8,
) ![]u8 {
    const file = std.fs.openFileAbsolute(NSM_DEV_PATH, .{ .mode = .read_write }) catch {
        return requestMock(allocator);
    };
    defer file.close();
    return requestReal(allocator, file.handle, nonce, public_key);
}

// ---------------------------------------------------------------------------
// Real hardware path
// ---------------------------------------------------------------------------

fn requestReal(
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    nonce: ?[]const u8,
    public_key: ?[]const u8,
) ![]u8 {
    var req_buf: [NSM_REQUEST_MAX_SIZE]u8 = undefined;
    const req_len = try encodeCborRequest(&req_buf, nonce, public_key);

    var resp_buf: [NSM_RESPONSE_MAX_SIZE]u8 = undefined;

    var raw = NsmRaw{
        .request = .{
            .addr = @intFromPtr(&req_buf),
            .len = @intCast(req_len),
        },
        .response = .{
            .addr = @intFromPtr(&resp_buf),
            .len = NSM_RESPONSE_MAX_SIZE,
        },
    };

    const rc = std.os.linux.syscall3(
        .ioctl,
        @intCast(fd),
        NSM_IOCTL_REQUEST,
        @intFromPtr(&raw),
    );
    if (std.os.linux.getErrno(rc) != .SUCCESS) return error.NsmIoctlFailed;

    // The driver updates response.len with the actual bytes written.
    // Validate before using as a slice bound: a buggy or adversarial driver
    // returning a value larger than the buffer would cause an out-of-bounds
    // slice and undefined behaviour.
    if (raw.response.len > NSM_RESPONSE_MAX_SIZE) return error.NsmResponseTooLarge;
    const resp_slice = resp_buf[0..raw.response.len];
    return extractAttestationDoc(allocator, resp_slice);
}

// ---------------------------------------------------------------------------
// Mock path (simulation / CI)
// ---------------------------------------------------------------------------

/// Returns a stable 96-byte placeholder for the attestation document.
/// The bytes are fixed so the bootstrap nonce is deterministic in tests.
fn requestMock(allocator: std.mem.Allocator) ![]u8 {
    const doc = try allocator.alloc(u8, 96);
    @memset(doc, 0xAA);
    return doc;
}

// ---------------------------------------------------------------------------
// Minimal CBOR encoder for the NSM attestation request
//
// Wire format: {"Attestation": {"nonce": <bytes>?, "public_key": <bytes>?}}
// Absent optional fields are simply omitted (not null) per the NSM CBOR spec.
// ---------------------------------------------------------------------------

fn encodeCborRequest(
    buf: []u8,
    nonce: ?[]const u8,
    public_key: ?[]const u8,
) !usize {
    var pos: usize = 0;

    // Outer map: 1 entry  {"Attestation": ...}
    if (pos + 1 > buf.len) return error.CborBufferOverflow;
    buf[pos] = 0xa1;
    pos += 1;

    // Key: text "Attestation" (length 11 → 0x6b)
    pos = try writeCborText(buf, pos, "Attestation");

    // Count inner map entries (only present fields included)
    var inner_count: u8 = 0;
    if (nonce != null) inner_count += 1;
    if (public_key != null) inner_count += 1;
    if (pos + 1 > buf.len) return error.CborBufferOverflow;
    buf[pos] = 0xa0 | inner_count;
    pos += 1;

    if (nonce) |n| {
        pos = try writeCborText(buf, pos, "nonce");
        pos = try writeCborBytes(buf, pos, n);
    }
    if (public_key) |pk| {
        pos = try writeCborText(buf, pos, "public_key");
        pos = try writeCborBytes(buf, pos, pk);
    }

    return pos;
}

/// Writes a CBOR text string into buf[start..].  Returns the new position.
/// Returns error.CborBufferOverflow if the string does not fit.
fn writeCborText(buf: []u8, start: usize, s: []const u8) !usize {
    var pos = start;
    const len = s.len;
    if (len < 24) {
        if (pos + 1 + len > buf.len) return error.CborBufferOverflow;
        buf[pos] = 0x60 | @as(u8, @intCast(len));
        pos += 1;
    } else {
        // one-byte extended length (supports strings up to 255 bytes)
        if (pos + 2 + len > buf.len) return error.CborBufferOverflow;
        buf[pos] = 0x78;
        pos += 1;
        buf[pos] = @intCast(len);
        pos += 1;
    }
    @memcpy(buf[pos..][0..len], s);
    return pos + len;
}

/// Writes a CBOR byte string into buf[start..].  Returns the new position.
/// Returns error.CborBufferOverflow or error.CborBytesTooLong on failure.
fn writeCborBytes(buf: []u8, start: usize, b: []const u8) !usize {
    var pos = start;
    const len = b.len;
    if (len < 24) {
        if (pos + 1 + len > buf.len) return error.CborBufferOverflow;
        buf[pos] = 0x40 | @as(u8, @intCast(len));
        pos += 1;
    } else if (len < 256) {
        if (pos + 2 + len > buf.len) return error.CborBufferOverflow;
        buf[pos] = 0x58;
        pos += 1;
        buf[pos] = @intCast(len);
        pos += 1;
    } else {
        return error.CborBytesTooLong;
    }
    @memcpy(buf[pos..][0..len], b);
    return pos + len;
}

// ---------------------------------------------------------------------------
// Minimal CBOR response scanner
//
// Extracts the byte string that immediately follows the text key "document"
// inside the NSM response map ({"Attestation": {"document": <bytes>}}).
// We do a linear scan rather than a full CBOR parser to keep the code small.
// ---------------------------------------------------------------------------

fn extractAttestationDoc(allocator: std.mem.Allocator, resp: []const u8) ![]u8 {
    const needle = "document";
    const idx = std.mem.indexOf(u8, resp, needle) orelse return error.NoDocumentKey;
    var pos = idx + needle.len;

    if (pos >= resp.len) return error.TruncatedResponse;

    // The next CBOR item must be a byte string (major type 2).
    const hdr = resp[pos];
    pos += 1;
    if ((hdr >> 5) != 2) return error.UnexpectedCborType;

    const doc_len: usize = switch (hdr & 0x1f) {
        0...23 => |n| n,
        24 => blk: {
            if (pos >= resp.len) return error.TruncatedResponse;
            const n = resp[pos];
            pos += 1;
            break :blk n;
        },
        25 => blk: {
            if (pos + 2 > resp.len) return error.TruncatedResponse;
            const n = std.mem.readInt(u16, resp[pos..][0..2], .big);
            pos += 2;
            break :blk n;
        },
        else => return error.UnsupportedCborLength,
    };

    // Sanity-cap the claimed length before any allocation: prevents a crafted
    // CBOR length field from triggering a large heap allocation that would then
    // be immediately freed by a TruncatedResponse error.
    if (doc_len > MAX_DOC_LEN) return error.DocTooLarge;
    if (pos + doc_len > resp.len) return error.TruncatedResponse;
    return try allocator.dupe(u8, resp[pos..][0..doc_len]);
}
