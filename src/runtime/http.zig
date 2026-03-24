/// HTTP/1.1 gateway server for the Verifiable Agent Runtime.
///
/// Exposes VAR session state over a REST-ish API bound to loopback (or the
/// vsock internal interface inside the enclave), turning VAR into a
/// "verifiable sidecar" that any co-located skill can call regardless of the
/// language or framework it was written in.
///
/// Endpoints:
///
///   POST /vault/secret   {"key":"…","value":"…"}           → 200 {"status":"ok"}
///   POST /log            {"msg":"…"}  (+X-Skill-Id header)  → 200 {"status":"ok"}
///   GET  /evidence                                           → 200 {"stream":"…","state":"…","sig":"…"}
///   GET  /attestation                                        → 200 {"pcr0":"…","public_key":"…","doc":"…"}
///   GET  /session                                            → 200 {"session_id":"…","bootstrap_nonce":"…","magic":"VARB","version":"01"}
///   GET  /health                                             → 200 {"status":"healthy"}
///
const std = @import("std");
const mem = std.mem;
const net = std.net;
const Allocator = mem.Allocator;

const SecureVault = @import("vault.zig").SecureVault;
const SecureLogger = @import("shell.zig").SecureLogger;
const AttestationQuote = @import("attestation.zig").AttestationQuote;

// ── Limits ─────────────────────────────────────────────────────────────────

/// Maximum byte length of any single JSON string value extracted from a
/// request body.  Prevents oversized allocations even when the caller crafts
/// a value that fills the entire request buffer.
const MAX_FIELD_BYTES: usize = 8192;

// ── Configuration ──────────────────────────────────────────────────────────

pub const GatewayConfig = struct {
    /// Host to bind. Defaults to loopback so only processes inside the enclave
    /// can reach the gateway; the host proxy remains the sole external surface.
    host: []const u8 = "127.0.0.1",
    port: u16 = 8765,
};

// ── Server ─────────────────────────────────────────────────────────────────

pub const GatewayServer = struct {
    allocator: Allocator,
    config: GatewayConfig,
    vault: *SecureVault,
    logger: *SecureLogger,
    quote: *AttestationQuote,
    /// UUID v4 session identifier (16 raw bytes).
    session_id: [16]u8,
    /// Bootstrap nonce = SHA-256(attestation_doc ‖ session_id).
    /// Exposed via GET /session so an external verifier can recompute and confirm it.
    bootstrap_nonce: [32]u8,

    pub fn init(
        allocator: Allocator,
        config: GatewayConfig,
        vault: *SecureVault,
        logger: *SecureLogger,
        quote: *AttestationQuote,
        session_id: [16]u8,
        bootstrap_nonce: [32]u8,
    ) GatewayServer {
        return .{
            .allocator = allocator,
            .config = config,
            .vault = vault,
            .logger = logger,
            .quote = quote,
            .session_id = session_id,
            .bootstrap_nonce = bootstrap_nonce,
        };
    }

    /// Blocks forever, accepting connections and spawning one thread per request.
    pub fn serve(self: *GatewayServer) !void {
        const addr = try net.Address.parseIp(self.config.host, self.config.port);
        var server = try addr.listen(.{ .reuse_address = true });
        defer server.deinit();

        std.log.info("[VAR-gateway] listening on {s}:{d}", .{ self.config.host, self.config.port });

        while (true) {
            const conn = server.accept() catch |err| {
                std.log.err("[VAR-gateway] accept: {}", .{err});
                continue;
            };
            const thread = std.Thread.spawn(.{}, handleConnection, .{ self, conn }) catch |err| {
                std.log.err("[VAR-gateway] thread spawn: {}", .{err});
                conn.stream.close();
                continue;
            };
            thread.detach();
        }
    }
};

// ── Request parsing ────────────────────────────────────────────────────────

const ParsedRequest = struct {
    method: []const u8,
    path: []const u8,
    /// Value of the X-Skill-Id header (slice into the read buffer).
    skill_id: []const u8,
    /// Body slice (points into the read buffer; valid while buf is live).
    body: []const u8,
};

/// Parses a minimal HTTP/1.1 request from `buf[0..len]`.
/// All returned slices point into `buf` — no allocation needed.
fn parseRequest(buf: []u8, len: usize) ?ParsedRequest {
    const raw = buf[0..len];

    // Locate end of headers.
    const header_end = mem.indexOf(u8, raw, "\r\n\r\n") orelse return null;
    const headers = raw[0..header_end];

    // Parse request line (METHOD SP path SP HTTP/x.y).
    const line_end = mem.indexOf(u8, headers, "\r\n") orelse headers.len;
    var parts = mem.splitScalar(u8, headers[0..line_end], ' ');
    const method = parts.next() orelse return null;
    const path = parts.next() orelse return null;

    // Parse headers we care about.
    var skill_id: []const u8 = "unknown";
    var content_length: usize = 0;
    var lines = mem.splitSequence(u8, headers[line_end..], "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = mem.trim(u8, line[0..colon], " \t");
        const val = mem.trim(u8, line[colon + 1 ..], " \t");
        if (mem.eql(u8, name, "X-Skill-Id")) skill_id = val;
        if (std.ascii.eqlIgnoreCase(name, "content-length"))
            content_length = std.fmt.parseInt(usize, val, 10) catch 0;
    }

    const body_start = header_end + 4;
    const body = if (content_length > 0 and body_start + content_length <= len)
        raw[body_start .. body_start + content_length]
    else
        raw[body_start..len];

    return .{
        .method = method,
        .path = path,
        .skill_id = skill_id,
        .body = body,
    };
}

// ── Connection handler ─────────────────────────────────────────────────────

fn handleConnection(server: *GatewayServer, conn: net.Server.Connection) void {
    defer conn.stream.close();

    // Fixed stack buffer — caps total request size (headers + body) at 16 KiB.
    var buf: [16384]u8 = undefined;
    var total: usize = 0;

    // Phase 1: read until we see the end-of-headers sentinel (\r\n\r\n).
    const header_end: usize = blk: {
        while (total < buf.len) {
            const n = conn.stream.read(buf[total..]) catch {
                _ = writeError(conn.stream, 400, "Bad Request") catch {};
                return;
            };
            if (n == 0) break;
            total += n;
            if (mem.indexOf(u8, buf[0..total], "\r\n\r\n")) |pos| break :blk pos;
        }
        _ = writeError(conn.stream, 400, "Bad Request") catch {};
        return;
    };

    // Extract Content-Length from the header block so we know exactly how many
    // body bytes to expect.  Parsing here (rather than relying on parseRequest)
    // lets us read the full body before handing off, eliminating the silent
    // partial-body acceptance that the single-extra-read approach had.
    var content_length: usize = 0;
    {
        var lines = mem.splitSequence(u8, buf[0..header_end], "\r\n");
        _ = lines.next(); // skip request line
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const colon = mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = mem.trim(u8, line[0..colon], " \t");
            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                const val = mem.trim(u8, line[colon + 1 ..], " \t");
                content_length = std.fmt.parseInt(usize, val, 10) catch 0;
            }
        }
    }

    // Phase 2: read until the body is fully received.
    //
    // Guard against integer overflow and buffer exhaustion before reading any
    // body bytes.  body_start <= total is guaranteed by Phase 1 (we found the
    // sentinel, so total >= header_end + 4 = body_start).
    const body_start_idx = header_end + 4;
    if (content_length > buf.len - body_start_idx) {
        _ = writeError(conn.stream, 413, "Request Too Large") catch {};
        return;
    }
    const needed = body_start_idx + content_length;
    while (total < needed) {
        const n = conn.stream.read(buf[total..needed]) catch {
            _ = writeError(conn.stream, 400, "Bad Request") catch {};
            return;
        };
        if (n == 0) {
            // Client closed the connection before sending the full body.
            _ = writeError(conn.stream, 400, "Bad Request") catch {};
            return;
        }
        total += n;
    }

    const req = parseRequest(&buf, total) orelse {
        writeError(conn.stream, 400, "Bad Request") catch {};
        return;
    };

    route(server, conn.stream, req) catch |err| {
        std.log.err("[VAR-gateway] handler error: {}", .{err});
        writeError(conn.stream, 500, "Internal Server Error") catch {};
    };
}

// ── Router ─────────────────────────────────────────────────────────────────

fn route(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    const post = mem.eql(u8, req.method, "POST");
    const get = mem.eql(u8, req.method, "GET");

    if (post and mem.eql(u8, req.path, "/vault/secret"))
        return handleVaultSecret(server, stream, req);
    if (post and mem.eql(u8, req.path, "/log"))
        return handleLog(server, stream, req);
    if (get and mem.eql(u8, req.path, "/evidence"))
        return handleEvidence(server, stream, req);
    if (get and mem.eql(u8, req.path, "/attestation"))
        return handleAttestation(server, stream, req);
    if (get and mem.eql(u8, req.path, "/session"))
        return handleSession(server, stream, req);
    if (get and mem.eql(u8, req.path, "/health"))
        return writeResponse(stream, 200, "{\"status\":\"healthy\"}");

    return writeError(stream, 404, "Not Found");
}

// ── Handlers ──────────────────────────────────────────────────────────────

fn handleVaultSecret(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    const key = jsonGetString(req.body, "key", server.allocator) orelse
        return writeError(stream, 400, "missing \"key\" field");
    defer server.allocator.free(key);
    const value = jsonGetString(req.body, "value", server.allocator) orelse
        return writeError(stream, 400, "missing \"value\" field");
    defer server.allocator.free(value);

    try server.vault.store(key, value);
    try writeResponse(stream, 200, "{\"status\":\"ok\"}");
}

fn handleLog(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    const msg = jsonGetString(req.body, "msg", server.allocator) orelse
        return writeError(stream, 400, "missing \"msg\" field");
    defer server.allocator.free(msg);

    // Prefix with skill identifier when provided so the evidence chain records
    // which modular skill emitted each entry.
    if (!mem.eql(u8, req.skill_id, "unknown")) {
        const tagged = try std.fmt.allocPrint(
            server.allocator,
            "[SKILL:{s}] {s}",
            .{ req.skill_id, msg },
        );
        defer server.allocator.free(tagged);
        try server.logger.logOutput(tagged);
    } else {
        try server.logger.logOutput(msg);
    }

    try writeResponse(stream, 200, "{\"status\":\"ok\"}");
}

fn handleEvidence(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    const body = try server.logger.getEvidenceBundleJson(server.allocator);
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

fn handleAttestation(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    const pcr0_h = try fmtHex(server.allocator, &server.quote.pcr0);
    defer server.allocator.free(pcr0_h);
    const pk_h = try fmtHex(server.allocator, &server.quote.public_key);
    defer server.allocator.free(pk_h);
    const doc_h = try fmtHex(server.allocator, server.quote.doc);
    defer server.allocator.free(doc_h);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"pcr0\":\"{s}\",\"public_key\":\"{s}\",\"doc\":\"{s}\"}}",
        .{ pcr0_h, pk_h, doc_h },
    );
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

fn handleSession(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    const sid_h = try fmtHex(server.allocator, &server.session_id);
    defer server.allocator.free(sid_h);
    const nonce_h = try fmtHex(server.allocator, &server.bootstrap_nonce);
    defer server.allocator.free(nonce_h);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"session_id\":\"{s}\",\"bootstrap_nonce\":\"{s}\",\"magic\":\"VARB\",\"version\":\"01\"}}",
        .{ sid_h, nonce_h },
    );
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

// ── JSON helpers ───────────────────────────────────────────────────────────

/// Extracts the string value for `key` from a flat JSON object.
/// Returns a heap-allocated copy; caller must free.  Returns null on any error.
fn jsonGetString(json: []const u8, key: []const u8, allocator: Allocator) ?[]u8 {
    var search_buf: [128]u8 = undefined;
    const pattern = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{key}) catch return null;
    const key_pos = mem.indexOf(u8, json, pattern) orelse return null;

    var rest = json[key_pos + pattern.len ..];
    rest = mem.trimLeft(u8, rest, " \t\r\n");
    if (rest.len == 0 or rest[0] != ':') return null;
    rest = mem.trimLeft(u8, rest[1..], " \t\r\n");
    if (rest.len == 0 or rest[0] != '"') return null;
    rest = rest[1..]; // skip opening quote

    // Scan to the closing quote, respecting backslash escapes so that a value
    // containing \" does not cause early truncation.  The raw (un-unescaped)
    // bytes are returned — correct for opaque values like API keys and log
    // messages that callers treat as byte strings, not decoded JSON text.
    // A hard cap at MAX_FIELD_BYTES prevents outsized allocations.
    var end: usize = 0;
    while (end < rest.len and end < MAX_FIELD_BYTES) {
        if (rest[end] == '\\') {
            // Skip the backslash and the character it escapes; any valid JSON
            // escape sequence is exactly two characters at this level.
            end += if (end + 1 < rest.len) 2 else 1;
            continue;
        }
        if (rest[end] == '"') break;
        end += 1;
    }
    if (end >= MAX_FIELD_BYTES) return null; // value exceeds hard cap
    return allocator.dupe(u8, rest[0..end]) catch null;
}

fn fmtHex(allocator: Allocator, bytes: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, bytes.len * 2);
    const chars = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        result[i * 2] = chars[b >> 4];
        result[i * 2 + 1] = chars[b & 0x0f];
    }
    return result;
}

// ── HTTP response helpers ──────────────────────────────────────────────────

fn writeResponse(stream: net.Stream, status: u16, body: []const u8) !void {
    const status_text: []const u8 = switch (status) {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Request Entity Too Large",
        500 => "Internal Server Error",
        else => "Unknown",
    };
    
    var h_buf: [512]u8 = undefined;
    const headers = try std.fmt.bufPrint(&h_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ status, status_text, body.len },
    );
    try stream.writeAll(headers);
    try stream.writeAll(body);
}

fn writeError(stream: net.Stream, status: u16, msg: []const u8) !void {
    var buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&buf, "{{\"error\":\"{s}\"}}", .{msg}) catch
        "{\"error\":\"unknown\"}";
    try writeResponse(stream, status, body);
}
