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
///   POST /exec           {"cmd":["arg0","arg1",…]}          → 200 {"exit_code":0,"stdout_b64":"…","stderr_b64":"…","stdout_hash":"…","stderr_hash":"…"}
///   POST /hibernate                                          → 200 {"sealed_state":"<hex>"}  (gateway exits cleanly after response)
///   GET  /evidence                                           → 200 {"stream":"…","state":"…","sig":"…","executions":[…]}
///   GET  /attestation                                        → 200 {"pcr0":"…","pcr1":"…","pcr2":"…","public_key":"…","doc":"…"}
///   GET  /session                                            → 200 {"session_id":"…","bootstrap_nonce":"…","magic":"VARB","version":"01","bundle_header":"BUNDLE_HEADER:…"}
///   GET  /verify-and-attest                                  → 200 {"decision":{…},"evidence":{…},"attestation":{…}}
///   GET  /health                                             → 200 {"status":"healthy"}
///
const std = @import("std");
const mem = std.mem;
const net = std.net;
const Allocator = mem.Allocator;

const SecureVault = @import("vault.zig").SecureVault;
const SecureLogger = @import("shell.zig").SecureLogger;
const AttestationQuote = @import("attestation.zig").AttestationQuote;
const sealed_state = @import("sealed_state.zig");

// ── Shutdown flag (set by signal handler in http_main.zig) ─────────────────

var g_shutdown = std.atomic.Value(bool).init(false);

/// Called from a SIGTERM/SIGINT handler to request a clean shutdown.
/// Safe to call from signal context — only touches an atomic store.
pub fn requestShutdown() void {
    g_shutdown.store(true, .monotonic);
}

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
    /// X25519 public key used for secret encryption.
    /// Included in GET /session so the bundle_header field is complete.
    enc_pub: [32]u8,

    pub fn init(
        allocator: Allocator,
        config: GatewayConfig,
        vault: *SecureVault,
        logger: *SecureLogger,
        quote: *AttestationQuote,
        session_id: [16]u8,
        bootstrap_nonce: [32]u8,
        enc_pub: [32]u8,
    ) GatewayServer {
        return .{
            .allocator = allocator,
            .config = config,
            .vault = vault,
            .logger = logger,
            .quote = quote,
            .session_id = session_id,
            .bootstrap_nonce = bootstrap_nonce,
            .enc_pub = enc_pub,
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
                if (g_shutdown.load(.monotonic)) return;
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

    // 30-second read timeout guards against slow-loris: a client that sends
    // headers one byte at a time and never completes them would otherwise hold
    // a thread indefinitely.  Failure is non-fatal — the connection proceeds
    // without a timeout (the buffer cap still limits total bytes read).
    const timeout = std.posix.timeval{ .sec = 30, .usec = 0 };
    std.posix.setsockopt(
        conn.stream.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout),
    ) catch {};

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
    if (post and mem.eql(u8, req.path, "/exec"))
        return handleExec(server, stream, req);
    if (post and mem.eql(u8, req.path, "/hibernate"))
        return handleHibernate(server, stream, req);
    if (get and mem.eql(u8, req.path, "/evidence"))
        return handleEvidence(server, stream, req);
    if (get and mem.eql(u8, req.path, "/attestation"))
        return handleAttestation(server, stream, req);
    if (get and mem.eql(u8, req.path, "/session"))
        return handleSession(server, stream, req);
    if (get and mem.eql(u8, req.path, "/verify-and-attest"))
        return handleVerifyAndAttest(server, stream, req);
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

    // Optional action_id links this log entry to an escrow event so the
    // evidence chain can be matched to a specific payment or settlement.
    const action_id = jsonGetString(req.body, "action_id", server.allocator);
    defer if (action_id) |id| server.allocator.free(id);

    const has_skill = !mem.eql(u8, req.skill_id, "unknown");

    // Build the final log line, incorporating skill and/or action tags when present.
    const line = if (has_skill and action_id != null)
        try std.fmt.allocPrint(server.allocator, "[SKILL:{s}][ACTION:{s}] {s}", .{ req.skill_id, action_id.?, msg })
    else if (has_skill)
        try std.fmt.allocPrint(server.allocator, "[SKILL:{s}] {s}", .{ req.skill_id, msg })
    else if (action_id != null)
        try std.fmt.allocPrint(server.allocator, "[ACTION:{s}] {s}", .{ action_id.?, msg })
    else
        try server.allocator.dupe(u8, msg);
    defer server.allocator.free(line);

    try server.logger.logOutput(line);
    try writeResponse(stream, 200, "{\"status\":\"ok\"}");
}

fn handleExec(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    // Parse {"cmd": ["arg0", "arg1", ...]} from the request body.
    var parsed = std.json.parseFromSlice(
        std.json.Value,
        server.allocator,
        req.body,
        .{},
    ) catch return writeError(stream, 400, "invalid JSON");
    defer parsed.deinit();

    const cmd_val = switch (parsed.value) {
        .object => |obj| obj.get("cmd") orelse return writeError(stream, 400, "missing \"cmd\" field"),
        else => return writeError(stream, 400, "request body must be a JSON object"),
    };
    const cmd_arr = switch (cmd_val) {
        .array => |arr| arr,
        else => return writeError(stream, 400, "\"cmd\" must be a JSON array"),
    };
    if (cmd_arr.items.len == 0)
        return writeError(stream, 400, "\"cmd\" must not be empty");

    // Build a [][]const u8 argv from the parsed array.
    var argv = try server.allocator.alloc([]const u8, cmd_arr.items.len);
    defer server.allocator.free(argv);
    for (cmd_arr.items, 0..) |item, i| {
        argv[i] = switch (item) {
            .string => |s| s,
            else => return writeError(stream, 400, "\"cmd\" items must be strings"),
        };
    }

    // Run the command, fold stdout into the L1 chain, and record exec metadata.
    const result = server.logger.runAndLog(argv) catch |err| {
        std.log.err("[VAR-gateway] exec failed: {}", .{err});
        return writeError(stream, 500, "exec failed");
    };
    defer result.deinit(server.allocator);

    // Base64-encode stdout and stderr for safe JSON embedding.
    const Encoder = std.base64.standard.Encoder;
    const stdout_b64 = try server.allocator.alloc(u8, Encoder.calcSize(result.stdout.len));
    defer server.allocator.free(stdout_b64);
    _ = Encoder.encode(stdout_b64, result.stdout);

    const stderr_b64 = try server.allocator.alloc(u8, Encoder.calcSize(result.stderr.len));
    defer server.allocator.free(stderr_b64);
    _ = Encoder.encode(stderr_b64, result.stderr);

    // Compute content hashes for the response (consistent with last_exec in /evidence).
    var stdout_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(result.stdout, &stdout_hash, .{});
    var stderr_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(result.stderr, &stderr_hash, .{});

    const sh = try fmtHex(server.allocator, &stdout_hash);
    defer server.allocator.free(sh);
    const eh = try fmtHex(server.allocator, &stderr_hash);
    defer server.allocator.free(eh);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"exit_code\":{d},\"stdout_b64\":\"{s}\",\"stderr_b64\":\"{s}\",\"stdout_hash\":\"{s}\",\"stderr_hash\":\"{s}\"}}",
        .{ result.exit_code, stdout_b64, stderr_b64, sh, eh },
    );
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

fn handleEvidence(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    const body = try server.logger.getEvidenceBundleJson(server.allocator);
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

fn handleHibernate(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    // Capture and seal all runtime state into an encrypted blob.
    var captured = try sealed_state.capture(server.allocator, server.vault, server.logger);
    defer captured.deinit();

    const blob = try sealed_state.seal(server.allocator, &captured);
    defer server.allocator.free(blob);

    const hex_blob = try fmtHex(server.allocator, blob);
    defer server.allocator.free(hex_blob);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"sealed_state\":\"{s}\"}}",
        .{hex_blob},
    );
    defer server.allocator.free(body);

    // Send the response before signalling shutdown — the current connection's
    // handler runs in a detached thread, so the response is flushed before the
    // main serve() loop exits.
    try writeResponse(stream, 200, body);
    std.log.info("[VAR-gateway] Hibernating ({d}-byte sealed blob). Sending SIGTERM.", .{blob.len});

    // Set the shutdown flag and interrupt the blocking accept() in serve().
    requestShutdown();
    std.posix.kill(std.c.getpid(), std.posix.SIG.TERM) catch {};
}

fn handleAttestation(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    const pcr0_h = try fmtHex(server.allocator, &server.quote.pcr0);
    defer server.allocator.free(pcr0_h);
    const pcr1_h = try fmtHex(server.allocator, &server.quote.pcr1);
    defer server.allocator.free(pcr1_h);
    const pcr2_h = try fmtHex(server.allocator, &server.quote.pcr2);
    defer server.allocator.free(pcr2_h);
    const pk_h = try fmtHex(server.allocator, &server.quote.public_key);
    defer server.allocator.free(pk_h);
    const doc_h = try fmtHex(server.allocator, server.quote.doc);
    defer server.allocator.free(doc_h);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"pcr0\":\"{s}\",\"pcr1\":\"{s}\",\"pcr2\":\"{s}\",\"public_key\":\"{s}\",\"doc\":\"{s}\"}}",
        .{ pcr0_h, pcr1_h, pcr2_h, pk_h, doc_h },
    );
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

fn handleSession(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    const sid_h     = try fmtHex(server.allocator, &server.session_id);
    defer server.allocator.free(sid_h);
    const nonce_h   = try fmtHex(server.allocator, &server.bootstrap_nonce);
    defer server.allocator.free(nonce_h);
    const enc_pub_h = try fmtHex(server.allocator, &server.enc_pub);
    defer server.allocator.free(enc_pub_h);
    const pcr0_h    = try fmtHex(server.allocator, &server.quote.pcr0);
    defer server.allocator.free(pcr0_h);
    const pcr1_h    = try fmtHex(server.allocator, &server.quote.pcr1);
    defer server.allocator.free(pcr1_h);
    const pcr2_h    = try fmtHex(server.allocator, &server.quote.pcr2);
    defer server.allocator.free(pcr2_h);
    const pk_h      = try fmtHex(server.allocator, &server.quote.public_key);
    defer server.allocator.free(pk_h);
    const doc_h     = try fmtHex(server.allocator, server.quote.doc);
    defer server.allocator.free(doc_h);

    // Reconstruct the full BUNDLE_HEADER line — identical to what protocol.zig
    // emits over vsock.  Returned here so clients (demo harness, verifier) can
    // pass it directly to verify.py without reconstructing it themselves.
    const bundle_header = try std.fmt.allocPrint(
        server.allocator,
        "BUNDLE_HEADER:magic=VARB:version=01:session={s}:nonce={s}:enc_pub={s}:QUOTE:pcr0={s}:pcr1={s}:pcr2={s}:pk={s}:doc={s}",
        .{ sid_h, nonce_h, enc_pub_h, pcr0_h, pcr1_h, pcr2_h, pk_h, doc_h },
    );
    defer server.allocator.free(bundle_header);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"session_id\":\"{s}\",\"bootstrap_nonce\":\"{s}\",\"magic\":\"VARB\",\"version\":\"01\",\"bundle_header\":\"{s}\"}}",
        .{ sid_h, nonce_h, bundle_header },
    );
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

fn handleVerifyAndAttest(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;

    // Evidence bundle — calling this advances the sequence counter and commits
    // the current L1 state, producing a fresh signed snapshot for the caller.
    const evidence_json = try server.logger.getEvidenceBundleJson(server.allocator);
    defer server.allocator.free(evidence_json);

    // Attestation fields (same as /attestation).
    const pcr0_h = try fmtHex(server.allocator, &server.quote.pcr0);
    defer server.allocator.free(pcr0_h);
    const pcr1_h = try fmtHex(server.allocator, &server.quote.pcr1);
    defer server.allocator.free(pcr1_h);
    const pcr2_h = try fmtHex(server.allocator, &server.quote.pcr2);
    defer server.allocator.free(pcr2_h);
    const pk_h = try fmtHex(server.allocator, &server.quote.public_key);
    defer server.allocator.free(pk_h);
    const doc_h = try fmtHex(server.allocator, server.quote.doc);
    defer server.allocator.free(doc_h);

    // Simulation mode: PCR0 = 0xAA * 48 (set by mock NSM when /dev/nsm absent).
    const sim_mode = for (server.quote.pcr0) |byte| {
        if (byte != 0xAA) break false;
    } else true;

    // Embed evidence and attestation as nested JSON objects (not quoted strings)
    // so a caller can parse the entire response as a single JSON document.
    // The caller MUST verify the Ed25519 signature in evidence.sig against
    // attestation.public_key before treating this response as authoritative.
    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"decision\":{{\"sim_mode\":{s},\"note\":\"Verify evidence.sig against attestation.public_key before releasing escrow.\"}},\"evidence\":{s},\"attestation\":{{\"pcr0\":\"{s}\",\"pcr1\":\"{s}\",\"pcr2\":\"{s}\",\"public_key\":\"{s}\",\"doc\":\"{s}\"}}}}",
        .{
            if (sim_mode) "true" else "false",
            evidence_json,
            pcr0_h, pcr1_h, pcr2_h, pk_h, doc_h,
        },
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

// ── Tests ──────────────────────────────────────────────────────────────────

test "parseRequest: valid GET" {
    var buf = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n".*;
    const req = parseRequest(&buf, buf.len).?;
    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/health", req.path);
    try std.testing.expectEqualStrings("", req.body);
}

test "parseRequest: valid POST with body" {
    var buf = "POST /log HTTP/1.1\r\nContent-Length: 15\r\nX-Skill-Id: demo\r\n\r\n{\"msg\":\"hello\"}".*;
    const req = parseRequest(&buf, buf.len).?;
    try std.testing.expectEqualStrings("POST", req.method);
    try std.testing.expectEqualStrings("/log", req.path);
    try std.testing.expectEqualStrings("demo", req.skill_id);
    try std.testing.expectEqualStrings("{\"msg\":\"hello\"}", req.body);
}

test "parseRequest: missing header terminator returns null" {
    // No \r\n\r\n — incomplete headers should not parse.
    var buf = "GET /health HTTP/1.1\r\nHost: localhost\r\n".*;
    try std.testing.expect(parseRequest(&buf, buf.len) == null);
}

test "parseRequest: empty input returns null" {
    var buf = [_]u8{};
    try std.testing.expect(parseRequest(&buf, 0) == null);
}

test "parseRequest: missing path returns null" {
    // Request line has only one token.
    var buf = "GET\r\n\r\n".*;
    try std.testing.expect(parseRequest(&buf, buf.len) == null);
}

test "parseRequest: unknown skill-id defaults to 'unknown'" {
    var buf = "POST /log HTTP/1.1\r\nContent-Length: 0\r\n\r\n".*;
    const req = parseRequest(&buf, buf.len).?;
    try std.testing.expectEqualStrings("unknown", req.skill_id);
}

test "jsonGetString: extracts plain value" {
    const json = "{\"key\":\"myvalue\",\"other\":\"x\"}";
    const val = jsonGetString(json, "key", std.testing.allocator).?;
    defer std.testing.allocator.free(val);
    try std.testing.expectEqualStrings("myvalue", val);
}

test "jsonGetString: returns null for missing key" {
    const json = "{\"other\":\"x\"}";
    try std.testing.expect(jsonGetString(json, "key", std.testing.allocator) == null);
}

test "jsonGetString: handles escaped quote in value" {
    const json = "{\"msg\":\"say \\\"hi\\\"\"}";
    const val = jsonGetString(json, "msg", std.testing.allocator).?;
    defer std.testing.allocator.free(val);
    // Raw bytes are returned (un-unescaped), so the backslashes are present.
    try std.testing.expect(val.len > 0);
}
