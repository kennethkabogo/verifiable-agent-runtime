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
///   POST /terminate                                          → 200 {"evidence":{…},"bundle_seal":"BUNDLE_SEAL:…"}  (final proof, no resume blob, then exits)
///   GET  /evidence                                           → 200 {"stream":"…","state":"…","sig":"…","executions":[…]}
///   GET  /evidence?from=<seq>&to=<seq>                       → 200 {"from":N,"to":N,"count":K,"packets":[…]}
///   GET  /evidence/stream                                    → 200 text/event-stream (one "data: {…}\n\n" per evidence emission)
///   GET  /attestation                                        → 200 {"pcr0":"…","pcr1":"…","pcr2":"…","public_key":"…","doc":"…"}
///   GET  /session                                            → 200 {"session_id":"…","bootstrap_nonce":"…","magic":"VARB","version":"01","bundle_header":"BUNDLE_HEADER:…"}
///   GET  /verify-and-attest                                  → 200 {"decision":{…},"evidence":{…},"attestation":{…}}
///   GET  /seal                                               → 200 {"bundle_seal":"BUNDLE_SEAL:…"}
///   POST /settle         {"escrow_id":"<32hex>","amount":"…","currency":"…","recipient":"<128hex>"}
///                                                            → 200 {"settlement":"SETTLEMENT:…"}
///   GET  /health                                             → 200 {"status":"healthy"}
///   GET  /benchmark                                          → 200 {"params":{"m":65536,"t":3,"p":1},"n":7,"mean_ms":…,"p50_ms":…,"p95_ms":…,"min_ms":…,"max_ms":…}
///
const std = @import("std");
const mem = std.mem;
const net = std.net;
const Allocator = mem.Allocator;

const SecureVault = @import("vault.zig").SecureVault;
const SecureLogger = @import("shell.zig").SecureLogger;
const SettlementParams = @import("shell.zig").SettlementParams;
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

    /// Blocks forever, accepting connections and dispatching them to a bounded
    /// thread pool.  Bounded concurrency (default 64 workers) prevents
    /// unbounded thread creation under load — excess connections queue in the
    /// pool and are served as workers become free.  Override with the
    /// VAR_WORKER_THREADS environment variable (must be a positive integer).
    pub fn serve(self: *GatewayServer) !void {
        const addr = try net.Address.parseIp(self.config.host, self.config.port);
        var server = try addr.listen(.{ .reuse_address = true });
        defer server.deinit();

        const n_workers: u32 = blk: {
            const s = std.posix.getenv("VAR_WORKER_THREADS") orelse break :blk 64;
            break :blk std.fmt.parseInt(u32, s, 10) catch 64;
        };
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = self.allocator, .n_jobs = n_workers });
        defer pool.deinit();

        std.log.info("[VAR-gateway] listening on {s}:{d} (worker threads: {d})", .{
            self.config.host, self.config.port, n_workers,
        });

        // Spawn vsock listener so the host EC2 instance can reach the gateway
        // via AF_VSOCK (same port).  No-op on non-Linux or kernels without vsock.
        const vsock_port = std.fmt.parseInt(
            u32,
            std.posix.getenv("VAR_VSOCK_PORT") orelse "8765",
            10,
        ) catch 8765;
        if (std.Thread.spawn(.{}, serveVsock, .{ self, &pool, vsock_port })) |t| {
            t.detach();
        } else |err| {
            std.log.warn("[VAR-gateway] vsock thread unavailable ({})", .{err});
        }

        while (true) {
            const conn = server.accept() catch |err| {
                if (g_shutdown.load(.monotonic)) return;
                std.log.err("[VAR-gateway] accept: {}", .{err});
                continue;
            };
            pool.spawn(handleConnection, .{ self, conn }) catch |err| {
                std.log.err("[VAR-gateway] pool spawn: {}", .{err});
                conn.stream.close();
                continue;
            };
        }
    }
};

fn serveVsock(server: *GatewayServer, pool: *std.Thread.Pool, port: u32) void {
    if (comptime @import("builtin").os.tag != .linux) return;
    const vsock = @import("vsock.zig");
    var vs = vsock.VsockServer.listen(port) catch |err| {
        std.log.warn("[VAR-gateway] vsock listen failed ({})", .{err});
        return;
    };
    defer vs.close();
    if (!vs.is_vsock) {
        std.log.warn("[VAR-gateway] AF_VSOCK not available; vsock listener skipped", .{});
        return;
    }
    std.log.info("[VAR-gateway] vsock listener on port {d}", .{port});
    while (!g_shutdown.load(.monotonic)) {
        const handler = vs.accept() catch |err| {
            if (g_shutdown.load(.monotonic)) return;
            std.log.err("[VAR-gateway] vsock accept: {}", .{err});
            continue;
        };
        const conn = net.Server.Connection{
            .stream = handler.stream,
            .address = net.Address.parseIp4("127.0.0.1", 0) catch unreachable,
        };
        pool.spawn(handleConnection, .{ server, conn }) catch |err| {
            std.log.err("[VAR-gateway] vsock pool spawn: {}", .{err});
            handler.stream.close();
        };
    }
}

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
    if (post and mem.eql(u8, req.path, "/terminate"))
        return handleTerminate(server, stream, req);
    if (get and mem.startsWith(u8, req.path, "/evidence")) {
        if (mem.eql(u8, req.path, "/evidence/stream"))
            return handleEvidenceStream(server, stream, req);
        if (mem.indexOfScalar(u8, req.path, '?') != null)
            return handleEvidenceRange(server, stream, req);
        return handleEvidence(server, stream, req);
    }
    if (get and mem.eql(u8, req.path, "/attestation"))
        return handleAttestation(server, stream, req);
    if (get and mem.eql(u8, req.path, "/session"))
        return handleSession(server, stream, req);
    if (get and mem.eql(u8, req.path, "/verify-and-attest"))
        return handleVerifyAndAttest(server, stream, req);
    if (get and mem.eql(u8, req.path, "/seal"))
        return handleSeal(server, stream, req);
    if (post and mem.eql(u8, req.path, "/settle"))
        return handleSettle(server, stream, req);
    if (get and mem.eql(u8, req.path, "/health"))
        return writeResponse(stream, 200, "{\"status\":\"healthy\"}");
    if (get and mem.eql(u8, req.path, "/benchmark"))
        return handleBenchmark(server, stream);

    return writeError(stream, 404, "Not Found");
}

// ── Handlers ──────────────────────────────────────────────────────────────

fn handleVaultSecret(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    const key = jsonGetString(req.body, "key", server.allocator) orelse
        return writeError(stream, 400, "missing \"key\" field");
    defer {
        std.crypto.secureZero(u8, key);
        server.allocator.free(key);
    }
    const value = jsonGetString(req.body, "value", server.allocator) orelse
        return writeError(stream, 400, "missing \"value\" field");
    defer {
        std.crypto.secureZero(u8, value);
        server.allocator.free(value);
    }

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
    if (has_skill) try server.logger.noteSkillId(req.skill_id);
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

fn handleEvidenceRange(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    const q_pos = mem.indexOfScalar(u8, req.path, '?') orelse
        return writeError(stream, 400, "missing query parameters");
    const query = req.path[q_pos + 1 ..];

    const from_seq = parseQueryParam(query, "from") orelse
        return writeError(stream, 400, "missing or invalid \"from\" parameter");
    const to_seq = parseQueryParam(query, "to") orelse
        return writeError(stream, 400, "missing or invalid \"to\" parameter");
    if (from_seq > to_seq)
        return writeError(stream, 400, "\"from\" must be <= \"to\"");

    const body = try server.logger.getEvidenceRange(server.allocator, from_seq, to_seq);
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

/// Parses a single named parameter from an application/x-www-form-urlencoded
/// query string (e.g. "from=3&to=7"). Returns null if the name is absent or
/// the value cannot be parsed as a base-10 u64.
fn parseQueryParam(query: []const u8, name: []const u8) ?u64 {
    var it = mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (mem.eql(u8, pair[0..eq], name))
            return std.fmt.parseInt(u64, pair[eq + 1 ..], 10) catch null;
    }
    return null;
}

fn handleEvidenceStream(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    try stream.writeAll(
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/event-stream\r\n" ++
        "Cache-Control: no-cache\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n",
    );

    var cursor: usize = 0;
    outer: while (!g_shutdown.load(.monotonic)) {
        var out = std.ArrayListUnmanaged([]u8){};
        defer {
            for (out.items) |j| server.allocator.free(j);
            out.deinit(server.allocator);
        }
        cursor = try server.logger.pollEvidenceSince(
            server.allocator, cursor, 5 * std.time.ns_per_s, &out,
        );
        for (out.items) |json| {
            if (!writeSSEPacket(stream, json)) break :outer;
        }
    }
}

fn writeSSEPacket(stream: net.Stream, json: []const u8) bool {
    stream.writeAll("data: ") catch return false;
    stream.writeAll(json) catch return false;
    stream.writeAll("\n\n") catch return false;
    return true;
}

fn handleHibernate(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;

    // Emit TEMPORAL_PROOF before capturing state — the sealed checkpoint must
    // not precede the proof emission (§9.5 ordering).  On error, the session
    // state is unchanged and the caller can retry.
    const tp = try server.logger.emitTemporalProof(server.allocator);
    defer server.allocator.free(tp.line);

    // Capture and seal all runtime state.  The TEMPORAL_PROOF has already
    // advanced sequence and prev_stream_hash; capture() will snapshot that state.
    var captured = try sealed_state.capture(server.allocator, server.vault, server.logger);
    defer captured.deinit();

    // Bind the TemporalProofHash into the sealed payload (§10.2).
    captured.temporal_proof_hash = tp.hash;

    const blob = try sealed_state.seal(server.allocator, &captured);
    defer server.allocator.free(blob);

    const hex_blob = try fmtHex(server.allocator, blob);
    defer server.allocator.free(hex_blob);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"sealed_state\":\"{s}\",\"temporal_proof\":\"{s}\"}}",
        .{ hex_blob, tp.line },
    );
    defer server.allocator.free(body);

    // Send the response and flush before signalling shutdown.
    try writeResponse(stream, 200, body);
    // Half-close the send side so the TCP stack flushes the response buffer to
    // the client before SIGTERM terminates the process.
    std.posix.shutdown(stream.handle, .send) catch {};
    std.log.info("[VAR-gateway] Hibernating ({d}-byte sealed blob). TEMPORAL_PROOF at seq={d}.", .{ blob.len, server.logger.sequence });

    requestShutdown();
    std.posix.kill(std.c.getpid(), std.posix.SIG.TERM) catch {};
}

fn handleTerminate(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    // Emit one final signed evidence packet covering any work since the last
    // /evidence call, then seal the bundle so the TerminalDigest is computed
    // over every packet signature including the one we just emitted.
    const evidence_json = try server.logger.getEvidenceBundleJson(server.allocator);
    defer server.allocator.free(evidence_json);

    const seal_line = server.logger.sealBundle(server.allocator) catch |err| {
        std.log.err("[VAR-gateway] terminate: sealBundle: {}", .{err});
        return writeError(stream, 500, "sealBundle failed");
    };
    defer server.allocator.free(seal_line);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"evidence\":{s},\"bundle_seal\":\"{s}\"}}",
        .{ evidence_json, seal_line },
    );
    defer server.allocator.free(body);

    try writeResponse(stream, 200, body);
    // Flush before signalling shutdown — same rationale as /hibernate.
    std.posix.shutdown(stream.handle, .send) catch {};
    std.log.info("[VAR-gateway] Terminating with final proof. Sending SIGTERM.", .{});

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

fn handleSeal(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    _ = req;
    const line = server.logger.sealBundle(server.allocator) catch |err| {
        std.log.err("[VAR-gateway] sealBundle: {}", .{err});
        return writeError(stream, 500, "sealBundle failed");
    };
    defer server.allocator.free(line);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"bundle_seal\":\"{s}\"}}",
        .{line},
    );
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

fn handleSettle(server: *GatewayServer, stream: net.Stream, req: ParsedRequest) !void {
    const escrow_id_str = jsonGetString(req.body, "escrow_id", server.allocator) orelse
        return writeError(stream, 400, "missing \"escrow_id\" field");
    defer server.allocator.free(escrow_id_str);

    const amount_str = jsonGetString(req.body, "amount", server.allocator) orelse
        return writeError(stream, 400, "missing \"amount\" field");
    defer server.allocator.free(amount_str);

    const currency_str = jsonGetString(req.body, "currency", server.allocator) orelse
        return writeError(stream, 400, "missing \"currency\" field");
    defer server.allocator.free(currency_str);

    const recipient_str = jsonGetString(req.body, "recipient", server.allocator) orelse
        return writeError(stream, 400, "missing \"recipient\" field");
    defer server.allocator.free(recipient_str);

    const escrow_id = parseHexFixed(16, escrow_id_str) catch
        return writeError(stream, 400, "\"escrow_id\" must be 32 hex chars");

    if (currency_str.len > 8)
        return writeError(stream, 400, "\"currency\" must be 8 characters or fewer");
    var currency: [8]u8 = [_]u8{' '} ** 8;
    @memcpy(currency[0..currency_str.len], currency_str);

    const recipient = parseHexFixed(64, recipient_str) catch
        return writeError(stream, 400, "\"recipient\" must be 128 hex chars");

    const params = SettlementParams{
        .escrow_id = escrow_id,
        .amount = amount_str,
        .currency = currency,
        .recipient = recipient,
    };

    const line = server.logger.settleBundle(server.allocator, params) catch |err| switch (err) {
        error.AmountTooLong => return writeError(stream, 400, "\"amount\" exceeds 31 bytes"),
        else => {
            std.log.err("[VAR-gateway] settleBundle: {}", .{err});
            return writeError(stream, 500, "settleBundle failed");
        },
    };
    defer server.allocator.free(line);

    const body = try std.fmt.allocPrint(
        server.allocator,
        "{{\"settlement\":\"{s}\"}}",
        .{line},
    );
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

// ── JSON helpers ───────────────────────────────────────────────────────────

// Argon2id floor params from APEX §5.7
const BENCH_M: u32 = 65536;
const BENCH_T: u32 = 3;
const BENCH_P: u32 = 1;
const BENCH_N: usize = 7;

fn handleBenchmark(server: *GatewayServer, stream: net.Stream) !void {
    const argon2 = std.crypto.pwhash.argon2;
    const params = argon2.Params{ .t = BENCH_T, .m = BENCH_M, .p = BENCH_P };

    var times_ns: [BENCH_N]u64 = undefined;
    var rng = std.Random.DefaultPrng.init(@truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
    const random = rng.random();

    var dk: [32]u8 = undefined;
    var password: [16]u8 = undefined;
    var salt: [16]u8 = undefined;

    for (0..BENCH_N) |i| {
        random.bytes(&password);
        random.bytes(&salt);
        const t0 = std.time.nanoTimestamp();
        argon2.kdf(server.allocator, &dk, &password, &salt, params, .argon2id) catch |err| {
            std.log.err("[VAR-gateway] argon2id kdf failed: {}", .{err});
            return writeError(stream, 500, "argon2id failed");
        };
        const t1 = std.time.nanoTimestamp();
        times_ns[i] = @intCast(t1 - t0);
        std.crypto.secureZero(u8, &dk);
    }

    var sorted = times_ns;
    std.mem.sort(u64, &sorted, {}, std.sort.asc(u64));

    var sum: u128 = 0;
    for (times_ns) |t| sum += t;
    const mean_ns: f64 = @as(f64, @floatFromInt(sum)) / BENCH_N;
    const p50_ns: f64 = @floatFromInt(sorted[BENCH_N / 2]);
    const p95_ns: f64 = @floatFromInt(sorted[BENCH_N * 95 / 100]);
    const min_ns: f64 = @floatFromInt(sorted[0]);
    const max_ns: f64 = @floatFromInt(sorted[BENCH_N - 1]);

    const body = try std.fmt.allocPrint(server.allocator,
        \\{{"params":{{"m":{d},"t":{d},"p":{d}}},"n":{d},"mean_ms":{d:.2},"p50_ms":{d:.2},"p95_ms":{d:.2},"min_ms":{d:.2},"max_ms":{d:.2}}}
    , .{
        BENCH_M, BENCH_T, BENCH_P, BENCH_N,
        mean_ns / 1_000_000.0,
        p50_ns  / 1_000_000.0,
        p95_ns  / 1_000_000.0,
        min_ns  / 1_000_000.0,
        max_ns  / 1_000_000.0,
    });
    defer server.allocator.free(body);
    try writeResponse(stream, 200, body);
}

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

/// Decodes a lowercase-hex string of exactly `N*2` characters into `[N]u8`.
fn parseHexFixed(comptime N: usize, s: []const u8) ![N]u8 {
    if (s.len != N * 2) return error.InvalidHex;
    var result: [N]u8 = undefined;
    for (0..N) |i| {
        const hi = std.fmt.charToDigit(s[i * 2], 16) catch return error.InvalidHex;
        const lo = std.fmt.charToDigit(s[i * 2 + 1], 16) catch return error.InvalidHex;
        result[i] = (hi << 4) | lo;
    }
    return result;
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

test "parseHexFixed: round-trips fmtHex output" {
    const input = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const hex_str = try fmtHex(std.testing.allocator, &input);
    defer std.testing.allocator.free(hex_str);
    const decoded = try parseHexFixed(4, hex_str);
    try std.testing.expectEqualSlices(u8, &input, &decoded);
}

test "parseHexFixed: wrong length returns InvalidHex" {
    try std.testing.expectError(error.InvalidHex, parseHexFixed(4, "deadbe")); // 3 bytes worth
}

test "parseHexFixed: non-hex char returns InvalidHex" {
    try std.testing.expectError(error.InvalidHex, parseHexFixed(2, "deadXX"));
}
