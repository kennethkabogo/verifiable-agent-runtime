/// VAR HTTP Gateway — entry point.
///
/// Boots a full VAR session (attestation + vault + hash-chained logger) and
/// then exposes it over a minimal HTTP/1.1 server bound to loopback:8765.
///
/// Any co-located process — an OpenClaw skill, a Python agent, a shell script —
/// can interact with the session without speaking the custom vsock line protocol.
///
/// Usage:
///   zig build                     # builds both VAR (vsock) and VAR-gateway (HTTP)
///   ./zig-out/bin/VAR-gateway     # default: 127.0.0.1:8765
///   VAR_PORT=9000 ./zig-out/bin/VAR-gateway
///
const std = @import("std");
const SecureVault = @import("runtime/vault.zig").SecureVault;
const SecureLogger = @import("runtime/shell.zig").SecureLogger;
const ProtocolHandler = @import("runtime/protocol.zig").ProtocolHandler;
const AttestationQuote = @import("runtime/attestation.zig").AttestationQuote;
const http = @import("runtime/http.zig");
const sealed_state = @import("runtime/sealed_state.zig");
const sandbox = @import("runtime/sandbox.zig");
const VsockHandler = @import("runtime/vsock.zig").VsockHandler;

/// Fetch the sealed resume state blob from the KMS proxy at startup.
///
/// The proxy serves resume state via VARService.GetResumeState on the same
/// vsock port as KMS (default 8443).  This lets the enclave resume without
/// baking VAR_RESUME_STATE into the Docker image — which would change PCR0
/// and cause the KMS key policy to reject the attestation document.
///
/// Returns an allocated byte slice (caller must secureZero + free) or null if:
///   • the proxy is not running (connection refused)
///   • the proxy has no resume state (empty SealedState field)
///   • any parse or decode error occurs
/// Null means "start fresh" — not an error.
fn fetchProxyResumeState(allocator: std.mem.Allocator) ?[]u8 {
    const port_str = std.posix.getenv("VAR_KMS_PROXY_PORT") orelse "8443";
    const port = std.fmt.parseInt(u16, port_str, 10) catch 8443;

    var conn = VsockHandler.connect(allocator, VsockHandler.VMADDR_CID_HOST, port) catch return null;
    defer conn.close();

    const body = "{}";
    const request = std.fmt.allocPrint(
        allocator,
        "POST / HTTP/1.0\r\n" ++
            "Content-Type: application/x-amz-json-1.1\r\n" ++
            "X-Amz-Target: VARService.GetResumeState\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n" ++
            "{s}",
        .{ body.len, body },
    ) catch return null;
    defer allocator.free(request);

    _ = conn.send(request) catch return null;

    var resp_buf = allocator.alloc(u8, 32768) catch return null;
    defer allocator.free(resp_buf);
    var total: usize = 0;
    while (total < resp_buf.len) {
        const n = conn.receive(resp_buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }

    if (total < 12) return null;
    if (!std.mem.startsWith(u8, resp_buf[0..total], "HTTP/1.") or resp_buf[9] != '2') return null;

    const sep = std.mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n") orelse return null;
    const resp_body = resp_buf[sep + 4 .. total];

    // Minimal JSON extract for "SealedState": "<base64>" — no allocations needed.
    const key = "\"SealedState\"";
    const key_pos = std.mem.indexOf(u8, resp_body, key) orelse return null;
    var rest = resp_body[key_pos + key.len ..];
    rest = std.mem.trimLeft(u8, rest, " \t\r\n:");
    if (rest.len == 0 or rest[0] != '"') return null;
    rest = rest[1..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    const b64 = rest[0..end];
    if (b64.len == 0) return null;

    const dec = std.base64.standard.Decoder;
    const out_len = dec.calcSizeForSlice(b64) catch return null;
    const out = allocator.alloc(u8, out_len) catch return null;
    dec.decode(out, b64) catch {
        std.crypto.secureZero(u8, out);
        allocator.free(out);
        return null;
    };
    return out;
}

/// Signal handler: requests a clean shutdown so the serve loop exits on the
/// next accept() interruption, allowing `defer vault.deinit()` to wipe secrets.
fn handleShutdown(sig: c_int) callconv(.c) void {
    _ = sig;
    http.requestShutdown();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Install before any secrets are loaded so the vault is always wiped on exit.
    const sa = std.posix.Sigaction{
        .handler = .{ .handler = handleShutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);

    std.log.info("[VAR-gateway] Initializing Verifiable Agent Runtime (HTTP mode)...", .{});

    // 1. Vault + attestation — identical root-of-trust bootstrap as the vsock runtime.
    var vault = SecureVault.init(allocator);
    defer vault.deinit();

    var protocol = try ProtocolHandler.init(allocator, &vault);
    defer protocol.deinit();

    // 2. Anchor the L1 hash chain to this session.  bootstrap_nonce was computed
    //    once in ProtocolHandler.init() — pass it directly so the logger, the
    //    bundle header, and GET /session all expose the identical value.
    var logger = try SecureLogger.init(allocator, protocol.bootstrap_nonce, protocol.session_id, protocol.keypair);
    defer logger.deinit();

    // 3. If resume state is available, unseal the hibernated state and restore
    //    the vault + logger before advertising the session to clients.
    //
    //    Production path: fetch sealed blob from the KMS proxy at startup via
    //    VARService.GetResumeState (does not require changing the EIF/PCR0).
    //    Dev/simulation fallback: VAR_RESUME_STATE hex env var.
    //
    //    The signing keypair is NOT restored — the fresh keypair generated above
    //    is used for this segment (keypair-per-segment model, spec §5.3).
    const proxy_blob: ?[]u8 = fetchProxyResumeState(allocator);
    defer if (proxy_blob) |b| { std.crypto.secureZero(u8, b); allocator.free(b); };

    const env_blob: ?[]u8 = blk: {
        if (proxy_blob != null) break :blk null; // proxy takes precedence
        const hex = std.posix.getenv("VAR_RESUME_STATE") orelse break :blk null;
        if (hex.len == 0 or hex.len % 2 != 0) break :blk null;
        const b = allocator.alloc(u8, hex.len / 2) catch break :blk null;
        _ = std.fmt.hexToBytes(b, hex) catch {
            std.crypto.secureZero(u8, b);
            allocator.free(b);
            break :blk null;
        };
        break :blk b;
    };
    defer if (env_blob) |b| { std.crypto.secureZero(u8, b); allocator.free(b); };

    if (proxy_blob orelse env_blob) |blob| {
        var captured = sealed_state.unseal(allocator, blob) catch |err| {
            std.log.err("[VAR-gateway] Resume state unseal failed: {}", .{err});
            return error.ResumeFailed;
        };
        defer captured.deinit();

        try sealed_state.restoreVault(&captured, &vault);
        try sealed_state.restoreLogger(&captured, &logger);

        // Patch protocol so the bundle header uses the original session identity.
        protocol.session_id = captured.session_id;
        protocol.bootstrap_nonce = captured.bootstrap_nonce;

        // Regenerate the attestation quote with the restored session_id as the
        // NSM nonce field so the resumed segment's attest_doc witnesses the
        // canonical session identity.  Keypair stays fresh; bootstrap_nonce is
        // preserved from the sealed state (not recomputed).
        const new_quote = try AttestationQuote.generate(
            allocator,
            protocol.keypair.public_key.toBytes(),
            captured.session_id,
        );
        protocol.quote.deinit(allocator);
        protocol.quote = new_quote;

        // Emit SESSION_RESUME as the first packet of the resumed segment (§9.3).
        const resume_packet = try logger.emitSessionResume(allocator);
        defer allocator.free(resume_packet);
        std.log.info("[VAR-gateway] Resumed session (seq {d}): {s}", .{ captured.sequence, resume_packet });
    }

    // 4. Emit the session root-of-trust header so operators can record it.
    const header = try protocol.prepareHandshake();
    defer allocator.free(header);
    std.log.info("[VAR-gateway] Session root: {s}", .{header});

    // 5. Resolve bind address from environment or use the default.
    const host = std.posix.getenv("VAR_HOST") orelse "127.0.0.1";
    const port_str = std.posix.getenv("VAR_PORT") orelse "8765";
    const port = std.fmt.parseInt(u16, port_str, 10) catch 8765;

    // 6a. Capture KMS config and warm NSM cache before the sandbox scrubs the
    //     environment and before seccomp blocks openat(257).  sealDek() reads
    //     from these cached values instead of the environment at request time.
    sealed_state.initSealConfig(allocator);

    // 6b. Harden the process: scrub env vars, install Landlock + caps-drop +
    //     seccomp-BPF.  All environment reads are complete above; socket bind
    //     happens inside serve() using only allowlisted syscalls.
    sandbox.hardenProcess();

    // 7. Start HTTP gateway — blocks forever serving skills.
    var gw = http.GatewayServer.init(
        allocator,
        .{ .host = host, .port = port },
        &vault,
        &logger,
        &protocol.quote,
        protocol.session_id,
        protocol.bootstrap_nonce,
        protocol.enc_public,
    );
    try gw.serve();
}
