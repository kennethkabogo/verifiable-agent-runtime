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
const http = @import("runtime/http.zig");

/// Signal handler: requests a clean shutdown so the serve loop exits on the
/// next accept() interruption, allowing `defer vault.deinit()` to wipe secrets.
fn handleShutdown(sig: c_int) callconv(.C) void {
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
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null) catch {};
    std.posix.sigaction(std.posix.SIG.INT, &sa, null) catch {};

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

    // 3. Emit the session root-of-trust header so operators can record it.
    const header = try protocol.prepareHandshake();
    defer allocator.free(header);
    std.log.info("[VAR-gateway] Session root: {s}", .{header});

    // 5. Resolve bind address from environment or use the default.
    const host = std.posix.getenv("VAR_HOST") orelse "127.0.0.1";
    const port_str = std.posix.getenv("VAR_PORT") orelse "8765";
    const port = std.fmt.parseInt(u16, port_str, 10) catch 8765;

    // 6. Start HTTP gateway — blocks forever serving skills.
    var gw = http.GatewayServer.init(
        allocator,
        .{ .host = host, .port = port },
        &vault,
        &logger,
        &protocol.quote,
        protocol.session_id,
        protocol.bootstrap_nonce,
    );
    try gw.serve();
}
