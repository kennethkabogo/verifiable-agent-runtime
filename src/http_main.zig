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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("[VAR-gateway] Initializing Verifiable Agent Runtime (HTTP mode)...", .{});

    // 1. Vault + attestation — identical root-of-trust bootstrap as the vsock runtime.
    var vault = SecureVault.init(allocator);
    defer vault.deinit();

    var protocol = try ProtocolHandler.init(allocator, &vault);
    defer protocol.deinit();

    // 2. Anchor the L1 hash chain to this session via the bootstrap nonce.
    var logger = try SecureLogger.init(allocator, protocol.quote.doc, protocol.session_id);

    // 3. Emit the session root-of-trust header so operators can record it.
    const header = try protocol.prepareHandshake();
    defer allocator.free(header);
    std.log.info("[VAR-gateway] Session root: {s}", .{header});

    // 4. Resolve bind address from environment or use the default.
    const host = std.posix.getenv("VAR_HOST") orelse "127.0.0.1";
    const port_str = std.posix.getenv("VAR_PORT") orelse "8765";
    const port = std.fmt.parseInt(u16, port_str, 10) catch 8765;

    // 5. Start HTTP gateway — blocks forever serving skills.
    var gw = http.GatewayServer.init(
        allocator,
        .{ .host = host, .port = port },
        &vault,
        &logger,
        &protocol.quote,
    );
    try gw.serve();
}
