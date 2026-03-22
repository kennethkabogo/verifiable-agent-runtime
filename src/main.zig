const std = @import("std");
const SecureVault = @import("runtime/vault.zig").SecureVault;
const SecureLogger = @import("runtime/shell.zig").SecureLogger;
const ProtocolHandler = @import("runtime/protocol.zig").ProtocolHandler;
const VsockServer = @import("runtime/vsock.zig").VsockServer;

/// Line-based agent protocol (all messages newline-terminated):
///
///   Enclave → Agent   BUNDLE_HEADER:magic=VARB:version=01:session=<hex>:nonce=<hex>:QUOTE:...
///   Enclave → Agent   READY
///   Agent   → Enclave SECRET:<key>:<value>
///   Agent   → Enclave LOG:<message>
///   Agent   → Enclave GET_EVIDENCE
///   Enclave → Agent   EVIDENCE:stream=<hex>:state=<hex>:sig=<...>
///
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("[VAR] Initializing Verifiable Agent Runtime...\n", .{});

    // 1. Vault + attestation setup.
    var vault = SecureVault.init(allocator);
    defer vault.deinit();

    var protocol = try ProtocolHandler.init(allocator, &vault);
    defer protocol.deinit();

    // 2. Anchor the L1 hash chain to this session.  bootstrap_nonce was computed
    //    once in ProtocolHandler.init() — pass it directly so the logger and the
    //    bundle header always use the identical value.
    var logger = try SecureLogger.init(allocator, protocol.bootstrap_nonce, protocol.session_id, protocol.keypair);
    defer logger.deinit();

    // 3. Listen for one incoming agent connection (vsock on Nitro, TCP in simulation).
    var server = try VsockServer.listen(5005);
    defer server.close();

    std.debug.print("[VAR] Waiting for agent connection...\n", .{});
    var conn = try server.accept();
    defer conn.close();
    std.debug.print("[VAR] Agent connected.\n", .{});

    // 4. Send Bundle Header — the session root-of-trust anchor.
    const header = try protocol.prepareHandshake();
    defer allocator.free(header);
    _ = try conn.send(header);
    _ = try conn.send("\n");

    // 5. Signal ready.
    _ = try conn.send("READY\n");

    // 6. Protocol dispatch loop.
    var line_buf: [4096]u8 = undefined;
    while (true) {
        const line = conn.readLine(&line_buf) catch |err| {
            std.debug.print("[VAR] Read error: {any}\n", .{err});
            break;
        };
        if (line.len == 0) break;

        if (std.mem.startsWith(u8, line, "SECRET:")) {
            try protocol.handleSecrets(line);
            std.debug.print("[VAR] Secret stored.\n", .{});
        } else if (std.mem.startsWith(u8, line, "LOG:")) {
            const msg = line[4..];
            try logger.logOutput(msg);
            std.debug.print("[VAR] Logged ({d} bytes): {s}\n", .{ msg.len, msg });
        } else if (std.mem.eql(u8, line, "GET_EVIDENCE")) {
            const evidence = try logger.getEvidenceBundle();
            defer allocator.free(evidence);
            _ = try conn.send(evidence);
            _ = try conn.send("\n");
            std.debug.print("[VAR] Evidence bundle sent.\n", .{});
            break;
        } else {
            std.debug.print("[VAR] Unknown message (ignored): {s}\n", .{line});
        }
    }

    std.debug.print("[VAR] Session complete.\n", .{});
}
