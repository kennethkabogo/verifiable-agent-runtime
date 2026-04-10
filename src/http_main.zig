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

    // 3. If VAR_RESUME_STATE is set, unseal the hibernated state and restore the
    //    vault + logger before advertising the session to clients.  The signing
    //    keypair is NOT restored — the fresh keypair generated above is used for
    //    this session segment (keypair-per-segment model, spec §5.3).
    //    After restore we patch the protocol fields so the bundle header emitted
    //    by GET /session carries the original session_id and bootstrap_nonce.
    if (std.posix.getenv("VAR_RESUME_STATE")) |hex_state| {
        if (hex_state.len > 0 and hex_state.len % 2 == 0) {
            const blob = try allocator.alloc(u8, hex_state.len / 2);
            defer allocator.free(blob);
            _ = try std.fmt.hexToBytes(blob, hex_state);

            var captured = sealed_state.unseal(allocator, blob) catch |err| {
                std.log.err("[VAR-gateway] VAR_RESUME_STATE unseal failed: {}", .{err});
                return error.ResumeFailed;
            };
            defer captured.deinit();

            try sealed_state.restoreVault(&captured, &vault);
            try sealed_state.restoreLogger(&captured, &logger);

            // Patch protocol so the bundle header uses the original session identity.
            protocol.session_id = captured.session_id;
            protocol.bootstrap_nonce = captured.bootstrap_nonce;

            // Regenerate the attestation quote with the restored session_id as the
            // NSM nonce field.  This ensures the resumed segment's attest_doc also
            // witnesses the canonical session identity (not the ephemeral fresh
            // session_id that was generated during init() above).
            // The keypair stays fresh (per-segment model); bootstrap_nonce is
            // NOT recomputed — it is preserved from the sealed state.
            protocol.quote.deinit(allocator);
            protocol.quote = try AttestationQuote.generate(
                allocator,
                protocol.keypair.public_key.toBytes(),
                captured.session_id,
            );

            std.log.info("[VAR-gateway] Resumed session {x} at seq {d}.", .{
                &captured.session_id, captured.sequence,
            });
        }
    }

    // 4. Emit the session root-of-trust header so operators can record it.
    const header = try protocol.prepareHandshake();
    defer allocator.free(header);
    std.log.info("[VAR-gateway] Session root: {s}", .{header});

    // 5. Resolve bind address from environment or use the default.
    const host = std.posix.getenv("VAR_HOST") orelse "127.0.0.1";
    const port_str = std.posix.getenv("VAR_PORT") orelse "8765";
    const port = std.fmt.parseInt(u16, port_str, 10) catch 8765;

    // 6. Harden the process: scrub env vars, install Landlock + caps-drop +
    //    seccomp-BPF.  All environment reads are complete above; socket bind
    //    happens inside serve() using only allowlisted syscalls.
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
