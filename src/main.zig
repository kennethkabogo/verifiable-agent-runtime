const std = @import("std");
const SecureVault = @import("runtime/vault.zig").SecureVault;
const SecureLogger = @import("runtime/shell.zig").SecureLogger;
const ProtocolHandler = @import("runtime/protocol.zig").ProtocolHandler;
const VsockServer = @import("runtime/vsock.zig").VsockServer;
const sealed_state = @import("runtime/sealed_state.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Line-based agent protocol (all messages newline-terminated):
///
///   Enclave → Agent   BUNDLE_HEADER:magic=VARB:version=01:session=<hex>:nonce=<hex>:QUOTE:...
///   Enclave → Agent   READY
///   Agent   → Enclave SECRET:<key>:<value>
///   Agent   → Enclave LOG:<message>
///   Agent   → Enclave EXEC:<cmd> [arg1] [arg2]…
///   Enclave → Agent   EXEC_RESULT:exit=<N>:stdout_b64=<b64>:stderr_b64=<b64>:stdout_hash=<hex>:stderr_hash=<hex>
///   Agent   → Enclave GET_EVIDENCE
///   Enclave → Agent   EVIDENCE:stream=<hex>:state=<hex>:sig=<...>
///   Agent   → Enclave HIBERNATE
///   Enclave → Agent   SEALED_STATE:<hex_blob>     (then enclave exits cleanly)
///   Agent   → Enclave RESUME:<hex_blob>           (sent after READY to restore state)
///   Enclave → Agent   RESUMED:session=<hex>:seq=<n>
///
/// No-op signal handler: converts SIGTERM/SIGINT into EINTR on blocked syscalls
/// so that the read loop's `catch` branch fires, breaks the loop, and the
/// `defer vault.deinit()` runs — wiping secrets before the process exits.
fn handleShutdown(sig: c_int) callconv(.c) void {
    _ = sig;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Install signal handlers before touching any secrets.  A no-op handler
    // causes SIGTERM/SIGINT to interrupt blocked syscalls (returning EINTR)
    // rather than terminating the process immediately, so the defers below
    // — including vault.deinit() which wipes all secrets — always run.
    const sa = std.posix.Sigaction{
        .handler = .{ .handler = handleShutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);

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
    // 64 KiB accommodates RESUME blobs carrying a full vault of secrets.
    var line_buf: [65536]u8 = undefined;
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
        } else if (std.mem.startsWith(u8, line, "EXEC:")) {
            // Split "EXEC:cmd arg1 arg2" by whitespace into argv.
            const cmd_line = line[5..];
            var argv_list = std.ArrayListUnmanaged([]const u8){};
            defer argv_list.deinit(allocator);
            var it = std.mem.splitScalar(u8, cmd_line, ' ');
            while (it.next()) |arg| {
                if (arg.len > 0) try argv_list.append(allocator, arg);
            }
            if (argv_list.items.len == 0) {
                _ = try conn.send("EXEC_ERROR:empty_command\n");
                continue;
            }

            const result = logger.runAndLog(argv_list.items) catch |err| {
                std.debug.print("[VAR] EXEC failed: {any}\n", .{err});
                _ = try conn.send("EXEC_ERROR:spawn_failed\n");
                continue;
            };
            defer result.deinit(allocator);

            const Encoder = std.base64.standard.Encoder;
            const b64_out = try allocator.alloc(u8, Encoder.calcSize(result.stdout.len));
            defer allocator.free(b64_out);
            _ = Encoder.encode(b64_out, result.stdout);

            const b64_err = try allocator.alloc(u8, Encoder.calcSize(result.stderr.len));
            defer allocator.free(b64_err);
            _ = Encoder.encode(b64_err, result.stderr);

            var stdout_hash: [32]u8 = undefined;
            Sha256.hash(result.stdout, &stdout_hash, .{});
            var stderr_hash: [32]u8 = undefined;
            Sha256.hash(result.stderr, &stderr_hash, .{});

            const response = try std.fmt.allocPrint(
                allocator,
                "EXEC_RESULT:exit={d}:stdout_b64={s}:stderr_b64={s}:stdout_hash={x}:stderr_hash={x}\n",
                .{ result.exit_code, b64_out, b64_err, stdout_hash, stderr_hash },
            );
            defer allocator.free(response);
            _ = try conn.send(response);
            std.debug.print("[VAR] EXEC done (exit={d}): {s}\n", .{ result.exit_code, cmd_line });

        } else if (std.mem.eql(u8, line, "GET_EVIDENCE")) {
            const evidence = try logger.getEvidenceBundle();
            defer allocator.free(evidence);
            _ = try conn.send(evidence);
            _ = try conn.send("\n");
            std.debug.print("[VAR] Evidence bundle sent.\n", .{});
            break;
        } else if (std.mem.eql(u8, line, "HIBERNATE")) {
            // Capture and seal all runtime state, send the opaque blob to the
            // agent/host for external storage, then exit cleanly.
            var captured = try sealed_state.capture(allocator, &vault, &logger);
            defer captured.deinit();

            const blob = try sealed_state.seal(allocator, &captured);
            defer allocator.free(blob);

            const hex_blob = try std.fmt.allocPrint(allocator, "{x}", .{blob});
            defer allocator.free(hex_blob);

            const response = try std.fmt.allocPrint(allocator, "SEALED_STATE:{s}\n", .{hex_blob});
            defer allocator.free(response);

            _ = try conn.send(response);
            std.debug.print("[VAR] State sealed and sent ({d} bytes). Hibernating.\n", .{blob.len});
            break;
        } else if (std.mem.startsWith(u8, line, "RESUME:")) {
            // Unseal a previously hibernated state blob and restore vault + logger.
            const hex_blob = line[7..];
            if (hex_blob.len == 0 or hex_blob.len % 2 != 0) {
                std.debug.print("[VAR] RESUME: invalid hex blob length.\n", .{});
                continue;
            }

            const blob = try allocator.alloc(u8, hex_blob.len / 2);
            defer allocator.free(blob);
            _ = try std.fmt.hexToBytes(blob, hex_blob);

            var captured = sealed_state.unseal(allocator, blob) catch |err| {
                std.debug.print("[VAR] RESUME: unseal failed: {any}\n", .{err});
                _ = try conn.send("RESUME_ERROR:unseal_failed\n");
                continue;
            };
            defer captured.deinit();

            try sealed_state.restoreVault(&captured, &vault);
            try sealed_state.restoreLogger(&captured, &logger);

            const sid_hex = try std.fmt.allocPrint(
                allocator, "{x}", .{&captured.session_id},
            );
            defer allocator.free(sid_hex);
            const resumed_msg = try std.fmt.allocPrint(
                allocator, "RESUMED:session={s}:seq={d}\n", .{ sid_hex, captured.sequence },
            );
            defer allocator.free(resumed_msg);

            _ = try conn.send(resumed_msg);
            std.debug.print("[VAR] State restored. Session {s} resumed at seq {d}.\n", .{
                sid_hex, captured.sequence,
            });
        } else {
            std.debug.print("[VAR] Unknown message (ignored): {s}\n", .{line});
        }
    }

    std.debug.print("[VAR] Session complete.\n", .{});
}
