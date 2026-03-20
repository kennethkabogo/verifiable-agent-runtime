const std = @import("std");
const SecureVault = @import("runtime/vault.zig").SecureVault;
const SecureLogger = @import("runtime/shell.zig").SecureLogger;
const ProtocolHandler = @import("runtime/protocol.zig").ProtocolHandler;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("[VAR] Initializing Verifiable Agent Runtime...\n", .{});

    // 1. Setup Local Enclave Components
    var vault = SecureVault.init(allocator);
    defer vault.deinit();

    // 2. Generate session ID, request attestation quote from NSM (or mock fallback).
    var protocol = try ProtocolHandler.init(allocator, &vault);
    defer protocol.deinit();

    // 3. Emit Bundle Header (magic, version, session ID, bootstrap nonce, attestation doc).
    const hello = try protocol.prepareHandshake();
    defer allocator.free(hello);
    std.debug.print("{s}\n", .{hello});

    // 4. Anchor the hash chain to this session: H_stream[0] = SHA-256(doc || session_id).
    var logger = try SecureLogger.init(allocator, protocol.quote.doc, protocol.session_id);

    // 5. Simulated Agent Execution Loop
    std.debug.print("[VAR] Waiting for Host to provide secrets and agent instructions...\n", .{});

    const mock_secret_packet = "SECRET:OPENAI_API_KEY:sk-proj-var-confidential-token-12345";
    try protocol.handleSecrets(mock_secret_packet);

    if (vault.get("OPENAI_API_KEY")) |key| {
        std.debug.print("[VAR] SUCCESS: Securely unlocked secret handle. Length: {d}\n", .{key.len});
    }

    // 6. Start Verifiable Shell Session
    try logger.logOutput("User: 'Analyze this sensitive data'\n");
    try logger.logOutput("Agent: 'Analyzing using unlocked OPENAI_API_KEY...'\n");

    const evidence = try logger.getEvidenceBundle();
    defer allocator.free(evidence);
    std.debug.print("[VAR] Evidence Bundle Generated: {s}\n", .{evidence});
}
