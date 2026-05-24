const std = @import("std");
const VerifiableTerminal = @import("vt.zig").VerifiableTerminal;
const exec = @import("exec.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Structured record of the most recent subprocess execution.
/// Stored in SecureLogger and emitted in the evidence bundle so verifiers
/// can bind a specific command invocation to the L1 hash chain without
/// needing to replay the raw PTY stream.
pub const ExecRecord = struct {
    /// Human-readable joined command line (e.g. "ls -la /tmp").  Owned by
    /// the SecureLogger allocator; freed when replaced or on deinit.
    cmd: []u8,
    /// SHA-256 of the raw stdout bytes.  The same bytes were folded into the
    /// L1 chain via logOutput, so a verifier can confirm the chain commitment.
    stdout_hash: [32]u8,
    /// SHA-256 of the raw stderr bytes (not in the L1 chain — stderr is
    /// recorded for auditability but does not affect the stream hash).
    stderr_hash: [32]u8,
    exit_code: u8,
    /// Value of SecureLogger.sequence at the time runAndLog was called.
    seq: u64,

    pub fn deinit(self: ExecRecord, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.cmd);
        allocator.free(self.cmd);
    }
};

/// SecureLogger handles the PTY master logic and provides a verifiable hash chain
/// of both the terminal stream and the reconstructed terminal state.
pub const SecureLogger = struct {
    allocator: std.mem.Allocator,
    /// Current L1 stream hash — H_stream[n] (spec §2.1).
    stream_hash: [32]u8,
    /// L1 hash captured at the previous evidence emission — H_stream[n-1].
    /// Used as PrevL1Hash in each signed packet so auditors can detect gaps
    /// (spec §3, §4 continuity check).  Initialized to the bootstrap nonce
    /// so the very first packet has a well-defined predecessor.
    prev_stream_hash: [32]u8,
    vt: VerifiableTerminal,
    mutex: std.Thread.Mutex = .{},
    /// Monotonically increasing counter incremented on every evidence emission.
    /// Included in the signed message so each bundle is unique even when the
    /// stream state has not changed, and a verifier can detect skipped packets.
    sequence: u64,
    /// Ephemeral Ed25519 keypair used to sign each evidence bundle.
    /// The corresponding public key is bound in the session's attestation quote.
    keypair: Ed25519.KeyPair,
    /// Session identifier included in every signature so a verifier can bind the
    /// signature to a specific session without trusting the gateway.
    session_id: [16]u8,
    /// Bootstrap nonce that anchors the L1 chain to the session attestation.
    /// Stored here so that sealed_state.capture() can persist it alongside the
    /// rest of the logger state and restore it on resume.
    bootstrap_nonce: [32]u8,
    /// Ordered log of every subprocess execution this session.
    /// Each runAndLog call appends one entry; nothing is ever removed.
    /// Verifiers iterate the full list to confirm that no command was hidden
    /// by a later benign one (the "cover-up" attack against last_exec-only designs).
    executions: std.ArrayListUnmanaged(ExecRecord) = .{},
    /// Raw Ed25519 signatures from every evidence packet, in emission order.
    /// Used to compute TerminalDigest = SHA-256(sig[0] ‖ sig[1] ‖ … ‖ sig[N-1])
    /// for the Bundle Seal and Settlement Block.
    sig_log: std.ArrayListUnmanaged([64]u8) = .{},

    /// init anchors the hash chain to the session.  The caller passes the
    /// pre-computed bootstrap_nonce (SHA-256(attestation_doc || session_id))
    /// from ProtocolHandler so the value is never computed more than once.
    ///
    ///   H_stream[0] = bootstrap_nonce   (spec §1.2)
    pub fn init(
        allocator: std.mem.Allocator,
        bootstrap_nonce: [32]u8,
        session_id: [16]u8,
        keypair: Ed25519.KeyPair,
    ) !SecureLogger {
        return SecureLogger{
            .allocator = allocator,
            .stream_hash = bootstrap_nonce,
            .prev_stream_hash = bootstrap_nonce,
            .bootstrap_nonce = bootstrap_nonce,
            .vt = try VerifiableTerminal.init(allocator, 80, 24),
            .sequence = 0,
            .keypair = keypair,
            .session_id = session_id,
        };
    }

    pub fn deinit(self: *SecureLogger) void {
        self.vt.deinit();
        for (self.executions.items) |rec| rec.deinit(self.allocator);
        self.executions.deinit(self.allocator);
        self.sig_log.deinit(self.allocator);
    }

    fn hex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
        var result = try allocator.alloc(u8, bytes.len * 2);
        const chars = "0123456789abcdef";
        for (bytes, 0..) |b, i| {
            result[i * 2] = chars[b >> 4];
            result[i * 2 + 1] = chars[b & 0x0f];
        }
        return result;
    }

    /// Appends a new output chunk and advances the hash chain (spec §2.1):
    ///   H_stream[n] = SHA-256(H_stream[n-1] || data_chunk[n])
    pub fn logOutput(self: *SecureLogger, data: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.logOutputLocked(data);
    }

    /// Same as logOutput but assumes the caller already holds self.mutex.
    /// Used by runAndLog to fold stdout into the chain and append the exec
    /// record in a single atomic critical section (see runAndLog comment).
    fn logOutputLocked(self: *SecureLogger, data: []const u8) void {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.stream_hash);
        hasher.update(data);
        hasher.final(&self.stream_hash);
        self.vt.processInput(data);
    }

    /// Runs a subprocess, folds its stdout into the L1 chain and VT parser,
    /// and records structured execution metadata in the executions log for
    /// inclusion in the next evidence bundle.
    ///
    /// stdout bytes are committed to the L1 chain identically to logOutput,
    /// so a verifier can confirm that each exec record's stdout_hash is
    /// consistent with the delta between consecutive L1 hashes (spec §2.3.4).
    ///
    /// stderr is captured and hashed but NOT folded into the L1 chain — it is
    /// diagnostic output that does not affect the verifiable stream.
    ///
    /// The stdout fold and exec record append happen under a single mutex
    /// acquisition so no concurrent getEvidenceBundleJson call can observe a
    /// bundle where the L1 hash has advanced without a corresponding exec record.
    ///
    /// Returns the raw ExecResult; caller must call `deinit` on it.
    pub fn runAndLog(self: *SecureLogger, argv: []const []const u8) !exec.ExecResult {
        // Run the subprocess outside the mutex — it may take a while.
        const result = try exec.run(self.allocator, argv);

        // Compute content hashes and build the cmd string before taking the
        // lock — these are pure computation / allocation with no shared state.
        var stdout_hash: [32]u8 = undefined;
        Sha256.hash(result.stdout, &stdout_hash, .{});
        var stderr_hash: [32]u8 = undefined;
        Sha256.hash(result.stderr, &stderr_hash, .{});
        const cmd_str = try std.mem.join(self.allocator, " ", argv);
        errdefer self.allocator.free(cmd_str);

        // Single lock acquisition: fold stdout into the L1 chain AND append
        // the exec record atomically so the two are always visible together.
        self.mutex.lock();
        defer self.mutex.unlock();

        if (result.stdout.len > 0) {
            self.logOutputLocked(result.stdout);
        }

        try self.executions.append(self.allocator, ExecRecord{
            .cmd = cmd_str,
            .stdout_hash = stdout_hash,
            .stderr_hash = stderr_hash,
            .exit_code = result.exit_code,
            .seq = self.sequence,
        });

        return result;
    }

    /// Signs an evidence snapshot following spec §3.1.
    ///
    /// Message layout (161 bytes):
    ///   Magic        (4)   "VARE" = 0x56 0x41 0x52 0x45
    ///   FormatVer    (1)   0x01
    ///   Sequence     (8)   u64, little-endian
    ///   PrevL1Hash   (32)  H_stream at the previous evidence emission
    ///   L1Hash       (32)  H_stream at this emission
    ///   L2Hash       (32)  terminal state digest
    ///   PayloadLen   (4)   u32 LE; 0 in snapshot mode (no discrete payload bytes)
    ///   SHA-256(Pay) (32)  SHA-256("") in snapshot mode
    ///   SessionID    (16)  snapshot-mode extension — binds the sig to this session
    ///
    /// The HTTP gateway uses snapshot mode: there are no discrete payload bytes
    /// per evidence packet (the full PTY stream is captured in the L1 chain).
    /// PayloadLen is therefore 0 and SHA-256(Payload) is SHA-256("").
    fn signEvidence(
        self: *SecureLogger,
        prev_stream_hash: [32]u8,
        stream_hash: [32]u8,
        state_hash: [32]u8,
        sequence: u64,
    ) !Ed25519.Signature {
        // SHA-256("") — used as SHA-256(Payload) in snapshot mode.
        const empty_payload_hash = comptime blk: {
            @setEvalBranchQuota(10000);
            var h: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash("", &h, .{});
            break :blk h;
        };

        var msg: [161]u8 = undefined;
        var pos: usize = 0;

        // Magic "VARE"
        @memcpy(msg[pos..][0..4], &[_]u8{ 0x56, 0x41, 0x52, 0x45 });
        pos += 4;
        // FormatVer
        msg[pos] = 0x01;
        pos += 1;
        // Sequence (u64 LE)
        std.mem.writeInt(u64, msg[pos..][0..8], sequence, .little);
        pos += 8;
        // PrevL1Hash
        @memcpy(msg[pos..][0..32], &prev_stream_hash);
        pos += 32;
        // L1Hash
        @memcpy(msg[pos..][0..32], &stream_hash);
        pos += 32;
        // L2Hash
        @memcpy(msg[pos..][0..32], &state_hash);
        pos += 32;
        // PayloadLen = 0 (snapshot mode, u32 LE)
        std.mem.writeInt(u32, msg[pos..][0..4], 0, .little);
        pos += 4;
        // SHA-256(Payload) = SHA-256("") (snapshot mode)
        @memcpy(msg[pos..][0..32], &empty_payload_hash);
        pos += 32;
        // SessionID (snapshot-mode extension)
        @memcpy(msg[pos..][0..16], &self.session_id);
        pos += 16;

        std.debug.assert(pos == 161);
        return self.keypair.sign(&msg, null);
    }

    /// Generates a signed bundle of the stream hash and the current terminal state.
    /// Returns an allocated string in the vsock line-protocol format.
    pub fn getEvidenceBundle(self: *SecureLogger) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Use next_seq as a local so sequence is only committed after the full
        // bundle is successfully constructed.  If any allocation below fails,
        // self.sequence and self.prev_stream_hash remain unchanged and the
        // caller can retry without creating a gap in the continuity chain.
        const next_seq = try std.math.add(u64, self.sequence, 1);
        const prev_hash = self.prev_stream_hash;
        const state_digest = self.vt.digestState();
        const sig = try self.signEvidence(prev_hash, self.stream_hash, state_digest, next_seq);
        const sig_bytes = sig.toBytes();

        const prev_h = try hex(self.allocator, &prev_hash);
        defer self.allocator.free(prev_h);
        const stream_h = try hex(self.allocator, &self.stream_hash);
        defer self.allocator.free(stream_h);
        const state_h = try hex(self.allocator, &state_digest);
        defer self.allocator.free(state_h);
        const sig_h = try hex(self.allocator, &sig_bytes);
        defer self.allocator.free(sig_h);

        const result = try std.fmt.allocPrint(self.allocator,
            "EVIDENCE:prev_stream={s}:stream={s}:state={s}:sig={s}:seq={d}",
            .{ prev_h, stream_h, state_h, sig_h, next_seq },
        );

        // Record signature before committing — if this fails (OOM) neither
        // sequence nor sig_log will have advanced and the caller can retry.
        try self.sig_log.append(self.allocator, sig_bytes);

        // Commit state only after the bundle is fully built.
        self.sequence = next_seq;
        self.prev_stream_hash = self.stream_hash;

        return result;
    }

    /// Returns the evidence bundle as a JSON object for the HTTP gateway.
    /// Caller must free the returned slice using `allocator`.
    pub fn getEvidenceBundleJson(self: *SecureLogger, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Same commit-last ordering as getEvidenceBundle: build the complete
        // JSON string before touching any persistent state so that an OOM
        // error leaves the continuity chain intact for a subsequent call.
        const next_seq = try std.math.add(u64, self.sequence, 1);
        const prev_hash = self.prev_stream_hash;
        const state_digest = self.vt.digestState();
        const sig = try self.signEvidence(prev_hash, self.stream_hash, state_digest, next_seq);
        const sig_bytes = sig.toBytes();

        const prev_h = try hex(allocator, &prev_hash);
        defer allocator.free(prev_h);
        const stream_h = try hex(allocator, &self.stream_hash);
        defer allocator.free(stream_h);
        const state_h = try hex(allocator, &state_digest);
        defer allocator.free(state_h);
        const sig_h = try hex(allocator, &sig_bytes);
        defer allocator.free(sig_h);

        // Build the executions JSON array.
        // Each entry: {"cmd":"...","stdout_hash":"...","stderr_hash":"...","exit_code":N,"seq":N}
        var execs_buf = std.ArrayListUnmanaged(u8){};
        defer execs_buf.deinit(allocator);
        try execs_buf.append(allocator, '[');
        for (self.executions.items, 0..) |rec, i| {
            if (i > 0) try execs_buf.append(allocator, ',');
            const sh = try hex(allocator, &rec.stdout_hash);
            defer allocator.free(sh);
            const eh = try hex(allocator, &rec.stderr_hash);
            defer allocator.free(eh);
            // JSON-escape the cmd string per RFC 8259.
            // Must handle all control characters (0x00-0x1F, 0x7F), not just
            // `"` and `\` — an unescaped newline or tab produces invalid JSON
            // that downstream parsers will reject or silently misparse.
            var escaped = std.ArrayListUnmanaged(u8){};
            defer escaped.deinit(allocator);
            for (rec.cmd) |ch| {
                switch (ch) {
                    '"'  => try escaped.appendSlice(allocator, "\\\""),
                    '\\' => try escaped.appendSlice(allocator, "\\\\"),
                    0x08 => try escaped.appendSlice(allocator, "\\b"),
                    0x09 => try escaped.appendSlice(allocator, "\\t"),
                    0x0A => try escaped.appendSlice(allocator, "\\n"),
                    0x0C => try escaped.appendSlice(allocator, "\\f"),
                    0x0D => try escaped.appendSlice(allocator, "\\r"),
                    0x00...0x07, 0x0B, 0x0E...0x1F, 0x7F => {
                        var tmp: [6]u8 = undefined;
                        const enc = std.fmt.bufPrint(&tmp, "\\u{x:0>4}", .{ch}) catch unreachable;
                        try escaped.appendSlice(allocator, enc);
                    },
                    else => try escaped.append(allocator, ch),
                }
            }
            const entry = try std.fmt.allocPrint(
                allocator,
                "{{\"cmd\":\"{s}\",\"stdout_hash\":\"{s}\",\"stderr_hash\":\"{s}\",\"exit_code\":{d},\"seq\":{d}}}",
                .{ escaped.items, sh, eh, rec.exit_code, rec.seq },
            );
            defer allocator.free(entry);
            try execs_buf.appendSlice(allocator, entry);
        }
        try execs_buf.append(allocator, ']');

        const result = try std.fmt.allocPrint(allocator,
            \\{{"prev_stream":"{s}","stream":"{s}","state":"{s}","sig":"{s}","sequence":{d},"executions":{s}}}
        , .{ prev_h, stream_h, state_h, sig_h, next_seq, execs_buf.items });

        // Record signature before committing — if this fails (OOM) neither
        // sequence nor sig_log will have advanced and the caller can retry.
        try self.sig_log.append(self.allocator, sig_bytes);

        // Commit state only after the bundle is fully built.
        self.sequence = next_seq;
        self.prev_stream_hash = self.stream_hash;

        return result;
    }
};

/// Parameters for a settlement authorisation (spec §6).
pub const SettlementParams = struct {
    /// UUID v4 identifying the escrow contract.
    escrow_id: [16]u8,
    /// Decimal amount string (e.g. "100.00"). Must be ≤ 31 bytes.
    amount: []const u8,
    /// ISO 4217 or "USDT", space-padded to 8 bytes.
    currency: [8]u8,
    /// Opaque recipient identifier, zero-padded to 64 bytes.
    recipient: [64]u8,
};

/// SHA-256(sig[0] ‖ sig[1] ‖ … ‖ sig[N-1]).
/// Caller must hold self.mutex.
fn computeTerminalDigestLocked(self: *const SecureLogger) [32]u8 {
    var hasher = Sha256.init(.{});
    for (self.sig_log.items) |sig| hasher.update(&sig);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Emits a Bundle Seal line (spec §7).
///
///   BUNDLE_SEAL:magic=APXZ:terminal_digest=<hex>:bundle_hash=<hex>:seal_sig=<hex>
///
/// TerminalDigest = SHA-256(all packet signatures in order)
/// BundleHash     = SHA-256("VARB" ‖ session_id ‖ bootstrap_nonce ‖ signing_pub ‖ TerminalDigest)
/// SealSig        = Ed25519(session_keypair, BundleHash)
pub fn sealBundle(self: *SecureLogger, allocator: std.mem.Allocator) ![]u8 {
    self.mutex.lock();
    defer self.mutex.unlock();

    const terminal_digest = self.computeTerminalDigestLocked();
    const signing_pub = self.keypair.public_key.toBytes();

    var bh_hasher = Sha256.init(.{});
    bh_hasher.update("VARB");
    bh_hasher.update(&self.session_id);
    bh_hasher.update(&self.bootstrap_nonce);
    bh_hasher.update(&signing_pub);
    bh_hasher.update(&terminal_digest);
    var bundle_hash: [32]u8 = undefined;
    bh_hasher.final(&bundle_hash);

    const seal_sig = try self.keypair.sign(&bundle_hash, null);
    const seal_sig_bytes = seal_sig.toBytes();

    const td_h = try hex(allocator, &terminal_digest);
    defer allocator.free(td_h);
    const bh_h = try hex(allocator, &bundle_hash);
    defer allocator.free(bh_h);
    const ss_h = try hex(allocator, &seal_sig_bytes);
    defer allocator.free(ss_h);

    return std.fmt.allocPrint(
        allocator,
        "BUNDLE_SEAL:magic=APXZ:terminal_digest={s}:bundle_hash={s}:seal_sig={s}",
        .{ td_h, bh_h, ss_h },
    );
}

/// Emits a Settlement Block line (spec §6).
///
///   SETTLEMENT:magic=APXT:escrow_id=<hex>:amount=<str>:currency=<str>:
///              recipient=<hex>:condition=01:terminal_digest=<hex>:sig=<hex>
///
/// SettlementSig = Ed25519(session_keypair, EscrowID ‖ Amount[32] ‖ Currency[8] ‖ TerminalDigest)
pub fn settleBundle(
    self: *SecureLogger,
    allocator: std.mem.Allocator,
    params: SettlementParams,
) ![]u8 {
    if (params.amount.len > 31) return error.AmountTooLong;

    self.mutex.lock();
    defer self.mutex.unlock();

    const terminal_digest = self.computeTerminalDigestLocked();

    // Fixed-width amount field: zero-padded to 32 bytes (spec §6).
    var amount_field: [32]u8 = [_]u8{0} ** 32;
    @memcpy(amount_field[0..params.amount.len], params.amount);

    // Signature scope: EscrowID(16) ‖ Amount(32) ‖ Currency(8) ‖ TerminalDigest(32) = 88 bytes
    var sig_msg: [88]u8 = undefined;
    @memcpy(sig_msg[0..16], &params.escrow_id);
    @memcpy(sig_msg[16..48], &amount_field);
    @memcpy(sig_msg[48..56], &params.currency);
    @memcpy(sig_msg[56..88], &terminal_digest);

    const settlement_sig = try self.keypair.sign(&sig_msg, null);
    const settlement_sig_bytes = settlement_sig.toBytes();

    const currency_str = std.mem.trimRight(u8, &params.currency, " \x00");

    const eid_h = try hex(allocator, &params.escrow_id);
    defer allocator.free(eid_h);
    const rec_h = try hex(allocator, &params.recipient);
    defer allocator.free(rec_h);
    const td_h = try hex(allocator, &terminal_digest);
    defer allocator.free(td_h);
    const ss_h = try hex(allocator, &settlement_sig_bytes);
    defer allocator.free(ss_h);

    return std.fmt.allocPrint(
        allocator,
        "SETTLEMENT:magic=APXT:escrow_id={s}:amount={s}:currency={s}:recipient={s}:condition=01:terminal_digest={s}:sig={s}",
        .{ eid_h, params.amount, currency_str, rec_h, td_h, ss_h },
    );
}

// ── Tests ──────────────────────────────────────────────────────────────────

test "executions: empty before any EXEC" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.create(null);
    var logger = try SecureLogger.init(allocator, [_]u8{0} ** 32, [_]u8{0} ** 16, kp);
    defer logger.deinit();

    try std.testing.expectEqual(@as(usize, 0), logger.executions.items.len);
}

test "executions: appends in order across multiple EXEC calls" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.create(null);
    var logger = try SecureLogger.init(allocator, [_]u8{0} ** 32, [_]u8{0} ** 16, kp);
    defer logger.deinit();

    // First command.
    const r1 = try logger.runAndLog(&.{ "/bin/echo", "first" });
    r1.deinit(allocator);

    // Second command.
    const r2 = try logger.runAndLog(&.{ "/bin/echo", "second" });
    r2.deinit(allocator);

    // Third command.
    const r3 = try logger.runAndLog(&.{ "/bin/sh", "-c", "exit 7" });
    r3.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), logger.executions.items.len);
    try std.testing.expectEqualStrings("/bin/echo first", logger.executions.items[0].cmd);
    try std.testing.expectEqualStrings("/bin/echo second", logger.executions.items[1].cmd);
    try std.testing.expectEqualStrings("/bin/sh -c exit 7", logger.executions.items[2].cmd);
    try std.testing.expectEqual(@as(u8, 7), logger.executions.items[2].exit_code);
}

test "executions: JSON bundle contains all records" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.create(null);
    var logger = try SecureLogger.init(allocator, [_]u8{0} ** 32, [_]u8{0} ** 16, kp);
    defer logger.deinit();

    const r1 = try logger.runAndLog(&.{ "/bin/echo", "hello" });
    r1.deinit(allocator);
    const r2 = try logger.runAndLog(&.{ "/bin/echo", "world" });
    r2.deinit(allocator);

    const json = try logger.getEvidenceBundleJson(allocator);
    defer allocator.free(json);

    // Both commands must appear in the JSON.
    try std.testing.expect(std.mem.indexOf(u8, json, "/bin/echo hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "/bin/echo world") != null);
    // The array field must be present.
    try std.testing.expect(std.mem.indexOf(u8, json, "\"executions\":[") != null);
}

test "sealBundle: terminal_digest is sha256 of accumulated packet signatures" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.create(null);
    var logger = try SecureLogger.init(allocator, [_]u8{0} ** 32, [_]u8{0} ** 16, kp);
    defer logger.deinit();

    // Emit two packets so sig_log has two entries.
    const e1 = try logger.getEvidenceBundle();
    allocator.free(e1);
    const e2 = try logger.getEvidenceBundle();
    allocator.free(e2);

    try std.testing.expectEqual(@as(usize, 2), logger.sig_log.items.len);

    // Recompute expected terminal digest independently.
    var hasher = Sha256.init(.{});
    for (logger.sig_log.items) |sig| hasher.update(&sig);
    var expected: [32]u8 = undefined;
    hasher.final(&expected);

    const seal = try logger.sealBundle(allocator);
    defer allocator.free(seal);

    // Extract the terminal_digest field from the emitted line.
    const td_prefix = "terminal_digest=";
    const td_start = (std.mem.indexOf(u8, seal, td_prefix) orelse
        return error.MissingTerminalDigest) + td_prefix.len;
    const td_end = std.mem.indexOfScalarPos(u8, seal, td_start, ':') orelse seal.len;
    const td_hex = seal[td_start..td_end];

    var actual: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&actual, td_hex);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "sealBundle: seal_sig verifies against bundle_hash with session public key" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.create(null);
    var logger = try SecureLogger.init(allocator, [_]u8{0} ** 32, [_]u8{0} ** 16, kp);
    defer logger.deinit();

    const e1 = try logger.getEvidenceBundle();
    allocator.free(e1);

    const seal = try logger.sealBundle(allocator);
    defer allocator.free(seal);

    // Parse bundle_hash and seal_sig from the emitted line.
    const bh_prefix = "bundle_hash=";
    const bh_start = (std.mem.indexOf(u8, seal, bh_prefix) orelse
        return error.MissingBundleHash) + bh_prefix.len;
    const bh_end = std.mem.indexOfScalarPos(u8, seal, bh_start, ':') orelse seal.len;

    const ss_prefix = "seal_sig=";
    const ss_start = (std.mem.indexOf(u8, seal, ss_prefix) orelse
        return error.MissingSealSig) + ss_prefix.len;

    var bundle_hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bundle_hash, seal[bh_start..bh_end]);
    var sig_bytes: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sig_bytes, seal[ss_start..]);

    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    try sig.verify(&bundle_hash, kp.public_key);
}

test "settleBundle: settlement_sig verifies against escrow_id+amount+currency+terminal_digest" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.create(null);
    var logger = try SecureLogger.init(allocator, [_]u8{0} ** 32, [_]u8{0} ** 16, kp);
    defer logger.deinit();

    const e1 = try logger.getEvidenceBundle();
    allocator.free(e1);

    var escrow_id: [16]u8 = undefined;
    std.crypto.random.bytes(&escrow_id);
    var currency: [8]u8 = [_]u8{' '} ** 8;
    @memcpy(currency[0..4], "USDT");
    const params = SettlementParams{
        .escrow_id = escrow_id,
        .amount = "100.00",
        .currency = currency,
        .recipient = [_]u8{0xAB} ** 64,
    };

    const line = try logger.settleBundle(allocator, params);
    defer allocator.free(line);

    // Confirm magic is present.
    try std.testing.expect(std.mem.indexOf(u8, line, "magic=APXT") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "condition=01") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "amount=100.00") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "currency=USDT") != null);

    // Re-derive terminal digest and reconstruct the signature scope.
    const terminal_digest = logger.computeTerminalDigestLocked();
    var amount_field: [32]u8 = [_]u8{0} ** 32;
    @memcpy(amount_field[0..6], "100.00");
    var sig_msg: [88]u8 = undefined;
    @memcpy(sig_msg[0..16], &escrow_id);
    @memcpy(sig_msg[16..48], &amount_field);
    @memcpy(sig_msg[48..56], &currency);
    @memcpy(sig_msg[56..88], &terminal_digest);

    // Extract settlement sig from the line and verify it.
    const ss_prefix = "sig=";
    const ss_start = (std.mem.lastIndexOf(u8, line, ss_prefix) orelse
        return error.MissingSig) + ss_prefix.len;
    var sig_bytes: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sig_bytes, line[ss_start..]);
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    try sig.verify(&sig_msg, kp.public_key);
}

test "settleBundle: amount longer than 31 bytes returns AmountTooLong" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.create(null);
    var logger = try SecureLogger.init(allocator, [_]u8{0} ** 32, [_]u8{0} ** 16, kp);
    defer logger.deinit();

    const params = SettlementParams{
        .escrow_id = [_]u8{0} ** 16,
        .amount = "1" ** 32,
        .currency = [_]u8{' '} ** 8,
        .recipient = [_]u8{0} ** 64,
    };
    try std.testing.expectError(error.AmountTooLong, logger.settleBundle(allocator, params));
}
