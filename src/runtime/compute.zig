const std = @import("std");

pub const ComputeResult = struct {
    /// Hex-encoded computation output. Caller frees.
    output: []u8,
    /// SHA-256(fn_name || ":" || canonical_inputs_json).
    /// Commits to exactly what was submitted so the evidence chain entry is
    /// independently reproducible from the same inputs.
    inputs_hash: [32]u8,

    pub fn deinit(self: ComputeResult, allocator: std.mem.Allocator) void {
        allocator.free(self.output);
    }
};

/// Dispatch a named computation over its canonical JSON-encoded inputs.
///
/// Extension point: add a branch for each fn_name you want to support.
/// The default branch returns hex(inputs_hash) — a deterministic,
/// content-addressed fingerprint that is safe to fold into the evidence chain
/// while the real implementation is being developed.
pub fn run(
    allocator: std.mem.Allocator,
    fn_name: []const u8,
    inputs_json: []const u8,
) !ComputeResult {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(fn_name);
    hasher.update(":");
    hasher.update(inputs_json);
    var inputs_hash: [32]u8 = undefined;
    hasher.final(&inputs_hash);

    // ── Dispatch ────────────────────────────────────────────────────────────
    // Add branches here as real computations are implemented.
    // Each branch receives `inputs_json` (canonical, re-stringified by the
    // caller) and must return an allocated []u8 that the caller will free.

    // Placeholder: echo inputs back — useful for round-trip integration tests.
    if (std.mem.eql(u8, fn_name, "echo")) {
        return ComputeResult{
            .output = try allocator.dupe(u8, inputs_json),
            .inputs_hash = inputs_hash,
        };
    }

    // Document hash verification.
    // Inputs: {"document": "<text>", "expected_hash": "<64-char lowercase hex>"}
    // Output: {"match":<bool>,"computed_hash":"<hex>","expected_hash":"<hex>"}
    //
    // The operator can see the document and the expected hash going in, and the
    // match result coming out — but cannot forge a "match:true" output without
    // running this exact EIF, because the evidence signature is produced by the
    // enclave's KMS-gated signing key. The result is operator-untrusted.
    if (std.mem.eql(u8, fn_name, "verify")) {
        return runVerify(allocator, inputs_json, inputs_hash);
    }

    // Default: output = hex(inputs_hash).
    // Deterministic and verifiable; replace by adding a named branch above.
    const hex_buf = std.fmt.bytesToHex(inputs_hash, .lower);
    const output = try allocator.dupe(u8, &hex_buf);
    return ComputeResult{ .output = output, .inputs_hash = inputs_hash };
}

fn runVerify(
    allocator: std.mem.Allocator,
    inputs_json: []const u8,
    inputs_hash: [32]u8,
) !ComputeResult {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, inputs_json, .{});
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InputsNotObject,
    };

    const doc_val = obj.get("document") orelse return error.MissingDocument;
    const exp_val = obj.get("expected_hash") orelse return error.MissingExpectedHash;

    const document = switch (doc_val) {
        .string => |s| s,
        else => return error.DocumentNotString,
    };
    const expected_hex = switch (exp_val) {
        .string => |s| s,
        else => return error.ExpectedHashNotString,
    };

    if (expected_hex.len != 64) return error.InvalidExpectedHashLength;

    var doc_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(document, &doc_hash, .{});
    const computed_hex = std.fmt.bytesToHex(doc_hash, .lower);

    const match = std.ascii.eqlIgnoreCase(&computed_hex, expected_hex);

    const output = try std.fmt.allocPrint(allocator,
        \\{{"match":{s},"computed_hash":"{s}","expected_hash":"{s}"}}
    , .{
        if (match) "true" else "false",
        computed_hex,
        expected_hex,
    });

    return ComputeResult{ .output = output, .inputs_hash = inputs_hash };
}
