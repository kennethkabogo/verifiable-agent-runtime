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

    // Default: output = hex(inputs_hash).
    // Deterministic and verifiable; replace by adding a named branch above.
    const output = try std.fmt.allocPrint(
        allocator,
        "{}",
        .{std.fmt.fmtSliceHexLower(&inputs_hash)},
    );
    return ComputeResult{ .output = output, .inputs_hash = inputs_hash };
}
