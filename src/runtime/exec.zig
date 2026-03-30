const std = @import("std");

/// Maximum bytes captured from a single output stream (stdout or stderr).
/// Commands producing more output have their excess silently dropped so the
/// enclave cannot be OOM-killed by a runaway process.
pub const MAX_OUTPUT_BYTES: usize = 1 * 1024 * 1024; // 1 MiB

/// Structured result of a subprocess execution.
/// Both `stdout` and `stderr` are heap-allocated and owned by the caller;
/// call `deinit` to release them.
pub const ExecResult = struct {
    stdout: []u8,
    stderr: []u8,
    /// Process exit code.  Signals are mapped to 128 + signal_number.
    /// 255 is used for any other termination cause (stopped, unknown).
    exit_code: u8,

    pub fn deinit(self: ExecResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

/// Spawns `argv[0]` with the remaining elements as arguments, waits for it
/// to exit, and returns captured stdout, stderr, and the exit code.
///
/// Output is captured up to MAX_OUTPUT_BYTES per stream.  If a stream exceeds
/// that limit the bytes after the limit are discarded and the field is replaced
/// with the literal "<output truncated>" so callers always receive valid UTF-8.
///
/// The caller owns the returned ExecResult and must call `deinit` on it.
pub fn run(allocator: std.mem.Allocator, argv: []const []const u8) !ExecResult {
    if (argv.len == 0) return error.EmptyArgv;

    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    const truncated_msg = "<output truncated>";

    var stdout_io_buf: [4096]u8 = undefined;
    const stdout = child.stdout.?.reader(&stdout_io_buf).readAllAlloc(allocator, MAX_OUTPUT_BYTES) catch |err| blk: {
        if (err == error.StreamTooLong) break :blk try allocator.dupe(u8, truncated_msg);
        return err;
    };
    errdefer allocator.free(stdout);

    var stderr_io_buf: [4096]u8 = undefined;
    const stderr = child.stderr.?.reader(&stderr_io_buf).readAllAlloc(allocator, MAX_OUTPUT_BYTES) catch |err| blk: {
        if (err == error.StreamTooLong) break :blk try allocator.dupe(u8, truncated_msg);
        return err;
    };
    errdefer allocator.free(stderr);

    const term = try child.wait();
    const exit_code: u8 = switch (term) {
        .Exited => |code| @truncate(code),
        .Signal => |sig| @truncate(128 + sig),
        else => 255,
    };

    return ExecResult{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = exit_code,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────────

test "run: captures stdout and exit code zero" {
    const result = try run(std.testing.allocator, &.{ "/bin/echo", "hello" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("hello\n", result.stdout);
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
    try std.testing.expectEqualStrings("", result.stderr);
}

test "run: captures non-zero exit code" {
    const result = try run(std.testing.allocator, &.{ "/bin/sh", "-c", "exit 42" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 42), result.exit_code);
}

test "run: captures stderr separately from stdout" {
    const result = try run(std.testing.allocator, &.{
        "/bin/sh", "-c", "echo out; echo err >&2",
    });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("out\n", result.stdout);
    try std.testing.expectEqualStrings("err\n", result.stderr);
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

test "run: empty argv returns error" {
    const empty: []const []const u8 = &.{};
    try std.testing.expectError(error.EmptyArgv, run(std.testing.allocator, empty));
}
