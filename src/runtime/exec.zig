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
        std.crypto.secureZero(u8, self.stdout);
        allocator.free(self.stdout);
        std.crypto.secureZero(u8, self.stderr);
        allocator.free(self.stderr);
    }
};

/// Read all bytes from a pipe file descriptor into a heap-allocated slice.
/// Reads in 4 KiB chunks using `File.read` (the lowest-level stable API).
/// If the stream exceeds `max_bytes` the excess is drained so the child
/// process can exit, and the returned slice is the literal "<output truncated>".
fn readPipe(allocator: std.mem.Allocator, file: std.fs.File, max_bytes: usize) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(allocator);
    var tmp: [4096]u8 = undefined;
    var truncated = false;
    while (true) {
        const n = file.read(&tmp) catch break;
        if (n == 0) break;
        if (truncated) continue; // drain so child can exit
        if (buf.items.len + n > max_bytes) {
            // Switch to drain-only mode and prepare the truncation message.
            buf.clearRetainingCapacity();
            try buf.appendSlice(allocator, "<output truncated>");
            truncated = true;
        } else {
            try buf.appendSlice(allocator, tmp[0..n]);
        }
    }
    return buf.toOwnedSlice(allocator);
}

/// Per-stream context for the concurrent pipe reader threads spawned by run().
const PipeCtx = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    max_bytes: usize,
    bytes: ?[]u8 = null, // set on success; null on error
    fail: ?anyerror = null, // set on error; null on success
};

fn readPipeFn(ctx: *PipeCtx) void {
    ctx.bytes = readPipe(ctx.allocator, ctx.file, ctx.max_bytes) catch |e| {
        ctx.fail = e;
        return;
    };
}

/// Spawns `argv[0]` with the remaining elements as arguments, waits for it
/// to exit, and returns captured stdout, stderr, and the exit code.
///
/// Output is captured up to MAX_OUTPUT_BYTES per stream.  If a stream exceeds
/// that limit the bytes after the limit are discarded and the field is replaced
/// with the literal "<output truncated>" so callers always receive valid UTF-8.
///
/// stdout and stderr are read concurrently to prevent a deadlock: if they were
/// read sequentially and the child filled the stderr pipe buffer (~64 KiB on
/// Linux) before closing stdout, the child would block on stderr while we
/// blocked waiting for stdout EOF — neither side would ever make progress.
///
/// The caller owns the returned ExecResult and must call `deinit` on it.
pub fn run(allocator: std.mem.Allocator, argv: []const []const u8) !ExecResult {
    if (argv.len == 0) return error.EmptyArgv;

    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    var stdout_ctx = PipeCtx{ .allocator = allocator, .file = child.stdout.?, .max_bytes = MAX_OUTPUT_BYTES };
    var stderr_ctx = PipeCtx{ .allocator = allocator, .file = child.stderr.?, .max_bytes = MAX_OUTPUT_BYTES };

    const stdout_thread = try std.Thread.spawn(.{}, readPipeFn, .{&stdout_ctx});
    const stderr_thread = std.Thread.spawn(.{}, readPipeFn, .{&stderr_ctx}) catch |err| {
        // stderr thread failed to start: join stdout, free any bytes it
        // may have already allocated, then kill and reap the child.
        stdout_thread.join();
        if (stdout_ctx.bytes) |b| allocator.free(b);
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return err;
    };

    stdout_thread.join();
    stderr_thread.join();

    const term = try child.wait();
    const exit_code: u8 = switch (term) {
        .Exited => |code| @truncate(code),
        .Signal => |sig| @truncate(128 + sig),
        else => 255,
    };

    if (stdout_ctx.fail) |e| {
        if (stderr_ctx.bytes) |b| allocator.free(b);
        return e;
    }
    if (stderr_ctx.fail) |e| {
        if (stdout_ctx.bytes) |b| allocator.free(b);
        return e;
    }

    return ExecResult{
        .stdout = stdout_ctx.bytes.?,
        .stderr = stderr_ctx.bytes.?,
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
