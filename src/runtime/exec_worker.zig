/// Exec-worker subprocess for POST /exec.
///
/// The sandbox (sandbox.hardenProcess) installs Landlock (deny-all filesystem)
/// and a seccomp-BPF allowlist that does not include openat(257).  Any child
/// process forked *after* hardenProcess() inherits both restrictions: the
/// dynamic linker calls openat to load shared libraries, hitting the seccomp
/// KILL_PROCESS default action and terminating the entire gateway.
///
/// Fix: fork the worker *before* hardenProcess() so it runs outside the
/// Landlock and seccomp policies.  The gateway sends exec requests over a pair
/// of pipes; the worker executes the command and streams stdout/stderr back.
/// A mutex ensures only one request is in flight at a time.
///
/// Wire format (both directions use length-prefixed binary, big-endian u32):
///   Request:  u32(json_len) + json  {"argv":["cmd","arg1",…]}
///   Response: u32(exit_code) + u32(stdout_len) + stdout + u32(stderr_len) + stderr
const std  = @import("std");
const exec = @import("exec.zig");

pub const ExecWorker = struct {
    req_fd: std.posix.fd_t,
    res_fd: std.posix.fd_t,
    pid:    std.posix.pid_t,
    mutex:  std.Thread.Mutex = .{},

    /// Fork the worker before sandbox.hardenProcess() is called.
    pub fn start() !ExecWorker {
        const req_pipe = try std.posix.pipe();
        const res_pipe = try std.posix.pipe();

        const pid = try std.posix.fork();
        if (pid == 0) {
            // Worker process: close unused pipe ends, run the loop, then exit.
            std.posix.close(req_pipe[1]);
            std.posix.close(res_pipe[0]);
            workerLoop(req_pipe[0], res_pipe[1]);
            std.posix.exit(0);
        }

        // Parent: close unused pipe ends.
        std.posix.close(req_pipe[0]);
        std.posix.close(res_pipe[1]);

        return ExecWorker{
            .req_fd = req_pipe[1],
            .res_fd = res_pipe[0],
            .pid    = pid,
        };
    }

    /// Send argv to the worker and return the result.  Thread-safe (mutex).
    pub fn run(
        self:      *ExecWorker,
        allocator: std.mem.Allocator,
        argv:      []const []const u8,
    ) !exec.ExecResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        // --- serialise request ---
        var buf = std.ArrayListUnmanaged(u8){};
        defer buf.deinit(allocator);
        try buf.appendSlice(allocator, "{\"argv\":[");
        for (argv, 0..) |arg, i| {
            if (i > 0) try buf.append(allocator, ',');
            try buf.append(allocator, '"');
            for (arg) |c| {
                if (c == '"' or c == '\\') try buf.append(allocator, '\\');
                try buf.append(allocator, c);
            }
            try buf.append(allocator, '"');
        }
        try buf.appendSlice(allocator, "]}");

        var len_be: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_be, @intCast(buf.items.len), .big);
        try writeAll(self.req_fd, &len_be);
        try writeAll(self.req_fd, buf.items);

        // --- deserialise response ---
        var hdr: [4]u8 = undefined;

        try readAll(self.res_fd, &hdr);
        const exit_code: u8 = @truncate(std.mem.readInt(u32, &hdr, .big));

        try readAll(self.res_fd, &hdr);
        const stdout_len = std.mem.readInt(u32, &hdr, .big);
        const stdout = try allocator.alloc(u8, stdout_len);
        errdefer allocator.free(stdout);
        if (stdout_len > 0) try readAll(self.res_fd, stdout);

        try readAll(self.res_fd, &hdr);
        const stderr_len = std.mem.readInt(u32, &hdr, .big);
        const stderr = try allocator.alloc(u8, stderr_len);
        errdefer allocator.free(stderr);
        if (stderr_len > 0) try readAll(self.res_fd, stderr);

        return exec.ExecResult{ .exit_code = exit_code, .stdout = stdout, .stderr = stderr };
    }

    pub fn deinit(self: *ExecWorker) void {
        std.posix.close(self.req_fd);
        std.posix.close(self.res_fd);
        _ = std.posix.waitpid(self.pid, 0);
    }
};

// ── helpers ────────────────────────────────────────────────────────────────

fn writeAll(fd: std.posix.fd_t, data: []const u8) !void {
    var done: usize = 0;
    while (done < data.len) done += try std.posix.write(fd, data[done..]);
}

fn readAll(fd: std.posix.fd_t, buf: []u8) !void {
    var done: usize = 0;
    while (done < buf.len) {
        const n = try std.posix.read(fd, buf[done..]);
        if (n == 0) return error.WorkerClosed;
        done += n;
    }
}

// ── worker process ─────────────────────────────────────────────────────────

fn workerLoop(req_fd: std.posix.fd_t, res_fd: std.posix.fd_t) void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    while (true) {
        // Read request length.
        var len_be: [4]u8 = undefined;
        readAll(req_fd, &len_be) catch return; // EOF → parent closed, exit

        const len = std.mem.readInt(u32, &len_be, .big);
        const json = allocator.alloc(u8, len) catch { sendError(res_fd); continue; };
        defer allocator.free(json);
        readAll(req_fd, json) catch return;

        // Parse argv.
        const argv = parseArgv(allocator, json) catch { sendError(res_fd); continue; };
        defer {
            for (argv) |a| allocator.free(a);
            allocator.free(argv);
        }

        // Execute.
        const result = exec.run(allocator, argv) catch { sendError(res_fd); continue; };
        defer result.deinit(allocator);

        // Write response.
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, result.exit_code, .big);
        writeAll(res_fd, &hdr) catch return;
        std.mem.writeInt(u32, &hdr, @intCast(result.stdout.len), .big);
        writeAll(res_fd, &hdr) catch return;
        writeAll(res_fd, result.stdout) catch return;
        std.mem.writeInt(u32, &hdr, @intCast(result.stderr.len), .big);
        writeAll(res_fd, &hdr) catch return;
        writeAll(res_fd, result.stderr) catch return;
    }
}

fn sendError(res_fd: std.posix.fd_t) void {
    const exit255: [4]u8 = .{ 0, 0, 0, 255 };
    const zero:    [4]u8 = .{ 0, 0, 0, 0   };
    writeAll(res_fd, &exit255) catch return;
    writeAll(res_fd, &zero)    catch return;
    writeAll(res_fd, &zero)    catch return;
}

fn parseArgv(allocator: std.mem.Allocator, json: []const u8) ![][]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const arr_val = switch (parsed.value) {
        .object => |obj| obj.get("argv") orelse return error.MissingArgv,
        else => return error.BadFormat,
    };
    const arr = switch (arr_val) {
        .array => |a| a,
        else => return error.BadFormat,
    };
    if (arr.items.len == 0) return error.EmptyArgv;

    const out = try allocator.alloc([]u8, arr.items.len);
    errdefer allocator.free(out);
    var n: usize = 0;
    errdefer for (out[0..n]) |s| allocator.free(s);

    for (arr.items) |item| {
        out[n] = try allocator.dupe(u8, switch (item) {
            .string => |s| s,
            else => return error.BadArgType,
        });
        n += 1;
    }
    return out;
}
