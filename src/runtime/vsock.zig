const std = @import("std");
const posix = std.posix;

// AF_VSOCK = 40 on Linux (not exposed in std.posix on non-Linux builds).
const AF_VSOCK: u32 = 40;

/// VsockHandler provides a unified interface for enclave-to-host communication.
/// It can be compiled to use either standard TCP (for local dev) or AF_VSOCK (for TEEs).
pub const VsockHandler = struct {
    stream: std.net.Stream,
    is_vsock: bool,

    // AWS Nitro vsock CIDs
    pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
    pub const VMADDR_CID_HOST: u32 = 2;

    /// Connects to the host. In simulation mode (Mac/Dev), uses TCP.
    pub fn connect(allocator: std.mem.Allocator, cid: u32, port: u32) !VsockHandler {
        if (connectVsock(cid, port)) |stream| {
            return VsockHandler{ .stream = stream, .is_vsock = true };
        } else |err| {
            std.debug.print("[VAR] VSOCK connection failed ({any}). Falling back to TCP loopback...\n", .{err});
            _ = allocator;
            const address = try std.net.Address.parseIp4("127.0.0.1", @intCast(port));
            const stream = try std.net.tcpConnectToAddress(address);
            return VsockHandler{ .stream = stream, .is_vsock = false };
        }
    }

    fn connectVsock(cid: u32, port: u32) !std.net.Stream {
        if (@import("builtin").os.tag != .linux) return error.UnsupportedOs;

        const fd = try posix.socket(AF_VSOCK, posix.SOCK.STREAM, 0);
        errdefer posix.close(fd);

        const SockaddrVm = extern struct {
            family: u16,
            reserved1: u16,
            port: u32,
            cid: u32,
            zero: [4]u8,
        };

        var addr = SockaddrVm{
            .family = @intCast(AF_VSOCK),
            .reserved1 = 0,
            .port = port,
            .cid = cid,
            .zero = [_]u8{0} ** 4,
        };

        try posix.connect(fd, @ptrCast(&addr), @sizeOf(SockaddrVm));
        return std.net.Stream{ .handle = fd };
    }

    pub fn send(self: *VsockHandler, data: []const u8) !usize {
        return try self.stream.write(data);
    }

    pub fn receive(self: *VsockHandler, buffer: []u8) !usize {
        return try self.stream.read(buffer);
    }

    /// Reads a newline-terminated line into buf.
    /// Returns the line content without the trailing '\n' (or '\r\n').
    /// Returns an empty slice if the connection closed cleanly.
    pub fn readLine(self: *VsockHandler, buf: []u8) ![]u8 {
        var pos: usize = 0;
        while (pos < buf.len) {
            var byte: [1]u8 = undefined;
            const n = try self.stream.read(&byte);
            if (n == 0) return buf[0..pos]; // connection closed
            if (byte[0] == '\n') return buf[0..pos];
            if (byte[0] != '\r') { // skip bare CR
                buf[pos] = byte[0];
                pos += 1;
            }
        }
        return error.LineTooLong;
    }

    pub fn close(self: *VsockHandler) void {
        self.stream.close();
    }
};

/// VsockServer listens for incoming agent connections.
/// On Linux it tries AF_VSOCK first; falls back to TCP 127.0.0.1 (simulation).
pub const VsockServer = struct {
    fd: posix.socket_t,
    is_vsock: bool,

    pub fn listen(port: u32) !VsockServer {
        if (comptime @import("builtin").os.tag == .linux) {
            if (listenVsock(port)) |fd| {
                std.debug.print("[VAR] Listening on vsock port {d}\n", .{port});
                return VsockServer{ .fd = fd, .is_vsock = true };
            } else |_| {}
        }
        // TCP fallback for dev / simulation.
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        errdefer posix.close(fd);
        const reuse: c_int = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse));
        var addr = try std.net.Address.parseIp4("127.0.0.1", @intCast(port));
        try posix.bind(fd, &addr.any, addr.getOsSockLen());
        try posix.listen(fd, 1);
        std.debug.print("[VAR] Listening on TCP 127.0.0.1:{d}\n", .{port});
        return VsockServer{ .fd = fd, .is_vsock = false };
    }

    fn listenVsock(port: u32) !posix.socket_t {
        const SockaddrVm = extern struct {
            family: u16,
            reserved1: u16,
            port: u32,
            cid: u32,
            zero: [4]u8,
        };
        const fd = try posix.socket(AF_VSOCK, posix.SOCK.STREAM, 0);
        errdefer posix.close(fd);
        var addr = SockaddrVm{
            .family = @intCast(AF_VSOCK),
            .reserved1 = 0,
            .port = port,
            .cid = VsockHandler.VMADDR_CID_ANY,
            .zero = [_]u8{0} ** 4,
        };
        try posix.bind(fd, @ptrCast(&addr), @sizeOf(SockaddrVm));
        try posix.listen(fd, 1);
        return fd;
    }

    pub fn accept(self: *VsockServer) !VsockHandler {
        const conn_fd = try posix.accept(self.fd, null, null, 0);
        return VsockHandler{
            .stream = std.net.Stream{ .handle = conn_fd },
            .is_vsock = self.is_vsock,
        };
    }

    pub fn close(self: *VsockServer) void {
        posix.close(self.fd);
    }
};
