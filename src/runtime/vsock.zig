const std = @import("std");
const posix = std.posix;

/// VsockHandler provides a unified interface for enclave-to-host communication.
/// It can be compiled to use either standard TCP (for local dev) or AF_VSOCK (for TEEs).
pub const VsockHandler = struct {
    stream: std.net.Stream,
    is_vsock: bool,

    // AWS Nitro vsock CID and Ports
    pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
    pub const VMADDR_CID_HOST: u32 = 2;

    /// Connects to the host. In simulation mode (Mac/Dev), uses TCP.
    pub fn connect(allocator: std.mem.Allocator, cid: u32, port: u32) !VsockHandler {
        // Check for TEE environment via build tags or runtime detection.
        // For this prototype, we'll try VSOCK and fallback to TCP.
        
        if (connectVsock(cid, port)) |stream| {
            return VsockHandler{ .stream = stream, .is_vsock = true };
        } else |err| {
            std.debug.print("[VAR] VSOCK connection failed ({any}). Falling back to TCP loopback...\n", .{err});
            _ = allocator;
            // Local fallback: assume proxy is at 127.0.0.1:port
            const address = try std.net.Address.parseIp4("127.0.0.1", @intCast(port));
            const stream = try std.net.tcpConnectToAddress(address);
            return VsockHandler{ .stream = stream, .is_vsock = false };
        }
    }

    fn connectVsock(cid: u32, port: u32) !std.net.Stream {
        // This requires a Linux environment with vsock support.
        if (@import("builtin").os.tag != .linux) return error.UnsupportedOs;

        const fd = try posix.socket(posix.AF.VSOCK, posix.SOCK.STREAM, 0);
        errdefer posix.close(fd);

        // sockaddr_vm structure for vsock
        const sockaddr_vm = extern struct {
            family: u16,
            reserved1: u16,
            port: u32,
            cid: u32,
            zero: [4]u8,
        };

        var addr = sockaddr_vm{
            .family = posix.AF.VSOCK,
            .reserved1 = 0,
            .port = port,
            .cid = cid,
            .zero = [_]u8{0} ** 4,
        };

        // Casting sockaddr_vm to sockaddr for the connect call
        try posix.connect(fd, @ptrCast(&addr), @sizeOf(sockaddr_vm));
        
        return std.net.Stream{ .handle = fd };
    }

    pub fn send(self: *VsockHandler, data: []const u8) !usize {
        return try self.stream.write(data);
    }

    pub fn receive(self: *VsockHandler, buffer: []u8) !usize {
        return try self.stream.read(buffer);
    }

    pub fn close(self: *VsockHandler) void {
        self.stream.close();
    }
};
