const std = @import("std");

pub const vt = @import("runtime/vt.zig");

pub const VerifiableTerminal = vt.VerifiableTerminal;

test {
    std.testing.refAllDecls(@This());
}
