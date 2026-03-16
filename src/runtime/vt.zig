const std = @import("std");

/// Cell represents a single terminal grid cell as returned by libghostty-vt.
///
/// codepoint_u32 uses a fixed 4-byte (UTF-32 / u32) encoding rather than
/// variable-length UTF-8. This is required for deterministic digest construction:
/// a raw UTF-8 concatenation would make codepoint "AB" (2 bytes) followed by
/// fg_color indistinguishable from codepoint "A" + codepoint "B" + fg_color if
/// two adjacent cells happen to produce the same byte sequence. The fixed-width
/// u32 encoding eliminates this ambiguity and matches ghostty-vt's internal cell
/// representation.
pub const Cell = struct {
    codepoint_u32: u32,  // Unicode scalar value, fixed 4 bytes (not variable UTF-8)
    fg_color_u32: u32,
    bg_color_u32: u32,
    attrs_u8: u8,
};

/// VerifiableTerminal maintains the terminal state and provides snapshots for audit.
/// This acts as a wrapper around libghostty-vt's state machine.
pub const VerifiableTerminal = struct {
    allocator: std.mem.Allocator,
    width: u16,
    height: u16,
    // cell_buffer: []Cell, // Hypothetical buffer from libghostty-vt

    pub fn init(allocator: std.mem.Allocator, w: u16, h: u16) !VerifiableTerminal {
        return VerifiableTerminal{
            .allocator = allocator,
            .width = w,
            .height = h,
        };
    }

    /// Processes raw terminal sequences (ANSI/XTERM) and updates internal state.
    pub fn processInput(self: *VerifiableTerminal, data: []const u8) !void {
        // In production, this calls ghostty_vt_write(self.vt_master, data)
        _ = self;
        _ = data;
    }

    /// Serializes the current terminal state (grid cells + cursor) and returns a digest.
    ///
    /// Cell digest input layout (per cell, all little-endian):
    ///   codepoint_u32  — 4 bytes, fixed-width UTF-32 scalar (NOT variable UTF-8)
    ///   fg_color_u32   — 4 bytes
    ///   bg_color_u32   — 4 bytes
    ///   attrs_u8       — 1 byte
    ///
    /// Using codepoint_u32 ensures the digest input is unambiguous: variable-length
    /// UTF-8 would make multi-byte codepoints collide with sequences of shorter
    /// codepoints that happen to produce the same byte run.
    pub fn digestState(self: *VerifiableTerminal) ![32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Mock: Hash the visual parameters for now
        hasher.update(std.mem.asBytes(&self.width));
        hasher.update(std.mem.asBytes(&self.height));

        // In production: Iterate through visible rows/cols and hash cell content + attributes
        // var y: u16 = 0;
        // while (y < self.height) : (y += 1) {
        //     var x: u16 = 0;
        //     while (x < self.width) : (x += 1) {
        //         const cell: Cell = self.getCell(x, y);
        //         hasher.update(std.mem.asBytes(&cell.codepoint_u32));  // fixed 4 bytes
        //         hasher.update(std.mem.asBytes(&cell.fg_color_u32));
        //         hasher.update(std.mem.asBytes(&cell.bg_color_u32));
        //         hasher.update(std.mem.asBytes(&cell.attrs_u8));
        //     }
        // }

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};
