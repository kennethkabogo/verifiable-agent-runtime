const std = @import("std");
const vt = @import("ghostty-vt");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// VerifiableTerminal is a bridge between the Ghostty VT state machine
/// and our verifiable execution runtime. It handles raw PTY input and
/// provides deterministic state digests for Remote Attestation.
pub const VerifiableTerminal = struct {
    terminal: vt.Terminal,
    allocator: std.mem.Allocator,
    // ReadonlyStream is Ghostty's optimized stream for non-interactive state tracking.
    stream: vt.ReadonlyStream,

    pub fn init(allocator: std.mem.Allocator, width: u16, height: u16) !VerifiableTerminal {
        // Ghostty Terminal initialization with fixed-width/height (cols/rows).
        var terminal = try vt.Terminal.init(allocator, .{
            .cols = width,
            .rows = height,
            .max_scrollback = 0, // Enclave only cares about current state, not historical scrollback.
        });

        return .{
            .terminal = terminal,
            .allocator = allocator,
            // Create a readonly stream tied to this terminal.
            .stream = terminal.vtStream(),
        };
    }

    pub fn deinit(self: *VerifiableTerminal) void {
        self.stream.deinit();
        self.terminal.deinit(self.allocator);
    }

    /// Feed raw PTY bytes into the VT state machine.
    pub fn processInput(self: *VerifiableTerminal, data: []const u8) void {
        self.stream.nextSlice(data);
    }

    /// Compute the L2 State Digest according to the Evidence Bundle Spec v1.1.
    /// Format: Header(magic, version, cursor, dims) || Row-major Cell Data.
    pub fn digestState(self: *VerifiableTerminal) [32]u8 {
        var hasher = Sha256.init(.{});
        const active_screen = self.terminal.screens.active;
        const width = self.terminal.cols;
        const height = self.terminal.rows;

        // 1. Hash Metadata: Format Version (1), Cursor X, Cursor Y, Width, Height
        var meta = [_]u8{0} ** 9;
        meta[0] = 1; // Format Version
        std.mem.writeInt(u16, meta[1..3], active_screen.cursor.x, .little);
        std.mem.writeInt(u16, meta[3..5], active_screen.cursor.y, .little);
        std.mem.writeInt(u16, meta[5..7], width, .little);
        std.mem.writeInt(u16, meta[7..9], height, .little);
        hasher.update(&meta);

        // 2. Hash Cells in Row-Major Order
        var y: u16 = 0;
        while (y < height) : (y += 1) {
            var x: u16 = 0;
            while (x < width) : (x += 1) {
                const pt = vt.point.Point{ .active = .{ .x = x, .y = y } };
                // Ghostty uses a sparse Page system. We pin the active point to get the cell.
                // pin() returns null when the point falls outside the active page region
                // (shouldn't happen with fixed 80×24 dimensions, but we emit zero bytes
                // rather than panic so the digest stays deterministic and the enclave keeps
                // running).
                const pin = active_screen.pages.pin(pt) orelse {
                    hasher.update(&[_]u8{0} ** (4 + 3 + 3 + 1)); // cp + fg + bg + attrs
                    continue;
                };
                const rac = pin.rowAndCell();
                const cell = rac.cell;

                // A. Codepoint (Serialized as UTF-8, null-padded to 4 bytes)
                var cp_buf = [_]u8{0} ** 4;
                if (cell.hasGrapheme()) {
                    // Pull from the page's grapheme storage.
                    const page = &pin.node.data;
                    if (page.lookupGrapheme(cell)) |cps| {
                        // Take the primary (first) codepoint of the grapheme cluster.
                        const len = std.unicode.utf8Encode(cps[0], &cp_buf) catch 0;
                        _ = len;
                    }
                } else {
                    const len = std.unicode.utf8Encode(cell.codepoint(), &cp_buf) catch 0;
                    _ = len;
                }
                hasher.update(&cp_buf);

                // B. Colors and Attributes
                const page = &pin.node.data;
                const style = page.styles.get(page.memory, cell.style_id);
                
                // Resolve final colors against the terminal-wide palette.
                const fg = style.fg(.{
                    .default = self.terminal.colors.foreground.get().?,
                    .palette = &self.terminal.colors.palette.current,
                });
                
                // bg() is an optional color, fallback to terminal background.
                const bg = style.bg(cell, &self.terminal.colors.palette.current) orelse self.terminal.colors.background.get().?;

                hasher.update(&[_]u8{ fg.r, fg.g, fg.b });
                hasher.update(&[_]u8{ bg.r, bg.g, bg.b });

                // C. Map SGR attributes to v1.1 8-bit bitmask.
                var attr_mask: u8 = 0;
                if (style.flags.bold) attr_mask |= 1 << 0;
                if (style.flags.italic) attr_mask |= 1 << 1;
                if (style.flags.faint) attr_mask |= 1 << 2;
                if (style.flags.blink) attr_mask |= 1 << 3;
                if (style.flags.inverse) attr_mask |= 1 << 4;
                if (style.flags.invisible) attr_mask |= 1 << 5;
                if (style.flags.strikethrough) attr_mask |= 1 << 6;
                // Ghostty supports many underline types (curly, double, etc.); we flatten to one bit.
                if (style.flags.underline != .none) attr_mask |= 1 << 7;
                hasher.update(&[_]u8{attr_mask});
            }
        }

        var out: [32]u8 = undefined;
        hasher.final(&out);
        return out;
    }
};
