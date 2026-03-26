const std = @import("std");
const testing = std.testing;
const vt = @import("ghostty-vt");
const Sha256 = std.crypto.hash.sha2.Sha256;

const build_options = @import("build_options");
const with_ghostty = build_options.with_ghostty;

/// VerifiableTerminal is a bridge between the Ghostty VT state machine
/// and our verifiable execution runtime. It handles raw PTY input and
/// provides deterministic state digests for Remote Attestation.
pub const VerifiableTerminal = struct {
    terminal: if (with_ghostty) vt.Terminal else void,
    allocator: std.mem.Allocator,
    // ReadonlyStream is Ghostty's optimized stream for non-interactive state tracking.
    stream: if (with_ghostty) vt.ReadonlyStream else void,

    pub fn init(allocator: std.mem.Allocator, width: u16, height: u16) !VerifiableTerminal {
        const Impl = struct {
            fn real(a: std.mem.Allocator, w: u16, h: u16) !VerifiableTerminal {
                var terminal = try vt.Terminal.init(a, .{
                    .cols = w,
                    .rows = h,
                    .max_scrollback = 0,
                });
                
                // Ensure deterministic default colors for the state digest.
                // In headless CI, these otherwise remain null/unset.
                terminal.colors.foreground.set(.{ .r = 0, .g = 0, .b = 0 });
                terminal.colors.background.set(.{ .r = 0xFF, .g = 0xFF, .b = 0xFF });

                return VerifiableTerminal{
                    .terminal = terminal,
                    .allocator = a,
                    .stream = terminal.vtStream(),
                };
            }
            fn mock(a: std.mem.Allocator, w: u16, h: u16) !VerifiableTerminal {
                _ = w; _ = h;
                std.debug.print("[VAR] Initializing Mock Terminal (80x24)\n", .{});
                return VerifiableTerminal{
                    .terminal = {},
                    .allocator = a,
                    .stream = {},
                };
            }
        };
        if (comptime with_ghostty) return Impl.real(allocator, width, height);
        return Impl.mock(allocator, width, height);
    }

    pub fn deinit(self: *VerifiableTerminal) void {
        const Impl = struct {
            fn real(s: *VerifiableTerminal) void {
                s.stream.deinit();
                s.terminal.deinit(s.allocator);
            }
            fn mock(s: *VerifiableTerminal) void { _ = s; }
        };
        if (comptime with_ghostty) return Impl.real(self);
        return Impl.mock(self);
    }

    /// Feed raw PTY bytes into the VT state machine.
    pub fn processInput(self: *VerifiableTerminal, data: []const u8) void {
        const Impl = struct {
            fn real(s: *VerifiableTerminal, d: []const u8) void { s.stream.nextSlice(d); }
            fn mock(s: *VerifiableTerminal, d: []const u8) void { _ = s; _ = d; }
        };
        if (comptime with_ghostty) return Impl.real(self, data);
        return Impl.mock(self, data);
    }

    /// Compute the L2 State Digest according to the Evidence Bundle Spec v1.1.
    pub fn digestState(self: *VerifiableTerminal) [32]u8 {
        const Impl = struct {
            fn real(s: *VerifiableTerminal) [32]u8 {
                var hasher = Sha256.init(.{});
                const active_screen = s.terminal.screens.active;
                const width = s.terminal.cols;
                const height = s.terminal.rows;

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
                        const style = if (cell.style_id > 0) page.styles.get(page.memory, cell.style_id).* else vt.Style{};
                        
                        // Resolve final colors against the terminal-wide palette.
                        // We strictly use the terminal's own default fg/bg, which are
                        // explicitly initialized during VerifiableTerminal.init.
                        const fg = style.fg(.{
                            .default = s.terminal.colors.foreground.get().?,
                            .palette = &s.terminal.colors.palette.current,
                        });
                        
                        // bg() is an optional color, fallback to terminal background.
                        const bg = style.bg(cell, &s.terminal.colors.palette.current) orelse s.terminal.colors.background.get().?;

                        hasher.update(&[_]u8{ fg.r, fg.g, fg.b });
                        hasher.update(&[_]u8{ bg.r, bg.g, bg.b });

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
                var digest: [32]u8 = undefined;
                hasher.final(&digest);
                return digest;
            }
            fn mock(s: *VerifiableTerminal) [32]u8 { _ = s; return [_]u8{0xDD} ** 32; }
        };
        if (comptime with_ghostty) return Impl.real(self);
        return Impl.mock(self);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────────

test "empty terminal digest is reproducible across instances" {
    // Two freshly-initialised terminals with no input must produce the same
    // hash — proves the digest is a pure function of visible state, not of
    // any pointer address or allocation order.
    var vt1 = try VerifiableTerminal.init(testing.allocator, 80, 24);
    defer vt1.deinit();
    var vt2 = try VerifiableTerminal.init(testing.allocator, 80, 24);
    defer vt2.deinit();

    try testing.expectEqualSlices(u8, &vt1.digestState(), &vt2.digestState());
}

test "digest changes after input" {
    if (!with_ghostty) return error.SkipZigTest;
    var term = try VerifiableTerminal.init(testing.allocator, 80, 24);
    defer term.deinit();

    const before = term.digestState();
    term.processInput("hello");
    const after = term.digestState();

    // The screen changed, so the hash must differ.
    try testing.expect(!std.mem.eql(u8, &before, &after));
}

test "same input on two instances produces identical digest" {
    // Core determinism claim: the digest is a function of the rendered screen,
    // not of when or how bytes arrived.  Feeding identical bytes to two
    // independent terminals must yield the same final hash.
    var vt1 = try VerifiableTerminal.init(testing.allocator, 80, 24);
    defer vt1.deinit();
    var vt2 = try VerifiableTerminal.init(testing.allocator, 80, 24);
    defer vt2.deinit();

    const input = "VAR determinism test\r\n";
    vt1.processInput(input);
    vt2.processInput(input);

    try testing.expectEqualSlices(u8, &vt1.digestState(), &vt2.digestState());
}

test "chunked vs whole input yields same digest" {
    // Bytes arriving in different chunk sizes must produce the same terminal
    // state — the VT state machine must be stateless with respect to framing.
    var whole = try VerifiableTerminal.init(testing.allocator, 80, 24);
    defer whole.deinit();
    var chunked = try VerifiableTerminal.init(testing.allocator, 80, 24);
    defer chunked.deinit();

    const input = "chunk test ABCDE\r\n";
    whole.processInput(input);
    // Feed the same bytes one at a time.
    for (input) |byte| {
        chunked.processInput(&[_]u8{byte});
    }

    try testing.expectEqualSlices(u8, &whole.digestState(), &chunked.digestState());
}

test "different inputs produce different digests" {
    if (!with_ghostty) return error.SkipZigTest;
    var vt1 = try VerifiableTerminal.init(testing.allocator, 80, 24);
    defer vt1.deinit();
    var vt2 = try VerifiableTerminal.init(testing.allocator, 80, 24);
    defer vt2.deinit();

    vt1.processInput("agent action A");
    vt2.processInput("agent action B");

    try testing.expect(!std.mem.eql(u8, &vt1.digestState(), &vt2.digestState()));
}
