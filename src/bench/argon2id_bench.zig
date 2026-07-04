const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;

// Floor params from APEX §5.7
const T_COST: u32 = 3;
const M_COST: u32 = 131072; // 128 MiB — production value post-benchmark
const P_COST: u32 = 1;
const DK_LEN: usize = 32;
const DEFAULT_ITERS: usize = 7;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const n: usize = if (args.len > 1)
        std.fmt.parseInt(usize, args[1], 10) catch DEFAULT_ITERS
    else
        DEFAULT_ITERS;

    const params = argon2.Params{ .t = T_COST, .m = M_COST, .p = P_COST };

    var times_ns = try allocator.alloc(u64, n);
    defer allocator.free(times_ns);

    var rng = std.Random.DefaultPrng.init(@truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
    const random = rng.random();

    var dk: [DK_LEN]u8 = undefined;
    var password: [16]u8 = undefined;
    var salt: [16]u8 = undefined;

    for (0..n) |i| {
        random.bytes(&password);
        random.bytes(&salt);
        const t0 = std.time.nanoTimestamp();
        try argon2.kdf(allocator, &dk, &password, &salt, params, .argon2id);
        const t1 = std.time.nanoTimestamp();
        times_ns[i] = @intCast(t1 - t0);
        std.crypto.secureZero(u8, &dk);
    }

    // Sort a copy to compute percentiles without mutating times_ns order.
    const sorted = try allocator.dupe(u64, times_ns);
    defer allocator.free(sorted);
    std.mem.sort(u64, sorted, {}, std.sort.asc(u64));

    const sum: u128 = blk: {
        var s: u128 = 0;
        for (times_ns) |t| s += t;
        break :blk s;
    };
    const mean_ns: f64 = @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(n));
    const p50_ns: f64 = @floatFromInt(sorted[n / 2]);
    const p95_ns: f64 = @floatFromInt(sorted[@min(n - 1, n * 95 / 100)]);
    const min_ns: f64 = @floatFromInt(sorted[0]);
    const max_ns: f64 = @floatFromInt(sorted[n - 1]);

    var out_buf: [512]u8 = undefined;
    const out = try std.fmt.bufPrint(&out_buf,
        \\{{
        \\  "params": {{"m": {d}, "t": {d}, "p": {d}}},
        \\  "n": {d},
        \\  "mean_ms": {d:.2},
        \\  "p50_ms":  {d:.2},
        \\  "p95_ms":  {d:.2},
        \\  "min_ms":  {d:.2},
        \\  "max_ms":  {d:.2}
        \\}}
        \\
    , .{
        M_COST,
        T_COST,
        P_COST,
        n,
        mean_ns / 1_000_000.0,
        p50_ns / 1_000_000.0,
        p95_ns / 1_000_000.0,
        min_ns / 1_000_000.0,
        max_ns / 1_000_000.0,
    });
    try std.fs.File.stdout().writeAll(out);
}
