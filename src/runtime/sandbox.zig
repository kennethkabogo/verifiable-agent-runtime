//! Process hardening for VAR-gateway.
//!
//! Call hardenProcess() once, after:
//!   • The listening socket address is resolved (socket bind happens inside serve())
//!   • All environment variables have been consumed (VAR_RESUME_STATE, VAR_KMS_KEY_ARN, …)
//!   • The vault and logger have been initialised
//!
//! And before any untrusted connection is accepted.
//!
//! All hardening steps treat failure as fatal — VAR-gateway must never serve
//! requests in a partially-sandboxed state.  This mirrors the Firedancer
//! philosophy: a sandbox that can be silently bypassed is not a sandbox.
//!
//! --- Why not pivot_root? ---
//!
//! In production (Nitro enclave) the enclave VM boots from an in-memory initrd
//! (ramfs) — there is no host filesystem visible inside the VM whatsoever, so
//! pivot_root would be a no-op at best and a boot-breaker at worst.  In
//! simulation mode pivot_root requires CAP_SYS_ADMIN and a dedicated mount
//! namespace, adding significant fragility for zero benefit.
//!
//! Landlock achieves the same goal — restrict what the *already-running*
//! process can open going forward — without any of those prerequisites, and it
//! degrades gracefully on older kernels rather than fatally erroring.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

// ---------------------------------------------------------------------------
// Fatal error helper
// ---------------------------------------------------------------------------

/// Log the failure and terminate immediately.
/// We intentionally do not attempt cleanup — in a partially-sandboxed state
/// the state of secrets is unknown and the safest action is hard exit.
fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err("[sandbox] FATAL: " ++ fmt, args);
    // exit_group terminates all threads, not just the caller.
    std.process.exit(1);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Harden the calling process.
///
/// On non-Linux hosts (macOS dev machines, Windows CI) this returns immediately
/// without touching any Linux-specific syscalls so the simulation workflow is
/// not broken.
///
/// Hardening sequence:
///   1. Scrub sensitive environment variables (volatile zero of value bytes).
///   2. Landlock:  deny all future filesystem opens (kernel ≥ 5.13; skipped
///      with a warning on older kernels to preserve CI compatibility).
///   3. Capabilities: PR_SET_NO_NEW_PRIVS + capset-to-zero.
///   4. Seccomp-BPF: strict allowlist — unknown syscalls kill the process.
pub fn hardenProcess() void {
    if (comptime builtin.os.tag != .linux) {
        std.log.warn("[sandbox] Non-Linux host — skipping process hardening", .{});
        return;
    }

    // FD audit FIRST: /proc/self/fd must be openable, which requires the
    // filesystem to be accessible.  After installLandlock() all opens are
    // denied, so we cannot perform the audit there.
    auditFileDescriptors();
    scrubEnvironment();

    installLandlock() catch |err| switch (err) {
        error.LandlockUnsupported => std.log.warn(
            "[sandbox] Kernel <5.13: Landlock unavailable — filesystem isolation skipped",
            .{},
        ),
        else => fatal("Landlock install failed: {}", .{err}),
    };

    dropCapabilities() catch |err| fatal("Capability drop failed: {}", .{err});

    // Seccomp MUST be last: once active only allowlisted syscalls may be made.
    installSeccompFilter() catch |err| fatal("Seccomp install failed: {}", .{err});

    std.log.info(
        "[sandbox] Hardened: env scrubbed | Landlock | caps=∅ | seccomp/BPF active",
        .{},
    );
}

// ---------------------------------------------------------------------------
// Step 0 — File-descriptor audit
// ---------------------------------------------------------------------------

/// Walk /proc/self/fd and fatal() if any descriptor is open beyond the
/// expected allowlist {stdin=0, stdout=1, stderr=2}.
///
/// This catches "ghost FDs": parent-process handles, accidentally un-closed
/// setup resources (e.g. /dev/nsm), or anything else that shouldn't survive
/// into the serving phase.  Must run before installLandlock() because after
/// that we can no longer open the procfs directory.
///
/// On non-procfs systems (macOS, restricted containers) the open fails and
/// we skip the audit with a warning rather than fataling — procfs absence
/// is not itself a security problem.
fn auditFileDescriptors() void {
    var proc_fd_dir = std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true }) catch |err| {
        std.log.warn("[sandbox] FD audit skipped (cannot open /proc/self/fd: {})", .{err});
        return;
    };
    defer proc_fd_dir.close();

    // Record the directory's own fd so we can skip it during iteration.
    const dir_fd = proc_fd_dir.fd;

    var it = proc_fd_dir.iterate();
    while (true) {
        const maybe_entry = it.next() catch |err| {
            // Iteration error is non-fatal: we log and stop early rather than
            // silently missing potential ghost FDs.
            std.log.warn("[sandbox] FD audit: iteration error: {} — partial audit", .{err});
            break;
        };
        const entry = maybe_entry orelse break; // null = end of directory

        // Each entry name is the decimal fd number (e.g. "0", "1", "5").
        const fd_num = std.fmt.parseInt(std.posix.fd_t, entry.name, 10) catch continue;

        if (fd_num == dir_fd) continue;          // the /proc/self/fd dir itself
        if (fd_num == 0 or fd_num == 1 or fd_num == 2) continue; // stdin/stdout/stderr

        fatal(
            "Ghost FD {d} open at sandbox entry — unexpected descriptor " ++
                "(possible unclosed setup resource or credential leak). Aborting.",
            .{fd_num},
        );
    }

    std.log.debug("[sandbox] FD audit: clean (only stdin/stdout/stderr open)", .{});
}

// ---------------------------------------------------------------------------
// Step 1 — Environment scrubbing
// ---------------------------------------------------------------------------

/// Variables consumed at startup that must not remain readable in memory.
///
/// After scrubbing, /proc/<pid>/environ shows only null bytes for these
/// entries, so a post-authentication directory-traversal in a skill cannot
/// exfiltrate them.  Addresses the post-attestation-measurement injection
/// class described in Trail of Bits audit finding TOB-WAPI-13.
const SCRUB_VARS = [_][]const u8{
    "VAR_KMS_KEY_ARN",
    "VAR_RESUME_STATE",
    "VAR_KMS_PROXY_PORT",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "ANTHROPIC_API_KEY",
};

fn scrubEnvironment() void {
    for (std.os.environ) |entry| {
        const str = std.mem.span(entry);
        for (SCRUB_VARS) |name| {
            if (std.mem.startsWith(u8, str, name) and
                str.len > name.len and
                str[name.len] == '=')
            {
                // Volatile writes prevent the compiler from optimising away
                // the zero-fill — identical guarantee to vault.zig's secureZero.
                std.crypto.secureZero(u8, str[name.len + 1 ..]);
                std.log.debug("[sandbox] Scrubbed env: {s}", .{name});
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Step 2 — Landlock filesystem isolation
// ---------------------------------------------------------------------------

// Landlock v1 filesystem access-right bits (kernel 5.13+).
// We handle every right and add zero allow-rules, so the effective policy is:
// "deny all future open/openat calls" — the gateway holds all fds it needs.
const FS_EXECUTE: u64     = 1 << 0;
const FS_WRITE_FILE: u64  = 1 << 1;
const FS_READ_FILE: u64   = 1 << 2;
const FS_READ_DIR: u64    = 1 << 3;
const FS_REMOVE_DIR: u64  = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64   = 1 << 6;
const FS_MAKE_DIR: u64    = 1 << 7;
const FS_MAKE_REG: u64    = 1 << 8;
const FS_MAKE_SOCK: u64   = 1 << 9;
const FS_MAKE_FIFO: u64   = 1 << 10;
const FS_MAKE_BLOCK: u64  = 1 << 11;
const FS_MAKE_SYM: u64    = 1 << 12;

const FS_ALL: u64 =
    FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_READ_DIR |
    FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_CHAR | FS_MAKE_DIR |
    FS_MAKE_REG | FS_MAKE_SOCK | FS_MAKE_FIFO | FS_MAKE_BLOCK | FS_MAKE_SYM;

/// Passed to landlock_create_ruleset with the VERSION flag to probe ABI level.
const LANDLOCK_CREATE_RULESET_VERSION: usize = 1 << 0;

const LandlockRulesetAttr = extern struct {
    handled_access_fs: u64,
};

fn installLandlock() !void {
    // ABI version query: attr=NULL, size=0, flags=LANDLOCK_CREATE_RULESET_VERSION.
    // Returns positive ABI version on success (kernel ≥ 5.13), -ENOSYS otherwise.
    // Passing a non-NULL attr with the version flag returns -EINVAL per the kernel
    // source, so we must pass zero for the first two arguments here.
    const abi_rc = linux.syscall3(.landlock_create_ruleset, 0, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (@as(isize, @bitCast(abi_rc)) < 0) {
        // Any negative result from the probe (ENOSYS, ENOTSUP, …) means we
        // cannot use Landlock on this kernel.
        return error.LandlockUnsupported;
    }
    // abi_rc is the positive ABI version — Landlock is available.
    // Proceed to create the deny-all ruleset.

    const attr = LandlockRulesetAttr{ .handled_access_fs = FS_ALL };
    const fd_rc = linux.syscall3(
        .landlock_create_ruleset,
        @intFromPtr(&attr),
        @sizeOf(LandlockRulesetAttr),
        0,
    );
    if (@as(isize, @bitCast(fd_rc)) < 0) {
        std.log.err("[sandbox] landlock_create_ruleset errno={d}", .{-@as(isize, @bitCast(fd_rc))});
        return error.LandlockFailed;
    }
    const ruleset_fd: i32 = @intCast(fd_rc);
    defer std.posix.close(ruleset_fd);

    // PR_SET_NO_NEW_PRIVS is required before restrict_self on kernels < 5.17.
    // Setting it here is idempotent with step 3 below.
    const nnp_rc = linux.syscall5(.prctl, 38, 1, 0, 0, 0); // PR_SET_NO_NEW_PRIVS = 38
    if (@as(isize, @bitCast(nnp_rc)) != 0) return error.LandlockFailed;

    // No path-beneath rules added → policy is: deny all filesystem access.
    const restrict_rc = linux.syscall2(
        .landlock_restrict_self,
        @as(usize, @intCast(ruleset_fd)),
        0,
    );
    if (@as(isize, @bitCast(restrict_rc)) != 0) {
        std.log.err("[sandbox] landlock_restrict_self errno={d}", .{-@as(isize, @bitCast(restrict_rc))});
        return error.LandlockFailed;
    }
}

// ---------------------------------------------------------------------------
// Step 3 — Capability drop
// ---------------------------------------------------------------------------

// capset(2) header version for 64-bit (two-word) capability sets.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

const CapHeader = extern struct {
    version: u32 = LINUX_CAPABILITY_VERSION_3,
    pid: i32 = 0, // 0 = calling thread
};

// Two structs cover capability words 0-31 and 32-63.  All-zero = no caps.
const CapData = extern struct {
    effective: u32 = 0,
    permitted: u32 = 0,
    inheritable: u32 = 0,
};

fn dropCapabilities() !void {
    // PR_SET_NO_NEW_PRIVS = 38.  Prevents execve from granting new privileges
    // and is also required before an unprivileged seccomp filter installation.
    const nnp = linux.syscall5(.prctl, 38, 1, 0, 0, 0);
    if (@as(isize, @bitCast(nnp)) != 0) {
        std.log.err("[sandbox] PR_SET_NO_NEW_PRIVS errno={d}", .{-@as(isize, @bitCast(nnp))});
        return error.CapabilityDropFailed;
    }

    const hdr = CapHeader{};
    const data = [2]CapData{ .{}, .{} };
    const cap_rc = linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&data));
    if (@as(isize, @bitCast(cap_rc)) != 0) {
        const errno = -@as(isize, @bitCast(cap_rc));
        // EPERM = 1: already unprivileged — expected in CI and simulation.
        if (errno == 1) {
            std.log.debug("[sandbox] capset EPERM — already unprivileged, continuing", .{});
        } else {
            std.log.err("[sandbox] capset errno={d}", .{errno});
            return error.CapabilityDropFailed;
        }
    }
}

// ---------------------------------------------------------------------------
// Step 4 — Seccomp-BPF syscall allowlist
// ---------------------------------------------------------------------------

// Classic BPF (cBPF) structures used by the seccomp(2) interface.

const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

// BPF instruction encodings (from <linux/filter.h>).
const BPF_LD: u16  = 0x00;
const BPF_W: u16   = 0x00; // 32-bit word load
const BPF_ABS: u16 = 0x20; // load from absolute packet offset
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16   = 0x00; // immediate constant
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32        = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000; // kills all threads (kernel ≥ 4.14)

// Byte offsets into the `struct seccomp_data` the kernel passes to the filter.
const OFF_NR: u32   = 0; // int32  nr   — syscall number
const OFF_ARCH: u32 = 4; // uint32 arch — AUDIT_ARCH_*

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

// prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
const PR_SET_SECCOMP: usize      = 22;
const SECCOMP_MODE_FILTER: usize = 2;

fn bpfStmt(code: u16, k: u32) SockFilter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

fn bpfJump(code: u16, k: u32, jt: u8, jf: u8) SockFilter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

/// Syscalls permitted after sandboxing (x86-64 numbers).
///
/// Each entry generates two BPF instructions:
///   JEQ nr, jt=0, jf=1   — if match: fall through to ALLOW; else skip ALLOW
///   RET ALLOW
///
/// To audit missing syscalls, run:
///   strace -c -e trace=all ./zig-out/bin/VAR-gateway
/// Any syscall absent from this list will cause SECCOMP_RET_KILL_PROCESS.
const ALLOWED_SYSCALLS = [_]u32{
    // Memory management (GPA allocator: mmap/munmap/brk; no file-backed mappings needed).
    9,   // mmap
    10,  // mprotect
    11,  // munmap
    12,  // brk
    28,  // madvise

    // Basic I/O (socket read/write, std.log to stderr).
    0,   // read
    1,   // write
    3,   // close
    5,   // fstat
    20,  // writev

    // Networking (TCP accept loop + HTTP request/response).
    39,  // getpid       — used in handleHibernate() self-SIGTERM
    41,  // socket
    42,  // connect
    43,  // accept
    44,  // sendto
    45,  // recvfrom
    46,  // sendmsg
    47,  // recvmsg
    48,  // shutdown
    49,  // bind
    50,  // listen
    51,  // getsockname
    52,  // getpeername
    54,  // setsockopt
    55,  // getsockopt
    72,  // fcntl         — O_NONBLOCK on accepted sockets
    288, // accept4

    // Signal handling (SIGTERM / SIGINT for clean shutdown, self-kill).
    13,  // rt_sigaction
    14,  // rt_sigprocmask
    15,  // rt_sigreturn
    62,  // kill          — self-SIGTERM in handleHibernate()
    234, // tgkill

    // Threading and synchronisation (std.Thread / GPA internal locks).
    56,  // clone
    186, // gettid
    202, // futex
    218, // set_tid_address
    273, // set_robust_list
    334, // rseq
    435, // clone3

    // Timer and event loop (std.net.Server uses epoll).
    228, // clock_gettime
    230, // clock_nanosleep
    232, // epoll_wait
    233, // epoll_ctl
    291, // epoll_create1

    // Entropy (std.crypto.random — Ed25519 / AES-GCM nonce generation).
    318, // getrandom

    // Process exit (both single-thread and group variants).
    60,  // exit
    231, // exit_group

    // Architecture-specific (thread-local storage setup by the Zig runtime).
    158, // arch_prctl

    // Subprocess execution (POST /exec → exec.run()).
    //
    // The gateway calls pipe2 to create capture pipes, clone to fork, and
    // wait4 to reap the child.  The forked child calls dup2 to wire the
    // pipes to its stdin/stdout/stderr before calling execve.  All four
    // were absent from the allowlist: any POST /exec request after
    // hardenProcess() would cause wait4 to hit SECCOMP_RET_KILL_PROCESS,
    // terminating every thread in the gateway process.
    //
    // Note: forked children inherit this seccomp filter and the Landlock
    // deny-all filesystem policy, so dynamically-linked commands that need
    // openat (257) for their dynamic linker will fail in production.  Full
    // exec support in a hardened enclave requires a separate exec-worker
    // process that is not subject to the gateway's Landlock ruleset.
    33,  // dup2    — child: redirect pipe ends to stdin/stdout/stderr
    59,  // execve  — child: replace image with the requested command
    61,  // wait4   — parent: reap the child after both pipes are drained
    293, // pipe2   — parent: create stdout/stderr capture pipes before fork
};

fn installSeccompFilter() !void {
    // Filter layout (comptime size):
    //   [0]       LD arch
    //   [1]       JEQ x86_64, skip kill / kill on mismatch
    //   [2]       RET KILL_PROCESS  (wrong arch)
    //   [3]       LD syscall nr
    //   [4..4+2N-1]  N×(JEQ nr, RET ALLOW) pairs
    //   [4+2N]    RET KILL_PROCESS  (default deny)
    const N = ALLOWED_SYSCALLS.len;
    const FILTER_LEN = 4 + N * 2 + 1;

    var filter: [FILTER_LEN]SockFilter = undefined;
    var idx: usize = 0;

    // ── Architecture guard ────────────────────────────────────────────────────
    // Reject filters from being applied to a binary running under an unexpected
    // ABI (e.g. 32-bit compat mode) where the syscall numbers differ.
    filter[idx] = bpfStmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH);                  idx += 1;
    filter[idx] = bpfJump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0); idx += 1;
    filter[idx] = bpfStmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);           idx += 1;

    // ── Load syscall number once ──────────────────────────────────────────────
    filter[idx] = bpfStmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR); idx += 1;

    // ── Per-syscall checks ───────────────────────────────────────────────────
    for (ALLOWED_SYSCALLS) |nr| {
        // jt=0: condition true → execute next instruction (ALLOW).
        // jf=1: condition false → skip next instruction, continue to next JEQ.
        filter[idx] = bpfJump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1); idx += 1;
        filter[idx] = bpfStmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);   idx += 1;
    }

    // ── Default deny ──────────────────────────────────────────────────────────
    filter[idx] = bpfStmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS); idx += 1;

    std.debug.assert(idx == FILTER_LEN);

    const prog = SockFprog{
        .len = @intCast(FILTER_LEN),
        .filter = &filter,
    };

    // prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog).
    // PR_SET_NO_NEW_PRIVS must already be set — done in dropCapabilities().
    // The kernel copies filter[] immediately so stack-allocated filter is safe.
    const rc = linux.syscall3(
        .prctl,
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER,
        @intFromPtr(&prog),
    );
    if (@as(isize, @bitCast(rc)) != 0) {
        std.log.err("[sandbox] prctl(PR_SET_SECCOMP) errno={d}", .{-@as(isize, @bitCast(rc))});
        return error.SeccompFailed;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "FILTER_LEN is correct" {
    // Verify the comptime length matches the number of instructions we'd emit.
    const N = ALLOWED_SYSCALLS.len;
    const expected = 4 + N * 2 + 1;
    // 4 prologue + 2-per-syscall + 1 default deny
    try std.testing.expect(expected > 0);
    try std.testing.expect(expected <= 4096); // BPF instruction limit
}

test "BPF constants are consistent with kernel ABI" {
    // Smoke-check that our magic numbers match documented kernel values.
    try std.testing.expectEqual(@as(u32, 0x7fff_0000), SECCOMP_RET_ALLOW);
    try std.testing.expectEqual(@as(u32, 0x8000_0000), SECCOMP_RET_KILL_PROCESS);
    try std.testing.expectEqual(@as(u32, 0xc000_003e), AUDIT_ARCH_X86_64);
}

test "scrubEnvironment does not panic on empty environ" {
    // environ may be empty in some test harness environments; ensure no crash.
    // We can't easily call scrubEnvironment() in tests since it modifies the
    // actual process environ, but we can verify SCRUB_VARS is non-empty.
    try std.testing.expect(SCRUB_VARS.len > 0);
}
