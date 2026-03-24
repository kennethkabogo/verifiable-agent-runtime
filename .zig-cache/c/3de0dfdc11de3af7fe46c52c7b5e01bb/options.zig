pub const @"src.terminal.build_options.Artifact" = enum (u1) {
    ghostty = 0,
    lib = 1,
};
pub const artifact: @"src.terminal.build_options.Artifact" = .lib;
pub const c_abi: bool = false;
pub const oniguruma: bool = false;
pub const simd: bool = true;
pub const slow_runtime_safety: bool = true;
pub const kitty_graphics: bool = false;
pub const tmux_control_mode: bool = false;
