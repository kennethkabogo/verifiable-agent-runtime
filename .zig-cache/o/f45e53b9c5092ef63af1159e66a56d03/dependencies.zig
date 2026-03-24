pub const packages = struct {
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/android-ndk" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/android-ndk";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/android-ndk");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/breakpad" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/breakpad";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/breakpad");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "breakpad", "N-V-__8AALw2uwF_03u4JRkZwRLc3Y9hakkYV7NKRR9-RIZJ" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/dcimgui" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/dcimgui";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/dcimgui");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "bindings", "N-V-__8AANT61wB--nJ95Gj_ctmzAtcjloZ__hRqNw5lC1Kr" },
            .{ "imgui", "N-V-__8AAEbOfQBnvcFcCX2W5z7tDaN8vaNZGamEQtNOe0UI" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
            .{ "freetype", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/freetype" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/fontconfig" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/fontconfig";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/fontconfig");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "fontconfig", "N-V-__8AAIrfdwARSa-zMmxWwFuwpXf1T3asIN7s5jqi9c1v" },
            .{ "freetype", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/freetype" },
            .{ "libxml2", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libxml2" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/freetype" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/freetype";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/freetype");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "freetype", "N-V-__8AAKLKpwC4H27Ps_0iL3bPkQb-z6ZVSrB-x_3EEkub" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
            .{ "libpng", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libpng" },
            .{ "zlib", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/zlib" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/glslang" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/glslang";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/glslang");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "glslang", "N-V-__8AABzkUgISeKGgXAzgtutgJsZc0-kkeqBBscJgMkvy" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/gtk4-layer-shell" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/gtk4-layer-shell";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/gtk4-layer-shell");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "gtk4_layer_shell", "N-V-__8AALiNBAA-_0gprYr92CjrMj1I5bqNu0TSJOnjFNSr" },
            .{ "wayland_protocols", "N-V-__8AAKw-DAAaV8bOAAGqA0-oD7o-HNIlPFYKRXSPT03S" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/harfbuzz" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/harfbuzz";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/harfbuzz");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "harfbuzz", "N-V-__8AAG02ugUcWec-Ndp-i7JTsJ0dgF8nnJRUInkGLG7G" },
            .{ "freetype", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/freetype" },
            .{ "macos", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/macos" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/highway" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/highway";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/highway");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "highway", "N-V-__8AAGmZhABbsPJLfbqrh6JTHsXhY6qCaLAQyx25e0XE" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
            .{ "android_ndk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/android-ndk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libintl" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libintl";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libintl");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "gettext", "N-V-__8AADcZkgn4cMhTUpIz6mShCKyqqB-NBtf_S2bHaTC-" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libpng" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libpng";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libpng");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "libpng", "N-V-__8AAJrvXQCqAT8Mg9o_tk6m0yf5Fz-gCNEOKLyTSerD" },
            .{ "zlib", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/zlib" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libxml2" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libxml2";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libxml2");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "libxml2", "N-V-__8AAG3RoQEyRC2Vw7Qoro5SYBf62IHn3HjqtNVY6aWK" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/macos" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/macos";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/macos");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/oniguruma" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/oniguruma";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/oniguruma");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "oniguruma", "N-V-__8AAHjwMQDBXnLq3Q2QhaivE0kE2aD138vtX2Bq1g7c" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/opengl" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/opengl";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/opengl");
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/sentry" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/sentry";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/sentry");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "sentry", "N-V-__8AAPlZGwBEa-gxrcypGBZ2R8Bse4JYSfo_ul8i2jlG" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
            .{ "breakpad", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/breakpad" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/simdutf" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/simdutf";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/simdutf");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
            .{ "android_ndk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/android-ndk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/spirv-cross" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/spirv-cross";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/spirv-cross");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "spirv_cross", "N-V-__8AANb6pwD7O1WG6L5nvD_rNMvnSc9Cpg1ijSlTYywv" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/utfcpp" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/utfcpp";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/utfcpp");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "utfcpp", "N-V-__8AAHffAgDU0YQmynL8K35WzkcnMUmBVQHQ0jlcKpjH" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
            .{ "android_ndk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/android-ndk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/wuffs" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/wuffs";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/wuffs");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "wuffs", "N-V-__8AAAzZywE3s51XfsLbP9eyEw57ae9swYB9aGB6fCMs" },
            .{ "pixels", "N-V-__8AADYiAAB_80AWnH1AxXC0tql9thT-R-DYO1gBqTLc" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/zlib" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/zlib";
        pub const build_zig = @import("/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/zlib");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zlib", "N-V-__8AAB0eQwD-0MdOEBmz7intriBReIsIDNlukNVoNu6o" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
        };
    };
    pub const @"N-V-__8AAAzZywE3s51XfsLbP9eyEw57ae9swYB9aGB6fCMs" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAAzZywE3s51XfsLbP9eyEw57ae9swYB9aGB6fCMs";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAB0eQwD-0MdOEBmz7intriBReIsIDNlukNVoNu6o" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAB0eQwD-0MdOEBmz7intriBReIsIDNlukNVoNu6o";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AABVbAwBwDRyZONfx553tvMW8_A2OKUoLzPUSRiLF" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AABVbAwBwDRyZONfx553tvMW8_A2OKUoLzPUSRiLF";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AABzkUgISeKGgXAzgtutgJsZc0-kkeqBBscJgMkvy" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AABzkUgISeKGgXAzgtutgJsZc0-kkeqBBscJgMkvy";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AADYiAAB_80AWnH1AxXC0tql9thT-R-DYO1gBqTLc" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AADYiAAB_80AWnH1AxXC0tql9thT-R-DYO1gBqTLc";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AADcZkgn4cMhTUpIz6mShCKyqqB-NBtf_S2bHaTC-" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AADcZkgn4cMhTUpIz6mShCKyqqB-NBtf_S2bHaTC-";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAEbOfQBnvcFcCX2W5z7tDaN8vaNZGamEQtNOe0UI" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAEbOfQBnvcFcCX2W5z7tDaN8vaNZGamEQtNOe0UI";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAG02ugUcWec-Ndp-i7JTsJ0dgF8nnJRUInkGLG7G" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAG02ugUcWec-Ndp-i7JTsJ0dgF8nnJRUInkGLG7G";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAG3RoQEyRC2Vw7Qoro5SYBf62IHn3HjqtNVY6aWK" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAG3RoQEyRC2Vw7Qoro5SYBf62IHn3HjqtNVY6aWK";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAGmZhABbsPJLfbqrh6JTHsXhY6qCaLAQyx25e0XE" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAGmZhABbsPJLfbqrh6JTHsXhY6qCaLAQyx25e0XE";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAHffAgDU0YQmynL8K35WzkcnMUmBVQHQ0jlcKpjH" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAHffAgDU0YQmynL8K35WzkcnMUmBVQHQ0jlcKpjH";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAHjwMQDBXnLq3Q2QhaivE0kE2aD138vtX2Bq1g7c" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAHjwMQDBXnLq3Q2QhaivE0kE2aD138vtX2Bq1g7c";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAIC5lwAVPJJzxnCAahSvZTIlG-HhtOvnM1uh-66x" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAIC5lwAVPJJzxnCAahSvZTIlG-HhtOvnM1uh-66x";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAIrfdwARSa-zMmxWwFuwpXf1T3asIN7s5jqi9c1v" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAIrfdwARSa-zMmxWwFuwpXf1T3asIN7s5jqi9c1v";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAJrvXQCqAT8Mg9o_tk6m0yf5Fz-gCNEOKLyTSerD" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAJrvXQCqAT8Mg9o_tk6m0yf5Fz-gCNEOKLyTSerD";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAKLKpwC4H27Ps_0iL3bPkQb-z6ZVSrB-x_3EEkub" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAKLKpwC4H27Ps_0iL3bPkQb-z6ZVSrB-x_3EEkub";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAKYZBAB-CFHBKs3u4JkeiT4BMvyHu3Y5aaWF3Bbs" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AAKrHGAAs2shYq8UkE6bGcR1QJtLTyOE_lcosMn6t" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AAKw-DAAaV8bOAAGqA0-oD7o-HNIlPFYKRXSPT03S" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AALiNBAA-_0gprYr92CjrMj1I5bqNu0TSJOnjFNSr" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AALw2uwF_03u4JRkZwRLc3Y9hakkYV7NKRR9-RIZJ" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AALw2uwF_03u4JRkZwRLc3Y9hakkYV7NKRR9-RIZJ";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAMVLTABmYkLqhZPLXnMl-KyN38R8UVYqGrxqO26s" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAMVLTABmYkLqhZPLXnMl-KyN38R8UVYqGrxqO26s";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AANT61wB--nJ95Gj_ctmzAtcjloZ__hRqNw5lC1Kr" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AANT61wB--nJ95Gj_ctmzAtcjloZ__hRqNw5lC1Kr";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AANb6pwD7O1WG6L5nvD_rNMvnSc9Cpg1ijSlTYywv" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AANb6pwD7O1WG6L5nvD_rNMvnSc9Cpg1ijSlTYywv";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"N-V-__8AAPlZGwBEa-gxrcypGBZ2R8Bse4JYSfo_ul8i2jlG" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/N-V-__8AAPlZGwBEa-gxrcypGBZ2R8Bse4JYSfo_ul8i2jlG";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv";
        pub const build_zig = @import("ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "libxev", "libxev-0.0.0-86vtc4IcEwCqEYxEYoN_3KXmc6A9VLcm22aVImfvecYs" },
            .{ "vaxis", "vaxis-0.5.1-BWNV_LosCQAGmCCNOLljCIw6j6-yt53tji6n6rwJ2BhS" },
            .{ "z2d", "z2d-0.10.0-j5P_Hu-6FgBsZNgwphIqh17jDnj8_yPtD8yzjO6PpHRQ" },
            .{ "zig_objc", "zig_objc-0.0.0-Ir_Sp5gTAQCvxxR7oVIrPXxXwsfKgVP7_wqoOQrZjFeK" },
            .{ "zig_js", "zig_js-0.0.0-rjCAV-6GAADxFug7rDmPH-uM_XcnJ5NmuAMJCAscMjhi" },
            .{ "uucode", "uucode-0.2.0-ZZjBPqZVVABQepOqZHR7vV_NcaN-wats0IB6o-Exj6m9" },
            .{ "zig_wayland", "wayland-0.5.0-dev-lQa1khrMAQDJDwYFKpdH3HizherB7sHo5dKMECfvxQHe" },
            .{ "zf", "zf-0.10.3-OIRy8RuJAACKA3Lohoumrt85nRbHwbpMcUaLES8vxDnh" },
            .{ "gobject", "gobject-0.3.0-Skun7ANLnwDvEfIpVmohcppXgOvg_I6YOJFmPIsKfXk-" },
            .{ "dcimgui", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/dcimgui" },
            .{ "fontconfig", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/fontconfig" },
            .{ "freetype", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/freetype" },
            .{ "gtk4_layer_shell", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/gtk4-layer-shell" },
            .{ "harfbuzz", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/harfbuzz" },
            .{ "highway", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/highway" },
            .{ "libintl", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libintl" },
            .{ "libpng", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/libpng" },
            .{ "macos", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/macos" },
            .{ "oniguruma", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/oniguruma" },
            .{ "opengl", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/opengl" },
            .{ "sentry", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/sentry" },
            .{ "simdutf", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/simdutf" },
            .{ "utfcpp", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/utfcpp" },
            .{ "wuffs", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/wuffs" },
            .{ "zlib", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/zlib" },
            .{ "glslang", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/glslang" },
            .{ "spirv_cross", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/spirv-cross" },
            .{ "wayland", "N-V-__8AAKrHGAAs2shYq8UkE6bGcR1QJtLTyOE_lcosMn6t" },
            .{ "wayland_protocols", "N-V-__8AAKw-DAAaV8bOAAGqA0-oD7o-HNIlPFYKRXSPT03S" },
            .{ "plasma_wayland_protocols", "N-V-__8AAKYZBAB-CFHBKs3u4JkeiT4BMvyHu3Y5aaWF3Bbs" },
            .{ "jetbrains_mono", "N-V-__8AAIC5lwAVPJJzxnCAahSvZTIlG-HhtOvnM1uh-66x" },
            .{ "nerd_fonts_symbols_only", "N-V-__8AAMVLTABmYkLqhZPLXnMl-KyN38R8UVYqGrxqO26s" },
            .{ "apple_sdk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/apple-sdk" },
            .{ "android_ndk", "/p/ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv/pkg/android-ndk" },
            .{ "iterm2_themes", "N-V-__8AABVbAwBwDRyZONfx553tvMW8_A2OKUoLzPUSRiLF" },
        };
    };
    pub const @"gobject-0.3.0-Skun7ANLnwDvEfIpVmohcppXgOvg_I6YOJFmPIsKfXk-" = struct {
        pub const available = false;
    };
    pub const @"libxev-0.0.0-86vtc4IcEwCqEYxEYoN_3KXmc6A9VLcm22aVImfvecYs" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/libxev-0.0.0-86vtc4IcEwCqEYxEYoN_3KXmc6A9VLcm22aVImfvecYs";
        pub const build_zig = @import("libxev-0.0.0-86vtc4IcEwCqEYxEYoN_3KXmc6A9VLcm22aVImfvecYs");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"uucode-0.1.0-ZZjBPj96QADXyt5sqwBJUnhaDYs_qBeeKijZvlRa0eqM" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/uucode-0.1.0-ZZjBPj96QADXyt5sqwBJUnhaDYs_qBeeKijZvlRa0eqM";
        pub const build_zig = @import("uucode-0.1.0-ZZjBPj96QADXyt5sqwBJUnhaDYs_qBeeKijZvlRa0eqM");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"uucode-0.2.0-ZZjBPqZVVABQepOqZHR7vV_NcaN-wats0IB6o-Exj6m9" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/uucode-0.2.0-ZZjBPqZVVABQepOqZHR7vV_NcaN-wats0IB6o-Exj6m9";
        pub const build_zig = @import("uucode-0.2.0-ZZjBPqZVVABQepOqZHR7vV_NcaN-wats0IB6o-Exj6m9");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"vaxis-0.5.1-BWNV_LosCQAGmCCNOLljCIw6j6-yt53tji6n6rwJ2BhS" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/vaxis-0.5.1-BWNV_LosCQAGmCCNOLljCIw6j6-yt53tji6n6rwJ2BhS";
        pub const build_zig = @import("vaxis-0.5.1-BWNV_LosCQAGmCCNOLljCIw6j6-yt53tji6n6rwJ2BhS");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zigimg", "zigimg-0.1.0-8_eo2vHnEwCIVW34Q14Ec-xUlzIoVg86-7FU2ypPtxms" },
            .{ "uucode", "uucode-0.1.0-ZZjBPj96QADXyt5sqwBJUnhaDYs_qBeeKijZvlRa0eqM" },
        };
    };
    pub const @"wayland-0.5.0-dev-lQa1khrMAQDJDwYFKpdH3HizherB7sHo5dKMECfvxQHe" = struct {
        pub const available = false;
    };
    pub const @"z2d-0.10.0-j5P_Hu-6FgBsZNgwphIqh17jDnj8_yPtD8yzjO6PpHRQ" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/z2d-0.10.0-j5P_Hu-6FgBsZNgwphIqh17jDnj8_yPtD8yzjO6PpHRQ";
        pub const build_zig = @import("z2d-0.10.0-j5P_Hu-6FgBsZNgwphIqh17jDnj8_yPtD8yzjO6PpHRQ");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"zf-0.10.3-OIRy8RuJAACKA3Lohoumrt85nRbHwbpMcUaLES8vxDnh" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/zf-0.10.3-OIRy8RuJAACKA3Lohoumrt85nRbHwbpMcUaLES8vxDnh";
        pub const build_zig = @import("zf-0.10.3-OIRy8RuJAACKA3Lohoumrt85nRbHwbpMcUaLES8vxDnh");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "vaxis", "vaxis-0.5.1-BWNV_LosCQAGmCCNOLljCIw6j6-yt53tji6n6rwJ2BhS" },
        };
    };
    pub const @"zig_js-0.0.0-rjCAV-6GAADxFug7rDmPH-uM_XcnJ5NmuAMJCAscMjhi" = struct {
        pub const available = false;
    };
    pub const @"zig_objc-0.0.0-Ir_Sp5gTAQCvxxR7oVIrPXxXwsfKgVP7_wqoOQrZjFeK" = struct {
        pub const available = true;
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/zig_objc-0.0.0-Ir_Sp5gTAQCvxxR7oVIrPXxXwsfKgVP7_wqoOQrZjFeK";
        pub const build_zig = @import("zig_objc-0.0.0-Ir_Sp5gTAQCvxxR7oVIrPXxXwsfKgVP7_wqoOQrZjFeK");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"zigimg-0.1.0-8_eo2vHnEwCIVW34Q14Ec-xUlzIoVg86-7FU2ypPtxms" = struct {
        pub const build_root = "/Users/kennjoroge/.cache/zig/p/zigimg-0.1.0-8_eo2vHnEwCIVW34Q14Ec-xUlzIoVg86-7FU2ypPtxms";
        pub const build_zig = @import("zigimg-0.1.0-8_eo2vHnEwCIVW34Q14Ec-xUlzIoVg86-7FU2ypPtxms");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "ghostty", "ghostty-1.3.2-dev-5UdBC3zy-wR7mukH96i_-4vjcgTF1VI9p_E7G-oiDPZv" },
};
