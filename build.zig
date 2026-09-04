const std = @import("std");

const c_sources = [_][]const u8{
    "ascon_perm.c",
    "ascon_hash.c",
    "ascon_xof.c",
    "ascon_aead.c",
};

const warn_flags = [_][]const u8{
    "-std=c99",
    "-Wall",
    "-Wextra",
    "-pedantic",
};
const lib_flags = warn_flags ++ [_][]const u8{"-ffreestanding"};
const host_flags = warn_flags;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library //
    // no libc
    const library_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = false,
    });

    library_module.addIncludePath(b.path("include"));
    library_module.addIncludePath(b.path("src"));
    library_module.addCSourceFiles(.{
        .root = b.path("src"),
        .files = &c_sources,
        .flags = &lib_flags,
    });

    const lib = b.addLibrary(.{
        .name = "ascon",
        .root_module = library_module,
        .linkage = .static,
    });

    lib.installHeader(b.path("include/ascon.h"), "ascon.h");

    // The default `zig build` installs the library alone, which succeeds on targets without libc.
    b.installArtifact(lib);

    // Demo //
    // demo uses libc.
    const demo_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    demo_module.addIncludePath(b.path("include"));
    demo_module.addCSourceFile(.{
        .file = b.path("demo/demo.c"),
        .flags = &host_flags,
    });
    demo_module.linkLibrary(lib);

    const demo = b.addExecutable(.{
        .name = "demo",
        .root_module = demo_module,
    });

    b.step("demo", "Build the demo into zig-out/bin")
        .dependOn(&b.addInstallArtifact(demo, .{}).step);

    // Known-answer tests //
    // KAT test uses libc.
    const kat_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    kat_module.addIncludePath(b.path("include"));
    kat_module.addCSourceFile(.{
        .file = b.path("tests/kat.c"),
        .flags = &host_flags,
    });
    kat_module.linkLibrary(lib);

    const kat = b.addExecutable(.{
        .name = "kat",
        .root_module = kat_module,
    });

    b.step("kat", "Build the KAT test").dependOn(&b.addInstallArtifact(kat, .{}).step);
}
