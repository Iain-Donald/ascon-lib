const std = @import("std");

const c_sources = [_][]const u8{
    "ascon_perm.c",
    "ascon_hash.c",
    "ascon_xof.c",
    "ascon_aead.c",
};
const c_flags = [_][]const u8{ "-std=c99", "-Wall", "-Wextra", "-pedantic", };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    
    // library
    const library_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    library_module.addIncludePath(b.path("include"));
    library_module.addIncludePath(b.path("src"));
    library_module.addCSourceFiles(.{
        .root = b.path("src"),
        .files = &c_sources,
        .flags = &c_flags,
    });

    const lib = b.addLibrary(.{
        .name = "ascon",
        .root_module = library_module,
        .linkage = .static,
    });

    // Only ascon.h import needed.
    lib.installHeader(b.path("include/ascon.h"), "ascon.h");
    b.installArtifact(lib);

    const demo_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    demo_module.addIncludePath(b.path("include"));
    demo_module.addCSourceFile(.{
        .file = b.path("demo/demo.c"),
        .flags = &c_flags,
    });
    demo_module.linkLibrary(lib);

    const demo = b.addExecutable(.{.name = "demo", .root_module = demo_module,});
    b.installArtifact(demo);

    const run_demo = b.addRunArtifact(demo);
    run_demo.step.dependOn(b.getInstallStep());
    b.step("demo", "Run demo program").dependOn(&run_demo.step);

    // Known-answer tests (KATs)
    const kat_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    kat_module.addIncludePath(b.path("include"));
    kat_module.addCSourceFile(.{
        .file = b.path("tests/kat.c"),
        .flags = &c_flags,
    });
    kat_module.linkLibrary(lib);

    const kat = b.addExecutable(.{
        .name = "kat",
        .root_module = kat_module,
    });

    const run_kat = b.addRunArtifact(kat);
    run_kat.setCwd(b.path("."));
    // Non-zero exit from the harness fails the build.
    run_kat.expectExitCode(0);

    b.step("test", "Run KATs").dependOn(&run_kat.step);
}
