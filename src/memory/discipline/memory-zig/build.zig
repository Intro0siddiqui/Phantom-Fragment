const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "phantom_memory",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    lib.linkLibC();

    // Try to link numa, but don't fail if not available
    // NUMA functions will return errors at runtime if library is missing
    const numa_option = b.option(
        bool,
        "numa",
        "Enable NUMA support (requires libnuma)",
    ) orelse false;

    if (numa_option) {
        lib.linkSystemLibrary("numa");
    }

    b.installArtifact(lib);
}
