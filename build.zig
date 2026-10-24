const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const exe = b.addExecutable(.{
        .name = "servar",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    exe.root_module.linkSystemLibrary("crypto", .{});
    b.installArtifact(exe);

    const bch_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bch_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_bch_tests = b.addRunArtifact(bch_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_bch_tests.step);
}
