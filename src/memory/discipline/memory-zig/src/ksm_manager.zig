const std = @import("std");
const c = @cImport({
    @cInclude("sys/mman.h");
});

pub const KsmManager = struct {
    pub fn enable() !void {
        const file = try std.fs.openFileAbsolute("/sys/kernel/mm/ksm/run", .{ .mode = .write_only });
        defer file.close();
        try file.writeAll("1");
    }

    pub fn adviseMergeable(ptr: [*]u8, len: usize) !void {
        const MADV_MERGEABLE = 12;
        // We assume ptr is aligned to 4096 because BufferPool uses alignedAlloc
        const aligned_ptr = @as(*align(4096) anyopaque, @ptrCast(@alignCast(ptr)));
        if (std.c.madvise(aligned_ptr, len, MADV_MERGEABLE) != 0) {
            return error.MadviseFailed;
        }
    }
};
