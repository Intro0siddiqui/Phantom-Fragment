const std = @import("std");
const linux = std.os.linux;
const c = @cImport({
    @cInclude("sys/mman.h");
});

pub const KsmManager = struct {
    pub fn enable() !void {
        const path: [*:0]const u8 = "/sys/kernel/mm/ksm/run";
        const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        const signed_fd: isize = @bitCast(fd);
        if (signed_fd < 0) return error.OpenFailed;
        defer _ = linux.close(@intCast(fd));

        const written = linux.write(@intCast(fd), "1", 1);
        if (@as(isize, @bitCast(written)) != 1) return error.WriteFailed;
    }

    pub fn adviseMergeable(ptr: [*]u8, len: usize) !void {
        const MADV_MERGEABLE = 12;
        // We assume ptr is aligned to 4096 because BufferPool uses alignedAlloc
        const aligned_ptr = @as(*align(4096) anyopaque, @ptrCast(@alignCast(ptr)));
        if (c.madvise(aligned_ptr, len, MADV_MERGEABLE) != 0) {
            return error.MadviseFailed;
        }
    }
};
