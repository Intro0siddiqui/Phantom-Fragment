const std = @import("std");
const Mutex = std.Thread.Mutex;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;

pub const BufferPool = struct {
    allocator: Allocator,
    buffer_size: usize,
    capacity: usize,
    buffers: ArrayListUnmanaged([]u8),
    mutex: Mutex,

    pub fn init(allocator: Allocator, buffer_size: usize, capacity: usize) !*BufferPool {
        const self = try allocator.create(BufferPool);
        self.* = .{
            .allocator = allocator,
            .buffer_size = buffer_size,
            .capacity = capacity,
            .buffers = ArrayListUnmanaged([]u8){},
            .mutex = Mutex{},
        };

        // Pre-allocate
        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            var ptr: ?*anyopaque = null;
            // Use posix_memalign for 4096 alignment
            if (std.c.posix_memalign(&ptr, 4096, buffer_size) == 0) {
                if (ptr) |p| {
                    const buf = @as([*]u8, @ptrCast(p))[0..buffer_size];
                    try self.buffers.append(allocator, buf);
                }
            }
        }

        return self;
    }

    pub fn deinit(self: *BufferPool) void {
        self.mutex.lock();

        for (self.buffers.items) |buf| {
            std.c.free(buf.ptr);
        }
        self.buffers.deinit(self.allocator);
        const alloc = self.allocator;

        self.mutex.unlock();
        alloc.destroy(self);
    }

    pub fn get(self: *BufferPool) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.buffers.items.len > 0) {
            return self.buffers.pop() orelse error.OutOfMemory;
        }

        // Allocate new if empty
        var ptr: ?*anyopaque = null;
        if (std.c.posix_memalign(&ptr, 4096, self.buffer_size) == 0) {
            if (ptr) |p| {
                return @as([*]u8, @ptrCast(p))[0..self.buffer_size];
            }
        }
        return error.OutOfMemory;
    }

    pub fn put(self: *BufferPool, buf: []u8) void {
        if (buf.len != self.buffer_size) {
            std.c.free(buf.ptr);
            return;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.buffers.items.len < self.capacity) {
            self.buffers.append(self.allocator, buf) catch {
                std.c.free(buf.ptr);
            };
        } else {
            std.c.free(buf.ptr);
        }
    }
};
