const std = @import("std");
const BufferPool = @import("buffer_pool.zig").BufferPool;
const KsmManager = @import("ksm_manager.zig").KsmManager;
const linux = std.os.linux;

// NUMA constants
const MPOL_DEFAULT = 0;
const MPOL_PREFERRED = 1;
const MPOL_BIND = 2;
const MPOL_INTERLEAVE = 3;
const MPOL_LOCAL = 4;
const MPOL_PREFERRED_MANY = 5;

// Syscall numbers for x86_64
const SYS_set_mempolicy = 238;
const SYS_mbind = 237;
const SYS_get_mempolicy = 239;
const SYS_sched_setaffinity = 203;

// NUMA state cache
var numa_cache_initialized = false;
var numa_available_cache: c_int = -1;
var numa_max_node_cache: c_int = -1;

// Read a sysfs file to get NUMA node information
fn readSysfsFile(path: []const u8, buf: []u8) !usize {
    // Convert path to null-terminated string
    var path_z_buf: [256]u8 = undefined;
    if (path.len >= path_z_buf.len) return error.PathTooLong;
    @memcpy(path_z_buf[0..path.len], path);
    path_z_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_z_buf);

    const fd = linux.open(path_z, linux.O{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (fd < 0) return error.OpenFailed;
    defer _ = linux.close(@intCast(fd));

    var total_read: usize = 0;
    while (total_read < buf.len) {
        const n = linux.read(@intCast(fd), buf.ptr + total_read, buf.len - total_read);
        if (n <= 0) break;
        total_read += @intCast(n);
    }
    return total_read;
}

// Parse a cpumap file to extract CPU mask
// Handles hex format like "f", "0000000f", "000000ff,0000000f"
fn parseCpumap(path: []const u8, mask: []u8) !usize {
    var buf: [256]u8 = undefined;
    const len = readSysfsFile(path, &buf) catch return error.ReadFailed;
    if (len == 0) return error.EmptyFile;

    // cpumap is in hex format, parse it
    // Each byte is two hex digits (low nibble = CPU bits, high nibble = next 4 CPUs)
    @memset(mask, 0);
    var mask_idx: usize = 0;
    var current_byte: u8 = 0;
    var nibble_count: u8 = 0;
    var last_nibble: u8 = 0;

    // First pass: collect all hex digits into the mask
    for (buf[0..len]) |c| {
        if (c == ',' or c == '\n' or c == ' ') continue;

        var nibble: u8 = undefined;
        if (c >= '0' and c <= '9') {
            nibble = c - '0';
        } else if (c >= 'a' and c <= 'f') {
            nibble = c - 'a' + 10;
        } else if (c >= 'A' and c <= 'F') {
            nibble = c - 'A' + 10;
        } else {
            continue;
        }

        // Process nibble: low nibble first (CPU bits), then high nibble
        last_nibble = nibble;
        if (nibble_count == 0) {
            current_byte = nibble;
            nibble_count = 1;
        } else {
            current_byte |= nibble << 4;
            if (mask_idx < mask.len) {
                mask[mask_idx] = current_byte;
                mask_idx += 1;
            }
            nibble_count = 0;
            current_byte = 0;
        }
    }

    // Handle single nibble case (e.g., "f")
    if (nibble_count == 1 and mask_idx < mask.len) {
        mask[mask_idx] = last_nibble;
        mask_idx += 1;
    }

    return if (mask_idx > 0) mask_idx else 1;
}

// Parse /sys/devices/system/node/online or /possible
fn parseNodeList(path: []const u8) !c_int {
    var buf: [256]u8 = undefined;
    const len = readSysfsFile(path, &buf) catch return error.ReadFailed;
    if (len == 0) return error.EmptyFile;

    var max_node: c_int = 0;
    var i: usize = 0;

    while (i < len) {
        // Skip whitespace
        while (i < len and (buf[i] == ' ' or buf[i] == '\n' or buf[i] == '\t')) {
            i += 1;
        }
        if (i >= len) break;

        // Parse start of range
        var start: c_int = 0;
        while (i < len and buf[i] >= '0' and buf[i] <= '9') {
            start = start * 10 + (buf[i] - '0');
            i += 1;
        }

        // Check for range (e.g., "0-3")
        if (i < len and buf[i] == '-') {
            i += 1;
            var end: c_int = 0;
            while (i < len and buf[i] >= '0' and buf[i] <= '9') {
                end = end * 10 + (buf[i] - '0');
                i += 1;
            }
            if (end > max_node) max_node = end;
        } else {
            if (start > max_node) max_node = start;
        }

        // Skip comma
        if (i < len and buf[i] == ',') i += 1;
    }

    return max_node;
}

// Initialize NUMA cache
fn initNumaCache() void {
    if (numa_cache_initialized) return;

    // Check if /sys/devices/system/node exists
    var stat_buf: linux.Stat = undefined;
    const result = linux.stat("/sys/devices/system/node", &stat_buf);
    if (result != 0) {
        numa_available_cache = 0;
        numa_max_node_cache = 0;
        numa_cache_initialized = true;
        return;
    }

    // Check if /sys/devices/system/node/online exists
    const online_result = linux.stat("/sys/devices/system/node/online", &stat_buf);
    if (online_result != 0) {
        numa_available_cache = 0;
        numa_max_node_cache = 0;
        numa_cache_initialized = true;
        return;
    }

    // Parse online nodes - NUMA is available if the subsystem exists
    if (parseNodeList("/sys/devices/system/node/online")) |max_node| {
        numa_max_node_cache = max_node;
        // NUMA subsystem exists, so it's available (even single-node systems)
        numa_available_cache = 1;
    } else |_| {
        numa_available_cache = 0;
        numa_max_node_cache = 0;
    }

    numa_cache_initialized = true;
}

// Convert node number to nodemask (bitmask)
fn nodeToMask(node: c_int) u64 {
    if (node < 0) return 0;
    return @as(u64, 1) << @intCast(node);
}

export fn phantom_numa_available() c_int {
    initNumaCache();
    return numa_available_cache;
}

export fn phantom_numa_max_node() c_int {
    initNumaCache();
    return numa_max_node_cache;
}

export fn phantom_numa_run_on_node(node: c_int) c_int {
    if (node < 0) return -1;

    initNumaCache();
    if (numa_available_cache != 1) return -1;

    // Validate node number is within valid range
    if (node > numa_max_node_cache) return -1;

    // Read cpumap for the specified node
    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/sys/devices/system/node/node{d}/cpumap", .{node}) catch return -1;

    var mask: [128]u8 = undefined;
    @memset(&mask, 0);

    const mask_len = parseCpumap(path, &mask) catch return -1;
    if (mask_len == 0) return -1;

    // Use sched_setaffinity to bind to node's CPUs
    const result = linux.syscall3(
        .sched_setaffinity,
        @as(usize, 0), // pid = 0 means current process
        @as(usize, mask.len), // Use full mask size: 128 bytes
        @intFromPtr(&mask),
    );

    if (result == 0) return 0;
    return -1;
}

export fn phantom_numa_bind_node(node: c_int) c_int {
    if (node < 0) return -1;

    initNumaCache();
    if (numa_available_cache != 1) return -1;

    // Validate node number is within valid range
    if (node > numa_max_node_cache) return -1;

    const nodemask = nodeToMask(node);
    if (nodemask == 0) return -1;

    // Set memory policy to bind to specific node
    // set_mempolicy(mode, nodemask, maxnode)
    const result = linux.syscall3(
        .set_mempolicy,
        MPOL_BIND, // mode: MPOL_BIND
        @intFromPtr(&nodemask), // nodemask pointer
        @as(usize, 64), // maxnode
    );

    if (result == 0) return 0;
    return -1;
}

export fn phantom_numa_alloc_on_node(size: usize, node: c_int) ?*anyopaque {
    if (size == 0 or node < 0) return null;

    initNumaCache();
    if (numa_available_cache != 1) {
        // Fall back to regular allocation
        const slice = std.heap.page_allocator.alloc(u8, size) catch return null;
        return slice.ptr;
    }

    // Validate node number is within valid range
    if (node > numa_max_node_cache) return null;

    // Allocate memory using page allocator
    const ptr = std.heap.page_allocator.alloc(u8, size) catch return null;

    // Get page size for alignment
    const page_size = std.heap.page_size_min;
    const aligned_size = (size + page_size - 1) & ~(page_size - 1);

    const nodemask = nodeToMask(node);
    if (nodemask == 0) {
        std.heap.page_allocator.free(ptr);
        return null;
    }

    // Use mbind to bind allocated memory to node
    // mbind(addr, len, mode, nodemask, maxnode, flags)
    const result = linux.syscall6(
        .mbind,
        @intFromPtr(ptr.ptr), // addr
        aligned_size, // len
        MPOL_BIND, // mode: MPOL_BIND
        @intFromPtr(&nodemask), // nodemask
        @as(usize, 64), // maxnode
        0, // flags
    );

    if (result != 0) {
        std.heap.page_allocator.free(ptr);
        return null;
    }

    return ptr.ptr;
}

export fn phantom_numa_free(start: ?*anyopaque, size: usize) void {
    if (start == null or size == 0) return;

    // Create a slice from the pointer and size
    const slice = @as([*]u8, @ptrCast(start.?))[0..size];
    std.heap.page_allocator.free(slice);
}

// CPU Affinity Exports - using raw syscall for portability

export fn phantom_set_cpu_affinity(cpu_ids: ?[*]const u32, len: usize) c_int {
    if (cpu_ids == null or len == 0) {
        return -1;
    }

    // CPU_SETSIZE is typically 1024, use 128 bytes (1024 bits)
    var mask: [128]u8 = undefined;
    @memset(&mask, 0);

    const cpu_ids_slice = cpu_ids.?[0..len];
    for (cpu_ids_slice) |cpu_id| {
        const byte_idx = cpu_id / 8;
        const bit_idx = cpu_id % 8;
        if (byte_idx < mask.len) {
            mask[byte_idx] |= @as(u8, 1) << @intCast(bit_idx);
        }
    }

    // sched_setaffinity syscall: pid=0 (current process), len, mask
    const result = linux.syscall3(
        .sched_setaffinity,
        @as(usize, 0), // pid = 0 means current process
        @as(usize, mask.len),
        @intFromPtr(&mask),
    );

    if (result == 0) {
        return 0;
    }
    return -1;
}

// Buffer Pool Exports

export fn phantom_buffer_pool_create(buffer_size: usize, initial_capacity: usize) ?*anyopaque {
    const allocator = std.heap.c_allocator;
    if (BufferPool.init(allocator, buffer_size, initial_capacity)) |pool| {
        return pool;
    } else |_| {
        return null;
    }
}

export fn phantom_buffer_pool_destroy(pool_ptr: ?*anyopaque) void {
    if (pool_ptr) |ptr| {
        const pool = @as(*BufferPool, @ptrCast(@alignCast(ptr)));
        pool.deinit();
    }
}

export fn phantom_buffer_pool_get(pool_ptr: ?*anyopaque, out_len: ?*usize) ?[*]u8 {
    if (pool_ptr) |ptr| {
        const pool = @as(*BufferPool, @ptrCast(@alignCast(ptr)));
        if (pool.get()) |slice| {
            if (out_len) |len| {
                len.* = slice.len;
            }
            return slice.ptr;
        } else |_| {
            return null;
        }
    }
    return null;
}

export fn phantom_buffer_pool_put(pool_ptr: ?*anyopaque, buf_ptr: ?[*]u8, len: usize) void {
    if (pool_ptr) |ptr| {
        if (buf_ptr) |buf| {
            const pool = @as(*BufferPool, @ptrCast(@alignCast(ptr)));
            const slice = buf[0..len];
            pool.put(slice);
        }
    }
}

// KSM Exports

export fn phantom_ksm_enable() c_int {
    if (KsmManager.enable()) {
        return 0;
    } else |_| {
        return -1;
    }
}

export fn phantom_ksm_advise_mergeable(addr: ?*anyopaque, len: usize) c_int {
    if (addr) |ptr| {
        const u8_ptr = @as([*]u8, @ptrCast(ptr));
        if (KsmManager.adviseMergeable(u8_ptr, len)) {
            return 0;
        } else |_| {
            return -1;
        }
    }
    return -1;
}
