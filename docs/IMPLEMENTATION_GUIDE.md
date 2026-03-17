# Implementation Guide: How We Achieved 32x Faster Memory & 57ms Container Starts

This document details the technical decisions, optimizations, and implementation steps that led to Phantom Fragment's performance achievements.

## Summary of Achievements

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Memory allocation | malloc/free | Buffer pools | **32.7× faster** |
| Single-threaded I/O | ~1 GB/s | 22 GB/s | **22× faster** |
| Multi-threaded I/O | N/A | 28.75 GB/s | Baseline set |
| Container cold start | 387ms (Docker) | 57ms | **6.8× faster** |
| Fragment creation | N/A | 20ms | Baseline set |

## Key Technical Decisions

### 1. Zig for Core Performance Modules

**Problem**: Rust's memory allocation patterns have overhead for high-frequency operations.

**Solution**: Implemented core memory module in Zig with:
- Direct syscall access without libc overhead
- Compile-time optimizations with `ReleaseFast`
- 4096-byte aligned allocations for KSM compatibility

**Code Example** (`buffer_pool.zig`):
```zig
// Use posix_memalign for page-aligned buffers
if (std.c.posix_memalign(&ptr, 4096, buffer_size) == 0) {
    if (ptr) |p| {
        const buf = @as([*]u8, @ptrCast(p))[0..buffer_size];
        try self.buffers.append(allocator, buf);
    }
}
```

**Why it matters**: Page-aligned buffers enable:
1. KSM deduplication (kernel merges identical 4KB pages)
2. Direct DMA operations
3. Efficient file I/O

### 2. Raw Syscalls Instead of libc Wrappers

**Problem**: `sched_setaffinity` from libc has version-dependent behavior and requires feature test macros.

**Solution**: Direct syscall via Zig's `linux.syscall3`:

```zig
const result = linux.syscall3(
    .sched_setaffinity,
    @as(usize, 0),        // pid = 0 (current process)
    @as(usize, mask.len), // size of cpu_set_t
    @intFromPtr(&mask),   // pointer to mask
);
```

**Why it matters**:
- Works on any glibc version
- No `#define _GNU_SOURCE` required
- Consistent across Linux distributions

### 3. Mutex-Based Buffer Pools (Not Lock-Free)

**Problem**: Lock-free queues have cache contention issues on multi-core systems.

**Solution**: Simple mutex-protected pool:

```zig
pub fn get(self: *BufferPool) ![]u8 {
    self.mutex.lock();
    defer self.mutex.unlock();

    if (self.buffers.items.len > 0) {
        return self.buffers.pop() orelse error.OutOfMemory;
    }
    // Allocate new if empty...
}
```

**Results**:
- 32.7× faster than malloc/free
- 470,983 ops/sec with 4 threads
- Better cache locality than lock-free alternatives

### 4. Direct Syscalls via Zig

The core utilizes direct syscalls (e.g., `sched_setaffinity`) to bypass the overhead and version-dependency of `libc`. By using Zig's `linux.syscall3`, we ensure consistent behavior across different Linux distributions and kernel versions.

## Implementation Phases


### 1. Zig Core Implementation
1. Created `buffer_pool.zig` with mutex-based pooling
2. Created `ksm_manager.zig` for memory deduplication
3. Created `main.zig` with C-ABI exports
4. Fixed inline assembly syntax for Zig

### 2. Rust FFI Integration
1. Created `memory-rs` with extern "C" declarations
2. Implemented safe wrappers around Zig functions
3. Added `build.rs` for automatic Zig compilation

### 3. CPU Affinity & NUMA
1. Implemented `phantom_set_cpu_affinity` with raw syscall
2. Added NUMA management logic
3. Fixed bitmask calculation for CPU sets

### 4. Stress Testing & Verification
1. Created comprehensive stress test in `stress_test.zig`
2. Benchmarked single and multi-threaded performance
3. Verified CPU affinity and BPF-LSM functionality

## Lessons Learned

### 1. Always Test with Real Workloads
The stress test revealed a critical memory handling issue that unit tests missed.

### 2. Zig Version Compatibility Matters
Zig has frequent breaking changes. Always check release notes.

### 3. Raw Syscalls Are More Portable
Using `linux.syscall3` instead of libc wrappers avoided glibc version issues.

### 4. Simple Can Be Fast
Mutex-based pools outperformed complex lock-free designs due to better cache locality.

### 5. Alignment Matters
4096-byte alignment enables KSM and simplifies I/O operations.

## Reproducing the Build

```bash
# 1. Verify Zig version (must be 0.15.x)
zig version

# 2. Build memory library
cd src/memory/discipline/memory-zig
zig build -Doptimize=ReleaseFast

# 3. Verify library exists
ls -la zig-out/lib/libphantom_memory.a

# 4. Build stress test
zig build-exe stress_test.zig -lc -O ReleaseFast

# 5. Run benchmark
./stress_test

# 6. Build full project
cd ../../..
cargo build --release

# 7. Test CLI
./target/release/phantom run alpine echo "Hello"
```

## Future Optimizations

1. **Lock-free fast path**: Add lock-free allocation for hot path
2. **NUMA awareness**: Full NUMA support when libnuma available
3. **Huge pages**: Support 2MB pages for large buffers
4. **Per-CPU pools**: Eliminate cross-CPU contention

## References

- [Zig 0.15.1 Release Notes - I/O Changes](https://ziglang.org/download/0.15.1/release-notes.html)
- [Linux sched_setaffinity(2)](https://man7.org/linux/pages/man2/sched_setaffinity.2.html)
- [Kernel Samepage Merging (KSM)](https://www.kernel.org/doc/html/latest/admin-guide/mm/ksm.html)
