# Implementation Plan: Zig 0.15.2 I/O Fast-Path (Proactor Model)

**Status**: ❌ NOT IMPLEMENTED - ARCHIVED  
**Target Version**: Phantom Fragment v0.5.0+  
**Primary Goal**: Achieve 8GB/s+ throughput using io_uring while avoiding unstable Zig 0.16 language features.

---

## ⚠️ Implementation Status (March 2026)

This document describes a **planned but NOT implemented** I/O architecture. 

**Current Reality**:
- ❌ No io_uring proactor implementation
- ❌ No `storage-fastpath` crate exists
- ❌ No `src/io/` directory
- ✅ Standard tokio/async I/O is the current implementation
- ✅ Current performance: 2.2 GB/s write, 6.2 GB/s read

**Note**: This plan was created before the decision to use standard Rust I/O was finalized. The standard I/O implementation is performant enough for current workloads.

---

## 1. Architectural Strategy: "The Raw Proactor"

To avoid the upcoming `async/await` redesign in Zig 0.16, we will NOT use the language's built-in async keywords. Instead, we will implement a **Manual Proactor Pattern**.

### Core Principles:
1. **Raw Syscalls**: Interface directly with the Linux kernel via `std.os.linux`.
2. **C-ABI Stability**: The interface between Rust and Zig will be pure C-style functions.
3. **No Language-Level Async**: We will manage the `io_uring` completion queue (CQ) manually in a dedicated thread.
4. **Kernel-Side Polling (SQPOLL)**: Utilize `IORING_SETUP_SQPOLL` to allow the kernel to pull data from our submission queue without any syscall overhead in the "hot path."

---

## 2. Technical Components (Proposed)

### A. The Ring Manager (`ring.zig`)
This component will handle the low-level memory mapping of the Submission Queue (SQ) and Completion Queue (CQ).
- **Target**: Zig 0.15.2 standard library `std.os.linux`.
- **Optimization**: Use `IORING_FEAT_FAST_POLL` to ensure the kernel handles multiple I/O depths efficiently.

### B. Fixed-Buffer Registry (`buffer_pool.zig`)
One of the biggest bottlenecks in current Rust I/O is the copying of data between the application and the kernel page cache.
- **Strategy**: Use `io_uring_register_buffers`. 
- **Implementation**: Pre-allocate 1GB of memory in Zig, register it with the kernel once, and then reuse these "fixed" slots for all blob transfers.

### C. The Completion Thread (`proactor.zig`)
A dedicated thread in Zig that runs a tight loop:
1. Wait for completion entries in the CQ.
2. Trigger the associated callback (defined via a simple C-function pointer provided by Rust).
3. Return the buffer to the pool.

---

## 3. The Stable C-ABI (The "Contract")

To ensure Rust remains stable regardless of Zig's evolution, we will expose this fixed interface:

```zig
// Defined in src/core/storage-fastpath/src/c_api.zig
pub const PhantomIoCtx = opaque {};

// Initialize the ring and pre-register buffers
pub export fn phantom_io_init(entries: u32, flags: u32) ?*PhantomIoCtx;

// Submit a blob write (Non-blocking)
// Returns a sequence ID for tracking
pub export fn phantom_io_write_blob(
    ctx: *PhantomIoCtx, 
    fd: i32, 
    buffer_idx: u32, 
    offset: u64, 
    callback: ?*const fn(seq_id: u64, result: i32) void
) u64;

// Poll for completions (Can be called by a dedicated thread)
pub export fn phantom_io_tick(ctx: *PhantomIoCtx) void;
```

---

## 4. Why this is the "Smart" choice for 0.15.2

| Risk | Mitigation |
| :--- | :--- |
| **Zig 0.16 breaking async** | We don't use the `async` keyword at all. Our logic is "C-style" Zig. |
| **Rust Runtime Wars** | We don't use Monoio or Glommio; we keep Tokio and offload only the heavy I/O to Zig. |
| **Maintenance Burden** | The code is "raw" and "explicit," making it easier to debug than complex async runtimes. |

---

## 5. Performance Targets vs. Current Baseline

| Metric | Current (Rust/Tokio) | New (Zig/io_uring) | Improvement |
| :--- | :--- | :--- | :--- |
| **Write Throughput** | 2.2 GB/s | **8.5 GB/s** | ~3.8x |
| **Syscall Overhead** | High (1 per op) | **Near Zero** (SQPOLL) | 100x reduction |
| **Memory Latency** | High (Buffer Copy) | **Zero** (Registered Buffers) | Instant |

---

## 6. Implementation Phases (NOT STARTED)

1. **Phase 1 (Setup)**: Create the directory structure and `build.zig` that can be called by Rust's `build.rs`.
2. **Phase 2 (The Ring)**: Implement the manual `mmap` of the io_uring ring buffers in Zig 0.15.2.
3. **Phase 3 (The Registry)**: Implement the fixed-buffer registration logic.
4. **Phase 4 (Rust Bridge)**: Create the `storage-fastpath-rs` crate to wrap the Zig C-ABI.
5. **Phase 5 (Verification)**: Run a 100GB blob-write benchmark to verify the 8GB/s target.

---
*Created: 2026-02-14*  
*Updated: 2026-03-04 - Marked as NOT IMPLEMENTED*  
*Owner: Systems Engineering*
