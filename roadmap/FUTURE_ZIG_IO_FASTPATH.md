# Future Vision: Zig-Based I/O Fast Path

**Status**: ❌ NOT IMPLEMENTED - ARCHIVED FOR FUTURE REFERENCE  
**Priority**: Medium-High  
**Estimated Effort**: 2-3 weeks  
**Target Release**: v4.0.0+

---

## ⚠️ Implementation Status

This document describes a **planned but NOT implemented** feature. The standard Rust I/O (`std::fs`, `tokio::fs`) remains the current implementation.

**Current State (March 2026)**: 
- ❌ No io_uring implementation exists
- ❌ No Zig-based I/O fastpath exists
- ❌ No `src/io/` directory
- ❌ No `storage-fastpath` crate
- ✅ Standard Rust I/O working well (~2.2 GB/s write, ~6.2 GB/s read)

---

## Executive Summary

This document outlines the planned high-performance I/O subsystem for Phantom Fragment using **Zig** and **io_uring**. This represents a significant performance upgrade over the current standard I/O implementation.

**Current State**: Phantom Fragment uses standard Rust I/O (`std::fs`, `tokio::fs`) which provides:
- ~1 GB/s sequential throughput
- ~200-500μs latency per operation
- Sufficient for current workloads

**Future Vision**: Zig-based io_uring implementation targeting:
- 3+ GB/s throughput (3x improvement)
- Sub-10μs latency (50x improvement)
- Zero-copy operations
- Batch processing for maximum efficiency

---

## Why io_uring?

### Current Limitations

Standard POSIX I/O syscalls (`read()`, `write()`) require:
1. **Context switches** between user and kernel space
2. **Data copying** between user buffers and kernel buffers
3. **Blocking or thread-per-connection** for async operations

### io_uring Advantages

Linux kernel 5.1+ introduced io_uring which provides:

1. **Asynchronous I/O without threads**
   - Single syscall can submit multiple operations
   - Completion notification via shared ring buffer
   - No thread context switching overhead

2. **Zero-copy operations**
   - Direct data transfer between disk and user buffers
   - Bypasses page cache for O_DIRECT operations
   - Reduces memory bandwidth pressure

3. **Batching**
   - Queue up to thousands of operations
   - Submit all with single syscall
   - Amortizes syscall overhead

4. **Polling modes**
   - `IOPOLL`: User-space polling for completions
   - `SQPOLL`: Kernel-side polling (no syscalls at all)
   - Sub-microsecond latency possible

---

## Proposed Architecture

### Core Components

```
src/io/
├── io-uring/
│   └── zig-io-fastpath/           # Zig implementation
│       ├── src/
│       │   ├── io.zig            # Core io_uring operations
│       │   ├── ring.zig          # Ring buffer management
│       │   ├── buffer.zig        # Buffer pool integration
│       │   ├── context.zig       # Context lifecycle
│       │   ├── controllers.zig   # Backpressure/congestion control
│       │   └── c_abi.zig         # C FFI exports
│       └── build.zig
│
└── bindings/
    └── io-fastpath-rs/           # Rust FFI bindings
        ├── src/
        │   ├── lib.rs            # Safe Rust API
        │   └── config.rs         # Configuration types
        └── build.rs              # Links Zig library
```

### Performance Targets

| Metric | Current (Verified) | Target (io_uring) | Improvement |
|--------|-------------------|-------------------|-------------|
| **Sequential Write** | **2.2 GB/s** | 4.0+ GB/s | **1.8x** |
| **Sequential Read** | **6.2 GB/s** | 8.0+ GB/s | **1.3x** |
| **Random I/O IOPS** | ~100K | 500K+ | **5x** |
| **Latency (p99)** | ~100μs | <10μs | **10x** |
| **CPU Usage** | Moderate | Low (polling) | **60% less** |

### Implementation Phases (NOT STARTED)

#### Phase 1: Basic io_uring (Week 1)
- [ ] Setup Zig project structure
- [ ] Implement basic ring buffer operations
- [ ] Single-threaded read/write operations
- [ ] C ABI exports for Rust integration

#### Phase 2: Advanced Features (Week 2)
- [ ] Multi-threading support with work-stealing
- [ ] Zero-copy operations using registered buffers
- [ ] Automatic capability detection (CAP_SYS_NICE, CAP_SYS_ADMIN)
- [ ] Graceful fallback to standard I/O

#### Phase 3: Optimization (Week 3)
- [ ] Polling modes (IOPOLL, SQPOLL)
- [ ] Buffer pool integration with memory discipline module
- [ ] Batch operations API
- [ ] Performance benchmarking and tuning

---

*Last Updated: 2026-03-04*  
*Status: ❌ NOT IMPLEMENTED - ARCHIVED*  
*Owner: I/O Performance Team*
