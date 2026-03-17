# Phantom Fragment Roadmap

This directory contains the technical roadmap and implementation plans for Phantom Fragment. Documents are organized by feature area and updated regularly to reflect current implementation status.

**Last Updated**: 2026-03-04

---

## Quick Reference: Implementation Status

| Document | Status | Summary |
|----------|--------|---------|
| [HYBRID_MODEL.md](./HYBRID_MODEL.md) | 🚧 Partial | Zygote pool complete, warm fragments partial, snapshots not started |
| [FUTURE_ZIG_IO_FASTPATH.md](./FUTURE_ZIG_IO_FASTPATH.md) | ❌ Not Implemented | io_uring fastpath planned but not built |
| [ZIG_015_IO_PLAN.md](./ZIG_015_IO_PLAN.md) | ❌ Not Implemented | Proactor I/O model planned but not built |
| [ZIG_KVM_BACKEND.md](./ZIG_KVM_BACKEND.md) | ❌ Not Implemented | KVM backend planned but not built |
| [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) | ✅/❌ Mixed | Wasm ✅, Network CLI ✅, Compose ❌ |

---

## Detailed Status

### ✅ Fully Implemented

#### 1. WebAssembly (Wasm) Execution Mode
- **Location**: `src/core/wasm-rs/`
- **Integration**: `src/core/execution/execution-rs/src/lib.rs`
- **Features**:
  - Full Wasmtime integration
  - WASI support with capability-based security
  - Configurable memory limits
  - Security policy integration
- **Usage**: `phantom run --mode wasm myapp.wasm`

#### 2. Network CLI
- **Location**: `src/cli/phantom-cli/src/commands/network.rs`
- **Features**:
  - `phantom network list` - List interfaces
  - `phantom network up <name>` - Bring interface up
  - `phantom network add-ip <interface> <ip>` - Add IP
  - `phantom network create-veth <host> <peer>` - Create VETH pair
- **Integration**: Full `network-rs` integration

#### 3. Zygote Pool Foundation
- **Location**: `src/core/zygote-rs/src/zygote.zig`
- **Features**:
  - Complete Zig implementation
  - Socketpair-based IPC
  - Process forking via clone3/vfork
  - Pool management (create/destroy/get/put)
- **Benchmarks**: Sub-millisecond spawn times achieved

---

### 🚧 Partially Implemented

#### 1. Warm/Mother Fragments (Phase 2 of Hybrid Model)
- **Status**: Beta/Experimental
- **What Works**:
  - Basic zygote forking
  - `phantom warm` command
  - Pool pre-warming
- **Issues**:
  - Daemon stability problems
  - IPC issues under load
  - Not fully integrated with `phantom run`
  - May fall back to cold start
- **Location**: `src/cli/phantom-cli/src/daemon/warm.rs`

#### 2. Network Loopback
- **Status**: Partial
- **Issue**: Loopback interface not auto-started
- **Location**: `src/core/network-rs/`

---

### ❌ Not Implemented

#### 1. io_uring I/O Fastpath
- **Documents**: [FUTURE_ZIG_IO_FASTPATH.md](./FUTURE_ZIG_IO_FASTPATH.md), [ZIG_015_IO_PLAN.md](./ZIG_015_IO_PLAN.md)
- **What Was Planned**:
  - Zig-based io_uring implementation
  - 8GB/s+ throughput target
  - Sub-10μs latency
  - Zero-copy operations
- **Current State**: Standard Rust I/O (`std::fs`, `tokio::fs`) in use
- **Performance**: 2.2 GB/s write, 6.2 GB/s read (sufficient for current needs)

#### 2. KVM Backend
- **Document**: [ZIG_KVM_BACKEND.md](./ZIG_KVM_BACKEND.md)
- **What Was Planned**:
  - Zig-based KVM VMM
  - VirtIO block/network devices
  - VM lifecycle management
  - <50ms VM cold start
- **Current State**: Process-based isolation used instead (namespaces/seccomp/Landlock)

#### 3. Phantom Compose
- **Document**: [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md)
- **What Was Planned**:
  - Multi-fragment orchestration
  - `phantom-compose.yml` parsing
  - Lifecycle management (`up`, `down`, `ps`)
- **Current State**: No implementation exists

#### 4. Memory Trimming (Phase 3 of Hybrid Model)
- **Document**: [HYBRID_MODEL.md](./HYBRID_MODEL.md)
- **What Was Planned**:
  - 5MB skeleton target for zygote pool
  - `madvise(MADV_DONTNEED)` in child_loop
- **Dependency**: Requires Phase 2 (Warm Fragments) completion

#### 5. Snapshot Foundations (Phase 4 of Hybrid Model)
- **Document**: [HYBRID_MODEL.md](./HYBRID_MODEL.md)
- **What Was Planned**:
  - Process state resurrection
  - `mmap` with `MAP_FIXED` support
  - Memory state overlay
- **Dependency**: Requires Phase 3 (Memory Trimming)

---

## Three-Tier Execution Architecture

Current implementation status:

| Tier | Command | Status | Performance |
|------|---------|--------|-------------|
| **Cold Start** | `phantom run alpine <cmd>` | ✅ Working | ~45ms |
| **Warm Fragments** | `phantom run --warm alpine <cmd>` | 🚧 Beta | Unreliable, falls back to cold |
| **Zygote Pool** | `phantom warm --benchmark` | 🚧 Benchmark only | <1ms (benchmarks only) |

---

## Document Index

### Architecture Plans
- **[HYBRID_MODEL.md](./HYBRID_MODEL.md)** - Zygote pool, warm fragments, and snapshotting roadmap
- **[ZIG_KVM_BACKEND.md](./ZIG_KVM_BACKEND.md)** - KVM backend implementation plan (NOT IMPLEMENTED)

### I/O Performance Plans
- **[FUTURE_ZIG_IO_FASTPATH.md](./FUTURE_ZIG_IO_FASTPATH.md)** - io_uring fastpath vision (NOT IMPLEMENTED)
- **[ZIG_015_IO_PLAN.md](./ZIG_015_IO_PLAN.md)** - Proactor I/O model (NOT IMPLEMENTED)

### Feature Implementation Plans
- **[IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md)** - Wasm, Network CLI, Compose status

---

## How to Use This Directory

1. **Check this README first** for quick status overview
2. **Read specific documents** for detailed technical plans
3. **Verify in codebase** - implementation status is marked with:
   - ✅ IMPLEMENTED - Feature exists and works
   - 🚧 PARTIAL - Feature partially works or has known issues
   - ❌ NOT IMPLEMENTED - Feature planned but not built
   - 📋 PLANNED - Feature in planning phase

---

*Maintained by: Phantom Fragment Core Team*  
*Update Frequency: Monthly or when major features change*
