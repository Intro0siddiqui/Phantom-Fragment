# Hybrid Model Roadmap

> **⚠️ DEVELOPMENT NOTICE: This document describes planned and in-progress features. Many components described here are NOT yet implemented or are partially complete. See status indicators below for each phase.**

The Hybrid Model represents the long-term vision for Phantom Fragment, combining fast Zygote-based spawning with advanced memory management and snapshotting capabilities.

---

## Phase 1: Foundation (Completed)
*   **Status**: ✅ **IMPLEMENTED**
*   **Zygote Pool**: Basic zygote pool infrastructure exists in `src/core/zygote-rs/`
*   **FFI Integration**: Zig-based zygote implementation with C ABI exports
*   **Commands**: `phantom warm` command available for warming the zygote pool
*   **Verified**: Zygote pool implementation is complete with:
    - `phantom_zygote_pool_create()` - Initialize pool
    - `phantom_zygote_fork()` - Fast process spawn
    - `phantom_zygote_pool_put()` - Return zygote to pool
    - `phantom_zygote_send_command()` - IPC via socketpair
    - Full socketpair-based IPC between parent/child

## Phase 2: Warm/Mother Fragments (Partial)
*   **Status**: 🚧 **PARTIALLY IMPLEMENTED**
*   **What Works**: Basic zygote forking via `phantom_zygote_fork()`
*   **What Doesn't**: Full warm fragment lifecycle, mother fragment persistence across daemon restarts
*   **Notes**: Current implementation provides process spawning speedup but lacks full state management
*   **Issues**: 
    - Daemon stability issues
    - IPC problems under load
    - May fall back to cold start
    - Not fully integrated with `phantom run` command

## Phase 3: Memory Trimming (Layer 3)
*   **Status**: ❌ **NOT IMPLEMENTED**
*   **Goal**: Hit the 5MB skeleton target for the Zygote pool.
*   **Technical Requirement**: Implement `madvise_syscall` in `src/core/zygote-rs/src/zygote.zig`.
*   **Mechanism**: Call `madvise(MADV_DONTNEED)` in the `child_loop` before entering the idle wait (`read_syscall`).
*   **Blockers**: Requires Phase 2 completion for proper idle state management

## Phase 4: Snapshot Foundations (Layer 1)
*   **Status**: ❌ **NOT IMPLEMENTED**
*   **Goal**: Implement process state resurrection.
*   **Technical Requirement**: Add `mmap` with `MAP_FIXED` support in Zig.
*   **Mechanism**: Logic to overlay saved memory states into the Zygote's address space before execution.
*   **Dependencies**: Requires Phase 3 memory trimming for efficient snapshot storage

---

## Implementation Status Summary

| Phase | Feature | Status | Notes |
|-------|---------|--------|-------|
| 1 | Zygote Pool Foundation | ✅ Complete | Full Zig implementation with IPC |
| 2 | Warm/Mother Fragments | 🚧 Partial | Daemon stability issues |
| 3 | Memory Trimming | ❌ Not Implemented | Planned for future |
| 4 | Snapshot Foundations | ❌ Not Implemented | Planned for future |

---

## Three-Tier Execution Status

Per AGENTS.md subsystem status:

| Tier | Command | Status | Performance |
|------|---------|--------|-------------|
| **Cold** | `phantom run alpine` | ✅ Working | ~45ms |
| **Warm** | `phantom run --warm alpine` | 🚧 Beta/Experimental | Unreliable, may fall back to cold |
| **Zygote** | `phantom warm --benchmark` | 🚧 Benchmark only | <1ms (in benchmarks) |

**Last Updated**: 2026-03-04
