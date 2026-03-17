# Zig KVM Backend Implementation Plan

**Status**: ❌ NOT IMPLEMENTED - ARCHIVED FOR FUTURE REFERENCE

---

## ⚠️ Implementation Status (March 2026)

This document describes a **planned but NOT implemented** KVM backend. 

**Current Reality**:
- ❌ No KVM backend exists in the codebase
- ❌ No `src/core/execution/kvm-zig/` directory
- ❌ No `/dev/kvm` integration
- ✅ Execution currently uses process-based isolation (Sandbox/Hardened modes)
- ✅ Three-tier execution architecture documented in AGENTS.md

**Note**: The current execution model uses Linux namespaces, seccomp, Landlock, and cgroups for isolation. KVM was considered as a potential future backend but has not been implemented.

---

## Overview

This document outlines the plan to implement a KVM (Kernel-based Virtual Machine) backend in Zig, replacing the previous Rust implementation. Zig offers better control over memory layout, direct syscall access, and zero-cost abstractions ideal for low-level VM management.

## Why Zig for KVM?

| Aspect | Rust | Zig |
|--------|------|-----|
| KVM ioctl calls | Requires crates, FFI bindings | Direct syscall via `std.os.linux` |
| Memory management | Box, Vec overhead | Direct mmap, custom allocators |
| Guest memory layout | vm-memory crate | Explicit control via `@ptrCast` |
| Build simplicity | Multiple crates | Single `zig build` |
| Performance | Good | Better (no hidden allocations) |

## Architecture (Proposed)

```
src/core/execution/kvm-zig/
├── build.zig                 # Build configuration
├── src/
│   ├── main.zig              # Entry point, exports C ABI
│   ├── kvm.zig               # KVM ioctl wrappers
│   ├── vm.zig                # VM lifecycle management
│   ├── vcpu.zig              # vCPU configuration and execution
│   ├── memory.zig            # Guest memory management
│   ├── devices/
│   │   ├── virtio_blk.zig    # Virtio block device
│   │   ├── virtio_net.zig    # Virtio network device
│   │   ├── serial.zig        # Serial console
│   │   └── irq.zig           # Interrupt controller
│   ├── loader.zig            # Kernel loader (ELF/bzImage)
│   └── regs.zig              # Register definitions (x86_64)
└── test/
    └── integration_test.zig  # Integration tests
```

## Implementation Phases (NOT STARTED)

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Phase 1 | 1 week | KVM device detection, memory setup |
| Phase 2 | 1 week | vCPU management, register setup |
| Phase 3 | 2 weeks | VirtIO block + serial devices |
| Phase 4 | 1 week | Full VM lifecycle, kernel boot |
| Phase 5 | 3 days | C ABI exports, Rust integration |
| Phase 6 | 2 days | Build system, documentation |

**Total: ~6 weeks (if implemented)**

---

## Success Criteria (If Implemented)

1. **Boot Test**: Successfully boot a minimal Linux kernel
2. **Console Access**: Serial console output visible
3. **Block Device**: Rootfs mounted from block device
4. **Performance**: <50ms VM cold start time
5. **Memory Efficiency**: <5MB overhead for 512MB guest
6. **Safety**: All memory operations bounds-checked

## Dependencies

- Zig 0.14+
- Linux kernel with KVM support (/dev/kvm)
- Kernel image (vmlinuz or bzImage)
- Root filesystem image (ext4, squashfs)

---

## Current Alternative

The project currently uses a **three-tier execution architecture**:

| Tier | Command | Status | Performance |
|------|---------|--------|-------------|
| **Cold** | `phantom run alpine` | ✅ Working | ~45ms |
| **Warm** | `phantom run --warm alpine` | ⚠️ Beta | Faster but unreliable |
| **Zygote** | `phantom warm --benchmark` | ⚠️ Bench only | <1ms (benchmarks) |

See AGENTS.md for complete subsystem status.

---

*Last Updated: 2026-03-04*  
*Status: ❌ NOT IMPLEMENTED - ARCHIVED*  
*Owner: Virtualization Team*
