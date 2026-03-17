# Warm Fragment / Zygote Pool Implementation Roadmap

> **Status**: BETA/EXPERIMENTAL - IN ACTIVE DEVELOPMENT | **Last Updated**: March 2026

---

## ⚠️ IMPORTANT NOTICE: Beta/Experimental Feature

**This feature is in beta/experimental status and NOT production ready.** The warm fragment / zygote pool system exists in the codebase but has significant gaps that prevent it from working reliably.

### Current Reality Check

| What Exists | What Actually Works |
|-------------|---------------------|
| `phantom warm` CLI command | Creates daemon processes, but **they exit immediately** |
| Fragment pool metadata storage | JSON persistence works, but **pool is not connected to execution** |
| Low-level zygote pool (Zig) | clone3/vfork implementation exists, but **not integrated with daemon** |
| Cold fallback | **Works correctly** - this is what users actually get |

### Critical Issues

1. **Daemon exits immediately** - The shell-based daemon loop polls for command files but has no persistent IPC mechanism
2. **No socket-based IPC** - File-based command passing is primitive and unreliable
3. **Zygote pool not connected** - The Zig zygote pool exists but is separate from the daemon architecture
4. **Warm execution path broken** - `phantom run` attempts warm execution but falls back to cold due to communication failures

### What Users Experience Today

```bash
$ phantom warm fragment create alpine 3
# Creates daemon processes that exit immediately
# Pool metadata is saved, but daemons are dead

$ phantom run alpine echo hello
# Attempts warm execution, fails to communicate
# Falls back to cold start (~45ms)
# Command succeeds via cold path
```

**Bottom line**: Cold execution works fine. Warm execution is not functional.

---

## Overview

This roadmap defines the implementation plan for the Warm Fragment / Zygote Pool feature in Phantom Fragment. The feature aims to achieve sub-millisecond container startup times through process pre-forking and caching.

## Terminology

| Term | Definition |
|------|------------|
| **Mother Fragment** | A long-lived `bwrap` daemon that stays alive (keeps engine warm) |
| **Zygote** | A forked child from the mother, frozen/minimized until activated |
| **Zygote Pool** | Collection of pre-forked zygotes ready to activate on demand |
| **Fragment** | Active running container (end result when zygote is activated) |

---

## Current State Analysis

### What Works (Production Ready)

| Component | Status | Location |
|-----------|--------|----------|
| Cold execution path | Fully functional | `commands/run.rs:202-258` |
| Fragment pool metadata storage | Works (JSON persistence) | `fragment_pool.rs:1-296` |
| Low-level zygote pool (Zig) | Implemented but standalone | `zygote-rs/src/lib.rs`, `zygote.zig` |
| `phantom warm` (without args) | Zygote pool benchmark mode | `commands/warm.rs:220-307` |

### Partially Implemented (Non-Functional)

| Component | Status | Issue |
|-----------|--------|-------|
| `phantom warm fragment create` | Shell-based daemon exits immediately | No persistent listener |
| Daemon IPC | File-based polling only | No socket protocol implemented |
| Warm execution path | Exists but broken | Cannot communicate with dead daemons |
| Zygote pool integration | Not connected | Zig pool separate from daemon architecture |

### Known Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Daemons exit immediately | Warm start impossible | Use cold execution (~45ms is still fast) |
| No cgroup resource limits for warm fragments | Cannot enforce memory/CPU limits | Use cold execution with full isolation |
| No health monitoring | Orphaned processes possible | Manual `pkill` to clean up |
| File-based IPC only | Race conditions, no response handling | Not recommended for production use |

### Key Files

```
src/cli/phantom-cli/src/
├── commands/warm.rs          # CLI warm command (daemon creation - PARTIAL)
├── commands/run.rs           # Run command (warm path broken, cold works)
├── fragment_pool.rs          # Pool metadata storage (functional)
└── config.rs                 # Path management

src/core/zygote-rs/
├── src/lib.rs                # Rust pool management (standalone)
└── src/zygote.zig            # Low-level fork/clone (not integrated)
```

---

## Implementation Roadmap

### Phase 0: Resource Limits Infrastructure

**Goal**: Enable unprivileged users to apply cgroup resource limits without sudo, similar to Docker rootless mode

**Status**: 🔴 NOT STARTED

#### Tasks

| # | Task | Status | Priority | Complexity | Dependencies |
|---|------|--------|----------|------------|--------------|
| 0.1 | Implement user cgroup delegation support | 🔴 NOT STARTED | P0 | High | - |
| 0.2 | Add systemd user slice integration | 🔴 NOT STARTED | P1 | Medium | 0.1 |
| 0.3 | Create cgroup delegation setup script | 🔴 NOT STARTED | P1 | Low | 0.1 |
| 0.4 | Add fallback to manual cgroup delegation | 🔴 NOT STARTED | P1 | Medium | 0.1 |
| 0.5 | Integrate with cgroups-rs for per-fragment limits | 🔴 NOT STARTED | P2 | High | 0.1 |

---

### Phase 1: Keep Mother Alive

**Goal**: Fix daemon to stay alive continuously and accept connections

**Status**: 🔴 NOT STARTED - Current shell-based daemon is broken

#### Tasks

| # | Task | Status | Complexity | Dependencies |
|---|------|--------|------------|--------------|
| 1.1 | Replace shell daemon with persistent listener | 🔴 NOT STARTED | Medium | - |
| 1.2 | Implement socket-based IPC protocol | 🔴 NOT STARTED | Medium | 1.1 |
| 1.3 | Add mother process health monitoring | 🔴 NOT STARTED | Medium | 1.2 |
| 1.4 | Create daemon pidfile on startup | 🔴 NOT STARTED | Low | 1.1 |
| 1.5 | Add daemon restart on crash | 🔴 NOT STARTED | Medium | 1.3 |
| 1.6 | Implement graceful shutdown | 🔴 NOT STARTED | Medium | 1.3 |

#### Current Broken Implementation

```bash
# Current daemon in warm.rs:324-349 - exits immediately
daemon_script = r""
while true; do
    for f in "$PHANTOM_CMD_DIR"/*.cmd; do
        # Polls for files - primitive and unreliable
        ...
    done
    sleep 0.1
done
""
```

---

### Phase 2: Zygote Pool Management

**Goal**: Create frozen zygotes from mother, store in pool, activate on demand

**Status**: 🔴 NOT STARTED

#### Tasks

| # | Task | Status | Complexity | Dependencies |
|---|------|--------|------------|--------------|
| 2.1 | Implement fork-from-mother in daemon | 🔴 NOT STARTED | High | Phase 1.2 |
| 2.2 | Add zygote state tracking (frozen/active) | 🔴 NOT STARTED | Medium | 2.1 |
| 2.3 | Implement zygote activation protocol | 🔴 NOT STARTED | Medium | 2.1 |
| 2.4 | Add zygote recycling on fragment exit | 🔴 NOT STARTED | Medium | 2.3 |
| 2.5 | Implement pool refill on low watermark | 🔴 NOT STARTED | Medium | 2.4 |
| 2.6 | Connect fragment_pool.rs to daemon | 🔴 NOT STARTED | Medium | 2.3 |

---

### Phase 3: Adaptive Resource Control

**Goal**: Child processes get independent limits from mother using cgroups

**Status**: 🔴 NOT STARTED

#### Tasks

| # | Task | Status | Complexity | Dependencies |
|---|------|--------|------------|--------------|
| 3.1 | Integrate cgroups-rs for per-fragment limits | 🔴 NOT STARTED | High | Phase 2 |
| 3.2 | Implement adaptive engine integration | 🔴 NOT STARTED | Medium | 3.1 |
| 3.3 | Add memory limit inheritance | 🔴 NOT STARTED | Medium | 3.1 |
| 3.4 | Implement CPU affinity control | 🔴 NOT STARTED | Medium | 3.1 |
| 3.5 | Add I/O limits per fragment | 🔴 NOT STARTED | High | 3.1 |
| 3.6 | Security policy application per fragment | 🔴 NOT STARTED | Medium | 3.2 |

---

### Phase 4: Integration & Polish

**Status**: 🔴 NOT STARTED

#### Tasks

| # | Task | Status | Complexity | Dependencies |
|---|------|--------|------------|--------------|
| 4.1 | Connect warm execution in run.rs | 🔴 NOT STARTED | Medium | Phase 2 |
| 4.2 | Add proper error handling | 🔴 NOT STARTED | Medium | Phase 2 |
| 4.3 | Implement pool metrics | 🔴 NOT STARTED | Low | Phase 2 |
| 4.4 | Add integration tests | 🔴 NOT STARTED | Medium | All phases |
| 4.5 | Performance benchmarking | 🔴 NOT STARTED | Low | Phase 2 |

---

## Dependencies Graph

```
Phase 0 (foundational - enables all others)
├── 0.1 User cgroup delegation ──────────────────────────┐
│   ├── 0.2 Systemd user slice                          │
│   ├── 0.3 Setup script                                │
│   ├── 0.4 Manual fallback                             │
│   └── 0.5 Cgroups-rs integration ────────────────────┤
│                                                       │
Phase 1                                                │
├── 1.1 Fix daemon script                              │
│   └── 1.2 Socket IPC protocol                        │
│       └── 1.3 Health monitoring                      │
│           ├── 1.5 Daemon restart                      │
│           └── 1.6 Graceful shutdown                   │
                                                        │
Phase 2                                                │
├── 2.1 Fork-from-mother ──────────────────────────────┤
│   └── 2.2 State tracking                             │
│       └── 2.3 Activation protocol                    │
│           └── 2.4 Recycling                          │
│               └── 2.5 Pool refill                    │
│                   └── 2.6 Pool integration            │
                                                │
Phase 3 (depends on Phase 0, Phase 2)                 │
├── 3.1 Cgroups integration ───────────────────────────┤
│   └── 3.2 Adaptive engine                            │
│       └── 3.3 Memory limits                          │
│       └── 3.4 CPU affinity                           │
│       └── 3.5 I/O limits                             │
│       └── 3.6 Security policy                         │
                                                │
Phase 4 (depends on all)                              │
├── 4.1 Connect run.rs ────────────────────────────────┘
├── 4.2 Error handling
├── 4.3 Metrics
├── 4.4 Integration tests
└── 4.5 Benchmarking
```

---

## Complexity Summary

| Phase | Tasks | Total Complexity | Est. Total Effort |
|-------|-------|------------------|-------------------|
| Phase 0 | 5 | High | 10-14 hours |
| Phase 1 | 6 | Medium | 12-18 hours |
| Phase 2 | 6 | Medium-High | 16-22 hours |
| Phase 3 | 6 | High | 12-18 hours |
| Phase 4 | 5 | Low-Medium | 8-12 hours |
| **TOTAL** | **28** | - | **58-84 hours** |

---

## Implementation Priority Order

1. **P0 (Critical)**: 0.1, 1.1, 1.2, 2.1, 4.1
2. **P1 (High)**: 0.2, 0.3, 0.4, 1.3, 2.2, 2.3, 3.1
3. **P2 (Medium)**: 0.5, 2.4, 2.5, 3.2, 4.2, 4.3, 4.4
4. **P3 (Low)**: 1.4, 1.5, 1.6, 3.3, 3.4, 3.5, 3.6, 4.5

---

## Testing Strategy (When Implemented)

### Unit Tests
- IPC protocol parsing
- State machine transitions
- Pool management logic

### Integration Tests
- `phantom warm fragment create alpine` → creates pool
- `phantom run alpine echo hello` → uses warm fragment
- Pool exhaustion → falls back to cold
- Daemon crash → restart + refill

### Benchmarking Targets
- Cold start: ~45ms (baseline - CURRENTLY ACHIEVED)
- Warm start target: <1ms (NOT YET ACHIEVED)
- Pool initialization: measure overhead

---

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Daemon crash leaves orphaned processes | High | Medium | Health monitor + restart (Phase 1.5) |
| Socket race conditions | Medium | Medium | Proper locking in Rust (Phase 1.2) |
| Cgroups permissions | Medium | High | Graceful degradation to cold execution |
| Memory pressure from too many zygotes | Medium | Medium | Pool size limits (Phase 2.5) |
| Rootfs changes not reflected | Medium | Low | Invalidate on image update |

---

## Future Enhancements (Post-MVP)

- [ ] NUMA-aware pool placement
- [ ] Landlock security on zygotes
- [ ] Cross-host zygote migration
- [ ] Priority-based pool allocation
- [ ] Predictive pre-warming based on usage patterns
