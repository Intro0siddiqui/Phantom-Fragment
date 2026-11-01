# AGENTS.md - Phantom Fragment Development Guide

## Project Overview

Phantom Fragment is a high-performance container alternative using Linux kernel features (namespaces, seccomp, Landlock, cgroups). Codebase: Primarily Rust with Zig for low-level components (zygote pool, memory management).

## Build Commands

```bash
# Build all components
cargo build --release
cargo build --workspace

# Build specific package
cargo build --package phantom-cli
cargo build --package execution-rs

# Check without building
cargo check --workspace

# Build Zig components (build.rs invokes zig automatically; standalone memory build below)
cd src/memory/discipline/memory-zig && zig build
```

## Test Commands

```bash
# Run all tests
cargo test --workspace

# Run tests for specific package
cargo test --package execution-rs
cargo test --package landlock-rs

# Run single test by name
cargo test --package execution-rs test_mode_selection
cargo test test_capability_detection

# Run tests with output
cargo test --workspace -- --nocapture

# Run ignored tests
cargo test -- --ignored

# Run integration tests
cargo test --package integration-tests
```

## Lint & Format Commands

```bash
# Format Rust code
cargo fmt

# Format Zig code
zig fmt src/memory/discipline/memory-zig/src/main.zig
zig fmt src/core/zygote-rs/src/zygote.zig

# Run Clippy
cargo clippy --workspace --all-targets -- -D warnings

# Check without building
cargo check --workspace
```

## Code Style Guidelines

### Rust

**Imports:** Group by external crates first, then internal modules.

```rust
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::executor::BuildContext;
use types_rs::PhantomError;
```

**Naming:**
- Types/Structs: `PascalCase` (`AdaptiveEngine`, `SecurityPolicy`)
- Functions/Methods: `snake_case` (`select_mode`, `apply_seccomp`)
- Constants: `SCREAMING_SNAKE_CASE` (`PHANTOM_ERROR_SUCCESS`)
- Modules: `snake_case` (`bpf_loader`, `task_analyzer`)
- Crates: `kebab-case` (`execution-rs`, `image-puller`)

**Error Handling:** Use `anyhow::Result` for application code, `thiserror` for custom errors.

```rust
#[derive(Error, Debug)]
pub enum BpfError {
    #[error("BPF-LSM not supported")]
    NotSupported,
    #[error("Failed to load policy: {0}")]
    LoadPolicy(String),
}
```

**Structs:** Use `#[derive]` attributes. Implement `Default` where sensible.

```rust
#[derive(Debug, Clone, Default)]
pub struct RiskProfile {
    pub network_access: bool,
    pub file_write: bool,
    pub privileged_ops: bool,
    pub untrusted_source: bool,
}
```

**Documentation:** Use `//!` for crate-level docs, `///` for public items.

```rust
/// Adaptive Execution Engine
/// 
/// Automatically selects the optimal execution mode based on workload risk.
pub struct AdaptiveEngine { ... }
```

**Tests:** Place unit tests in same file with `#[cfg(test)]` module.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_capability_detection() {
        let loader = BpfProgramLoader::new();
        assert!(loader.is_ok());
    }
}
```

### Zig

**Exports:** Use `export fn` for C-compatible FFI with `c_int` returns.

```zig
export fn phantom_zygote_fork() c_int {
    // ...
}
```

**Naming:** `snake_case` for functions, `PascalCase` for types.

**Formatting:** Use `zig fmt`.

## Workspace Structure

```
src/
├── cli/phantom-cli/          # Main CLI binary
│   └── src/
│       ├── main.rs           # CLI entry point (~205 lines, command dispatch)
│       ├── commands/         # Modular command pattern (~25 modules)
│       │   ├── mod.rs
│       │   ├── run.rs        # Run command
│       │   ├── create.rs     # Create command
│       │   ├── list.rs       # List command
│       │   ├── logs.rs       # Logs command
│       │   ├── delete.rs     # Destroy command
│       │   ├── health.rs     # Health check
│       │   ├── metrics.rs    # Metrics
│       │   ├── warm.rs       # Zygote warm-up
│       │   └── ...           # Other subcommands
│       ├── config.rs         # Config + PhantomPaths
│       ├── ui.rs             # Standardized UI output
│       ├── io_utils.rs       # Shared file I/O utilities
│       └── fragment_registry.rs
├── core/
│   ├── execution/execution-rs    # Adaptive execution engine
│   ├── types/types-rs            # Shared FFI-safe types
│   ├── zygote-rs                 # Zygote pool (Zig)
│   ├── task-analyzer-rs          # Command analysis
│   ├── network-rs                # Network management
│   ├── compression-rs            # Compression utilities
│   ├── wasm-rs                   # WebAssembly execution
│   └── config-rs                 # Configuration handling
├── security/
│   ├── bpf-lsm/bpf-lsm-rs        # BPF-LSM integration
│   ├── orchestration/security-rs # Security manager
│   ├── policy-dsl-rs             # Policy DSL
│   ├── seccomp-rs                # Syscall filtering
│   ├── landlock-rs               # Filesystem sandboxing
│   ├── cgroups-rs                # Resource limits
│   └── capabilities-rs           # Linux capabilities
├── memory/
│   └── discipline/
│       ├── memory-rs             # Memory management (Rust)
│       └── memory-zig            # Low-level memory (Zig)
├── storage/
│   ├── image-store-rs            # Image storage
│   ├── oci-registry-rs           # OCI registry client
│   ├── storage-rs                # Storage abstraction
│   └── image-puller/             # Image pulling and rootfs setup
├── monitoring/
│   ├── metrics/metrics-rs        # Prometheus metrics
│   ├── health/health-rs          # Health checks
│   └── debug/debug-rs            # Debugging tools
└── tools/
    ├── integration-tests/        # Integration tests
    ├── phantom-build/            # Build tool
    └── phantom-migrate/          # Migration tool
```

## Key Patterns

**CLI Modular Architecture:** Commands are extracted into separate modules under `commands/`. Each subcommand implements an `exec` function. This reduces `main.rs` from ~2300 lines to ~205 lines.

```rust
// main.rs dispatches to command modules
match cli.command {
    Commands::Run { ... } => commands::run::exec(...).await?,
    Commands::List { all } => commands::list::exec(...)?,
    // ...
}

// commands/run.rs contains the implementation
pub async fn exec(...) -> Result<()> { ... }
```

**PhantomPaths:** Centralized path management in `config.rs` provides consistent paths for logs, volumes, registry, storage, and rootfs.

**UI Module:** Standardized output functions in `ui.rs` (info!, success!, error!, warn!, dimmed!).

**IO Utils:** Shared file I/O in `io_utils.rs` for tail_file, follow_file operations.

**Graceful Degradation:** Security features fall back silently if unsupported.

```rust
if let Err(_) = ctx.apply() {
    log::warn!("Failed to apply Landlock ruleset");
    return Ok(());  // Continue without Landlock
}
```

**FFI Pattern:** Zig exports C ABI, Rust links via `extern "C"`.

**Execution Modes (increasing isolation):** `Sandbox` < `Hardened`

## Commit Convention

Use Conventional Commits:
- `feat(scope): description`
- `fix(scope): description`
- `refactor(scope): description`
- `docs(scope): description`

## Requirements

- Rust 1.99.1 (pinned in `rust-toolchain.toml`)
- Zig 0.16+
- libseccomp development headers (`libseccomp-dev` on Debian/Ubuntu, `libseccomp-devel` on Fedora/RHEL)
- Linux kernel 5.13+ (for Landlock), 6.5+ recommended (for BPF-LSM)

## Languages Used

| Language | Files | Role |
|----------|-------|------|
| **Rust** | 69 | Primary implementation |
| **Zig** | 7 | Low-level memory/zygote (FFI to Rust) |
| **C** | 1 | BPF-LSM kernel program |
| **Shell** | 2 | Testing/benchmarking scripts |
| **Python** | 1 | Debug utility |

**FFI Integration:**
- `zygote-rs` → links `libzygote.a` (Zig)
- `memory-rs` → links `libphantom_memory.a` (Zig)
- `bpf-lsm-rs` → loads `monitor.o` (compiled C BPF)

## I/O System

| Component | Implementation | Notes |
|-----------|----------------|-------|
| File I/O | `std::fs` + `tokio::fs` | Sync for storage, async for network |
| Network I/O | `reqwest` + `tokio` | HTTP client for OCI registry |

**Note:** No separate I/O crate. Using std::fs for sync operations (storage), tokio::fs for async (network).
io_uring is NOT implemented - uses standard tokio async I/O.

## Binaries & Linking

**Compiled Binaries:**
| Binary | Size | Location |
|--------|------|----------|
| `phantom` | 19MB | `target/release/phantom` |

**Unified CLI**: `phantom` includes all subcommands: `run`, `create`, `list`, `logs`, `destroy`, `health`, `metrics`, `warm`, `clean`, `search`, `images`, `network`, `profile`, `inspect`, `update`, `restart`, `monitor`, `benchmark`, `volume`, `security`, `debug`, `stop`, `build`, `migrate`.

**Current Linking:** Dynamic (glibc, OpenSSL, libseccomp)

**Recommendation:** Statically link OpenSSL and libseccomp for portability:
```toml
# In Cargo.toml
openssl = { version = "0.10", features = ["vendored"] }
libseccomp = { version = "0.3", features = ["static"] }
```

## Test Coverage

| Status | Count |
|--------|-------|
| Passed | 103+ |
| Failed | 0 |
| Ignored | 2 |

**Packages Without Tests:** landlock-rs, memory-rs, types-rs, zygote-rs, network-rs, compression-rs, config-rs

**Known Issue:** `execution-rs` tests hang due to zygote pool initialization in test environment.

## Fragment Profiles (phantom.toml)

Custom execution profiles can be defined in `phantom.toml` or `~/.phantom/config.toml`:

```toml
[profiles.network_ghost]
isolation = "sandbox"
network = false
file_write = true
memory_mb = 1024
cpu_affinity = []

[profiles.vault]
isolation = "hardened"
network = false
file_write = false
memory_mb = 256
cpu_count = 1
```

Profile options:
- `isolation`: "sandbox", "hardened", "wasm"
- `network`: bool (false = network isolated via --unshare-net)
- `file_write`: bool (false = read-only rootfs)
- `memory_mb`: integer memory limit
- `cpu_count`: number of CPU cores
- `cpu_affinity`: list of core IDs to pin to

## Three-Tier Execution Architecture

Phantom Fragment supports three distinct execution tiers, from standard cold start to optimized sub-millisecond warm starts:

### What "warm" means (read this before touching warm or zygote)

"Warm" is an umbrella term, not one mechanism. The three methods differ in what is kept
between runs and therefore in what a start actually costs:

| Method | What is kept | What a start does | Implemented? |
|---|---|---|---|
| **Mother fragment** | a live, already-sandboxed process | `fork` + `exec` inside the sandbox it built once | ✅ yes, `--warm` |
| **Zygote** | a frozen, compressed process image (memory, fds, namespaces, security state) | restore the image; no build, no boot | ❌ no, design only |
| **Artifact / cache** | files: layers, rootfs, build outputs | the full cold path, with less I/O work | ⚠️ partial: images and rootfs only |

Rules that follow, and that docs and comments must not break:

- **A zygote is a stored image that becomes a new execution.** Nothing in this tree does
  that. No checkpoint, no compression, no restore; `rg 'criu|checkpoint|freeze|SIGSTOP' src/`
  returns nothing.
- **The `--zygote` flag is not a zygote.** `src/core/zygote-rs` is a *pre-fork spawn
  accelerator*: it keeps idle processes and forks a grandchild per request (`fork`/`clone`
  + `execve`), applying `CLONE_NEWNS`, a bind-mounted rootfs and `pivot_root`. It applies
  no user/PID/net namespace, no seccomp, no Landlock and no capability drop, and it is
  skipped whenever a security policy is requested.
- **An artifact is not a snapshot.** The artifact/cache method stores files, not process
  state. It makes the cold path cheaper; it does not skip it.
- **Firecracker-style snapshot restore is the zygote row**, not the artifact row and not
  the mother.
- Do not describe `--warm` as a snapshot: the mother stays alive and is forked. Do not
  describe `--zygote` as frozen-state activation.

Canonical description: `docs/architecture/components/warm-exec-v2.md` (Methods 1-3,
decisions D1-D16).

### Tier 1: Cold Start (Default)
- **Command**: `phantom run alpine <cmd>`
- **Mechanism**: Native engine (`engine/native.rs`): user/mount/PID/IPC/UTS namespaces, network ns when disabled, chroot, `/proc`, `/dev`, `/tmp`, then Landlock → capability drop → seccomp → `execve`. `--engine auto|native|bwrap` selects the backend; `bwrap` (`RootfsExecutor`) applies namespace isolation only and is never used for a profile that requires confinement.
- **Performance**: ~39 ms measured (release, 30 samples, median)
- **Use Case**: Default, works reliably on all systems
- **Status**: ✅ **Production Ready**

### Tier 2: Warm Fragments / Mother Fragments
- **Command**: `phantom warm create alpine 3` then `phantom run --warm alpine <cmd>`
- **Mechanism**: The daemon forks one long-lived, pre-sandboxed "mother fragment" at startup. The mother applies cgroup, userns/mount ns, chroot, tmpfs, Landlock, caps and seccomp **once**, then serves each request by forking and `exec`ing the child over a daemon↔mother socketpair. The security profile is bound at pool creation (`warm create -p`), and a mismatched `PHANTOM_PROFILE` is refused.
- **Performance**: Faster than cold start (no per-request sandbox setup)
- **Use Case**: When you need faster startup than cold, without pre-fork complexity
- **Status**: 🚧 **Beta/Experimental** - Mother is pre-sandboxed (Phase 3.4/3.5) with the cold namespace set and procfs; stdio is passed over the socket (a client-owned pty when interactive), signals are relayed and dead-client slots are reclaimed. One command per fragment at a time (D5).

### Tier 3: Zygote Pool (spawn accelerator)
- **Command**: `phantom run --zygote alpine <cmd>`
- **Mechanism**: A Zig pool of pre-forked processes (`fork`/`clone` + `execve`, socketpair IPC). Each child gets `CLONE_NEWNS`, a bind-mounted rootfs and `pivot_root`; every request still forks a grandchild.
- **Performance**: Sub-millisecond spawn in the pool's own benchmark. This is pre-forking, not frozen-state activation.
- **Use Case**: High-frequency spawning where no security policy is requested.
- **Limitation**: It is not a sandbox. No user, PID or network namespace, no seccomp, no Landlock, no capability drop. `run --zygote` skips the pool whenever a policy is requested and runs cold instead.
- **Status**: 🚧 **Beta/Experimental** - Wired into `phantom run --zygote`; falls back to cold execution if the pool is unavailable. The intended design (a batch of fragments frozen and compressed, restored on demand) is **not implemented**; see `docs/architecture/components/warm-exec-v2.md`, Method 2.

### Current Implementation Status

| Tier | Command | Status | Performance |
|------|---------|--------|-------------|
| **Cold** | `phantom run alpine` | ✅ Working | ~39 ms measured |
| **Warm** | `phantom run --warm alpine` | 🚧 Beta/Experimental | ~12 ms measured; falls back to cold if no slot is free |
| **Zygote** | `phantom run --zygote alpine` | 🚧 Beta/Experimental | Sub-ms spawn in benchmarks; no security stack; falls back to cold |

**Note**: The zygote pool (Tier 3) is connected to `phantom run` via the `--zygote` flag and falls back to cold execution when the pool cannot be initialized. It is a spawn accelerator, not a batch of frozen fragments: nothing is checkpointed, compressed or restored, and the pool is skipped when a security policy is requested. The warm fragment daemon (Tier 2) is in beta/experimental status: Phase 1 correctness (chroot, security stack, setsid, health probe, Landlock TSYNC) and Phase 3.4/3.5 (pre-sandboxed mother fragment, profile binding) have landed; stdio handoff (D2), a client-owned pty (D15), the cold namespace set plus procfs (D16), signal relay and slot-lease reclaim are implemented. Remaining: one command per fragment at a time (D5), semi-mother.

See `docs/architecture/components/warm-exec-v2.md` for full implementation details.

## Key Functions by Module

**Execution (execution-rs):**
- `select_mode()` - Chooses Sandbox/Hardened based on risk
- `AdaptiveEngine::new()` - Initializes execution engine

**Security:**
- `apply_seccomp()` - Syscall filtering
- `apply_landlock()` - Filesystem sandboxing
- `BpfLsmSecurity::load_bpf_bytecode()` - BPF-LSM loading

**Memory (Zig FFI):**
- `phantom_zygote_pool_create()` - Initialize zygote pool with specified size
- `phantom_zygote_fork()` - Fast process spawn (`fork`/`clone` + `execve`)
- `phantom_numa_available()` - NUMA support check

---

## Subsystem Status Map

> Last Updated: November 2026
> This section tracks completion status of all subsystems.

### Summary

| Category | Total | Complete | Partial | Broken |
|----------|-------|----------|---------|--------|
| **Core** | 8 | 7 | 1 | 0 |
| **Security** | 7 | 6 | 1 | 0 |
| **Storage** | 4 | 4 | 0 | 0 |
| **Monitoring** | 3 | 2 | 1 | 0 |
| **Memory** | 2 | 2 | 0 | 0 |
| **CLI** | 27 | 25 | 2 | 0 |
| **Tools** | 4 | 4 | 0 | 0 |
| **Total** | **55** | **49 (89%)** | **6 (11%)** | **0 (0%)** |

### Core Subsystems

| Subsystem | Status | Notes |
|-----------|--------|-------|
| **execution-rs** | ✅ Complete | Adaptive engine, 3 modes (Sandbox/Hardened/Wasm) |
| **types-rs** | ✅ Complete | FFI-safe types, no_std crate |
| **zygote-rs** | ⚠️ Partial | Zig pre-fork spawn accelerator; sub-ms spawn in benchmarks, but no seccomp/Landlock/caps and no frozen-state restore; skipped when a policy is set |
| **task-analyzer-rs** | ✅ Complete | Component detection, memory estimation |
| **network-rs** | ✅ Complete | Loopback auto-start implemented for new network namespaces |
| **compression-rs** | ✅ Complete | Zstd/Gzip/LZ4 |
| **wasm-rs** | ✅ Complete | Wasmtime, limited network isolation |
| **config-rs** | ✅ Complete | TOML config, minimal validation |

### Security Subsystems

| Subsystem | Status | Notes |
|-----------|--------|-------|
| **seccomp-rs** | ✅ Complete | Multiple profiles, libseccomp |
| **landlock-rs** | ✅ Complete | Filesystem sandboxing, kernel 5.13+ |
| **cgroups-rs** | ✅ Complete | Full cgroup v2, user slice auto-detection |
| **capabilities-rs** | ✅ Complete | Capability dropping |
| **policy-dsl-rs** | ✅ Complete | YAML → seccomp/landlock compilation |
| **bpf-lsm-rs** | ⚠️ Partial | Requires kernel 5.7+, CAP_SYS_ADMIN (graceful fallback) |
| **security-rs** | ✅ Complete | Central orchestrator |

### Storage Subsystems

| Subsystem | Status | Notes |
|-----------|--------|-------|
| **storage-rs** | ✅ Complete | CAS with compression, GC |
| **image-store-rs** | ✅ Complete | LRU eviction, deduplication |
| **oci-registry-rs** | ✅ Complete | Full OCI client |
| **image-puller** | ✅ Complete | Pull → extract → execute |

### Monitoring Subsystems

| Subsystem | Status | Notes |
|-----------|--------|-------|
| **metrics-rs** | ✅ Complete | Prometheus metrics |
| **health-rs** | ✅ Complete | Health checks |
| **debug-rs** | ⚠️ Partial | Inspector/Monitor work, GDB/Delve are stubs |

### Memory Subsystems

| Subsystem | Status | Notes |
|-----------|--------|-------|
| **memory-rs** | ✅ Complete | Rust FFI wrapper |
| **memory-zig** | ✅ Complete | Zig implementation, buffer pool, NUMA |

### CLI Commands (27 total)

| Status | Count | Commands |
|--------|-------|----------|
| **Complete** | 25 | run, create, delete, list, logs, health, metrics, clean, search, images, network, profile, inspect, update, restart, monitor, benchmark, volume, debug, stop, status, explain, build, migrate, registry |
| **Partial** | 2 | warm (Phase 1 + 3.4/3.5 mother landed; stdio/pty/namespaces/signals/lease reclaim done; one command per fragment), security scan (placeholder) |
| **Minimal** | 0 | — |

### Tools

| Tool | Status | Notes |
|------|--------|-------|
| **integration-tests** | ✅ Active | 100+ tests |
| **phantom-build** | ✅ Active | Multi-stage builds |
| **phantom-migrate** | ✅ Active | Docker/Podman migration |

### Three-Tier Execution Status

| Tier | Command | Status | Performance |
|------|---------|--------|-------------|
| **Cold** | `phantom run alpine` | ✅ Working | ~32ms |
| **Warm** | `phantom run --warm` | ⚠️ Beta | ~12 ms measured; falls back to cold if no slot is free |
| **Zygote** | `phantom run --zygote` | ⚠️ Beta | Sub-ms spawn (benchmarks); no security stack; falls back to cold |

### Known Issues

1. **bpf-lsm-rs**: Requires kernel 5.7+ and CAP_SYS_ADMIN
2. **debug-rs**: GDB/Delve attachment are stubs
3. **warm**: Daemon stability issues, IPC problems
4. **execution-rs**: Tests may hang due to zygote pool init

### Performance Reality

| Feature | Target | Actual | Notes |
|---------|--------|--------|-------|
| Cold start (Sandbox) | <25ms | ~39 ms | Default mode |
| Cold start (Hardened) | <60ms | ~39 ms+ | Maximum security |
| Zygote spawn | <1ms | <1ms | Spawn only; no sandbox applied, skipped when a policy is set |


---

# Contributing to Phantom Fragment

Thank you for your interest in contributing to Phantom Fragment! This document provides guidelines for contributing.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Intro0siddiqui/Phantom-Fragment.git
cd Phantom-Fragment

# Build all components
cargo build --release

# Run tests
cargo test --workspace
```

## Development Setup

### Prerequisites

- **Rust**: 1.99.1 (pinned in `rust-toolchain.toml`)
- **Zig**: 0.16+ (for memory modules and the zygote pool)
- **libseccomp headers**: `libseccomp-dev` on Debian/Ubuntu, `libseccomp-devel` on Fedora/RHEL
- **Linux**: Kernel 3.x+ (6.5+ for Landlock/BPF)

### Building

```bash
# Build Rust components
cargo build --release

# Build Zig memory module
cd src/memory/discipline/memory-zig
zig build
```

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific package
cargo test --package memory-rs

# With output
cargo test --workspace -- --nocapture
```

## Code Structure

```
src/
├── cli/              # CLI binary (phantom-cli)
├── core/             # Core engine (execution, driver, types)
├── memory/           # Memory management (Zig + Rust)
├── security/         # Security (seccomp, landlock, capabilities)
├── monitoring/       # Metrics and observability
```

## Coding Guidelines

### Rust

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` before committing
- Use `cargo clippy` to catch common issues
- Document public APIs with rustdoc

### Zig

- Follow Zig style guide
- Export C-compatible functions with `pub export fn`
- Gate debug prints behind `const DEBUG = false`
- Use `zig fmt` before committing

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(io): add batch_write_fast for 3GB/s throughput
fix(cli): handle missing config file gracefully
docs(readme): update performance benchmarks
refactor(security): consolidate policy loading
```

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feat/my-feature`
3. **Make** your changes
4. **Test** thoroughly: `cargo test --workspace`
5. **Format** code: `cargo fmt && zig fmt src/memory/**/*.zig`
6. **Commit** with descriptive message
7. **Push** and create Pull Request

### PR Checklist

- [ ] Tests pass (`cargo test --workspace`)
- [ ] Code formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Documentation updated if needed
- [ ] CHANGELOG.md updated for significant changes

## Areas for Contribution

### Good First Issues
- Documentation improvements
- Test coverage
- Error message improvements

### Intermediate
- Performance optimizations
- New CLI commands
- Security policy enhancements

### Advanced
- I/O subsystem improvements (Zig)
- Memory management (Zig)
- Kernel feature integration

## Getting Help

- Open an issue for bugs or feature requests
- Discussions for questions and ideas

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
