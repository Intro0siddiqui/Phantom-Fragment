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

# Build Zig components
cd src/memory/discipline/memory-zig && zig build
cd src/core/zygote-rs && zig build
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
├── mcp/                          # MCP server for AI agents
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

- Rust 1.75+ (stable)
- Zig 0.14+
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
| `phantom-mcp` | 3.5M | `target/release/phantom-mcp` |

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

### Tier 1: Cold Start (Default)
- **Command**: `phantom run alpine <cmd>`
- **Mechanism**: Standard fork/exec with fresh process
- **Performance**: ~45ms startup time
- **Use Case**: Default, works reliably on all systems
- **Status**: ✅ **Production Ready**

### Tier 2: Warm Fragments / Mother Fragments
- **Command**: `phantom warm fragment create alpine 3` then `phantom run --warm alpine <cmd>`
- **Mechanism**: Pre-warmed daemon processes ("mother fragments") that stay alive and fork on demand
- **Performance**: Faster than cold start (avoids image setup overhead)
- **Use Case**: When you need faster startup than cold, without pre-fork complexity
- **Status**: 🚧 **Beta/Experimental** - Currently has significant limitations (daemon stability, IPC issues)

### Tier 3: Zygote Pool (Fastest)
- **Command**: Currently `phantom warm --benchmark` (for testing); future: integrated with run command
- **Mechanism**: Pre-forked processes via Zig zygote pool using clone3/vfork syscalls
- **Performance**: Sub-millisecond (<1ms) target
- **Use Case**: High-frequency execution, serverless workloads, maximum performance
- **Status**: 🚧 **Partial** - Low-level implementation complete, not yet integrated with run command

### Current Implementation Status

| Tier | Command | Status | Performance |
|------|---------|--------|-------------|
| **Cold** | `phantom run alpine` | ✅ Working | ~45ms |
| **Warm** | `phantom run --warm alpine` | 🚧 Beta/Experimental | Unreliable, may fall back to cold |
| **Zygote** | `phantom warm --benchmark` | 🚧 Benchmark only | <1ms (in benchmarks) |

**Note**: The zygote pool (Tier 3) exists as a low-level Zig implementation but is not yet connected to the `phantom run` command. The warm fragment daemon (Tier 2) is in beta/experimental status with significant limitations.

See `docs/architecture/components/warm-fragment-roadmap.md` for full implementation details.

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
- `phantom_zygote_fork()` - Fast process spawn (clone/vfork)
- `phantom_numa_available()` - NUMA support check

---

## Subsystem Status Map

> Last Updated: March 2026
> This section tracks completion status of all subsystems.

### Summary

| Category | Total | Complete | Partial | Broken |
|----------|-------|----------|---------|--------|
| **Core** | 8 | 7 | 1 | 0 |
| **Security** | 7 | 6 | 1 | 0 |
| **Storage** | 4 | 4 | 0 | 0 |
| **Monitoring** | 3 | 2 | 1 | 0 |
| **Memory** | 2 | 2 | 0 | 0 |
| **CLI** | 27 | 24 | 2 | 1 |
| **Tools** | 4 | 4 | 0 | 0 |
| **Total** | **55** | **49 (89%)** | **5 (9%)** | **1 (2%)** |

### Core Subsystems

| Subsystem | Status | Notes |
|-----------|--------|-------|
| **execution-rs** | ✅ Complete | Adaptive engine, 3 modes (Sandbox/Hardened/Wasm) |
| **types-rs** | ✅ Complete | FFI-safe types, no_std crate |
| **zygote-rs** | ✅ Complete | Zig pool, <1ms in benchmarks, not fully integrated with run |
| **task-analyzer-rs** | ✅ Complete | Component detection, memory estimation |
| **network-rs** | ⚠️ Partial | Loopback auto-start NOT implemented |
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
| **Complete** | 24 | run, create, delete, list, logs, health, metrics, clean, search, images, network, profile, inspect, update, restart, monitor, benchmark, volume, debug, stop, status, explain, build, migrate |
| **Partial** | 2 | warm (daemon stability issues), security scan (placeholder) |
| **Minimal** | 1 | registry (12-line placeholder) |

### Tools

| Tool | Status | Notes |
|------|--------|-------|
| **integration-tests** | ✅ Active | 100+ tests |
| **phantom-build** | ✅ Active | Multi-stage builds |
| **phantom-migrate** | ✅ Active | Docker/Podman migration |
| **phantom-mcp** | ✅ Production | MCP server, 11 tools |

### Three-Tier Execution Status

| Tier | Command | Status | Performance |
|------|---------|--------|-------------|
| **Cold** | `phantom run alpine` | ✅ Working | ~45ms |
| **Warm** | `phantom run --warm` | ⚠️ Beta | Unreliable, falls back to cold |
| **Zygote** | `phantom warm --benchmark` | ⚠️ Bench only | <1ms (benchmarks) |

### Known Issues

1. **network-rs**: Loopback interface not auto-started
2. **bpf-lsm-rs**: Requires kernel 5.7+ and CAP_SYS_ADMIN
3. **debug-rs**: GDB/Delve attachment are stubs
4. **warm**: Daemon stability issues, IPC problems
5. **zygote**: Not connected to `phantom run` command
6. **execution-rs**: Tests may hang due to zygote pool init

### Performance Reality

| Feature | Target | Actual | Notes |
|---------|--------|--------|-------|
| Cold start (Sandbox) | <25ms | ~45ms | Default mode |
| Cold start (Hardened) | <60ms | ~45ms+ | Maximum security |
| Zygote spawn | <1ms | <1ms | ✅ Achieved in benchmarks |
