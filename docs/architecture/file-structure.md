# Phantom Fragment - File Structure

## New Organized Structure

```
phantom-fragment/
│
├── src/                          # All source code
│   ├── cli/                      # Command-line interface
│   │   └── phantom-cli/          # Main CLI binary
│   │
│   ├── core/                     # Core container engine
│   │   ├── execution/            # ⭐ ADAPTIVE EXECUTION ENGINE
│   │   │   └── execution-rs/     # ✅ IMPLEMENTED
│   │   ├── container/            # Container lifecycle
│   │   │   └── driver-rs/
│   │   ├── types/                # Shared types
│   │   │   └── types-rs/
│   │   ├── phantom-utils-rs/     # Utilities
│   │   ├── bwrap-rs/             # Bubblewrap integration
│   │   ├── zygote-rs/            # Zygote spawner
│   │   ├── fragments-rs/         # Fragment management
│   │   ├── orchestrator-rs/      # Orchestration
│   │   └── task-analyzer-rs/     # Task analysis
│   │
│   ├── security/                 # Security subsystem
│   │   ├── bpf-lsm/              # BPF-LSM (Zig)
│   │   │   └── bpf-lsm-rs/       # Rust bindings
│   │   ├── seccomp/              # Seccomp (Zig)
│   │   │   └── src/seccomp.zig
│   │   ├── landlock/             # Landlock (Zig)
│   │   │   └── src/landlock.zig
│   │   ├── orchestration/        # Security coordinator
│   │   │   └── security-rs/
│   │   └── policy-dsl-rs/        # Policy DSL
│   │
│   ├── memory/                   # Memory management
│   │   ├── jemalloc/             # Jemalloc bindings (C)
│   │   ├── discipline/           # Memory discipline
│   │   │   └── memory-rs/
│   │   └── ksm/                  # KSM integration (Zig)
│   │
│   ├── storage/                  # Storage layer (uses std::fs)
│   │   ├── overlay/
│   │   │   └── overlay-rs/
│   │   ├── rootfs/
│   │   │   └── rootfs-rs/
│   │   └── storage-rs/
│   │
│   ├── monitoring/               # Observability
│   │   ├── metrics/
│   │   │   └── metrics-rs/
│   │   ├── health/
│   │   │   └── health-rs/
│   │   └── debug/
│   │       └── debug-rs/
│   │
│   └── tools/                    # Development tools
│       ├── integration-tests/
│       └── validation-c/
│
├── docs/                         # Documentation
│   ├── architecture/
│   ├── components/
│   ├── getting-started/
│   ├── migration/
│   └── security/
│
├── roadmap/                      # Project roadmap and implementation plans
│   └── IMPLEMENTATION_PLAN.md
│
├── tests/                        # Test files and benchmarks
│   ├── TEST.md                   # Testing documentation
│   └── TODO_FUTURE_TESTS.md      # Planned tests
│
├── tools/                        # Development utilities
│   ├── benchmark.sh              # Performance benchmarking
│   ├── benchmark_memory.rs       # Memory benchmark
│   └── debug_inspector.py        # Debug tool
│
├── Cargo.toml                    # Root Cargo workspace
├── CMakeLists.txt                # C build system (minimal)
└── README.md
```

## Language Distribution

| Language | Usage | Components |
|----------|-------|------------|
| **Rust** | ~80% | CLI, MCP, core engine, orchestration |
| **Zig** | ~18% | I/O fast path, memory discipline, security shims |
| **C** | ~1% | Minimal BPF shims |
| **Python/Shell** | ~1% | Tools, benchmarking scripts |

## Build System

- **Rust**: Root `Cargo.toml` workspace - `cargo build --release`
- **Zig**: `src/memory/discipline/memory-zig/build.zig` - `zig build` (memory management only)
- **C**: `CMakeLists.txt` - Minimal CMake for BPF/hardware shims

## Working Components

| Component | Path | Status |
|-----------|------|--------|
| **I/O** | Storage layer (`std::fs`, `tokio::fs`) | ~1 GB/s throughput |
| **CLI** | `src/cli/phantom-cli/` | Complete (Unified) |
| **MCP Server** | `src/mcp/` | Complete |
| **Execution Engine** | `src/core/execution/execution-rs/` | Complete |
| **Zygote Pool** | `src/core/zygote-rs/` | Complete (vfork fallback) |
| **Profile Management** | `phantom profile list/show` | Complete |
| **Warm Start** | `phantom warm --benchmark` | Complete |
| **Fragment Lifecycle** | `create/run/list/logs/destroy/stop/restart/update/inspect` | Complete |

## Notes

- **I/O**: Currently uses standard Rust I/O. Zig io_uring fast path is planned for future.
- **Zig**: Used for low-level process spawning (Zygote) and memory management via FFI.

