# Phantom Fragment Roadmap

Status: current for *unbuilt* work, historical for anything already shipped. Where this
file and a component document disagree, the component document wins — in particular
[`docs/architecture/components/warm-exec-v2.md`](../docs/architecture/components/warm-exec-v2.md)
is authoritative for warm execution.

## Quick reference

| Topic | Status | Summary |
|---|---|---|
| Hybrid model (warm / zygote / snapshots) | 🚧 Partial | Mother fragment works but is slower than cold; zygote pool is a spawn accelerator; snapshots not started |
| io_uring fastpath | ❌ Not implemented | I/O is `std::fs` / `tokio::fs` |
| Zig proactor I/O | ❌ Not implemented | Not built |
| KVM backend | ❌ Not implemented | Process isolation used instead |
| Wasm | ✅ Working | Wasmtime/WASI, no Landlock or seccomp |
| Network CLI | ✅ Working | `network list/up/add-ip/create-veth` |
| Compose | ❌ Not implemented | No parser, no lifecycle |
| Container lifecycle (`create`/`-d`/`exec`/`attach`) | ❌ Not implemented | `create` currently registers a host `sleep` with no namespaces |

## Implemented

### Wasm execution
- `src/core/wasm-rs/`, dispatched from `execution-rs::spawn_wasm`.
- Wasmtime with WASI capabilities and a configurable memory limit.
- Usage: `phantom run --wasm myapp.wasm` (or pass a `.wasm` path).
- Caveat: no Landlock and no seccomp; isolation is the WASI capability model.

### Network CLI
- `src/cli/phantom-cli/src/commands/network.rs` over `network-rs`.
- `network list`, `up`, `add-ip`, `create-veth`.
- Loopback is brought up automatically inside a new network namespace.

### Zygote pool
- `src/core/zygote-rs/src/zygote.zig`: socketpair IPC, pre-forked processes,
  `unshare(CLONE_NEWNS)` + bind rootfs + `pivot_root` + `execve`.
- Sub-millisecond spawn in benchmarks. It is a spawn accelerator, not a sandbox: no user
  namespace, no PID/net namespace, no seccomp, no Landlock, no capability drop, so
  `run --zygote` skips it whenever a policy is requested.
- It is **not** frozen-state activation. Each request still forks a grandchild.

## Partial

### Warm / mother fragments
- Pre-sandboxed mother: cgroup (when delegated), user namespace, mount namespace, chroot,
  tmpfs, Landlock, caps, seccomp, `setsid`, health probe, `PR_SET_PDEATHSIG`.
- Profile bound at pool creation; a mismatched request is a hard error.
- Open: no semi mother, no frozen zygotes.
- Measured 11 ms end to end, versus 39 ms cold and 378 ms rootless podman (release,
  30 samples, median).

### Artifact / cache warm
- Image layers, the extracted rootfs and the build cache are reused by later cold runs.
- No compiled-artifact or executed-work cache; no measurement of the latency drop.

## Not implemented

### io_uring I/O fastpath
Planned: Zig io_uring, 8 GB/s target, sub-10 µs latency, zero-copy. Not built; the I/O
path is standard Rust. The previously quoted "2.2 GB/s write, 6.2 GB/s read" was never
measured and has been removed.

### KVM backend
Planned: Zig KVM VMM, VirtIO block/network, <50 ms VM cold start. Not built; process
isolation (namespaces, seccomp, Landlock) is used instead.

### Phantom Compose
Planned: `phantom-compose.yml`, `up`/`down`/`ps`. No implementation exists.

### Memory trimming for the pool
Planned: ~5 MB resident target for an idle pool, `madvise(MADV_DONTNEED)` in the child
loop. `trim_idle_memory` exists in `zygote.zig`; nothing measures the target.

### Snapshot foundations
Planned: process state resurrection, `MAP_FIXED` remapping, memory overlay. This is the
prerequisite for real frozen-state zygotes. Not started.

## Execution tiers today

| Tier | Command | Status | Measured |
|---|---|---|---|
| Cold | `phantom run alpine <cmd>` | ✅ Working, default | 39 ms |
| Warm | `phantom run --warm alpine <cmd>` | 🚧 Beta | 11 ms |
| Zygote | `phantom run --zygote alpine <cmd>` | 🚧 Beta, falls back | <1 ms spawn in benchmarks, no security stack |

## How to read the markers

- ✅ works, and is exercised
- 🚧 partially works, with the gaps stated next to it
- ❌ planned, not built

Plans for topics that were consolidated here have been removed; their detail is in git
history. Do not add a status marker to this file without a corresponding claim you can
point at in the code.
