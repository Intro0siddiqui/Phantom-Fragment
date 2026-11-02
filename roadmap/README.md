# Phantom Fragment Roadmap

Status: current for *unbuilt* work, historical for anything already shipped. Where this
file and a component document disagree, the component document wins — in particular
[`docs/architecture/components/warm-exec-v2.md`](../docs/architecture/components/warm-exec-v2.md)
is authoritative for warm execution.

## Quick reference

| Topic | Status | Summary |
|---|---|---|
| Hybrid model (warm / resume) | 🚧 Partial | Mother fragment works and matches cold latency, with no per-run margin; fragment save/resume is design only, and `--zygote` is an unrelated pre-fork spawn accelerator |
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

### Pre-fork spawn pool (`--zygote`)
- `src/core/zygote-rs/src/zygote.zig`: socketpair IPC, pre-forked processes,
  `unshare(CLONE_NEWNS)` + bind rootfs + `pivot_root` + `execve`.
- Sub-millisecond spawn in benchmarks. It is a spawn accelerator, not a sandbox: no user
  namespace, no PID/net namespace, no seccomp, no Landlock, no capability drop, so
  `run --zygote` skips it whenever a policy is requested.
- The name is historical. It has nothing to do with fragment save/resume, and it is not
  frozen-state activation: each request still forks a grandchild.

## Partial

### Warm / mother fragments
- Pre-sandboxed mother: cgroup (when delegated), user namespace, mount namespace, chroot,
  tmpfs, Landlock, caps, seccomp, `setsid`, health probe, `PR_SET_PDEATHSIG`.
- Profile bound at pool creation; a mismatched request is a hard error.
- Open: no semi mother.
- Measured 3.1 ms end to end, the same as cold and ~72× faster than rootless podman
  (release, 40 samples, median). Warm has no margin left on single runs: the image stack
  no longer runs on the cold path, and the CLI now starts on a current-thread runtime.
  Under a burst, removing hot-path metadata lock contention and fsync gives warm a slight
  edge (16 simultaneous commands: 12.6 ms cold vs 11.8 ms on a one-slot pool, 10.9 ms on four).

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
loop. `trim_idle_memory` exists in the pre-fork pool (`zygote.zig`); nothing measures the target.

### Fragment save / resume (sessions)
Design only; see
[`warm-exec-v2`](../docs/architecture/components/warm-exec-v2.md#not-a-warm-method-fragment-save--resume).
Three rungs: live + `attach` (blocked on D5, one command per fragment at a time),
`freeze` (`cgroup.freeze`/`SIGSTOP`), and checkpoint/restore (CRIU, the only rung that
survives a reboot). It is a persistence feature, not a faster start. Not started: no
attach, no freeze, no checkpoint.

## Execution tiers today

| Tier | Command | Status | Measured |
|---|---|---|---|
| Cold | `phantom run alpine <cmd>` | ✅ Working, default | 3.1 ms |
| Warm | `phantom run --warm alpine <cmd>` | 🚧 Beta | 3.1 ms single run (no margin over cold); 11.8 ms (pool 1) / 10.9 ms (pool 4) for a 16-command burst vs 12.6 ms cold |

Two tiers only. Fragment save/resume is a persistence feature, not a tier, and
`--zygote` is a pre-fork spawn accelerator (<1 ms spawn in benchmarks, no security
stack, skipped when a policy is set) rather than a start tier of its own.

## How to read the markers

- ✅ works, and is exercised
- 🚧 partially works, with the gaps stated next to it
- ❌ planned, not built

Plans for topics that were consolidated here have been removed; their detail is in git
history. Do not add a status marker to this file without a corresponding claim you can
point at in the code.
