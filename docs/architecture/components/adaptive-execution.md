# Adaptive Execution Modes

Status: implemented. Last verified against `8b51686`.

`execution-rs` answers two questions: **which mode** a workload should run in, and
**how to spawn it** once the mode is chosen. It is not the confinement layer — that
lives in `engine/sandbox.rs` and is shared with the native cold engine and the warm
mother. `execution-rs` decides, then either hands off or applies the stack itself on the
host fork-exec path.

## Modes

```rust
// src/core/execution/execution-rs/src/lib.rs
pub enum ExecutionMode {
    Sandbox,   // default
    Hardened,  // seccomp + no network + read-only rootfs
    Wasm,      // Wasmtime/WASI
}
```

The modes are not three isolation technologies. `Sandbox` and `Hardened` run the same
native sandbox with a different `ChildPolicy`; `Wasm` is a different runtime entirely.

| Mode | Runtime | Landlock | seccomp profile | Network | Rootfs |
|---|---|---|---|---|---|
| `Sandbox` | native namespaces | yes, write allowed where the profile permits | `default` | on unless `-n` | writable |
| `Hardened` | native namespaces | yes, no write | `hardened` (denies `clone3` with `ENOSYS`) | off | read-only |
| `Wasm` | Wasmtime | n/a (WASI capability model) | `strict` mapping exists, not applied to a process | n/a | n/a |

## Mode selection

```rust
pub fn select_mode(&self, risk: &RiskProfile, _perf: &PerformanceProfile) -> ExecutionMode {
    if risk.untrusted_source || (risk.privileged_ops && risk.network_access) {
        return ExecutionMode::Hardened;
    }
    if risk.untrusted_source && !risk.privileged_ops {
        return ExecutionMode::Wasm;
    }
    self.default_mode
}
```

`RiskProfile` carries `network_access`, `file_write`, `privileged_ops` and
`untrusted_source`.

**Known defect:** the second branch is unreachable. Anything with `untrusted_source`
already returned `Hardened` on the first line, so `Wasm` can never be selected
automatically. In practice `Wasm` is only reachable by asking for it — a `wasm` profile or
a `.wasm` command. Either the first condition should exclude `untrusted_source` alone, or
the Wasm branch should go; this is a decision, not an oversight to paper over.

`PerformanceProfile` is accepted but unused (note the `_perf`). Mode is decided by risk
only.

## Spawning

```rust
pub fn spawn(
    &self,
    mode: ExecutionMode,
    command: &str,
    hardware: Option<&HardwareProfile>,
    security_policy: Option<&SecurityPolicy>,
) -> Result<i32, PhantomError>
```

- `Sandbox | Hardened` → `spawn_sandboxed`.
- `Wasm` → `spawn_wasm` (Wasmtime via `wasm-rs`; `max_memory_mb` from the hardware
  profile).

`spawn_sandboxed` has two paths:

1. **Zygote fast path**, taken only when `security_policy` is `None`. The zygote child
   applies namespace isolation only, so seccomp/Landlock/capabilities cannot be installed
   there.
2. **Fork-exec**, which applies the `SecurityPolicy` and the hardware profile in the child
   immediately before `execve`.

This is a **host** fork-exec: namespaces and a rootfs are *not* created here. For image
runs the CLI takes the native engine instead. This path is what `phantom run <command>`
(no image) uses.

`apply_hardware_isolation` applies CPU affinity and the NUMA node binding, both through
the Zig memory crate. Cgroup limits are applied separately, after the child exists, and
only where the host delegates a cgroup.

## Where the stack is actually applied

| Path | Who applies Landlock / caps / seccomp |
|---|---|
| `phantom run <image>` (default) | `engine/native.rs` in the command child, just before `execve` |
| `phantom run --warm` | the mother, once at pool fill; each request is a plain `fork` + `exec` |
| `phantom run <command>` (no image) | `execution-rs::spawn_sandboxed` in the forked child |
| `--zygote` with a policy | not applied — the CLI warns and takes the normal path |

## Gaps

- `Wasm` is unreachable through automatic selection (above).
- `Wasm` gets no Landlock and no seccomp; it relies on WASI capabilities.
- The host fork-exec path has no namespaces, so it isolates syscalls and files but not
  what the process can see.
- `PerformanceProfile` is dead weight today.
