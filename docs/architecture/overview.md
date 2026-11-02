# Technical Overview

Status: index. Last verified against `8b51686` (native cold engine), version 3.1.0.

This page is a map, not a specification. Each claim below has a document behind it; if
the two disagree, the component document is correct and this page is stale.

## What Phantom Fragment is

A rootless container runtime for Linux. It runs OCI images as process trees in private
kernel namespaces, applies a security stack to the process that actually runs untrusted
code, and needs no root, no image daemon and no per-container supervisor.

The three primitives:

- **namespaces** — what the process can see,
- **Landlock** — which files it can touch,
- **seccomp** — which syscalls it can make,

plus capability dropping and `no_new_privs` so those restrictions survive `execve`.

## Measured, on one machine

Release build, 14-core Ultra 5 225H, kernel 7.3.0. `alpine` cached locally, command
`true`, 40 samples after 3 warm-ups, median (min in parentheses):

| Path | Time |
|---|---|
| `phantom --version` (no container work) | 1.2 ms |
| cold `run alpine true` (native engine) | **3.1 ms** (2.7) |
| warm `run --warm alpine true` | **3.1 ms** (2.8) |
| rootless `podman run --rm alpine:latest true` | **224 ms** (210) |
| direct daemon RPC `Exec` | 2–3 ms |

Binary: ~19 MB, dynamically linked (glibc, OpenSSL, libseccomp).

So cold is ~72× faster than rootless podman, and warm is the same as cold within noise.
Two changes brought cold down and, in doing so, removed warm's margin:

- The image puller used to build a registry client and open the image store on every run,
  even for an already-extracted rootfs (~23 ms). That work now happens only inside
  `pull()`, so cold fell from 39 ms.
- The CLI built a multi-thread tokio runtime before parsing the command (one worker per
  core, ~1.4 ms measured in isolation and more inside the 398-crate binary). It now runs
  on a current-thread runtime; the warm daemon still builds its own multi-thread runtime.
  `--version` fell from 6.9 ms and cold from 14 ms.

What is left of cold is process startup plus the sandbox itself. In the same session,
`phantom --version` measures 1.2 ms, so ~1.9 ms covers image lookup, `unshare` with
uid/gid maps, mounts, `chroot`, Landlock, capability drop, seccomp, `execve` and the
command. Warm replaces that with a pool acquire, a socket round trip and a `fork` inside
the mother, which costs the same or slightly more for single commands. Under a 16-command
burst, eliminating hot-path fsync and lock contention allows warm to edge ahead (12.6 ms
cold versus 11.8 ms on a one-slot warm pool, 10.9 ms on four). See
[warm-exec-v2](components/warm-exec-v2.md) for the three warm methods and what is
actually implemented.


## How a run is dispatched

```text
phantom run <image> <cmd>
├── --wasm / *.wasm   -> Wasmtime (wasm-rs)
├── --warm            -> listener -> mother fragment -> fork + exec
├── --zygote          -> Zig pool, mount ns + pivot_root (no seccomp/Landlock/caps)
├── --proot           -> proot emulation (no namespaces)
├── --overlay         -> fuse-overlayfs + bwrap
├── --runtime <r>     -> hand the bundle to an OCI runtime
├── --root            -> bwrap as uid 0 (needs sudo)
└── default           -> native engine (full stack)
                         bwrap fallback (namespaces only, never for a confined profile)
```

`--engine auto|native|bwrap` selects the backend explicitly. `auto` falls back to bwrap
only when the host cannot provide a namespace or mount primitive; a Landlock, seccomp,
capability or exec failure is fatal and never falls back.

## Documents

| Document | Covers |
|---|---|
| [native-executor](components/native-executor.md) | the default cold engine: process layout, mounts, verified behaviour, gaps |
| [warm-exec-v2](components/warm-exec-v2.md) | what warm is, the three methods, protocol plan, known limitations |
| [adaptive-execution](components/adaptive-execution.md) | `execution-rs`: mode selection and the host fork-exec path |
| [memory-discipline](components/memory-discipline.md) | the Zig buffer pool, KSM and NUMA |
| [policy-dsl](components/policy-dsl.md) | YAML policy -> seccomp/Landlock rules |
| [CLI reference](../usage/cli-reference.md) | every subcommand |
| [configuration](../CONFIGURATION_GUIDE.md) | `phantom.toml` and profiles |
| [migration](../migration/from-docker.md) | coming from Docker/Podman |
| [testing](../testing/README.md) | how to run the suites |

## What is not built

Stated here so no other page has to imply otherwise:

- `create` / `run -d` / `exec` / `attach` are not real containers yet.
- Warm serves one command per fragment at a time; interactive runs use a client-owned pty.
- The cold path creates no cgroup, so profile memory/CPU limits are unenforced.
- BPF-LSM is not attached to image runs.
- Pulled images carry no `ENTRYPOINT`/`CMD`/`USER`; only `phantom build` images do.
- No volumes, no checkpoint/restore, no image export/import.
