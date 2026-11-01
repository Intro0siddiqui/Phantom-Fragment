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
`true`, 30 samples after 3 warm-ups, median (min in parentheses):

| Path | Time |
|---|---|
| `phantom --version` (no container work) | 7 ms |
| cold `run alpine true` (native engine) | **14 ms** (13) |
| warm `run --warm alpine true` | **12 ms** (11) |
| rootless `podman run --rm alpine:latest true` | **342 ms** (320) |
| direct daemon RPC `Exec` | 2–3 ms |

Binary: ~19 MB, dynamically linked (glibc, OpenSSL, libseccomp).

So cold is ~24× faster than rootless podman and warm is ~28× faster, with warm ~1.2×
faster than cold. Warm used to look ~3× faster because cold built a registry client and
opened the image store on every run, even for an extracted rootfs (~23 ms). That work now
happens only inside `pull()`, so cold fell to 14 ms and warm's remaining saving is the
per-run sandbox setup (~6 ms) minus the socket round trip. See
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
