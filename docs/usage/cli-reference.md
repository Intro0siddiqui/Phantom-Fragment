# CLI Reference

Status: current for `phantom run`. `phantom <command> --help` is authoritative — this
page documents the flags whose behaviour is not obvious, not every flag.

## Commands

| Command | Purpose |
|---|---|
| `run` | execute a command in a fragment (image or host command) |
| `create` | register a fragment (not a container yet — see below) |
| `list` | list registered fragments |
| `logs` | read `~/.phantom/logs/<name>.log` |
| `destroy` | remove a fragment (module: `commands/delete.rs`) |
| `stop` | stop a running fragment |
| `restart` | restart a fragment |
| `inspect`, `status`, `monitor` | fragment detail, summary, live view |
| `update` | change a fragment's configuration |
| `health` | system health checks |
| `metrics` | Prometheus metrics; optionally serve them |
| `clean` | remove rootfs images and cached state |
| `images`, `search` | local images; Docker Hub search |
| `build` | build an image from a Fragmentfile |
| `migrate` | import from Docker/Podman |
| `network` | `list`, `up`, `add-ip`, `create-veth` |
| `volume` | volume management |
| `profile` | list and inspect profiles |
| `warm` | warm pool: `create`, `list`, `remove`, benchmark mode |
| `security` | `scan` an image; `explain` the model |
| `registry` | registry credentials/endpoints |
| `debug` | inspection helpers |
| `benchmark` | run the performance suite |
| `explain` | print the security model |

## `phantom run`

```bash
phantom run [OPTIONS] IMAGE [COMMAND...]
phantom run [OPTIONS] COMMAND...          # no image: host fork-exec
```

| Flag | Short | Meaning |
|---|---|---|
| `--profile <p>` | `-p` | `direct`, `sandbox`, `hardened`, `wasm`. Defaults to `sandbox` for cold runs; the warm path uses the pool's bound profile |
| `--engine <e>` | | `auto` (default), `native`, `bwrap`. Image runs only |
| `--network` | `-n` | keep the host network namespace and resolv.conf |
| `--root` | `-r` | real uid 0 via bwrap (requires sudo) |
| `--proot` | | proot emulation, no namespaces |
| `--overlay` | | fuse-overlayfs + bwrap |
| `--runtime <r>` | | hand the bundle to an OCI runtime |
| `--wasm` | | run a `.wasm` module via Wasmtime |
| `--warm` | | use a warm pool (beta; pty for interactive runs, one command per fragment) |
| `--zygote` | | use the Zig spawn pool (skipped if a policy is set) |
| `--no-pull` | | do not pull the image if it is missing (unused by `--warm`: a warm fragment already owns its rootfs) |
| `--verify` | | verify layer SHA256 on pull (unused by `--warm`, which pulls nothing) |
| `--config <path>` | | alternate config file |

### Engine selection

`--engine auto` (default) uses the native sandbox and falls back to bubblewrap **only**
when the host cannot provide a namespace or mount primitive. A Landlock, seccomp,
capability or `execve` failure is fatal and never falls back, and a profile that requires
confinement (`hardened`, `file_write = false`, non-default seccomp) never falls back
either.

`--engine native` cannot be combined with `--proot`, `--overlay`, `--runtime`, `--root`
or `--wasm`; those are rejected rather than silently ignored.

### Examples

```bash
phantom run alpine sh                        # native engine, sandbox profile
phantom run -p hardened alpine sh            # no writes, no network
phantom run -n alpine apk update             # network enabled
phantom run --engine bwrap alpine sh         # force the fallback engine
phantom run --warm alpine true               # warm pool (exit code only)
phantom run --wasm app.wasm                  # WASM module
phantom run sh -c 'uname -a'                 # no image: host fork-exec
```

## `phantom create` — read this before using it

`create` is **not** a container yet. It fork-execs `sleep 999999999` on the host with
seccomp, Landlock and capabilities applied to the child, but with no namespaces and no
rootfs, then records that pid in `~/.phantom/registry.json`. There is no `exec` into it
and no `-d`/`--name` on `run` to produce one. Treat `create`/`list`/`destroy` as registry
bookkeeping until the lifecycle work lands.

## `phantom warm`

```bash
phantom warm create <image> [size] [-p profile]   # build a pool
phantom warm list                                 # pools and their state
phantom warm remove <image>                       # tear down (and kill the daemon)
phantom warm                                      # benchmark mode
```

`-p` binds the profile at pool creation. A later `phantom run --warm -p <other>` is a hard
error, not a silent downgrade to cold.

## Exit codes

`run` propagates the command's exit status. A failure inside the sandbox setup reports
`127` (the command was never executed). Signals are forwarded, so a `SIGTERM` to the CLI
exits `143`.

## Environment

`PHANTOM_PROFILE` carries the requested profile to the warm daemon, which strips it
before exec. `HOME` is preserved across the sudo re-exec used for BPF-LSM.
