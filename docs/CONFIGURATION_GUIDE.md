# Configuration

Status: current. Last verified against `8b51686`.

Profiles are the only thing the config file configures. A profile is a named bundle of
isolation level, network, write access and hardware hints; `phantom run -p <name>` selects
one.

## File location

`phantom` reads, in order:

1. `$PHANTOM_CONFIG`, if set (this file wins outright — the others are not merged),
2. `~/.phantom/config.toml`,
3. `/etc/phantom/config.toml`.

Missing files are not an error: the built-in profiles are always available. `--config
<path>` on a subcommand overrides the search.

There is no project-local `phantom.toml` lookup.

## Built-in profiles

| Name | isolation | network | file_write | Notes |
|---|---|---|---|---|
| `sandbox` | `sandbox` | yes | yes | default for cold runs |
| `hardened` | `hardened` | no | no | read-only rootfs, hardened seccomp |
| `wasm` | `wasm` | n/a | n/a | Wasmtime, WASI capabilities |

`direct` is not a profile in the config: it is a name the CLI special-cases to mean "no
confinement, run on the host", and it maps to `Sandbox` mode with no policy applied.

## Format

```toml
[profiles.vault]
isolation = "hardened"
network = false
file_write = false
memory_mb = 256
cpu_count = 1

[profiles.pinned]
isolation = "sandbox"
network = false
file_write = true
cpu_affinity = [0, 1, 2, 3]
numa_node = 0
```

## Options

| Key | Type | Default | Meaning |
|---|---|---|---|
| `isolation` | string | `sandbox` | `sandbox`, `hardened`, `wasm`, `direct`. Anything else is treated as `sandbox` |
| `network` | bool | `true` | false ⇒ new network namespace with no route |
| `file_write` | bool | `true` | false ⇒ read-only rootfs and no Landlock write rule |
| `memory_mb` | int | unset | memory limit. **Not enforced on the cold path** — no cgroup is created |
| `cpu_count` | int | unset | CPU count hint. Not enforced |
| `cpu_affinity` | list of int | unset | pins the command to those cores (`sched_setaffinity`) |
| `numa_node` | int | unset | binds the command to a NUMA node (`mbind`) |
| `seccomp_rules` | list of tables | unset | extra syscall rules, applied on top of the profile's seccomp profile |

Unknown keys are **silently ignored** — `Config` does not set `deny_unknown_fields`, so a
typo in a key name produces a default value rather than an error. Check `phantom profile
list` output if a setting appears to have no effect.

## What a profile actually controls

| Field | Cold (native) | Warm mother |
|---|---|---|
| `isolation` | selects the seccomp profile and the Landlock ruleset | bound at pool creation; a mismatch is a hard error |
| `network` | `--unshare-net` or not | same, fixed at pool creation |
| `file_write` | Landlock write rule + read-only rootfs | same |
| `cpu_affinity`, `numa_node` | applied in the command child | applied to the mother; inherited |
| `memory_mb`, `cpu_count` | **not enforced** | enforced only if the host delegates a cgroup |

## Using profiles

```bash
phantom run -p vault alpine sh
phantom run -p hardened alpine sh
phantom profile list
```

`phantom run -p hardened` and `phantom run --profile hardened` are the same flag.

A warm pool binds its profile at creation:

```bash
phantom warm create alpine 3 -p hardened
phantom run --warm -p sandbox alpine true    # hard error, not a downgrade
```
