# Testing

Status: current. Last verified against `8b51686`.

## Layout

| Suite | Location | Count |
|---|---|---|
| CLI unit tests | `src/cli/phantom-cli/src/**` (`#[cfg(test)]`) | 66 |
| Integration tests | `src/tools/integration-tests/src/` | ~24 |
| Per-crate unit tests | `src/core/*`, `src/security/*`, `src/storage/*` | varies |
| Doctests | workspace | few |

The integration crate has four areas: `execution_integration_tests`, `security_integration_tests`,
`storage_integration_tests`, `system_tests`, plus `test_helpers`.

## Running

```bash
# one crate
cargo test -p phantom --bin phantom
cargo test -p security-rs
cargo test -p integration-tests

# a single test
cargo test -p phantom --bin phantom engine_selection

# with output
cargo test -p phantom --bin phantom -- --nocapture
```

**Do not run `cargo test --workspace` on a normal box.** `execution-rs` tests initialise
the zygote pool and hang in environments where the pool cannot be created. CI uses
`cargo nextest run --locked --workspace` with a `ci` profile, which handles this; a local
`--workspace` run does not. Run the CLI suite and the integration crate instead:

```bash
cargo test -p phantom --bin phantom -- --test-threads=2
cargo test -p integration-tests
```

`--test-threads=2` is deliberate: several tests fork and one of them manipulates the
process's own namespaces.

## Requirements

- Zig 0.16 on `PATH` — `memory-rs` and `zygote-rs` build Zig static libraries in
  `build.rs`.
- `libseccomp` headers. On a distro without `libseccomp-devel`, point the linker at the
  runtime library:

  ```bash
  mkdir -p /tmp/opencode/lib
  ln -sf /usr/lib/libseccomp.so.2 /tmp/opencode/lib/libseccomp.so
  export RUSTFLAGS="-L native=/tmp/opencode/lib"
  ```

- Unprivileged user namespaces (`/proc/sys/kernel/unprivileged_userns_clone` = 1) for the
  namespace and chroot tests. Tests that need Landlock or BPF-LSM self-skip when the
  kernel does not provide them.
- No root, no network access and no bubblewrap are required.

## What the tests do and do not cover

Covered:

- uid/gid map formatting, profile → seccomp mapping, engine selection, fallback
  classification (unit).
- chroot visibility, `/proc` showing the reaper as PID 1, `/tmp` as tmpfs, no route with
  networking disabled, hardened write denied, sandbox write allowed, signal forwarding,
  exit-code propagation (integration, host with userns).
- storage round-trips and compression.
- warm daemon protocol, health probe, profile mismatch.

Not covered:

- A live image with a non-root `USER` (no such image was available during development).
- PTY behaviour on the warm path (no PTY exists; resize and full-screen programs are unsupported).
- BPF-LSM attachment (requires root and a BPF-capable kernel).
- Real password-entered `sudo` elevation.
- cgroup limits on the cold path (no cgroup is created).

## CI

`.github/workflows/ci.yml`:

1. `cargo build --release --locked --workspace`
2. `cargo nextest run --locked --workspace --profile ci --no-fail-fast`
3. `cargo test --locked --workspace --doc`
4. `cargo fmt --all --check` and `zig fmt --check $(git ls-files '*.zig')`
5. `cargo clippy --locked --workspace --all-targets -- -D warnings`

Warnings are errors in CI; do not add `#[allow]` to get a build through.

## Adding a test

- Unit tests live in the same file as the code, in `#[cfg(test)] mod tests`.
- Kernel-dependent tests must self-skip, not fail, when the feature is unavailable —
  CI runners rarely have Landlock ABI 8 or BPF-LSM.
- If a test forks, restore signal masks in both branches; the existing suites do this
  before `fork()` and after.
