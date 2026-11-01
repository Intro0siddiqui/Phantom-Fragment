# Changelog

All notable changes to Phantom Fragment are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Numbers in older entries have been corrected where they were never measured. Where a
claim could not be verified it is marked `unmeasured` rather than repeated.

## [Unreleased]

### Added
- **Native cold engine** (`engine/native.rs`): user/mount/PID/IPC/UTS namespaces, network
  namespace when disabled, private root, `/proc`, `/tmp`, `/dev`, then Landlock,
  capability drop and seccomp in the command child immediately before `execve`. Default
  for image runs; ~32 ms measured.
- **`--engine auto|native|bwrap`** with classified fallback: `Unsupported` (namespace or
  mount primitive unavailable) may fall back to bwrap in `auto`; a Landlock, seccomp,
  capability or exec failure is `Fatal` and never falls back, and a profile that requires
  confinement never falls back.
- **Shared security stack** (`engine/sandbox.rs`) used by both the native engine and the
  warm mother, replacing the warm-only copy.
- **Pre-sandboxed mother fragment**: the warm mother applies cgroup, namespaces, chroot,
  tmpfs, Landlock, caps and seccomp once at pool fill; each request is a `fork` + `exec`.
- **Profile binding for warm pools**: a request whose `PHANTOM_PROFILE` differs from the
  pool's profile is a hard error instead of a silent fallback to cold.

### Changed
- **Zig 0.16 migration**: native memory and zygote libraries target the Zig 0.16 std API;
  build scripts fail fast when Zig is missing or older than 0.16.
- **Versioning**: `[workspace.package] version` is the single source of truth, so
  `phantom --version`, the workspace crates and this changelog agree.
- **BPF-LSM privilege prompt**: choosing sudo now re-execs the CLI under `sudo` with
  `HOME` preserved. `run` no longer reports BPF-LSM as "active" when no program is
  attached.

### Fixed
- **warm**: `clone3` denied by the hardened seccomp profile broke modern glibc; the
  filter now returns `ENOSYS`.
- **warm**: `warm remove` left daemons running.
- **warm**: the mother did not `chroot` into the image rootfs.
- **network-rs**: automatic loopback interface startup when creating network namespaces.
- **phantom-build**: command injection when constructing `bwrap` arguments for build
  steps.

### Removed
- **MCP server**: the integration was removed. Any `mcp` subcommand, config key or doc
  reference is stale.

## [3.1.0] - 2025-12-09

### Changed
- Documentation updated to describe standard Rust I/O. The previously claimed
  "2.2 GB/s write / 6.2 GB/s read" was never measured and has been dropped.

## [3.0.0] - 2025-11-30

### Added
- Rust + Zig implementation, replacing the Go codebase.
- CLI lifecycle commands, fragment registry, BPF capability detection, NUMA binding with
  UMA fallback, PSI monitoring.

### Changed
- Binary size: 47 MB (Go) → ~19 MB (Rust, dynamically linked). The earlier 3.6 MB figure
  was wrong.
- Cold start: measured ~32 ms on the development machine. The earlier ~7 ms figure was
  never reproduced; it is roughly `phantom --version` (9 ms) and excludes container work.

## [2.0.0] - 2025-11-15

### Added
- Zig implementations of the memory and I/O paths, with Rust FFI bindings.

### Changed
- Memory management moved from Go to Zig.

### Notes
- This release advertised an io_uring fast path with SQPOLL/IOPOLL. There is no io_uring
  code in the current tree; the I/O path is `std::fs` / `tokio::fs`.

## [1.0.0] - 2025-10-01

### Added
- Initial Go implementation: basic container isolation, seccomp, capabilities, Landlock,
  and an MCP server (since removed).

---

## Migration Notes

### From 2.x to 3.x
- Binary renamed: `phantom-fragment` → `phantom`.
- Configuration format unchanged.
- The MCP server was removed; there is no replacement protocol.

### From Go (1.x) to Rust/Zig (2.x+)
- Complete rewrite, not backwards compatible.
- New CLI interface and configuration format.
