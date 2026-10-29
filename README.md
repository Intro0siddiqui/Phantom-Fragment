# Phantom Fragment

A low-latency, rootless container runtime with measured cold starts and layered kernel sandboxing.

## 🚀 Project Overview

**Phantom Fragment** is a specialized execution engine designed to bridge the gap between native process performance and container isolation. It is written primarily in **Rust**, with **Zig** used for low-level process and memory components, and it avoids a long-running daemon for normal cold execution.

### Core Value Proposition:
- **Measured Performance**: ~32 ms cold start on the reference machine, versus ~330 ms for Docker (~10× faster).
- **Small Footprint**: ~19 MB binary, dynamically linked against glibc, OpenSSL and libseccomp; no daemon memory when no warm daemon is running.
- **Layered Security**: Seccomp, Landlock, cgroups v2 and capability dropping by default; optional BPF-LSM on kernels that support it (requires root).
- **Rootless by Design**: Normal execution uses user namespaces and `bubblewrap`, without elevated privileges.

## 📊 Actual Performance (Verified)

*System: Intel i3-6006U @ 2.00GHz, Linux 6.18.9, 7.5GB RAM*

> ⚠️ **BETA WARNING: Warm Start Feature**
>
> Warm start is **beta/experimental** and not production-ready:
> - stdout/stderr from the workload are currently discarded (D2), and there is no stdin or PTY support.
> - The daemon still re-applies sandbox setup per request (Phase 3 is in progress).
> - It may fall back to cold start automatically if a warm fragment is unavailable.

| Metric | Phantom Fragment | Docker | Notes |
|--------|------------------|--------|-------|
| **Cold Start** | **~32 ms (measured)** | ~330 ms | **~10× faster** |
| **Warm Start (Beta/Experimental)** | **~37–40 ms before the Phase 3 rewrite** | — | Target floor is ~12 ms; the CLI alone costs ~9 ms, so shell-level warm runs cannot go below that |
| **Binary Size** | **~19 MB** | — | Dynamically linked: glibc, OpenSSL, libseccomp |
| **Daemon RSS** | **0 MB cold / ~25 MB per warm daemon** | — | Warm daemons are started on demand |

## 🛠️ System Architecture

Phantom Fragment utilizes a tiered isolation model, selecting the optimal execution path based on the workload's risk profile:

1. **Zygote Engine (Zig)**: An experimental pre-forked process pool targeting low-latency spawns. It is **beta**, and it cannot apply seccomp or Landlock; when a security policy is requested, `--zygote` silently falls back to normal execution.
2. **Adaptive Execution (Rust)**: Orchestrates namespaces, cgroups v2, and hardware isolation (NUMA/CPU affinity).
3. **Kernel Sentry (eBPF)**: Optional BPF-LSM hooks (kernel 5.7+ and `CAP_SYS_ADMIN`/root required) add kernel-boundary checks; without them the runtime applies no BPF-LSM policy.
4. **Filesystem Sandbox (Landlock)**: Fine-grained, path-based access control that follows the process even across namespace boundaries.

## ✅ Working Features

- **OCI Compatibility**: Full support for pulling and executing standard images (Alpine, Ubuntu, etc.) from Docker Hub.
- **Rootless Execution**: Leverages `bubblewrap` and user namespaces for secure, non-privileged operation.
- **Security Stack**: Seccomp and Landlock with graceful degradation for older kernels.
- **Hardware Isolation**: Native NUMA node binding and CPU affinity management.
- **WASM Support**: Native WebAssembly execution mode using Wasmtime/WASI.

## 🚧 Beta / Partial Features

- **Warm Fragments (Beta)**: Pre-warmed daemon processes for faster startup. Workload output is discarded, there is no stdin/PTY, and sandbox setup is re-applied per request (Phase 3 in progress); may fall back to cold start.
- **Zygote Pool (Beta)**: `phantom run --zygote` uses a pre-forked pool, but it cannot apply seccomp or Landlock and silently falls back to normal execution when a security policy is requested.
- **BPF-LSM (Partial)**: Optional and requires kernel 5.7+ plus `CAP_SYS_ADMIN` (root); it degrades to no BPF-LSM enforcement otherwise. The unified privilege prompt can suggest a sudo re-run, but it does not elevate yet.

## ⚡ Quick Start

### 🚀 One-Line Installation

```bash
# Install latest release system-wide (downloads pre-built binary)
curl -fsSL https://raw.githubusercontent.com/Intro0siddiqui/Phantom-Fragment/main/install.sh | sudo bash

# Or from Codeberg
curl -fsSL https://codeberg.org/Intro0siddiqui/Phantom-Fragment/raw/branch/main/install.sh | sudo bash

# User-only installation (no sudo required)
curl -fsSL https://raw.githubusercontent.com/Intro0siddiqui/Phantom-Fragment/main/install.sh | bash -s -- --install-dir $HOME/bin
```

### 📦 Manual Installation

```bash
# Clone repository
git clone https://github.com/Intro0siddiqui/Phantom-Fragment
cd Phantom-Fragment

# Run installation script (downloads pre-built binary or builds from source)
# System-wide (recommended):
sudo ./install.sh

# User-only:
./install.sh --install-dir $HOME/bin

# Binary is installed globally
phantom --version
```

### 🛠️ Build from Source

Requires **Rust 1.99.1** and **Zig 0.16+**, plus the libseccomp development
headers (`libseccomp-dev` on Debian/Ubuntu, `libseccomp-devel` on Fedora/RHEL).

```bash
git clone https://github.com/Intro0siddiqui/Phantom-Fragment
cd Phantom-Fragment
cargo build --release

# Binary: target/release/phantom
./target/release/phantom --version
```

### 💡 Usage Examples

```bash
# Run a command in an isolated fragment
phantom run alpine echo "Hello from Phantom!"

# Interactive shell with standard sandboxing
phantom run --profile sandbox ubuntu bash

# Search Docker Hub
phantom search ubuntu

# Build from Fragmentfile
phantom build -t my-image:latest .

# Check version
phantom --version  # Shows: phantom 3.1.0
```

## 🤖 AI Agent Integration

Phantom Fragment ships an agent skill at [`.opencode/skills/phantom/SKILL.md`](.opencode/skills/phantom/SKILL.md): a terse Docker-to-`phantom` command mapping that agents load on demand. There is no separate server binary — agents drive the same CLI you do.

## 📖 Documentation

- [CLI Reference](docs/usage/cli-reference.md) - Complete command guide
- [Implementation Guide](docs/IMPLEMENTATION_GUIDE.md) - Deep dive into memory and I/O optimizations
- [Architecture Overview](docs/architecture/overview.md) - Detailed system design

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
