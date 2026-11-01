# Phantom Fragment

A low-latency, rootless container runtime with measured cold starts and layered kernel sandboxing.

## 🚀 Project Overview

**Phantom Fragment** is a specialized execution engine designed to bridge the gap between native process performance and container isolation. It is written primarily in **Rust**, with **Zig** used for low-level process and memory components, and it avoids a long-running daemon for normal cold execution.

### Core Value Proposition:
- **Measured Performance**: ~32 ms cold start on the reference machine, versus ~330 ms for Docker (~10× faster).
- **Small Footprint**: ~19 MB binary, dynamically linked against glibc, OpenSSL and libseccomp; no daemon memory when no warm daemon is running.
- **Layered Security**: The native cold engine and the warm path both apply seccomp, Landlock and capability dropping; only the warm path adds cgroups v2. The bubblewrap fallback applies namespace isolation only and is never used for a profile that requires confinement. BPF-LSM is optional, requires root, and is not attached to image fragments yet.
- **Rootless by Design**: Normal execution uses user namespaces and a native sandbox, with `bubblewrap` as a fallback, without elevated privileges.

## 📊 Actual Performance (Verified)

*System: Intel Core Ultra 5 225H (14 threads), Linux 7.3.0, release build, `alpine` cached, command `true`, 30 samples, median*

> ⚠️ **BETA WARNING: Warm Start Feature**
>
> Warm start is **beta/experimental** and not production-ready:
> - stdin/stdout/stderr work; interactive runs get a client-owned pty (raw mode, window resize).
> - Sandbox setup is applied once, when the pool is created; a request only forks and execs.
> - A fragment serves one command at a time, and it may fall back to cold start if no slot is free.

| Metric | Phantom Fragment | Podman (rootless) | Notes |
|--------|------------------|-------------------|-------|
| **Cold Start** | **39 ms (measured)** | 378 ms | **~10× faster** |
| **Warm Start (Beta/Experimental)** | **11 ms (measured)** | 378 ms | **~34× faster**; ~3.5× faster than cold |
| **Binary Size** | **~19 MB** | — | Dynamically linked: glibc, OpenSSL, libseccomp |
| **Daemon RSS** | **0 MB cold / ~25 MB per warm daemon** | — | Warm daemons are started on demand |

Docker was not measured on this machine; podman is the measured comparison. Numbers move
with image cache state, so treat the ratios as the signal, not the milliseconds.

## 🛠️ System Architecture

Phantom Fragment utilizes a tiered isolation model, selecting the optimal execution path based on the workload's risk profile:

1. **Zygote Engine (Zig)**: An experimental pre-forked process pool targeting low-latency spawns. It is **beta**, and it cannot apply seccomp or Landlock; when a security policy is requested, `--zygote` silently falls back to normal execution.
2. **Adaptive Execution (Rust)**: Orchestrates namespaces, cgroups v2, and hardware isolation (NUMA/CPU affinity).
3. **Kernel Sentry (eBPF)**: Optional BPF-LSM hooks (kernel 5.7+ and `CAP_SYS_ADMIN`/root required) add kernel-boundary checks; without them the runtime applies no BPF-LSM policy.
4. **Filesystem Sandbox (Landlock)**: Fine-grained, path-based access control that follows the process even across namespace boundaries.

## ✅ Working Features

- **OCI Compatibility**: Full support for pulling and executing standard images (Alpine, Ubuntu, etc.) from Docker Hub.
- **Rootless Execution**: Uses user namespaces and a native cold engine, with `bubblewrap` as a classified fallback, for non-privileged operation.
- **Security Stack**: Seccomp, Landlock and capability dropping on both the native cold path and the warm path, with graceful degradation for older kernels. The `bubblewrap` fallback applies namespace isolation only.
- **Hardware Isolation**: Native NUMA node binding and CPU affinity management.
- **WASM Support**: Native WebAssembly execution mode using Wasmtime/WASI.

## 🚧 Beta / Partial Features

- **Warm Fragments (Beta)**: One pre-sandboxed mother fragment per pool, forked and exec'd per request, with the caller's stdio passed over the socket and Ctrl+C relayed to the command. Interactive runs use a client-owned pty; one command per fragment at a time; may fall back to cold start.
- **Zygote Pool (Beta)**: `phantom run --zygote` uses a pre-forked pool, but it cannot apply seccomp or Landlock and silently falls back to normal execution when a security policy is requested.
- **BPF-LSM (Partial)**: Optional and requires kernel 5.7+ plus `CAP_SYS_ADMIN` (root); it degrades to no BPF-LSM enforcement otherwise. The unified privilege prompt can re-run the CLI under `sudo`, preserving `HOME` so the elevated run still sees the user's images, pools and config; the password is read by `sudo`, never by phantom.

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

# Force a specific execution engine (auto = native, falling back to bwrap)
phantom run --engine native alpine uname -a

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
- [Architecture Overview](docs/architecture/overview.md) - Deep dive into memory and I/O optimizations
- [Architecture Overview](docs/architecture/overview.md) - Detailed system design

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.


---

# Installation Guide

## 🏗️ Complete Installation Instructions

This guide provides detailed installation instructions for Phantom Fragment across different platforms and use cases.

## System Requirements

### Minimum Requirements
- **Rust Version**: 1.99.1 (pinned in `rust-toolchain.toml`)
- **Zig Version**: 0.16.0 or later (builds the memory and zygote libraries)
- **libseccomp headers**: `libseccomp-dev` (Debian/Ubuntu) or `libseccomp-devel` (Fedora/RHEL)
- **Kernel**: Linux 3.x+ (6.5+ recommended for security features)
- **Memory**: 256MB RAM (2GB recommended)
- **Disk Space**: 100MB free space

### Recommended Setup
- **Linux Kernel**: 6.5+ for Landlock/BPF-LSM support
- **CPU**: x86_64 or ARM64 architecture
- **Memory**: 4GB+ RAM for memory discipline features
- **Storage**: NVMe SSD recommended

### Cross-Platform Support
Phantom Fragment is **Linux-native first**, with experimental support for other platforms:

| Platform | Status | Features Supported |
|----------|--------|-------------------|
| Linux | ✅ Full | All features including Landlock, BPF, namespaces |
| macOS | ⚠️ Partial | Limited security features |
| Windows | 🚧 Experimental | Basic containerization (WSL2 required) |

## Installation Methods

### Method 1: Build from Source (Recommended)

#### Prerequisites

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify Rust installation
rustc --version  # Should show 1.99.1
cargo --version

# Install Zig (required for core performance components)
# Phantom Fragment requires Zig 0.16 or newer.
# See: https://ziglang.org/learn/getting-started/#installing-zig

# Install libseccomp development headers (required by seccomp-rs)
# Debian/Ubuntu:
sudo apt-get install -y libseccomp-dev pkg-config
# Fedora/RHEL:
# sudo dnf install -y libseccomp-devel pkgconf
```

#### Build Process

```bash
# Clone the repository
git clone https://github.com/Intro0siddiqui/Phantom-Fragment.git
cd Phantom-Fragment

# Build release binaries (optimized)
cargo build --release

# Binary is now in target/release/phantom
#   (Unified CLI: build, migrate, run, warm, etc.)

# Optional: Install to PATH
sudo cp target/release/phantom /usr/local/bin/
```

### Method 2: Quick Install (Script)

```bash
curl -fsSL https://raw.githubusercontent.com/Intro0siddiqui/Phantom-Fragment/main/installation-scripts/get.sh | bash
```

This automatically handles the build and installation process for the unified binary.

## Configuration Setup

### Basic Configuration

Phantom Fragment uses TOML configuration files:

```bash
# Create configuration directory
mkdir -p ~/.config/phantom-fragment

# Create basic configuration file
cat > ~/.config/phantom-fragment/config.toml << 'EOF'
# Phantom Fragment Configuration

[core]
default_profile = "sandbox"

[security]
enable_landlock = true
enable_seccomp = true

[performance]
buffer_pool_size = 1000

[network]
allow_outbound = false
EOF
```

## Verification

### Basic Functionality Test

```bash
# Test that phantom is installed correctly
phantom --version

# Run a simple command
phantom run alpine echo "Hello from Phantom Fragment!"

# Build a fragment
phantom build -t myapp .
```

### Feature Verification

```bash
# Check system health
phantom health

# View metrics
phantom metrics
```

## Troubleshooting

### Runtime Issues

#### Permission Errors
```bash
# Check if user namespaces are enabled
cat /proc/sys/kernel/unprivileged_userns_clone
# Should be 1 (if not, use 'sudo sysctl -w kernel.unprivileged_userns_clone=1')
```

## Next Steps

1. 🛡️ **[CLI Reference](docs/usage/cli-reference.md)** - Full command guide
2. 🔒 **[Security](docs/architecture/components/native-executor.md)** - What the isolation stack actually applies
3. 🚀 **[Architecture](docs/architecture/overview.md)** - How it works
