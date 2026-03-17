# Phantom Fragment

A high-performance, rootless container runtime engineered for sub-millisecond execution and line-rate security.

## 🚀 Project Overview

**Phantom Fragment** is a specialized execution engine designed to bridge the gap between native process performance and container isolation. By leveraging a hybrid architecture of **Rust** and **Zig**, it eliminates the overhead inherent in traditional daemon-based runtimes like Docker.

### Core Value Proposition:
- **Elite Performance**: ~7x faster cold starts than Docker (~45ms vs ~330ms).
- **Extreme Efficiency**: 9.0MB static binary with zero background daemon memory.
- **Line-Rate Security**: Proactive enforcement via BPF-LSM and Landlock, providing deeper isolation than standard namespaces.
- **Rootless by Design**: Operates entirely without elevated privileges, utilizing user namespaces and modern kernel features.

## 📊 Actual Performance (Verified)

*System: Intel i3-6006U @ 2.00GHz, Linux 6.18.9, 7.5GB RAM*

> ⚠️ **BETA WARNING: Warm Start Feature**
> 
> The Warm Start feature is currently in **beta/experimental** stage and may be unreliable.
> - May fallback to cold start automatically if warm fragment is unavailable
> - Actively being improved for production readiness
> - Use with caution in production environments

| Metric | Phantom Fragment | Docker | Improvement |
|--------|---------|--------|-------|
| **Warm Start (Beta/Experimental)** | **~5-10ms (unreliable)** | ~330ms | **~33× Faster (when working)** |
| **Cold Start** | **~45ms** | ~330ms | **~7× Faster** |
| **Binary Size** | **19MB** | 161MB | **~8× Smaller** |
| **Daemon RSS** | **0 MB** | ~92MB | **Zero Overhead** |
| **Runtime RSS** | **~1.7MB** | ~15MB | **~8× More Efficient** |
## 🛠️ System Architecture

Phantom Fragment utilizes a tiered isolation model, selecting the optimal execution path based on the workload's risk profile:

1. **Zygote Engine (Zig)**: A high-performance process pool that bypasses standard `fork/exec` overhead for sub-millisecond warm starts.(note zygote engine is a technology that is actively being developed currently in beta and had bugs)
2. **Adaptive Execution (Rust)**: Orchestrates namespaces, cgroups v2, and hardware isolation (NUMA/CPU affinity).
3. **Kernel Sentry (eBPF)**: BPF-LSM hooks provide programmatic, un-bypassable security checks at the kernel boundary.
4. **Filesystem Sandbox (Landlock)**: Fine-grained, path-based access control that follows the process even across namespace boundaries.

## ✅ Working Features

- **OCI Compatibility**: Full support for pulling and executing standard images (Alpine, Ubuntu, etc.) from Docker Hub.
- **Rootless Execution**: Leverages `bubblewrap` and user namespaces for secure, non-privileged operation.
- **Security Stack**: Integrated BPF-LSM, Landlock, and Seccomp with graceful degradation for older kernels.
- **Hardware Isolation**: Native NUMA node binding and CPU affinity management.
- **WASM Support**: Native WebAssembly execution mode using Wasmtime/WASI.
- **Warm Fragments (Beta/Experimental)**: Pre-warmed daemon processes for faster startup (currently unstable; may fallback to cold start).
- **MCP Integration**: First-class support for AI agents via the Model Context Protocol.

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

Requires **Rust 1.75+** and **Zig 0.14+**.

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
phantom --version  # Shows: phantom 1.0.0
```

## 🤖 AI Agent Integration (MCP)

Phantom Fragment includes first-class support for AI agents (like Claude or Cursor) via the **Model Context Protocol (MCP)**. This allows agents to safely execute code and manage fragments directly.

Add this to your `mcp_config.json`:

```json
{
  "mcpServers": {
    "phantom-fragment": {
      "command": "phantom-mcp"
    }
  }
}
```

## 📖 Documentation

- [CLI Reference](docs/usage/cli-reference.md) - Complete command guide
- [Implementation Guide](docs/IMPLEMENTATION_GUIDE.md) - Deep dive into memory and I/O optimizations
- [Architecture Overview](docs/architecture/overview.md) - Detailed system design

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
