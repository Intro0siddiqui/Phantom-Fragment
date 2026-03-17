# Installation Guide

## 🏗️ Complete Installation Instructions

This guide provides detailed installation instructions for Phantom Fragment across different platforms and use cases.

## System Requirements

### Minimum Requirements
- **Rust Version**: 1.75.0 or later (with Cargo)
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
rustc --version  # Should show 1.75+
cargo --version

# Install Zig (required for core performance components)
# See: https://ziglang.org/learn/getting-started/#installing-zig
```

#### Build Process

```bash
# Clone the repository
git clone https://github.com/Intro0siddiqui/Phantom-Fragment.git
cd Phantom-Fragment

# Build release binaries (optimized)
cargo build --release

# Binaries are now in target/release/:
#   - phantom (Unified CLI: build, migrate, run, warm, etc.)
#   - phantom-mcp (Dedicated AI service)

# Optional: Install to PATH
sudo cp target/release/phantom /usr/local/bin/
sudo cp target/release/phantom-mcp /usr/local/bin/
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

1. 🛡️ **[CLI Reference](../usage/cli-reference.md)** - Full command guide
2. 🔒 **[Security](../security/security-line-rate.md)** - Deep dive into isolation
3. 🚀 **[Architecture](../architecture/overview.md)** - How it works
