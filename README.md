# AI Sandbox

A lightweight, LLM-native sandboxing environment for AI agents. Provides secure, isolated execution with minimal overhead using Alpine Linux rootfs and bubblewrap/chroot/Lima.

## Phase 1: CLI Foundation ✨

This phase introduces a comprehensive CLI interface with profile management, rootfs handling, and container lifecycle management.

## Quick Start

```bash
# Build the CLI
go build -o bin/aisbx ./cmd/aisbx

# Initialize the sandbox
./bin/aisbx init

# List available profiles
./bin/aisbx profile list

# Run a command in sandbox
./bin/aisbx run python script.py

# Create a persistent container
./bin/aisbx create --profile python-dev

# Destroy containers
./bin/aisbx destroy [container-id]
```

## CLI Commands

### Core Commands
- `aisbx init` - Initialize sandbox with rootfs and default profiles
- `aisbx run` - Run commands in sandboxed environment
- `aisbx create` - Create persistent containers
- `aisbx destroy` - Clean up containers
- `aisbx profile` - Manage configuration profiles
- `aisbx logs` - View container logs

### Profile Management
```bash
aisbx profile list          # List all profiles
aisbx profile show default  # Show profile details
aisbx profile create myapp  # Create new profile
```

## Configuration

Configuration is stored in `~/.aisbx/`:
- `config.yaml` - Global configuration
- `profiles/` - YAML profile definitions
- `cache/` - Rootfs and container cache

## Build

```bash
# Build for current platform
./build.sh

# Or manually
go build -o bin/aisbx ./cmd/aisbx
```

## Architecture

```
cmd/aisbx/          # CLI entry point
internal/
├── commands/       # CLI commands
├── config/         # Configuration management
└── rootfs/         # Rootfs extraction and management
pkg/
├── bwrap/          # Bubblewrap integration
├── driver/         # Sandbox drivers
├── rootfs/         # Rootfs utilities
└── types/          # Common types
```

