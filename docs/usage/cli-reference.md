# CLI Reference

## Complete Command Line Interface Guide

This document provides a reference for all Phantom Fragment CLI commands.

## Overview

Phantom Fragment provides a unified CLI toolset:

- **`phantom`** - Main unified binary for management, execution, building, and migration
- **`phantom-mcp`** - Dedicated AI service binary for Model Context Protocol integration

## Getting Help

```bash
# General help
phantom --help

# Command-specific help
phantom run --help
phantom create --help
phantom destroy --help
```

## Core Commands

### `phantom run` - Execute Commands in Fragments

Execute commands in secure sandboxed environments.

```bash
# Syntax
phantom run [OPTIONS] IMAGE COMMAND [ARGS...]
```

#### Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--profile` | `-p` | Security and performance profile | `sandbox`, `hardened`, `direct` |
| `--name` | `-n` | Container name (for reuse) | `my-container` |
| `--network` | | Enable network access | |
| `--root` | | Run as root (within container) | |

#### Examples

```bash
# Simple command execution
phantom run alpine echo "Hello!"

# Interactive shell session
phantom run --profile sandbox ubuntu bash

# Network access
phantom run --network alpine apk update
```

### `phantom create` - Create Persistent Fragments

```bash
# Syntax
phantom create [OPTIONS] --name NAME --profile PROFILE
```

### `phantom destroy` - Remove Fragments

```bash
# Syntax
phantom destroy [OPTIONS] NAME [NAME...]
```

### `phantom list` - List Active Fragments

```bash
# Syntax
phantom list
```

## 📊 Monitoring & Metrics

### `phantom metrics` - Show System Metrics

Show performance metrics and resource usage.

### `phantom logs` - View Fragment Logs

Retrieve and view logs from fragments.

```bash
# Syntax
phantom logs CONTAINER_NAME
```

## 🔧 Management Commands

### `phantom inspect` - Fragment Details

Examine detailed information about a fragment's configuration and state.

### `phantom health` - System Health

Check the status of system components (BPF-LSM, Zygote, etc.).

## 🛡️ Profile Commands

### `phantom profile list` - Available Profiles

### `phantom profile show` - Profile Details

## 🔄 Image Commands

### `phantom images` - List Local Images

### `phantom search` - Search Docker Hub

## 🔒 Security Commands

### `phantom security` - Security Management

## 🔍 Debugging Commands

### `phantom debug` - Debugging and Tracing

## 🔄 Advanced Commands

### `phantom network` - Network Management

### `phantom warm` - Zygote Warm Up (Beta/Experimental)

**Warning: This feature is in beta/experimental status and may be unstable.**

Warms up the zygote pool for sub-millisecond container startups.

```bash
phantom warm --size 5
```

## Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 0 | Success | Command completed successfully |
| 1 | General Error | Generic error occurred |

This CLI reference covers the primary Phantom Fragment command set. For the latest options and examples, always refer to `phantom --help`.
