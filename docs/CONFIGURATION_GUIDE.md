# Phantom Fragment Configuration Guide

Phantom Fragment supports a flexible configuration system that allows you to define custom execution profiles. This enables you to tailor isolation levels, resource limits, and hardware access without modifying the code.

## Configuration File Location

Phantom looks for the configuration file in the following order:
1.  `$PHANTOM_CONFIG` environment variable
2.  `~/.phantom/config.toml`
3.  `/etc/phantom/config.toml`

## File Structure (`config.toml`)

The configuration file uses TOML syntax. You can define multiple profiles under the `[profiles]` section.

### Example Configuration

```toml
# ~/.phantom/config.toml

# Default settings
[defaults]
log_level = "info"
storage_path = "~/.phantom/storage"

# --- Execution Profiles ---

# 1. Standard Sandbox (Default)
[profiles.sandbox]
isolation = "namespace" # Options: direct, namespace, hardened, wasm
network = true
file_write = true
memory_limit = "512MB"

# 2. Hardened Security
[profiles.secure]
isolation = "hardened"
network = false
file_write = false
seccomp = "strict"

# 3. GPU Workstation (Direct Hardware Access)
[profiles.gpu]
isolation = "direct"
cpu_affinity = [0, 1, 2, 3] # Pin to specific cores
devices = ["/dev/nvidia0", "/dev/nvidiactl"]
```

## Using Profiles

Once you have defined a profile in `config.toml`, you can use it with the `--profile` flag:

```bash
# Run with the 'secure' profile defined above
phantom run --profile secure alpine /bin/sh

# Run with the 'gpu' profile
phantom run --profile gpu ubuntu-cuda python train.py
```

## Profile Options Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `isolation` | string | "namespace" | Isolation mode: `direct`, `namespace`, `hardened`, `wasm` |
| `network` | bool | true | Allow network access |
| `file_write` | bool | true | Allow file system writes |
| `memory_mb` | integer | 512 | Memory limit in Megabytes |
| `cpu_count` | integer | 1 | Number of CPU cores to allocate |
| `cpu_affinity` | list | [] | List of CPU core IDs to pin to |
| `seccomp_rules` | list | [] | Custom syscall filters |


## Best Practices

*   **Version Control**: Keep your `config.toml` in dotfiles for consistency across machines.
*   **Least Privilege**: Create specific profiles for specific tasks (e.g., `build_profile` with network but no root, `test_profile` with no network).
