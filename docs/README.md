# Phantom Fragment Documentation

Welcome to the Phantom Fragment documentation.

## Quick Links

| Document | Description |
|----------|-------------|
| [Main README](../README.md) | Overview, installation, quick start |
| [CLI Reference](usage/cli-reference.md) | Complete CLI documentation |
| [Comparison](comparison.md) | vs Docker, Podman, Firecracker |
| [Architecture Overview](architecture/overview.md) | Detailed technical design |

---

## Getting Started

1. **[Installation](getting-started/installation.md)** - Build and install
2. **[Architecture Overview](architecture/overview.md)** - Understand the core
3. **[CLI Reference](usage/cli-reference.md)** - How to use the tool

---

## Architecture

- **[Technical Overview](architecture/overview.md)** - High-level design
- **[File Structure](architecture/file-structure.md)** - Codebase organization

### Components

| Component | Description |
|-----------|-------------|
| [Adaptive Execution](architecture/components/adaptive-execution.md) | Smart execution modes |
| [Memory Discipline](architecture/components/memory-discipline.md) | Efficient memory management |
| [Zygote Spawner](architecture/components/zygote-spawner.md) | Ultra-fast process spawning |

---

## Migration

Coming from Docker?

- **[Migration Guide](migration/from-docker.md)** - Transitioning your workloads

---

## Reference

- **[Implementation Guide](IMPLEMENTATION_GUIDE.md)** - Technical performance deep-dive
- **[Configuration](CONFIGURATION_GUIDE.md)** - Config file format
- **[Changelog](CHANGELOG.md)** - Version history
