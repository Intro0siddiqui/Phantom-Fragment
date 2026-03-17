# Contributing to Phantom Fragment

Thank you for your interest in contributing to Phantom Fragment! This document provides guidelines for contributing.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Intro0siddiqui/Phantom-Fragment.git
cd Phantom-Fragment

# Build all components
cargo build --release

# Run tests
cargo test --workspace
```

## Development Setup

### Prerequisites

- **Rust**: 1.75+ (stable)
- **Zig**: 0.11+ (for memory modules)
- **Linux**: Kernel 3.x+ (6.5+ for Landlock/BPF)

### Building

```bash
# Build Rust components
cargo build --release

# Build Zig memory module
cd src/memory/discipline/memory-zig
zig build
```

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific package
cargo test --package memory-rs

# With output
cargo test --workspace -- --nocapture
```

## Code Structure

```
src/
├── cli/              # CLI binary (phantom-cli)
├── core/             # Core engine (execution, driver, types)
├── memory/           # Memory management (Zig + Rust)
├── security/         # Security (seccomp, landlock, capabilities)
├── monitoring/       # Metrics and observability
└── mcp/              # MCP server for AI agents
```

## Coding Guidelines

### Rust

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` before committing
- Use `cargo clippy` to catch common issues
- Document public APIs with rustdoc

### Zig

- Follow Zig style guide
- Export C-compatible functions with `pub export fn`
- Gate debug prints behind `const DEBUG = false`
- Use `zig fmt` before committing

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(io): add batch_write_fast for 3GB/s throughput
fix(cli): handle missing config file gracefully
docs(readme): update performance benchmarks
refactor(security): consolidate policy loading
```

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feat/my-feature`
3. **Make** your changes
4. **Test** thoroughly: `cargo test --workspace`
5. **Format** code: `cargo fmt && zig fmt src/memory/**/*.zig`
6. **Commit** with descriptive message
7. **Push** and create Pull Request

### PR Checklist

- [ ] Tests pass (`cargo test --workspace`)
- [ ] Code formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Documentation updated if needed
- [ ] CHANGELOG.md updated for significant changes

## Areas for Contribution

### Good First Issues
- Documentation improvements
- Test coverage
- Error message improvements

### Intermediate
- Performance optimizations
- New CLI commands
- Security policy enhancements

### Advanced
- I/O subsystem improvements (Zig)
- Memory management (Zig)
- Kernel feature integration

## Getting Help

- Open an issue for bugs or feature requests
- Discussions for questions and ideas

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
