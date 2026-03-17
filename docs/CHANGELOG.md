# Changelog

All notable changes to Phantom Fragment are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **network-rs**: Implemented automatic loopback interface startup when creating network namespaces

## [3.1.0] - 2025-12-09

### Added
- **I/O Performance**: Standard Rust I/O with verified 2.2 GB/s write, 6.2 GB/s read

### Changed
- Updated documentation to reflect actual I/O performance

### Fixed
- Various bug fixes and improvements

## [3.0.0] - 2025-11-30

### Added
- **Complete Rust + Zig Migration**: 100% of codebase migrated from Go
- **CLI Management**: Full fragment lifecycle (create, run, list, destroy, health, metrics)
- **Fragment Registry**: JSON-based persistent tracking with lifecycle management
- **BPF Loader**: Capability detection with graceful fallback to seccomp
- **NUMA Manager**: NUMA node detection and binding with UMA fallback
- **PSI Monitor**: Pressure Stall Information monitoring

### Changed
- Binary size reduced from 47MB (Go) to 3.6MB (Rust)
- Memory usage reduced from <10MB to ~1.7MB per fragment
- Cold start improved from <80ms target to ~7ms actual

## [2.0.0] - 2025-11-15

### Added
- Initial Zig implementation of I/O fast path
- io_uring integration with SQPOLL/IOPOLL support
- Rust FFI bindings for Zig modules

### Changed
- Migrated memory management from Go to Zig
- Migrated I/O subsystem from Go to Zig

## [1.0.0] - 2025-10-01

### Added
- Initial Go implementation
- Basic container isolation
- MCP server integration
- Security policies (seccomp, capabilities, landlock)

---

## Migration Notes

### From 2.x to 3.x
- Binary renamed: `phantom-fragment` → `phantom`
- Configuration format unchanged
- MCP protocol unchanged

### From Go (1.x) to Rust/Zig (2.x+)
- Complete rewrite - not backwards compatible
- New CLI interface
- New configuration format
