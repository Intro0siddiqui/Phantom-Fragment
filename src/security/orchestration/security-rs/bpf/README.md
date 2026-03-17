# Phantom Fragment - eBPF Security Module

This directory contains the eBPF programs for the BPF-LSM security module.

## Prerequisites
To compile the BPF programs, you need:
1. `bpf-linker`: `cargo install bpf-linker`
2. `cargo-bpf` (part of `cargo-generate` template usually, or independent setup)

## Structure
- `monitor.bpf.c` or `monitor.rs`: The kernel-space code.
- `monitor.o` or `monitor.skel.rs`: The compiled output used by `security-rs`.

## Compilation
Currently, this module is a placeholder. When implementing the actual logic:
```bash
cargo build-bpf
```
The resulting object file should be placed here as `monitor.o`.

## Integration
The `security-rs` crate detects the `bpf-lsm` feature.
- Enabled: Attempts to load `monitor.o`.
- Disabled: Falls back to `seccomp`.
