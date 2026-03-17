# Implementation Plans: Wasm Mode, Phantom Compose, Network CLI

Three feature plans based on codebase analysis. Each is scoped independently.

---

## Feature 1: Wasm Mode

**Status**: ✅ **IMPLEMENTED**

### Goal
Add WebAssembly execution as a first-class fragment mode, enabling sub-millisecond startup of untrusted `.wasm` binaries with capability-based security (WASI).

### Current State (March 2026)
- ✅ `ExecutionMode::Wasm` variant exists in `src/core/execution/execution-rs/src/lib.rs`
- ✅ `spawn_wasm()` handler fully implemented
- ✅ `wasm-rs` crate complete with Wasmtime integration
- ✅ WASI support with configurable resource limits
- ✅ Security policy integration for Wasm mode
- ✅ CLI support via `--mode wasm` or profile configuration

### Implementation Details

#### Execution Engine (`execution-rs`)

**`src/core/execution/wasm-rs/`** - Complete crate:
- **`Cargo.toml`**: Depends on `wasmtime`, `wasmtime-wasi`.
- **`src/lib.rs`**: `WasmBackend` struct for executing `.wasm` via WASI.
- Features:
  - Configurable memory limits
  - Preopened directories
  - Environment variable support
  - WASI capability-based security

**`src/core/execution/execution-rs/src/lib.rs`**
- ✅ `spawn_wasm()` fully implemented
- ✅ `ExecutionMode::Wasm` wired in `spawn()`
- ✅ Security policies applied for Wasm mode

#### CLI (`phantom-cli`)

**`src/cli/phantom-cli/src/config.rs`**
- ✅ `wasm` profile supported

**Usage**:
```bash
phantom run --mode wasm myapp.wasm
```

---

## Feature 2: Phantom Compose

**Status**: ❌ **NOT IMPLEMENTED**

### Goal
Enable multi-fragment orchestration via a declarative YAML file (`phantom-compose.yml`).

### Current State (March 2026)
- ❌ No `phantom-compose` crate exists
- ❌ No `src/tools/phantom-compose/` directory
- ❌ No compose subcommand in CLI
- ❌ No YAML parsing for orchestration

### Proposed Changes (If Implemented)

#### New Crate

**`[NEW] src/tools/phantom-compose/`**
New binary crate for orchestration logic:
- Parse `phantom-compose.yml`.
- Manage lifecycle (`up`, `down`, `ps`).

#### Integration

**`[MODIFY] src/cli/phantom-cli/src/main.rs`**
- Add `Compose` subcommand alias.

---

## Feature 3: Network CLI

**Status**: ✅ **IMPLEMENTED**

### Goal
Expose existing `network-rs` functionality through `phantom network` subcommands.

### Current State (March 2026)
- ✅ `phantom network` subcommand fully implemented
- ✅ `src/cli/phantom-cli/src/commands/network.rs` complete
- ✅ All planned subcommands working:
  - `phantom network list` - List all network interfaces
  - `phantom network up <name>` - Bring interface up
  - `phantom network add-ip <interface> <ip>` - Add IP address
  - `phantom network create-veth <host> <peer>` - Create VETH pair

### Implementation Details

**`src/cli/phantom-cli/src/commands/network.rs`**:
```rust
pub enum NetworkCommands {
    List,
    Up { name: String },
    AddIp { interface: String, ip: String },
    CreateVeth { host_name: String, peer_name: String },
}
```

**Integration with `network-rs`**:
- Uses `NetworkManager` for all operations
- Async/await pattern for network operations
- Proper error handling and user feedback

---

## Summary Table

| Feature | Status | Location |
|---------|--------|----------|
| Wasm Mode | ✅ Implemented | `src/core/wasm-rs/`, `execution-rs` |
| Phantom Compose | ❌ Not Implemented | N/A |
| Network CLI | ✅ Implemented | `src/cli/phantom-cli/src/commands/network.rs` |

---

## Recommended Implementation Order (Original)
1. **Network CLI** (Prerequisite) - ✅ COMPLETED
2. **Wasm Mode** - ✅ COMPLETED
3. **Phantom Compose** - ❌ NOT STARTED

---

*Last Updated: 2026-03-04*
