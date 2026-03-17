//! WASM Execution Backend
//!
//! Provides WebAssembly execution capabilities for Phantom Fragment using Wasmtime.
//! Supports WASI with configurable resource limits and filesystem access.

use anyhow::{Context, Result};
use std::path::Path;
use std::time::Instant;
use wasi_common::sync::WasiCtxBuilder;
use wasi_common::I32Exit;
use wasmtime::{Config, Engine, Linker, Module, Store};

/// Default maximum memory in MB
const DEFAULT_MAX_MEMORY_MB: usize = 128;

/// WASM execution backend
pub struct WasmBackend {
    engine: Engine,
    config: WasmConfig,
}

/// Configuration for WASM execution
pub struct WasmConfig {
    /// Maximum memory in megabytes
    pub max_memory_mb: usize,
    /// Directories to preopen (guest_path, host_path)
    pub allowed_dirs: Vec<(String, std::path::PathBuf)>,
    /// Environment variables to set
    pub env_vars: Vec<(String, String)>,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: DEFAULT_MAX_MEMORY_MB,
            allowed_dirs: vec![("/tmp".to_string(), std::path::PathBuf::from("/tmp"))],
            env_vars: Vec::new(),
        }
    }
}

impl WasmBackend {
    /// Creates a new WASM backend with default configuration
    pub fn new() -> Result<Self> {
        let config = Config::new();
        let engine = Engine::new(&config).context("Failed to create Wasmtime engine")?;

        Ok(Self {
            engine,
            config: WasmConfig::default(),
        })
    }

    /// Sets custom configuration
    pub fn with_config(mut self, config: WasmConfig) -> Self {
        self.config = config;
        self
    }

    /// Runs a WASM module with the given arguments
    ///
    /// Returns the exit code from the WASM module
    pub fn run(&self, wasm_path: &Path, args: &[String]) -> Result<i32> {
        let start_time = Instant::now();
        log::info!("Starting WASM execution: {}", wasm_path.display());

        let module = Module::from_file(&self.engine, wasm_path)
            .with_context(|| format!("Failed to load WASM module from {}", wasm_path.display()))?;

        let mut wasi_builder = WasiCtxBuilder::new();
        wasi_builder.args(args).context("Failed to set WASI args")?;

        for (key, value) in &self.config.env_vars {
            wasi_builder
                .env(key, value)
                .context("Failed to set WASI environment variable")?;
        }

        // Preopen directories
        for (guest_path, host_path) in &self.config.allowed_dirs {
            let dir = std::fs::OpenOptions::new()
                .read(true)
                .open(host_path)
                .with_context(|| format!("Failed to open directory: {}", host_path.display()))?;

            wasi_builder
                .preopened_dir(wasi_common::sync::Dir::from_std_file(dir), guest_path)
                .with_context(|| {
                    format!(
                        "Failed to preopen directory {} -> {}",
                        host_path.display(),
                        guest_path
                    )
                })?;
        }

        let wasi_ctx = wasi_builder.build();
        let mut store = Store::new(&self.engine, wasi_ctx);

        let mut linker = Linker::new(&self.engine);
        wasi_common::sync::add_to_linker(&mut linker, |ctx| ctx)
            .context("Failed to add WASI to linker")?;

        let instance = linker
            .instantiate(&mut store, &module)
            .context("Failed to instantiate WASM module")?;

        let run = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .context("Failed to get _start function")?;

        let exit_code = match run.call(&mut store, ()) {
            Ok(_) => 0,
            Err(e) => {
                if let Some(exit) = e.downcast_ref::<I32Exit>() {
                    exit.0
                } else {
                    return Err(e).context("WASM execution failed");
                }
            }
        };

        let elapsed = start_time.elapsed();
        log::info!(
            "WASM execution completed: exit_code={}, duration={:.2?}",
            exit_code,
            elapsed
        );

        Ok(exit_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_backend_creation() {
        let backend = WasmBackend::new();
        assert!(backend.is_ok());
    }

    #[test]
    fn test_default_config() {
        let config = WasmConfig::default();
        assert_eq!(config.max_memory_mb, 128);
        assert_eq!(config.allowed_dirs.len(), 1);
        assert!(config.env_vars.is_empty());
    }
}
