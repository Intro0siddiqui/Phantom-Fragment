//! # Phantom Debug Library
//!
//! A comprehensive debugging and monitoring library for Phantom Fragment containers.
//! Provides functionality for attaching debuggers, inspecting runtime state, monitoring
//! resources, analyzing logs, and profiling performance.

pub mod attacher;
pub mod error;
pub mod inspector;
pub mod logs;
pub mod monitor;
pub mod profiler;
pub mod types;

#[cfg(test)]
mod tests;

pub use error::{DebugError, Result};
pub use types::*;

// Re-export DebugInspector for easy access
pub use types::ActiveFragment;
pub use types::DebugConfig;
pub use types::DebugInspector;
pub use types::ResourceUsage;
pub use types::SystemInfo;
