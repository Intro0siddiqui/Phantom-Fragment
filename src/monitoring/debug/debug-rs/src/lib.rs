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

// Re-export key structs for convenient access
pub use types::{
    ActiveFragment, DebugConfig, DebugInspector, FragmentAttacher, FragmentInspector,
    FragmentProfiler, FragmentState, LogAnalyzer, ResourceMetrics, ResourceMonitor,
    ResourceMonitorWithHistory, ResourceUsage, SystemInfo,
};
