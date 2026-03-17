//! Error types for the debug library

use thiserror::Error;

/// Result type alias for debug operations
pub type Result<T> = std::result::Result<T, DebugError>;

/// Comprehensive error type for debug operations
#[derive(Error, Debug)]
pub enum DebugError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Process not found: {0}")]
    ProcessNotFound(String),

    #[error("Debugger error: {0}")]
    Debugger(String),

    #[error("Profiler error: {0}")]
    Profiler(String),

    #[error("Log analysis error: {0}")]
    LogAnalysis(String),

    #[error("Monitoring error: {0}")]
    Monitoring(String),

    #[error("Inspection error: {0}")]
    Inspection(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("System call error: {0}")]
    SystemCall(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    #[error("Fragment not found: {0}")]
    FragmentNotFound(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

impl DebugError {
    /// Create a new process not found error
    pub fn process_not_found<S: Into<String>>(pid: S) -> Self {
        Self::ProcessNotFound(pid.into())
    }

    /// Create a new fragment not found error
    pub fn fragment_not_found<S: Into<String>>(id: S) -> Self {
        Self::FragmentNotFound(id.into())
    }

    /// Create a new debugger error
    pub fn debugger<S: Into<String>>(msg: S) -> Self {
        Self::Debugger(msg.into())
    }

    /// Create a new profiler error
    pub fn profiler<S: Into<String>>(msg: S) -> Self {
        Self::Profiler(msg.into())
    }

    /// Create a new invalid argument error
    pub fn invalid_argument<S: Into<String>>(msg: S) -> Self {
        Self::InvalidArgument(msg.into())
    }

    /// Create a new unsupported operation error
    pub fn unsupported<S: Into<String>>(msg: S) -> Self {
        Self::Unsupported(msg.into())
    }
}
