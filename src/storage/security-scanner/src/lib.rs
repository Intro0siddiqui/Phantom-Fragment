//! Security Scanner for Phantom Fragment
//!
//! Provides vulnerability scanning for container images including:
//! - Package vulnerability detection (CVE scanning)
//! - Misconfiguration detection
//! - Security best practices validation
//! - Risk scoring and reporting
//!
//! Scan depths:
//! - `quick`: Fast scan checking only critical vulnerabilities
//! - `standard`: Default scan with common CVE databases
//! - `deep`: Comprehensive scan including all packages and configurations

mod analyzer;
mod reporter;
mod scanner;
mod vulnerability_db;

pub use analyzer::{ConfigIssue, ImageAnalysis, PackageInfo};
pub use reporter::{ReportFormat, ScanReport};
pub use scanner::{
    PackageSummary, RiskLevel, ScanConfig, ScanDepth, ScanResult, SecurityScanner,
    VulnerabilityFinding,
};
pub use vulnerability_db::{Severity, Vulnerability, VulnerabilityDatabase};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Image not found: {0}")]
    ImageNotFound(String),

    #[error("Invalid image format: {0}")]
    InvalidImageFormat(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Analysis error: {0}")]
    AnalysisError(String),

    #[error("Scanner error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ScannerError>;
