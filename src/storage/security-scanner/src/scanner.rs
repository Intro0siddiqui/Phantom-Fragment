//! Security Scanner Module
//!
//! Main scanner implementation that coordinates vulnerability scanning.

use crate::analyzer::ImageAnalyzer;
use crate::vulnerability_db::{Severity, Vulnerability, VulnerabilityDatabase};
use crate::{Result, ScannerError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Scan depth levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanDepth {
    /// Quick scan - only critical vulnerabilities
    Quick,
    /// Standard scan - common CVE databases
    Standard,
    /// Deep scan - comprehensive analysis
    Deep,
}

impl ScanDepth {
    /// Parse from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "quick" => ScanDepth::Quick,
            "deep" => ScanDepth::Deep,
            _ => ScanDepth::Standard,
        }
    }
}

impl std::fmt::Display for ScanDepth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanDepth::Quick => write!(f, "quick"),
            ScanDepth::Standard => write!(f, "standard"),
            ScanDepth::Deep => write!(f, "deep"),
        }
    }
}

/// Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Scan depth
    pub depth: ScanDepth,

    /// Only report vulnerabilities above this severity
    pub min_severity: Severity,

    /// Include configuration issues
    pub include_config_issues: bool,

    /// Include package information
    pub include_packages: bool,

    /// Timeout in seconds
    pub timeout_secs: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            depth: ScanDepth::Standard,
            min_severity: Severity::Low,
            include_config_issues: true,
            include_packages: true,
            timeout_secs: 300, // 5 minutes
        }
    }
}

/// Vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    /// Vulnerability details
    pub vulnerability: Vulnerability,

    /// Installed package version
    pub installed_version: String,

    /// Fixed version (if available)
    pub fixed_version: Option<String>,

    /// Whether a fix is available
    pub fix_available: bool,
}

/// Scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Image reference
    pub image_ref: String,

    /// Scan timestamp
    pub scan_timestamp: u64,

    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,

    /// Scan depth used
    pub scan_depth: ScanDepth,

    /// Found vulnerabilities
    pub vulnerabilities: Vec<VulnerabilityFinding>,

    /// Configuration issues
    pub config_issues: Vec<crate::analyzer::ConfigIssue>,

    /// Package summary
    pub package_summary: PackageSummary,

    /// Overall risk score (0-100)
    pub risk_score: f32,

    /// Risk level
    pub risk_level: RiskLevel,
}

/// Package summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSummary {
    /// Total packages scanned
    pub total_packages: usize,

    /// Packages with vulnerabilities
    pub vulnerable_packages: usize,

    /// Packages with updates available
    pub outdated_packages: usize,
}

/// Risk level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Safe,
}

impl RiskLevel {
    /// From risk score (0-100)
    pub fn from_score(score: f32) -> Self {
        if score >= 80.0 {
            RiskLevel::Critical
        } else if score >= 60.0 {
            RiskLevel::High
        } else if score >= 40.0 {
            RiskLevel::Medium
        } else if score >= 20.0 {
            RiskLevel::Low
        } else {
            RiskLevel::Safe
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "CRITICAL"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Safe => write!(f, "SAFE"),
        }
    }
}

/// Security Scanner
pub struct SecurityScanner {
    config: ScanConfig,
    vulnerability_db: VulnerabilityDatabase,
}

impl SecurityScanner {
    /// Create a new scanner with default configuration
    pub fn new() -> Self {
        Self {
            config: ScanConfig::default(),
            vulnerability_db: VulnerabilityDatabase::new(),
        }
    }

    /// Create a new scanner with custom configuration
    pub fn with_config(config: ScanConfig) -> Self {
        Self {
            config,
            vulnerability_db: VulnerabilityDatabase::new(),
        }
    }

    /// Scan an image at the given rootfs path
    pub async fn scan(&self, image_ref: &str, rootfs_path: &Path) -> Result<ScanResult> {
        let start_time = SystemTime::now();

        log::info!("Starting security scan for: {}", image_ref);
        log::info!("Scan depth: {}", self.config.depth);

        // Analyze image
        let analyzer = ImageAnalyzer::new(rootfs_path);
        let analysis = analyzer
            .analyze(image_ref)
            .map_err(|e| ScannerError::AnalysisError(e.to_string()))?;

        log::info!(
            "Analysis complete: {} packages, {} config issues",
            analysis.packages.len(),
            analysis.config_issues.len()
        );

        // Find vulnerabilities
        let mut vulnerabilities = Vec::new();

        for package in &analysis.packages {
            let vulns = self
                .vulnerability_db
                .get_vulnerabilities(&package.name, &package.version);

            for vuln in vulns {
                // Filter by severity
                if vuln.severity < self.config.min_severity {
                    continue;
                }

                // For quick scan, only include critical
                if self.config.depth == ScanDepth::Quick && vuln.severity != Severity::Critical {
                    continue;
                }

                vulnerabilities.push(VulnerabilityFinding {
                    vulnerability: vuln.clone(),
                    installed_version: package.version.clone(),
                    fixed_version: vuln.fixed_version.clone(),
                    fix_available: vuln.fixed_version.is_some(),
                });
            }
        }

        // Calculate risk score
        let risk_score = self.calculate_risk_score(&vulnerabilities, &analysis.config_issues);
        let risk_level = RiskLevel::from_score(risk_score);

        let end_time = SystemTime::now();
        let duration = end_time
            .duration_since(start_time)
            .unwrap_or_default()
            .as_millis() as u64;

        log::info!(
            "Scan complete in {}ms. Found {} vulnerabilities, risk level: {}",
            duration,
            vulnerabilities.len(),
            risk_level
        );

        Ok(ScanResult {
            image_ref: image_ref.to_string(),
            scan_timestamp: start_time
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            scan_duration_ms: duration,
            scan_depth: self.config.depth,
            vulnerabilities: vulnerabilities.clone(),
            config_issues: if self.config.include_config_issues {
                analysis.config_issues
            } else {
                Vec::new()
            },
            package_summary: PackageSummary {
                total_packages: if self.config.include_packages {
                    analysis.packages.len()
                } else {
                    0
                },
                vulnerable_packages: vulnerabilities
                    .iter()
                    .map(|v| &v.vulnerability.package)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                outdated_packages: vulnerabilities.iter().filter(|v| v.fix_available).count(),
            },
            risk_score,
            risk_level,
        })
    }

    /// Calculate risk score based on vulnerabilities and issues
    fn calculate_risk_score(
        &self,
        vulnerabilities: &[VulnerabilityFinding],
        config_issues: &[crate::analyzer::ConfigIssue],
    ) -> f32 {
        let mut score = 0.0;

        // Score from vulnerabilities
        for finding in vulnerabilities {
            score += finding.vulnerability.cvss_score * 2.0;
        }

        // Score from config issues
        for issue in config_issues {
            let severity_score = match issue.severity.as_str() {
                "CRITICAL" => 20.0,
                "HIGH" => 15.0,
                "MEDIUM" => 10.0,
                "LOW" => 5.0,
                _ => 2.0,
            };
            score += severity_score;
        }

        // Normalize to 0-100
        score.min(100.0)
    }

    /// Get the vulnerability database
    pub fn database(&self) -> &VulnerabilityDatabase {
        &self.vulnerability_db
    }

    /// Update the vulnerability database from remote
    pub async fn update_database(&mut self) -> Result<()> {
        // In production, this would fetch from NVD/OSV
        log::info!("Updating vulnerability database...");
        self.vulnerability_db
            .update_from_remote("https://example.com/vuln-db")
            .await?;
        log::info!("Vulnerability database updated");
        Ok(())
    }

    /// Scan a fragment by name (requires rootfs path resolution)
    pub async fn scan_fragment(
        &self,
        fragment_name: &str,
        rootfs_path: &Path,
    ) -> Result<ScanResult> {
        self.scan(fragment_name, rootfs_path).await
    }
}

impl Default for SecurityScanner {
    fn default() -> Self {
        Self::new()
    }
}
