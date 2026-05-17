//! Scan Reporter Module
//!
//! Generates scan reports in various formats.

use crate::scanner::ScanResult;
use serde::{Deserialize, Serialize};

/// Report format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// Markdown format
    Markdown,
}

impl ReportFormat {
    /// Parse from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => ReportFormat::Json,
            "markdown" | "md" => ReportFormat::Markdown,
            _ => ReportFormat::Text,
        }
    }
}

/// Scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Result data
    pub result: ScanResult,

    /// Report format
    pub format: ReportFormat,
}

impl ScanReport {
    /// Create a new report
    pub fn new(result: ScanResult, format: ReportFormat) -> Self {
        Self { result, format }
    }

    /// Generate report as string
    pub fn generate(&self) -> String {
        match self.format {
            ReportFormat::Text => self.generate_text(),
            ReportFormat::Json => self.generate_json(),
            ReportFormat::Markdown => self.generate_markdown(),
        }
    }

    /// Generate text report
    fn generate_text(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "╔══════════════════════════════════════════════════════════════╗\n"
        ));
        output.push_str(&format!(
            "║  Security Scan Report: {:<46} ║\n",
            truncate(&self.result.image_ref, 46)
        ));
        output.push_str(&format!(
            "╚══════════════════════════════════════════════════════════════╝\n\n"
        ));

        // Summary
        output.push_str(&format!(
            "  {:<20} {}\n",
            "Scan Depth:", self.result.scan_depth
        ));
        output.push_str(&format!(
            "  {:<20} {} ms\n",
            "Duration:", self.result.scan_duration_ms
        ));
        output.push_str(&format!(
            "  {:<20} {}\n",
            "Risk Score:",
            format!("{:.1}/100", self.result.risk_score)
        ));
        output.push_str(&format!(
            "  {:<20} {}\n",
            "Risk Level:",
            format_risk_level(&self.result.risk_level)
        ));
        output.push_str("\n");

        // Package summary
        output.push_str(&format!(
            "  {:<20} {}\n",
            "Packages Scanned:", self.result.package_summary.total_packages
        ));
        output.push_str(&format!(
            "  {:<20} {}\n",
            "Vulnerable:", self.result.package_summary.vulnerable_packages
        ));
        output.push_str(&format!(
            "  {:<20} {}\n",
            "Updates Available:", self.result.package_summary.outdated_packages
        ));
        output.push_str("\n");

        // Vulnerabilities
        if !self.result.vulnerabilities.is_empty() {
            output.push_str(&format!(
                "  {} Vulnerabilities Found: {}\n\n",
                emoji_for_count(self.result.vulnerabilities.len()),
                self.result.vulnerabilities.len()
            ));

            for (i, vuln) in self.result.vulnerabilities.iter().enumerate() {
                output.push_str(&format!(
                    "    [{}] {} ({})\n",
                    i + 1,
                    vuln.vulnerability.id,
                    format_severity(&vuln.vulnerability.severity)
                ));
                output.push_str(&format!(
                    "        Package: {}@{}\n",
                    vuln.vulnerability.package, vuln.installed_version
                ));
                output.push_str(&format!(
                    "        CVSS Score: {:.1}\n",
                    vuln.vulnerability.cvss_score
                ));
                output.push_str(&format!(
                    "        Description: {}\n",
                    vuln.vulnerability.description
                ));
                if vuln.fix_available {
                    output.push_str(&format!(
                        "        Fix: Upgrade to {}\n",
                        vuln.fixed_version
                            .as_ref()
                            .unwrap_or(&"unknown".to_string())
                    ));
                }
                output.push_str("\n");
            }
        } else {
            output.push_str(&format!("  {} No vulnerabilities found\n\n", "✓"));
        }

        // Configuration issues
        if !self.result.config_issues.is_empty() {
            output.push_str(&format!(
                "  {} Configuration Issues: {}\n\n",
                emoji_for_count(self.result.config_issues.len()),
                self.result.config_issues.len()
            ));

            for (i, issue) in self.result.config_issues.iter().enumerate() {
                output.push_str(&format!(
                    "    [{}] {} ({})\n",
                    i + 1,
                    issue.id,
                    issue.severity
                ));
                output.push_str(&format!("        Title: {}\n", issue.title));
                output.push_str(&format!("        Description: {}\n", issue.description));
                output.push_str(&format!(
                    "        Recommendation: {}\n",
                    issue.recommendation
                ));
                if let Some(path) = &issue.path {
                    output.push_str(&format!("        Path: {}\n", path));
                }
                output.push_str("\n");
            }
        }

        // Recommendations
        output.push_str("  Recommendations:\n");
        if self.result.risk_level == crate::scanner::RiskLevel::Safe {
            output.push_str(
                "    • Image appears secure. Continue monitoring for new vulnerabilities.\n",
            );
        } else {
            output.push_str("    • Update vulnerable packages to their latest versions.\n");
            output.push_str("    • Review and fix configuration issues.\n");
            output.push_str("    • Consider using a minimal base image (e.g., distroless).\n");
            output.push_str("    • Run scans regularly as part of CI/CD pipeline.\n");
        }

        output
    }

    /// Generate JSON report
    fn generate_json(&self) -> String {
        serde_json::to_string_pretty(&self.result).unwrap_or_default()
    }

    /// Generate Markdown report
    fn generate_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "# Security Scan Report: {}\n\n",
            self.result.image_ref
        ));

        output.push_str("## Summary\n\n");
        output.push_str(&format!("| Metric | Value |\n"));
        output.push_str(&format!("|--------|-------|\n"));
        output.push_str(&format!("| Scan Depth | {} |\n", self.result.scan_depth));
        output.push_str(&format!(
            "| Duration | {} ms |\n",
            self.result.scan_duration_ms
        ));
        output.push_str(&format!(
            "| Risk Score | {:.1}/100 |\n",
            self.result.risk_score
        ));
        output.push_str(&format!("| Risk Level | {} |\n", self.result.risk_level));
        output.push_str(&format!(
            "| Packages Scanned | {} |\n",
            self.result.package_summary.total_packages
        ));
        output.push_str(&format!(
            "| Vulnerable Packages | {} |\n",
            self.result.package_summary.vulnerable_packages
        ));
        output.push_str("\n");

        if !self.result.vulnerabilities.is_empty() {
            output.push_str("## Vulnerabilities\n\n");

            for vuln in &self.result.vulnerabilities {
                output.push_str(&format!(
                    "### {} ({})\n\n",
                    vuln.vulnerability.id,
                    format_severity(&vuln.vulnerability.severity)
                ));
                output.push_str(&format!(
                    "- **Package**: {}@{}\n",
                    vuln.vulnerability.package, vuln.installed_version
                ));
                output.push_str(&format!(
                    "- **CVSS Score**: {:.1}\n",
                    vuln.vulnerability.cvss_score
                ));
                output.push_str(&format!(
                    "- **Description**: {}\n",
                    vuln.vulnerability.description
                ));
                if vuln.fix_available {
                    output.push_str(&format!(
                        "- **Fix**: Upgrade to {}\n",
                        vuln.fixed_version
                            .as_ref()
                            .unwrap_or(&"unknown".to_string())
                    ));
                }
                output.push_str("\n");
            }
        } else {
            output.push_str("## Vulnerabilities\n\n");
            output.push_str("✓ No vulnerabilities found.\n\n");
        }

        if !self.result.config_issues.is_empty() {
            output.push_str("## Configuration Issues\n\n");

            for issue in &self.result.config_issues {
                output.push_str(&format!("### {} ({})\n\n", issue.id, issue.severity));
                output.push_str(&format!("- **Title**: {}\n", issue.title));
                output.push_str(&format!("- **Description**: {}\n", issue.description));
                output.push_str(&format!("- **Recommendation**: {}\n", issue.recommendation));
                if let Some(path) = &issue.path {
                    output.push_str(&format!("- **Path**: `{}`\n", path));
                }
                output.push_str("\n");
            }
        }

        output.push_str("## Recommendations\n\n");
        output.push_str("- Update vulnerable packages to their latest versions.\n");
        output.push_str("- Review and fix configuration issues.\n");
        output.push_str("- Consider using a minimal base image (e.g., distroless).\n");
        output.push_str("- Run scans regularly as part of CI/CD pipeline.\n");

        output
    }
}

/// Helper functions for formatting

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

fn format_severity(severity: &crate::vulnerability_db::Severity) -> String {
    match severity {
        crate::vulnerability_db::Severity::Critical => "🔴 CRITICAL".to_string(),
        crate::vulnerability_db::Severity::High => "🟠 HIGH".to_string(),
        crate::vulnerability_db::Severity::Medium => "🟡 MEDIUM".to_string(),
        crate::vulnerability_db::Severity::Low => "🔵 LOW".to_string(),
        crate::vulnerability_db::Severity::Info => "⚪ INFO".to_string(),
    }
}

fn format_risk_level(level: &crate::scanner::RiskLevel) -> String {
    match level {
        crate::scanner::RiskLevel::Critical => "🔴 CRITICAL".to_string(),
        crate::scanner::RiskLevel::High => "🟠 HIGH".to_string(),
        crate::scanner::RiskLevel::Medium => "🟡 MEDIUM".to_string(),
        crate::scanner::RiskLevel::Low => "🔵 LOW".to_string(),
        crate::scanner::RiskLevel::Safe => "🟢 SAFE".to_string(),
    }
}

fn emoji_for_count(count: usize) -> &'static str {
    if count == 0 {
        "✓"
    } else if count <= 3 {
        "⚠"
    } else {
        "✗"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{PackageSummary, ScanDepth};

    fn create_test_result() -> ScanResult {
        ScanResult {
            image_ref: "test:latest".to_string(),
            scan_timestamp: 0,
            scan_duration_ms: 100,
            scan_depth: ScanDepth::Standard,
            vulnerabilities: vec![],
            config_issues: vec![],
            package_summary: PackageSummary {
                total_packages: 10,
                vulnerable_packages: 0,
                outdated_packages: 0,
            },
            risk_score: 0.0,
            risk_level: crate::scanner::RiskLevel::Safe,
        }
    }

    #[test]
    fn test_report_format_from_str() {
        assert_eq!(ReportFormat::from_str("json"), ReportFormat::Json);
        assert_eq!(ReportFormat::from_str("markdown"), ReportFormat::Markdown);
        assert_eq!(ReportFormat::from_str("md"), ReportFormat::Markdown);
        assert_eq!(ReportFormat::from_str("text"), ReportFormat::Text);
    }

    #[test]
    fn test_text_report_generation() {
        let result = create_test_result();
        let report = ScanReport::new(result, ReportFormat::Text);
        let output = report.generate();

        assert!(output.contains("Security Scan Report"));
        assert!(output.contains("test:latest"));
        assert!(output.contains("SAFE"));
    }

    #[test]
    fn test_json_report_generation() {
        let result = create_test_result();
        let report = ScanReport::new(result, ReportFormat::Json);
        let output = report.generate();

        assert!(output.contains("\"image_ref\""));
        assert!(output.contains("\"test:latest\""));
    }

    #[test]
    fn test_markdown_report_generation() {
        let result = create_test_result();
        let report = ScanReport::new(result, ReportFormat::Markdown);
        let output = report.generate();

        assert!(output.contains("# Security Scan Report"));
        assert!(output.contains("| Metric | Value |"));
    }
}
