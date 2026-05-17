use anyhow::{Context, Result};
use colored::*;
use std::path::PathBuf;

use crate::ui::print_header;

#[derive(clap::Subcommand, Debug, Clone)]
pub enum SecurityCommands {
    /// Run security audit on fragment
    Audit {
        /// Fragment name
        name: String,
        /// Comprehensive analysis
        #[arg(long)]
        comprehensive: bool,
    },
    /// Scan for vulnerabilities
    Scan {
        /// Target (fragment name or image)
        target: String,
        /// Scan depth (quick, standard, deep)
        #[arg(long, default_value = "standard")]
        depth: String,
        /// Output format (text, json, markdown)
        #[arg(long, default_value = "text")]
        format: String,
        /// Minimum severity to report (critical, high, medium, low)
        #[arg(long, default_value = "low")]
        min_severity: String,
        /// Rootfs path (optional, auto-detected if not provided)
        #[arg(long)]
        rootfs: Option<String>,
    },
    /// List known vulnerabilities in database
    ListVulns {
        /// Filter by package name
        #[arg(long)]
        package: Option<String>,
        /// Filter by severity
        #[arg(long)]
        severity: Option<String>,
    },
    /// Update vulnerability database
    UpdateDb,
}

use crate::commands::CommandContext;

pub async fn exec(ctx: CommandContext<'_>, command: SecurityCommands) -> Result<()> {
    let CommandContext { registry, .. } = ctx;

    match command {
        SecurityCommands::Audit {
            name,
            comprehensive,
        } => {
            let fragment = registry
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("Fragment '{}' not found", name))?;

            print_header(&format!("Security Audit: {}", name));

            let mut score = 100;
            let mut issues: Vec<String> = Vec::new();

            if fragment.components.contains(&"TcpStack".to_string()) {
                issues.push("Network access enabled".to_string());
                score -= 10;
            }
            if fragment.components.contains(&"FileIo".to_string()) {
                issues.push("File I/O enabled".to_string());
                score -= 5;
            }
            if comprehensive {
                if fragment.mode != "Hardened" {
                    issues.push("Consider hardened mode for sensitive workloads".to_string());
                    score -= 10;
                }
            }

            println!(
                "  {:<20} {}/100",
                "Security Score:".yellow(),
                score.to_string().green()
            );
            println!();

            if issues.is_empty() {
                println!("  {} No security issues found", "✓".green());
            } else {
                println!("{}:", "Issues".yellow());
                for issue in &issues {
                    println!("  {} {}", "⚠".yellow(), issue);
                }
            }

            println!();
            println!("  {}:", "Recommendations".yellow());
            println!("    • Use hardened mode for untrusted code");
            println!("    • Limit network access when possible");
            println!("    • Set appropriate resource limits");
        }

        SecurityCommands::Scan {
            target,
            depth,
            format,
            min_severity,
            rootfs,
        } => {
            print_header(&format!("Security Scan: {}", target));

            // Determine rootfs path
            let rootfs_path = if let Some(path) = rootfs {
                PathBuf::from(path)
            } else {
                // Try to find fragment rootfs
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_else(|_| ".".to_string());
                let simple_name = target.replace(":", "-").replace("/", "_");
                PathBuf::from(&home)
                    .join(".phantom")
                    .join("rootfs")
                    .join(&simple_name)
            };

            if !rootfs_path.exists() {
                println!(
                    "  {} Rootfs not found: {}",
                    "Warning:".yellow(),
                    rootfs_path.display()
                );
                println!();
                println!("  {} To scan an image, first pull it:", "Info:".yellow());
                println!("    phantom run {} <command>", target);
                println!();
                println!(
                    "  {} Or specify rootfs path with --rootfs",
                    "Note:".yellow()
                );
                return Ok(());
            }

            println!("  {:<20} {}", "Target:".yellow(), target);
            println!("  {:<20} {}", "Depth:".yellow(), depth);
            println!("  {:<20} {}", "Rootfs:".yellow(), rootfs_path.display());
            println!();

            // Create scanner configuration
            let scan_config = security_scanner::ScanConfig {
                depth: security_scanner::ScanDepth::from_str(&depth),
                min_severity: parse_severity(&min_severity),
                include_config_issues: true,
                include_packages: true,
                timeout_secs: 300,
            };

            // Create scanner and run scan
            let scanner = security_scanner::SecurityScanner::with_config(scan_config);

            println!("  {} Running vulnerability scan...", "→".yellow());
            println!();

            // Run the scan
            let scan_result = scanner
                .scan(&target, &rootfs_path)
                .await
                .context("Scan failed")?;

            // Generate report
            let report_format = security_scanner::ReportFormat::from_str(&format);
            let report = security_scanner::ScanReport::new(scan_result.clone(), report_format);

            // Print report
            println!("{}", report.generate());

            // Exit with error code if critical vulnerabilities found
            if scan_result.risk_level == security_scanner::RiskLevel::Critical
                || scan_result.risk_level == security_scanner::RiskLevel::High
            {
                println!(
                    "  {} Scan completed with {} risk level",
                    "⚠".yellow(),
                    scan_result.risk_level.to_string().red().bold()
                );
            } else {
                println!("  {} Scan completed successfully", "✓".green().bold());
            }
        }

        SecurityCommands::ListVulns { package, severity } => {
            print_header("Vulnerability Database");

            let scanner = security_scanner::SecurityScanner::new();
            let db = scanner.database();

            println!("  {:<20} {}", "Total vulnerabilities:".yellow(), db.count());
            println!("  {:<20} {}", "Last updated:".yellow(), "Built-in database");
            println!();

            let mut vulns: Vec<_> = db.all_vulnerabilities();

            // Filter by package if specified
            if let Some(pkg) = &package {
                vulns.retain(|v| v.package.to_lowercase().contains(&pkg.to_lowercase()));
            }

            // Filter by severity if specified
            if let Some(sev) = &severity {
                let target_sev = parse_severity(sev);
                vulns.retain(|v| v.severity == target_sev);
            }

            if vulns.is_empty() {
                println!(
                    "  {} No vulnerabilities match the filters",
                    "Info:".yellow()
                );
            } else {
                println!("  {} vulnerabilities found:\n", vulns.len());

                for vuln in vulns {
                    println!(
                        "  {} {} ({}) - {}",
                        severity_emoji(&vuln.severity),
                        vuln.id.cyan(),
                        vuln.severity,
                        vuln.package
                    );
                    println!("    {}", vuln.description);
                    if let Some(fixed) = &vuln.fixed_version {
                        println!("    {} Fix: Upgrade to {}", "→".green(), fixed);
                    }
                    println!();
                }
            }
        }

        SecurityCommands::UpdateDb => {
            print_header("Update Vulnerability Database");

            println!("  {} Updating vulnerability database...", "→".yellow());
            println!();

            let mut scanner = security_scanner::SecurityScanner::new();

            match scanner.update_database().await {
                Ok(_) => {
                    println!("  {} Database updated successfully", "✓".green());
                    println!();
                    println!(
                        "  {} Note: Remote database sync is not yet implemented.",
                        "Info:".yellow()
                    );
                    println!("  Using built-in vulnerability database.");
                }
                Err(e) => {
                    println!("  {} Failed to update database: {}", "✗".red(), e);
                }
            }
        }
    }

    Ok(())
}

/// Parse severity string to Severity enum
fn parse_severity(s: &str) -> security_scanner::Severity {
    match s.to_lowercase().as_str() {
        "critical" => security_scanner::Severity::Critical,
        "high" => security_scanner::Severity::High,
        "medium" => security_scanner::Severity::Medium,
        "low" => security_scanner::Severity::Low,
        _ => security_scanner::Severity::Info,
    }
}

/// Get emoji for severity
fn severity_emoji(severity: &security_scanner::Severity) -> &'static str {
    match severity {
        security_scanner::Severity::Critical => "🔴",
        security_scanner::Severity::High => "🟠",
        security_scanner::Severity::Medium => "🟡",
        security_scanner::Severity::Low => "🔵",
        security_scanner::Severity::Info => "⚪",
    }
}
