use security_scanner::*;
use security_scanner::{PackageSummary, ScanDepth, ScanResult};

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
        risk_level: RiskLevel::Safe,
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
