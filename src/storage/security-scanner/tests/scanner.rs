use security_scanner::*;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_scanner_creation() {
    let scanner = SecurityScanner::new();
    assert_eq!(scanner.config.depth, ScanDepth::Standard);
}

#[tokio::test]
async fn test_scan_empty_rootfs() {
    let temp_dir = TempDir::new().unwrap();
    let scanner = SecurityScanner::new();

    let result = scanner.scan("test:latest", temp_dir.path()).await.unwrap();
    assert_eq!(result.image_ref, "test:latest");
    assert_eq!(result.risk_level, RiskLevel::Safe);
}

#[tokio::test]
async fn test_scan_with_alpine_structure() {
    let temp_dir = TempDir::new().unwrap();

    // Create Alpine-like structure
    fs::create_dir_all(temp_dir.path().join("lib/apk/db")).unwrap();
    fs::create_dir_all(temp_dir.path().join("etc")).unwrap();
    fs::write(
        temp_dir.path().join("lib/apk/db/installed"),
        "P:busybox\nV:1.35.0\no:desc\n\nP:openssl\nV:1.1.1\no:desc\n\n",
    )
    .unwrap();
    fs::write(temp_dir.path().join("etc/alpine-release"), "3.18.0").unwrap();

    let scanner = SecurityScanner::new();
    let result = scanner.scan("alpine:3.18", temp_dir.path()).await.unwrap();

    assert!(result.package_summary.total_packages > 0);
}

#[test]
fn test_risk_level_from_score() {
    assert_eq!(RiskLevel::from_score(90.0), RiskLevel::Critical);
    assert_eq!(RiskLevel::from_score(70.0), RiskLevel::High);
    assert_eq!(RiskLevel::from_score(50.0), RiskLevel::Medium);
    assert_eq!(RiskLevel::from_score(30.0), RiskLevel::Low);
    assert_eq!(RiskLevel::from_score(10.0), RiskLevel::Safe);
}

#[test]
fn test_scan_depth_from_str() {
    assert_eq!(ScanDepth::from_str("quick"), ScanDepth::Quick);
    assert_eq!(ScanDepth::from_str("standard"), ScanDepth::Standard);
    assert_eq!(ScanDepth::from_str("deep"), ScanDepth::Deep);
    assert_eq!(ScanDepth::from_str("unknown"), ScanDepth::Standard);
}
