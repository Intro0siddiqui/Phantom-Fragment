use security_scanner::*;

#[test]
fn test_severity_scoring() {
    assert_eq!(Severity::Critical.score(), 10.0);
    assert_eq!(Severity::High.score(), 7.5);
    assert_eq!(Severity::Medium.score(), 5.0);
    assert_eq!(Severity::Low.score(), 2.5);
    assert_eq!(Severity::Info.score(), 0.5);
}

#[test]
fn test_severity_from_cvss() {
    assert_eq!(Severity::from_cvss(9.5), Severity::Critical);
    assert_eq!(Severity::from_cvss(7.5), Severity::High);
    assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
    assert_eq!(Severity::from_cvss(2.0), Severity::Low);
    assert_eq!(Severity::from_cvss(0.5), Severity::Info);
}

#[test]
fn test_vulnerability_lookup() {
    let db = VulnerabilityDatabase::new();
    let vulns = db.get_vulnerabilities("openssl", "1.1.1");
    assert!(!vulns.is_empty());
}

#[test]
fn test_vulnerability_by_id() {
    let db = VulnerabilityDatabase::new();
    let vuln = db.get_by_id("CVE-2024-0001");
    assert!(vuln.is_some());
    assert_eq!(vuln.unwrap().package, "openssl");
}
