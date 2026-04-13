use security_scanner::*;
use tempfile::TempDir;

#[test]
fn test_analyzer_creation() {
    let temp_dir = TempDir::new().unwrap();
    let analyzer = ImageAnalyzer::new(temp_dir.path());
    assert_eq!(analyzer.rootfs_path, temp_dir.path());
}
