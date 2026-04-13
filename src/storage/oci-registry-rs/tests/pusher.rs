use oci_registry_rs::*;

#[test]
fn test_push_config_default() {
    let config = PushConfig::default();
    assert_eq!(config.max_concurrent, 3);
    assert!(config.compress);
}
