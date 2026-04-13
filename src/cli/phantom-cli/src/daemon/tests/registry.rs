use crate::fragment_registry::*;
use tempfile::TempDir;

#[test]
fn test_registry_create_and_list() {
    let temp_dir = TempDir::new().unwrap();
    let registry_path = temp_dir.path().join("registry.json");
    let mut registry = FragmentRegistry::with_path(&registry_path).unwrap();

    let info = FragmentInfo {
        name: "test-fragment".to_string(),
        profile: "sandbox".to_string(),
        pid: Some(12345),
        created_at: 1234567890,
        status: FragmentStatus::Running,
        components: vec!["tcp".to_string(), "dns".to_string()],
        memory_kb: 8192,
        cpu_count: None,
        mode: "sandbox".to_string(),
        last_validated: None,
        image: None,
    };

    registry.register(info.clone()).unwrap();

    let listed = registry.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "test-fragment");
}

#[test]
fn test_registry_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let registry_path = temp_dir.path().join("registry.json");

    {
        let mut registry = FragmentRegistry::with_path(&registry_path).unwrap();
        let info = FragmentInfo {
            name: "persistent-fragment".to_string(),
            profile: "direct".to_string(),
            pid: Some(99999),
            created_at: 1234567890,
            status: FragmentStatus::Running,
            components: vec![],
            memory_kb: 4096,
            cpu_count: None,
            mode: "direct".to_string(),
            last_validated: None,
            image: None,
        };
        registry.register(info).unwrap();
    }

    // Reload and verify
    let registry = FragmentRegistry::with_path(&registry_path).unwrap();
    assert_eq!(registry.list().len(), 1);
    assert_eq!(
        registry.get("persistent-fragment").unwrap().pid,
        Some(99999)
    );
}

#[test]
#[ignore = "cleanup_old method not implemented"]
fn test_cleanup_old() {
    // This test requires the cleanup_old method which is not yet implemented.
    // When implemented, it should:
    // 1. Create a registry with old stopped and recent running fragments
    // 2. Call cleanup_old with a max age (e.g., 3600 seconds)
    // 3. Verify old stopped fragments are removed
    // 4. Verify recent running fragments remain
    panic!("cleanup_old method not implemented - this test is a placeholder");
}
