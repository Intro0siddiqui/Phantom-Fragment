use types_rs::*;

#[test]
fn test_rust_fragment_metadata_serde() {
    let meta = RustFragmentMetadata {
        id: "test-1".to_string(),
        name: "test".to_string(),
        version: "1.0.0".to_string(),
        description: Some("A test".to_string()),
    };
    let json = serde_json::to_string(&meta).unwrap();
    let restored: RustFragmentMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.id, "test-1");
    assert_eq!(restored.name, "test");
}

#[test]
fn test_fragment_state_variants() {
    let _loaded = FragmentState::Loaded;
    let _running = FragmentState::Running;
    let _completed = FragmentState::Completed;
    let _failed = FragmentState::Failed("error".to_string());

    // All variants should be distinct
    assert!(!format!("{:?}", FragmentState::Loaded).contains("Failed"));
    assert!(!format!("{:?}", FragmentState::Failed("x".to_string())).contains("Loaded"));
}

#[test]
fn test_execution_result_serde() {
    let result = ExecutionResult {
        output: "hello world".to_string(),
        exit_code: 0,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ExecutionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.output, "hello world");
    assert_eq!(restored.exit_code, 0);
}
