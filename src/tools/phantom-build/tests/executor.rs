use phantom_build::executor::*;
use phantom_build::parser::Instruction;
use std::path::PathBuf;

#[test]
fn test_cache_key_generation() {
    let ctx = BuildContext::new(".");
    let executor = BuildExecutor::new(ctx);

    let inst1 = Instruction::Run {
        command: vec!["echo".to_string(), "hello".to_string()],
        mounts: vec![],
    };

    let inst2 = Instruction::Run {
        command: vec!["echo".to_string(), "world".to_string()],
        mounts: vec![],
    };

    let key1 = executor.calculate_cache_key(&inst1);
    let key2 = executor.calculate_cache_key(&inst2);

    // Different commands = different cache keys
    assert_ne!(key1, key2);
    assert!(key1.starts_with("sha256:"));
}

#[test]
fn test_build_context_creation() {
    let ctx = BuildContext::new("/tmp/test");
    assert_eq!(ctx.context_path, PathBuf::from("/tmp/test"));
    assert!(ctx.enable_cache);
    assert_eq!(ctx.workdir, PathBuf::from("/"));
}

#[test]
fn test_workdir_setting() {
    let ctx = BuildContext::new(".");
    let mut executor = BuildExecutor::new(ctx);

    // Simulate setting workdir
    executor.context.workdir = PathBuf::from("/app");
    assert_eq!(executor.context.workdir, PathBuf::from("/app"));
}

#[test]
fn test_substitute_vars_basic() {
    let ctx = BuildContext::new(".");
    let mut executor = BuildExecutor::new(ctx);
    executor
        .context
        .environment
        .insert("HOME".to_string(), "/root".to_string());

    let result = executor.substitute_vars("Path is $HOME/bin");
    assert_eq!(result, "Path is /root/bin");
}

#[test]
fn test_substitute_vars_with_build_arg() {
    let ctx = BuildContext::new(".");
    let mut executor = BuildExecutor::new(ctx);
    executor
        .context
        .build_args
        .insert("VERSION".to_string(), "1.2.3".to_string());

    let result = executor.substitute_vars("v${VERSION}");
    assert_eq!(result, "v1.2.3");
}

#[test]
fn test_substitute_vars_missing() {
    let ctx = BuildContext::new(".");
    let executor = BuildExecutor::new(ctx);

    // Missing variable should remain unchanged
    let result = executor.substitute_vars("$MISSING_VAR");
    assert_eq!(result, "$MISSING_VAR");
}

#[test]
fn test_copy_dir_recursive() {
    // Create temp directories
    let temp_dir = std::env::temp_dir().join(format!(
        "phantom_build_test_{}",
        std::process::id()
    ));
    let src_dir = temp_dir.join("src");
    let dst_dir = temp_dir.join("dst");

    // Clean up if exists from previous run
    let _ = std::fs::remove_dir_all(&temp_dir);

    // Create source structure
    std::fs::create_dir_all(src_dir.join("subdir")).unwrap();
    std::fs::write(src_dir.join("file1.txt"), "hello").unwrap();
    std::fs::write(src_dir.join("subdir").join("file2.txt"), "world").unwrap();

    // Run copy
    copy_dir_recursive(&src_dir, &dst_dir).unwrap();

    // Verify
    assert!(dst_dir.join("file1.txt").exists());
    assert!(dst_dir.join("subdir").join("file2.txt").exists());
    assert_eq!(
        std::fs::read_to_string(dst_dir.join("file1.txt")).unwrap(),
        "hello"
    );
    assert_eq!(
        std::fs::read_to_string(dst_dir.join("subdir").join("file2.txt")).unwrap(),
        "world"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_execute_copy_with_file() {
    // Create temp directories
    let temp_dir = std::env::temp_dir().join(format!(
        "phantom_copy_test_{}",
        std::process::id()
    ));
    let context_dir = temp_dir.join("context");
    let build_rootfs = temp_dir.join("rootfs");

    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&context_dir).unwrap();
    std::fs::create_dir_all(&build_rootfs).unwrap();

    // Create a source file in context
    std::fs::write(context_dir.join("app.txt"), "test content").unwrap();

    // Create build context
    let mut ctx = BuildContext::new(&context_dir);
    ctx.build_rootfs = build_rootfs.clone();

    let mut executor = BuildExecutor::new(ctx);

    // Execute copy instruction
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        executor
            .execute_copy(None, "app.txt", "/dest/app.txt")
            .await
            .unwrap();
    });

    // Verify file was copied
    let dest_file = build_rootfs.join("dest/app.txt");
    assert!(dest_file.exists());
    assert_eq!(std::fs::read_to_string(&dest_file).unwrap(), "test content");

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}
