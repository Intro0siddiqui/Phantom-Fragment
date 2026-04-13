use zygote_rs::*;

#[test]
fn test_command_serialize() {
    let cmd = ZygoteCommand::new("/bin/echo".to_string())
        .args(vec!["hello".to_string(), "world".to_string()])
        .cwd("/tmp".to_string())
        .flags(0);

    let serialized = cmd.serialize().unwrap();
    assert!(!serialized.is_empty());

    assert_eq!(serialized[0..4], (serialized.len() as u32).to_le_bytes());
}

#[test]
fn test_command_serialize_with_env() {
    let cmd = ZygoteCommand::new("/bin/sh".to_string())
        .args(vec!["-c".to_string(), "echo $FOO".to_string()])
        .env("FOO", "bar")
        .cwd("/".to_string())
        .flags(0);

    let serialized = cmd.serialize().unwrap();
    assert!(!serialized.is_empty());
}

#[test]
fn test_pool_create() {
    let pool = ZygotePool::new(4);
    assert!(pool.is_ok());
    let pool = pool.expect("Failed to create zygote pool");
    assert!(pool.pool_size() > 0);
}

#[test]
fn test_pool_zero_size() {
    let pool = ZygotePool::new(0);
    assert!(pool.is_err());
}

#[test]
fn test_pool_spawn_and_execute() {
    let mut pool = ZygotePool::new(2).expect("Failed to create pool");

    let cmd = ZygoteCommand::new("/bin/echo".to_string())
        .args(vec!["test".to_string()])
        .cwd("/".to_string())
        .flags(0);

    let result = pool.execute(cmd);
    assert!(result.is_ok());

    let exit_status = result.unwrap();
    // Exit status 0 means success (exit code 0)
    assert_eq!(exit_status, 0);

    // Release the zygote back to the pool
    pool.release(exit_status);
}

#[test]
fn test_command_too_long() {
    let long_path = "/".repeat(5000);
    let cmd = ZygoteCommand::new(long_path);
    assert!(cmd.serialize().is_err());
}

#[test]
fn test_empty_args() {
    let cmd = ZygoteCommand::new("/bin/true".to_string())
        .cwd("/".to_string())
        .flags(0);

    let serialized = cmd.serialize().unwrap();
    assert!(!serialized.is_empty());
}
