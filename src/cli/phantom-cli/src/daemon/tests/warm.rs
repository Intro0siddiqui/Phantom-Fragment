//! Tests for warm daemon message parsing and helper functions
//!
//! Extracted from inline #[cfg(test)] modules in src/daemon/warm.rs

use crate::daemon::warm::*;
use std::collections::HashMap;

#[test]
fn test_message_serialize_deserialize() {
    let msg = Message::new(MessageType::Exec, vec![1, 2, 3, 4]);
    let serialized = msg.serialize().unwrap();
    let deserialized = Message::deserialize(&serialized).unwrap();

    assert_eq!(msg.msg_type, deserialized.msg_type);
    assert_eq!(msg.payload, deserialized.payload);
}

#[test]
fn test_is_safe_command() {
    assert!(is_safe_command("/bin/echo"));
    assert!(is_safe_command("ls -la"));
    assert!(is_safe_command("cat /etc/passwd"));
    assert!(!is_safe_command("ls; rm -rf /"));
    assert!(!is_safe_command("echo `whoami`"));
    assert!(!is_safe_command("cat $(cat /etc/shadow)"));
}

#[test]
fn test_exec_request_parse() {
    let request = ExecRequest {
        command: "/bin/echo".to_string(),
        args: vec!["hello".to_string(), "world".to_string()],
        env: HashMap::new(),
        cwd: Some("/tmp".to_string()),
        hardware_profile: None,
    };

    assert_eq!(request.command, "/bin/echo");
    assert_eq!(request.args.len(), 2);
}
