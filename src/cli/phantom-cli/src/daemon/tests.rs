//! Integration Tests for Socket-based Warm Fragment Daemon
//!
//! This module contains integration tests for the warm daemon functionality.
//! Tests cover daemon lifecycle, command execution, security validation,
//! cgroup cleanup, and concurrent request handling.
//!
//! Note: Some tests require root privileges or specific capabilities and
//! are marked with #[ignore]. Run with `cargo test -- --ignored` to execute them.

mod supervisor;
mod warm;
mod registry;
mod permission;

#[cfg(test)]
mod tests {
    use crate::daemon::warm::{
        exec_in_daemon, is_safe_command, DaemonConfig, ExecRequest, ExecResponse, Message,
        MessageType, WarmDaemon,
    };
    use execution_rs::HardwareProfile;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    /// Create a temporary directory and socket path for testing
    fn setup_test_env(test_name: &str) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let socket_path = temp_dir.path().join(format!("{}.sock", test_name));
        (temp_dir, socket_path)
    }

    /// Create a default daemon configuration for testing
    fn create_test_config(socket_path: PathBuf, rootfs_path: PathBuf) -> DaemonConfig {
        DaemonConfig {
            socket_path,
            rootfs_path,
            hardware_profile: None,
            metrics_port: 9090,
        }
    }

    /// Start a daemon in a background thread and return the join handle
    fn start_daemon_background_thread(
        mut daemon: WarmDaemon,
    ) -> thread::JoinHandle<Result<(), anyhow::Error>> {
        thread::spawn(move || daemon.run_test_loop())
    }

    /// Wait for socket to become available
    fn wait_for_socket(socket_path: &Path, timeout_ms: u64) -> Result<(), String> {
        let start = std::time::Instant::now();
        while start.elapsed().as_millis() < timeout_ms as u128 {
            if socket_path.exists() {
                // Try to connect to verify it's actually listening
                if UnixStream::connect(socket_path).is_ok() {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err(format!(
            "Socket {:?} did not become available within {}ms",
            socket_path, timeout_ms
        ))
    }

    /// Send an exec request and receive response
    fn send_exec_request(
        socket_path: &Path,
        command: &str,
        args: Vec<String>,
    ) -> Result<ExecResponse, anyhow::Error> {
        let request = ExecRequest {
            command: command.to_string(),
            args,
            env: HashMap::new(),
            cwd: None,
            hardware_profile: None,
        };
        exec_in_daemon(socket_path, &request)
    }

    /// Create a simple test rootfs directory with basic executables
    fn create_test_rootfs(temp_dir: &TempDir) -> PathBuf {
        let rootfs = temp_dir.path().join("rootfs");
        fs::create_dir_all(&rootfs).expect("Failed to create rootfs");
        fs::create_dir_all(rootfs.join("bin")).expect("Failed to create bin");

        // Create /bin/true mock
        let bin_true = rootfs.join("bin/true");
        fs::write(&bin_true, "#!/bin/sh\nexit 0\n").expect("Failed to write /bin/true");

        // Create /bin/false mock
        let bin_false = rootfs.join("bin/false");
        fs::write(&bin_false, "#!/bin/sh\nexit 1\n").expect("Failed to write /bin/false");

        // Create /bin/echo mock
        let bin_echo = rootfs.join("bin/echo");
        fs::write(&bin_echo, "#!/bin/sh\necho \"$@\"\nexit 0\n")
            .expect("Failed to write /bin/echo");

        // Create /bin/pwd mock
        let bin_pwd = rootfs.join("bin/pwd");
        fs::write(&bin_pwd, "#!/bin/sh\npwd\nexit 0\n").expect("Failed to write /bin/pwd");

        // Create /bin/sh mock (just a copy of bin_true for basic testing)
        let bin_sh = rootfs.join("bin/sh");
        fs::copy(&bin_true, &bin_sh).expect("Failed to copy /bin/sh");

        // Make them executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for bin in &[&bin_true, &bin_false, &bin_echo, &bin_pwd, &bin_sh] {
                let mut perms = fs::metadata(bin).unwrap().permissions();
                perms.set_mode(0o755);
                fs::set_permissions(bin, perms).unwrap();
            }
        }

        // Create a simple test script that we can execute
        let test_script = rootfs.join("test_echo.sh");
        fs::write(&test_script, "#!/bin/sh\necho \"test output\"\nexit 0\n")
            .expect("Failed to write test script");

        // Make it executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&test_script).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&test_script, perms).unwrap();
        }

        rootfs
    }

    // ========================================================================
    // Test 1: test_daemon_start_stop
    // ========================================================================

    /// Test that the daemon can be started, socket exists, and stopped cleanly
    #[test]
    fn test_daemon_start_stop() {
        let (temp_dir, socket_path) = setup_test_env("test_daemon_start_stop");
        let rootfs = create_test_rootfs(&temp_dir);

        let config = create_test_config(socket_path.clone(), rootfs);
        let daemon = WarmDaemon::new(config).expect("Failed to create daemon");

        // Start daemon in background thread
        let handle = start_daemon_background_thread(daemon);

        // Wait for socket
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // Test 1: Execute /bin/true (should return exit code 0)
        let response = send_exec_request(&socket_path, "/bin/true", vec![])
            .expect("Failed to send exec request");
        assert_eq!(response.exit_code, 0, "/bin/true should exit with code 0");
        assert!(
            response.error.is_none(),
            "Should not have error for /bin/true"
        );

        // Test 2: Execute /bin/false (should return exit code 1)
        let response = send_exec_request(&socket_path, "/bin/false", vec![])
            .expect("Failed to send exec request");
        assert_eq!(response.exit_code, 1, "/bin/false should exit with code 1");

        // Test 3: Execute echo with arguments
        let response = send_exec_request(
            &socket_path,
            "/bin/echo",
            vec!["hello".to_string(), "world".to_string()],
        )
        .expect("Failed to send exec request");
        assert_eq!(response.exit_code, 0, "echo should succeed");

        // Test 4: Execute non-existent command (should fail)
        let response = send_exec_request(&socket_path, "/nonexistent/command", vec![])
            .expect("Failed to send exec request");
        assert_eq!(
            response.exit_code, 127,
            "Non-existent command should return 127"
        );
        assert!(
            response.error.is_some(),
            "Should have error for non-existent command"
        );

        // Shutdown daemon
        {
            let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect");
            let shutdown_msg = Message::new(MessageType::Shutdown, vec![]);
            let data = shutdown_msg.serialize().expect("Failed to serialize");
            stream.write_all(&data).expect("Failed to send shutdown");
        }

        thread::sleep(Duration::from_millis(100));
        let _ = handle.join();
    }

    // ========================================================================
    // Test 3: test_invalid_command
    // ========================================================================

    /// Test that commands with unsafe characters are rejected
    #[test]
    fn test_invalid_command() {
        let (temp_dir, socket_path) = setup_test_env("test_invalid_command");
        let rootfs = create_test_rootfs(&temp_dir);

        let config = create_test_config(socket_path.clone(), rootfs);
        let daemon = WarmDaemon::new(config).expect("Failed to create daemon");

        // Start daemon in background
        let handle = start_daemon_background_thread(daemon);

        // Wait for socket
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // Test command injection attempts - these should all be rejected

        // Test 1: Semicolon injection
        let request = ExecRequest {
            command: "/bin/echo; rm -rf /".to_string(),
            args: vec![],
            env: HashMap::new(),
            cwd: None,
            hardware_profile: None,
        };
        let response = exec_in_daemon(&socket_path, &request).expect("Request should be processed");
        assert!(
            response.error.is_some(),
            "Semicolon injection should be rejected"
        );
        assert!(
            response.error.as_ref().unwrap().contains("unsafe"),
            "Error should mention unsafe characters"
        );

        // Test 2: Pipe injection
        let request = ExecRequest {
            command: "/bin/echo | cat".to_string(),
            args: vec![],
            env: HashMap::new(),
            cwd: None,
            hardware_profile: None,
        };
        let response = exec_in_daemon(&socket_path, &request).expect("Request should be processed");
        assert!(
            response.error.is_some(),
            "Pipe injection should be rejected"
        );

        // Test 3: Backtick injection
        let request = ExecRequest {
            command: "/bin/echo `whoami`".to_string(),
            args: vec![],
            env: HashMap::new(),
            cwd: None,
            hardware_profile: None,
        };
        let response = exec_in_daemon(&socket_path, &request).expect("Request should be processed");
        assert!(
            response.error.is_some(),
            "Backtick injection should be rejected"
        );

        // Test 4: Dollar sign injection
        let request = ExecRequest {
            command: "/bin/echo $(id)".to_string(),
            args: vec![],
            env: HashMap::new(),
            cwd: None,
            hardware_profile: None,
        };
        let response = exec_in_daemon(&socket_path, &request).expect("Request should be processed");
        assert!(
            response.error.is_some(),
            "Dollar sign injection should be rejected"
        );

        // Test 5: Ampersand injection
        let request = ExecRequest {
            command: "/bin/echo & rm -rf /".to_string(),
            args: vec![],
            env: HashMap::new(),
            cwd: None,
            hardware_profile: None,
        };
        let response = exec_in_daemon(&socket_path, &request).expect("Request should be processed");
        assert!(
            response.error.is_some(),
            "Ampersand injection should be rejected"
        );

        // Test 6: Redirect injection
        let request = ExecRequest {
            command: "/bin/echo > /etc/passwd".to_string(),
            args: vec![],
            env: HashMap::new(),
            cwd: None,
            hardware_profile: None,
        };
        let response = exec_in_daemon(&socket_path, &request).expect("Request should be processed");
        assert!(
            response.error.is_some(),
            "Redirect injection should be rejected"
        );

        // Test 7: Valid command should still work
        let response = send_exec_request(&socket_path, "/bin/echo", vec!["safe".to_string()])
            .expect("Valid request should succeed");
        assert_eq!(response.exit_code, 0, "Valid command should succeed");
        assert!(
            response.error.is_none(),
            "Valid command should have no error"
        );

        // Shutdown daemon
        {
            let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect");
            let shutdown_msg = Message::new(MessageType::Shutdown, vec![]);
            let data = shutdown_msg.serialize().expect("Failed to serialize");
            stream.write_all(&data).expect("Failed to send shutdown");
        }

        thread::sleep(Duration::from_millis(100));
        let _ = handle.join();
    }

    // ========================================================================
    // Test 4: test_cgroup_cleanup
    // ========================================================================

    /// Test that cgroups are cleaned up after command execution
    ///
    /// This test requires root privileges to create cgroups.
    /// Run with: cargo test -- --ignored --nocapture
    #[test]
    #[ignore = "Requires root privileges to create cgroups"]
    fn test_cgroup_cleanup() {
        let (temp_dir, socket_path) = setup_test_env("test_cgroup_cleanup");
        let rootfs = create_test_rootfs(&temp_dir);

        // Create config with hardware profile to trigger cgroup creation
        let hardware_profile = Some(HardwareProfile {
            cpu_affinity: None,
            numa_node: None,
            cpu_count: 1,
            memory_mb: 64,
        });

        let config = DaemonConfig {
            socket_path: socket_path.clone(),
            rootfs_path: rootfs,
            hardware_profile,
            metrics_port: 9090,
        };

        let daemon = WarmDaemon::new(config).expect("Failed to create daemon");

        // Start daemon in background
        let handle = start_daemon_background_thread(daemon);

        // Wait for socket
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // Get list of cgroups before execution
        let cgroup_base = PathBuf::from("/sys/fs/cgroup");
        let cgroups_before = list_phantom_cgroups(&cgroup_base);

        // Execute a command with hardware profile
        let request = ExecRequest {
            command: "/bin/true".to_string(),
            args: vec![],
            env: HashMap::new(),
            cwd: None,
            hardware_profile: None,
        };

        let response = exec_in_daemon(&socket_path, &request)
            .expect("Failed to send exec request with cgroup");
        assert_eq!(response.exit_code, 0, "Command should succeed");

        // Give cgroup cleanup time
        thread::sleep(Duration::from_millis(200));

        // Get list of cgroups after execution
        let cgroups_after = list_phantom_cgroups(&cgroup_base);

        // Verify no new phantom cgroups remain
        let new_cgroups: Vec<_> = cgroups_after
            .iter()
            .filter(|c| !cgroups_before.contains(c))
            .collect();

        assert!(
            new_cgroups.is_empty(),
            "All phantom cgroups should be cleaned up. Remaining: {:?}",
            new_cgroups
        );

        // Execute multiple commands and verify cleanup
        for i in 0..5 {
            let request = ExecRequest {
                command: "/bin/echo".to_string(),
                args: vec![format!("test_{}", i)],
                env: HashMap::new(),
                cwd: None,
                hardware_profile: None,
            };
            let _ = exec_in_daemon(&socket_path, &request);
            thread::sleep(Duration::from_millis(50));
        }

        thread::sleep(Duration::from_millis(300));

        let cgroups_final = list_phantom_cgroups(&cgroup_base);
        let leaked_cgroups: Vec<_> = cgroups_final
            .iter()
            .filter(|c| !cgroups_before.contains(c))
            .collect();

        assert!(
            leaked_cgroups.is_empty(),
            "No cgroups should leak after multiple executions. Leaked: {:?}",
            leaked_cgroups
        );

        // Shutdown daemon
        {
            let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect");
            let shutdown_msg = Message::new(MessageType::Shutdown, vec![]);
            let data = shutdown_msg.serialize().expect("Failed to serialize");
            stream.write_all(&data).expect("Failed to send shutdown");
        }

        thread::sleep(Duration::from_millis(100));
        let _ = handle.join();
    }

    /// Helper to list phantom-related cgroups
    fn list_phantom_cgroups(base: &Path) -> Vec<String> {
        let mut cgroups = Vec::new();

        if let Ok(entries) = fs::read_dir(base) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("phantom_") || name.starts_with("phantom_warm_") {
                        cgroups.push(name.to_string());
                    }
                }
            }
        }

        cgroups
    }

    // ========================================================================
    // Test 5: test_concurrent_requests
    // ========================================================================

    /// Test handling multiple concurrent client requests
    #[test]
    fn test_concurrent_requests() {
        let (temp_dir, socket_path) = setup_test_env("test_concurrent_requests");
        let rootfs = create_test_rootfs(&temp_dir);

        let config = create_test_config(socket_path.clone(), rootfs);
        let mut daemon = WarmDaemon::new(config).expect("Failed to create daemon");

        // Start daemon in background
        let handle = start_daemon_background_thread(daemon);

        // Wait for socket
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // Number of concurrent clients
        let num_clients = 10;
        let barrier = Arc::new(Barrier::new(num_clients));
        let results: Arc<Mutex<Vec<(usize, i32, Option<String>)>>> =
            Arc::new(Mutex::new(Vec::new()));

        // Spawn concurrent clients
        let mut handles = Vec::new();
        for i in 0..num_clients {
            let socket_path_cloned = socket_path.clone();
            let barrier = Arc::clone(&barrier);
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                // Wait for all threads to be ready
                barrier.wait();

                // Each client sends a request
                let request = ExecRequest {
                    command: "/bin/echo".to_string(),
                    args: vec![format!("client_{}", i)],
                    env: HashMap::new(),
                    cwd: None,
                    hardware_profile: None,
                };

                match exec_in_daemon(&socket_path_cloned, &request) {
                    Ok(response) => {
                        results
                            .lock()
                            .unwrap()
                            .push((i, response.exit_code, response.error));
                    }
                    Err(e) => {
                        results.lock().unwrap().push((i, -1, Some(e.to_string())));
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all clients to complete
        for handle in handles {
            handle.join().expect("Client thread should complete");
        }

        // Verify all requests were processed
        let results = results.lock().unwrap();
        assert_eq!(
            results.len(),
            num_clients,
            "All {} clients should receive responses",
            num_clients
        );

        // Verify all successful responses
        for (client_id, exit_code, error) in results.iter() {
            assert_eq!(
                *exit_code, 0,
                "Client {} should receive successful response",
                client_id
            );
            assert!(
                error.is_none(),
                "Client {} should not have error",
                client_id
            );
        }

        // Test rapid sequential requests from same client
        for i in 0..20 {
            let response = send_exec_request(&socket_path, "/bin/true", vec![])
                .expect("Sequential request should succeed");
            assert_eq!(response.exit_code, 0, "Request {} should succeed", i);
        }

        // Shutdown daemon
        {
            let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect");
            let shutdown_msg = Message::new(MessageType::Shutdown, vec![]);
            let data = shutdown_msg.serialize().expect("Failed to serialize");
            stream.write_all(&data).expect("Failed to send shutdown");
        }

        thread::sleep(Duration::from_millis(100));
        let _ = handle.join();
    }

    // ========================================================================
    // Additional Unit Tests for Helper Functions
    // ========================================================================

    /// Test the is_safe_command function directly
    #[test]
    fn test_is_safe_command() {
        // Valid commands
        assert!(is_safe_command("/bin/echo"));
        assert!(is_safe_command("/usr/bin/python3"));
        assert!(is_safe_command("echo hello"));
        assert!(is_safe_command("/bin/ls -la"));
        assert!(is_safe_command("my_command"));
        assert!(is_safe_command("test+value=123"));

        // Invalid commands (injection attempts)
        assert!(!is_safe_command("/bin/echo; rm -rf /"));
        assert!(!is_safe_command("/bin/echo | cat"));
        assert!(!is_safe_command("/bin/echo `whoami`"));
        assert!(!is_safe_command("/bin/echo $(id)"));
        assert!(!is_safe_command("/bin/echo & background"));
        assert!(!is_safe_command("/bin/echo > file"));
        assert!(!is_safe_command("/bin/echo < file"));
        assert!(!is_safe_command("/bin/echo && next"));
        assert!(!is_safe_command("/bin/echo || fallback"));
        assert!(!is_safe_command("/bin/echo $VAR"));
        assert!(!is_safe_command(""));

        // Edge cases
        assert!(!is_safe_command("")); // Empty string
    }

    /// Test message serialization and deserialization
    #[test]
    fn test_message_serialization() {
        let original = Message::new(MessageType::Exec, vec![1, 2, 3, 4, 5]);
        let serialized = original.serialize().expect("Should serialize");

        let deserialized = Message::deserialize(&serialized).expect("Should deserialize");

        assert_eq!(original.msg_type, deserialized.msg_type);
        assert_eq!(original.payload, deserialized.payload);
    }

    /// Test health check functionality
    #[test]
    fn test_health_check() {
        let (temp_dir, socket_path) = setup_test_env("test_health_check");
        let rootfs = create_test_rootfs(&temp_dir);

        let config = create_test_config(socket_path.clone(), rootfs);
        let daemon = WarmDaemon::new(config).expect("Failed to create daemon");

        // Start daemon in background
        let handle = start_daemon_background_thread(daemon);

        // Wait for socket
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // Send health check
        {
            let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect");

            let health_msg = Message::new(MessageType::HealthCheck, vec![]);
            let data = health_msg.serialize().expect("Failed to serialize");
            stream
                .write_all(&data)
                .expect("Failed to send health check");

            // Read response
            let mut header = [0u8; 10];
            stream
                .read_exact(&mut header)
                .expect("Failed to read header");

            let msg_type = MessageType::from(header[5]);
            assert_eq!(msg_type, MessageType::HealthResponse);

            let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;
            let mut response = vec![0u8; length];
            stream
                .read_exact(&mut response)
                .expect("Failed to read response");

            let response_str = String::from_utf8_lossy(&response);
            assert!(
                response_str.contains("OK"),
                "Health response should contain OK"
            );
            assert!(
                response_str.contains("pid="),
                "Health response should contain PID"
            );
        }

        // Shutdown daemon
        {
            let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect");
            let shutdown_msg = Message::new(MessageType::Shutdown, vec![]);
            let data = shutdown_msg.serialize().expect("Failed to serialize");
            stream.write_all(&data).expect("Failed to send shutdown");
        }

        thread::sleep(Duration::from_millis(100));
        let _ = handle.join();
    }

    /// Test exec request with environment variables
    #[test]
    fn test_exec_with_env() {
        let (temp_dir, socket_path) = setup_test_env("test_exec_with_env");
        let rootfs = create_test_rootfs(&temp_dir);

        let config = create_test_config(socket_path.clone(), rootfs);
        let daemon = WarmDaemon::new(config).expect("Failed to create daemon");

        // Start daemon in background
        let handle = start_daemon_background_thread(daemon);

        // Wait for socket
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // Create request with environment variables
        let mut env = HashMap::new();
        env.insert("TEST_VAR".to_string(), "test_value".to_string());
        env.insert("PHANTOM_TEST".to_string(), "1".to_string());

        let request = ExecRequest {
            command: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "exit 0".to_string()],
            env,
            cwd: None,
            hardware_profile: None,
        };

        let response =
            exec_in_daemon(&socket_path, &request).expect("Request with env should succeed");
        assert_eq!(response.exit_code, 0);

        // Shutdown daemon
        {
            let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect");
            let shutdown_msg = Message::new(MessageType::Shutdown, vec![]);
            let data = shutdown_msg.serialize().expect("Failed to serialize");
            stream.write_all(&data).expect("Failed to send shutdown");
        }

        thread::sleep(Duration::from_millis(100));
        let _ = handle.join();
    }

    /// Test exec request with working directory
    #[test]
    fn test_exec_with_cwd() {
        let (temp_dir, socket_path) = setup_test_env("test_exec_with_cwd");
        let rootfs = create_test_rootfs(&temp_dir);

        // Create a subdirectory in rootfs
        let subdir = rootfs.join("subdir");
        fs::create_dir_all(&subdir).expect("Failed to create subdir");

        let config = create_test_config(socket_path.clone(), rootfs);
        let daemon = WarmDaemon::new(config).expect("Failed to create daemon");

        // Start daemon in background
        let handle = start_daemon_background_thread(daemon);

        // Wait for socket
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // Execute pwd in the subdirectory
        let request = ExecRequest {
            command: "/bin/pwd".to_string(),
            args: vec![],
            env: HashMap::new(),
            cwd: Some(subdir.to_string_lossy().to_string()),
            hardware_profile: None,
        };

        let response =
            exec_in_daemon(&socket_path, &request).expect("Request with cwd should succeed");
        assert_eq!(response.exit_code, 0);

        // Shutdown daemon
        {
            let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect");
            let shutdown_msg = Message::new(MessageType::Shutdown, vec![]);
            let data = shutdown_msg.serialize().expect("Failed to serialize");
            stream.write_all(&data).expect("Failed to send shutdown");
        }

        thread::sleep(Duration::from_millis(100));
        let _ = handle.join();
    }
}
