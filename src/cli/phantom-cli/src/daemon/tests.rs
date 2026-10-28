//! Integration Tests for Socket-based Warm Fragment Daemon
//!
//! This module contains integration tests for the warm daemon functionality.
//! Tests cover daemon lifecycle, command execution, security validation,
//! cgroup cleanup, and concurrent request handling.
//!
//! Note: Some tests require root privileges or specific capabilities and
//! are marked with #[ignore]. Run with `cargo test -- --ignored` to execute them.

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::daemon::warm::{
        exec_in_daemon, is_safe_command, ping_daemon, read_message, write_message, DaemonConfig,
        ExecRequest, ExecResponse, Message, MessageType, WarmDaemon,
    };
    use execution_rs::HardwareProfile;

    use std::collections::HashMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
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

    /// Send the shutdown message and wait for the daemon thread to finish.
    fn shutdown_daemon(socket_path: &Path, handle: thread::JoinHandle<Result<(), anyhow::Error>>) {
        {
            let mut stream = UnixStream::connect(socket_path).expect("Failed to connect");
            let shutdown_msg = Message::new(MessageType::Shutdown, vec![]);
            let data = shutdown_msg.serialize().expect("Failed to serialize");
            stream.write_all(&data).expect("Failed to send shutdown");
        }

        thread::sleep(Duration::from_millis(100));
        let _ = handle.join();
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

    /// Copy a host file into the test rootfs at the same absolute path,
    /// creating parent directories and marking the copy executable.
    fn copy_host_file(rootfs: &Path, source: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let destination = rootfs.join(source.strip_prefix("/").expect("source must be absolute"));
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("Failed to create {:?}: {}", parent, e));
        }
        fs::copy(source, &destination)
            .unwrap_or_else(|e| panic!("Failed to copy {:?} to {:?}: {}", source, destination, e));

        let mut perms = fs::metadata(&destination).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&destination, perms).unwrap();
    }

    /// Create a simple test rootfs directory with basic executables.
    ///
    /// The mock commands are `#!/bin/sh` scripts, so the rootfs needs a real
    /// interpreter: after chroot(2) the host's /bin/sh is no longer reachable.
    /// Copy dash plus the dynamic loader and libc at their absolute paths.
    fn create_test_rootfs(temp_dir: &TempDir) -> PathBuf {
        let rootfs = temp_dir.path().join("rootfs");
        fs::create_dir_all(&rootfs).expect("Failed to create rootfs");
        fs::create_dir_all(rootfs.join("bin")).expect("Failed to create bin");

        // Real /bin/sh and its runtime dependencies. `ldd /bin/sh` on this
        // glibc box reports libc.so.6 and the /lib64 loader; glibc's built-in
        // search path here is /usr/lib64, while ldd reports /usr/lib, so install
        // libc under both names.
        copy_host_file(&rootfs, Path::new("/bin/sh"));
        copy_host_file(&rootfs, Path::new("/lib64/ld-linux-x86-64.so.2"));
        copy_host_file(&rootfs, Path::new("/usr/lib64/libc.so.6"));
        copy_host_file(&rootfs, Path::new("/usr/lib/libc.so.6"));

        // Create /bin/true mock
        let bin_true = rootfs.join("bin/true");
        fs::write(&bin_true, "#!/bin/sh\nexit 0\n").expect("Failed to write /bin/true");

        // Create /bin/false mock
        let bin_false = rootfs.join("bin/false");
        fs::write(&bin_false, "#!/bin/sh\nexit 1\n").expect("Failed to write /bin/false");

        // Create /bin/echo mock. The marker argument proves that this script
        // (not the host's /bin/echo) ran.
        let bin_echo = rootfs.join("bin/echo");
        fs::write(
            &bin_echo,
            "#!/bin/sh\nif [ \"$1\" = \"__phantom_rootfs_probe__\" ]; then\n  exit 42\nfi\necho \"$@\"\nexit 0\n",
        )
        .expect("Failed to write /bin/echo");

        // Create /bin/pwd mock: records the cwd inside the chroot.
        let bin_pwd = rootfs.join("bin/pwd");
        fs::write(&bin_pwd, "#!/bin/sh\npwd > /cwd.txt\nexit 0\n")
            .expect("Failed to write /bin/pwd");

        // Create /bin/fs-probe mock: succeeds only when host-only files are
        // invisible, i.e. when the process really is chrooted.
        let bin_fs_probe = rootfs.join("bin/fs-probe");
        fs::write(
            &bin_fs_probe,
            "#!/bin/sh\nif [ -e /etc/os-release ]; then\n  exit 1\nfi\nexit 0\n",
        )
        .expect("Failed to write /bin/fs-probe");

        // Make them executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for bin in &[&bin_true, &bin_false, &bin_echo, &bin_pwd, &bin_fs_probe] {
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
        let daemon = WarmDaemon::new(config).expect("Failed to create daemon");

        // Start daemon in background
        let handle = start_daemon_background_thread(daemon);

        // Wait for socket
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // Number of concurrent clients
        let num_clients = 10;
        let barrier = Arc::new(Barrier::new(num_clients));
        type ClientResults = Arc<std::sync::Mutex<Vec<(usize, i32, Option<String>)>>>;
        let results: ClientResults = Arc::new(std::sync::Mutex::new(Vec::new()));

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

    // ========================================================================
    // Chroot isolation tests
    // ========================================================================

    /// Regression test: the binary inside the rootfs must be the one that runs.
    ///
    /// A bare `echo` must resolve through the rootfs PATH after chroot, so the
    /// rootfs script (which exits 42 for the marker argument) runs instead of
    /// the host's /bin/echo (which would exit 0).
    #[test]
    fn test_rootfs_binary_is_executed() {
        let (temp_dir, socket_path) = setup_test_env("test_rootfs_binary");
        let rootfs = create_test_rootfs(&temp_dir);

        let daemon = WarmDaemon::new(create_test_config(socket_path.clone(), rootfs))
            .expect("Failed to create daemon");
        let handle = start_daemon_background_thread(daemon);
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        let response = send_exec_request(
            &socket_path,
            "echo",
            vec!["__phantom_rootfs_probe__".to_string()],
        )
        .expect("Failed to send exec request");

        assert_eq!(
            response.exit_code, 42,
            "bare `echo` must execute the rootfs script, not the host binary"
        );
        assert!(
            response.error.is_none(),
            "successful rootfs exec should not report an error: {:?}",
            response.error
        );

        shutdown_daemon(&socket_path, handle);
    }

    /// An absolute path that exists on the host but not in the rootfs must not
    /// be executable.
    #[test]
    fn test_host_only_binary_is_unreachable() {
        let (temp_dir, socket_path) = setup_test_env("test_host_only_binary");
        let rootfs = create_test_rootfs(&temp_dir);

        // /usr/bin/true exists on the host; the synthetic rootfs has no
        // /usr/bin directory at all.
        assert!(
            Path::new("/usr/bin/true").exists(),
            "test assumption: host must provide /usr/bin/true"
        );

        let daemon = WarmDaemon::new(create_test_config(socket_path.clone(), rootfs))
            .expect("Failed to create daemon");
        let handle = start_daemon_background_thread(daemon);
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        let response = send_exec_request(&socket_path, "/usr/bin/true", vec![])
            .expect("Failed to send exec request");

        assert_eq!(
            response.exit_code, 127,
            "a host-only binary must not be executable"
        );
        assert!(
            response.error.is_some(),
            "a host-only binary must be reported as an error"
        );

        shutdown_daemon(&socket_path, handle);
    }

    /// chdir(2) must happen after chroot(2), so the cwd observed by the child
    /// is the path inside the image, not the host path.
    #[test]
    fn test_exec_cwd_is_inside_chroot() {
        let (temp_dir, socket_path) = setup_test_env("test_exec_cwd_chroot");
        let rootfs = create_test_rootfs(&temp_dir);

        let subdir = rootfs.join("subdir");
        fs::create_dir_all(&subdir).expect("Failed to create subdir");

        let daemon = WarmDaemon::new(create_test_config(socket_path.clone(), rootfs.clone()))
            .expect("Failed to create daemon");
        let handle = start_daemon_background_thread(daemon);
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // The rootfs /bin/pwd mock records its cwd in /cwd.txt, which lands in
        // the rootfs on the host.
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

        let recorded = fs::read_to_string(rootfs.join("cwd.txt"))
            .expect("child should have written /cwd.txt inside the rootfs");
        assert_eq!(
            recorded.trim(),
            "/subdir",
            "cwd must be the path inside the chroot"
        );

        shutdown_daemon(&socket_path, handle);
    }

    /// Files that only exist on the host must not be visible in the child.
    #[test]
    fn test_host_filesystem_not_visible() {
        let (temp_dir, socket_path) = setup_test_env("test_host_fs_not_visible");
        let rootfs = create_test_rootfs(&temp_dir);

        // The probe exits 1 if the host's /etc/os-release is visible.
        assert!(
            Path::new("/etc/os-release").exists(),
            "test assumption: host must provide /etc/os-release"
        );

        let daemon = WarmDaemon::new(create_test_config(socket_path.clone(), rootfs))
            .expect("Failed to create daemon");
        let handle = start_daemon_background_thread(daemon);
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        let response = send_exec_request(&socket_path, "/bin/fs-probe", vec![])
            .expect("Failed to send exec request");

        assert_eq!(
            response.exit_code, 0,
            "host-only files must not be visible inside the rootfs"
        );
        assert!(
            response.error.is_none(),
            "probe should run successfully: {:?}",
            response.error
        );

        shutdown_daemon(&socket_path, handle);
    }

    // ========================================================================
    // IPC framing tests (deterministic, no daemon required)
    // ========================================================================

    const TEST_MAGIC: u32 = 0x5048_4E54; // "PHNT"
    const TEST_VERSION: u8 = 1;

    /// Build a raw frame header so malformed frames can be injected.
    fn frame_header(magic: u32, version: u8, msg_type: u8, length: u32) -> Vec<u8> {
        let mut header = Vec::with_capacity(10);
        header.extend_from_slice(&magic.to_le_bytes());
        header.push(version);
        header.push(msg_type);
        header.extend_from_slice(&length.to_le_bytes());
        header
    }

    /// Reader that yields at most one byte per `read` call.
    struct OneByteReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl Read for OneByteReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    #[test]
    fn test_read_message_handles_partial_reads() {
        let msg = Message::new(MessageType::Exec, vec![1, 2, 3, 4, 5]);
        let data = msg.serialize().unwrap();

        let mut reader = OneByteReader { data, pos: 0 };
        let parsed = read_message(&mut reader).expect("partial reads must be reassembled");

        assert_eq!(parsed.msg_type, MessageType::Exec);
        assert_eq!(parsed.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_read_message_rejects_absurd_length() {
        // The length field must be validated before allocating: u32::MAX would
        // otherwise request a 4 GiB buffer.
        let header = frame_header(TEST_MAGIC, TEST_VERSION, MessageType::Exec as u8, u32::MAX);
        let mut reader = OneByteReader {
            data: header,
            pos: 0,
        };

        let err = read_message(&mut reader).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_read_message_rejects_invalid_magic() {
        let header = frame_header(0xDEAD_BEEF, TEST_VERSION, MessageType::Exec as u8, 0);
        let mut reader = OneByteReader {
            data: header,
            pos: 0,
        };

        let err = read_message(&mut reader).unwrap_err();
        assert!(
            err.to_string().contains("Invalid protocol magic"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_read_message_rejects_unsupported_version() {
        let header = frame_header(TEST_MAGIC, TEST_VERSION + 1, MessageType::Exec as u8, 0);
        let mut reader = OneByteReader {
            data: header,
            pos: 0,
        };

        let err = read_message(&mut reader).unwrap_err();
        assert!(
            err.to_string().contains("Unsupported protocol version"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_read_message_rejects_truncated_payload() {
        let mut frame = frame_header(TEST_MAGIC, TEST_VERSION, MessageType::Exec as u8, 64);
        frame.extend_from_slice(&[1, 2, 3]); // only 3 of the promised 64 bytes

        let mut reader = OneByteReader {
            data: frame,
            pos: 0,
        };
        let err = read_message(&mut reader).unwrap_err();
        assert!(
            err.to_string().contains("Failed to read message payload"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_serialize_rejects_oversized_payload() {
        let oversized = vec![0u8; 1024 * 1024 + 1];
        let msg = Message::new(MessageType::Exec, oversized);

        let err = msg.serialize().unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "unexpected error: {}",
            err
        );
    }

    // ========================================================================
    // Client-side framing tests (fake daemon, no rootfs required)
    // ========================================================================

    /// Serve exec connections until `stop` is set, replying with `reply`.
    ///
    /// The client gives up after at most three attempts and may return before
    /// the server has accepted a connection (for example when the response
    /// parses far enough to fail client-side). A fixed accept count would then
    /// leave the server blocked forever in `accept()` and hang `join()`, so the
    /// listener is non-blocking and the loop exits as soon as `stop` is set.
    fn spawn_fake_daemon(
        listener: UnixListener,
        reply: Vec<u8>,
    ) -> (thread::JoinHandle<()>, Arc<AtomicBool>) {
        listener
            .set_nonblocking(true)
            .expect("Failed to make fake daemon listener non-blocking");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Consume the client request before answering.
                        let _ = read_message(&mut stream);
                        let _ = stream.write_all(&reply);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });

        (handle, stop)
    }

    fn simple_request() -> ExecRequest {
        ExecRequest {
            command: "/bin/true".to_string(),
            args: vec![],
            env: HashMap::new(),
            cwd: None,
            hardware_profile: None,
        }
    }

    #[test]
    fn test_client_rejects_absurd_response_length() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("fake.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let reply = frame_header(
            TEST_MAGIC,
            TEST_VERSION,
            MessageType::ExecResponse as u8,
            u32::MAX,
        );
        let (server, stop) = spawn_fake_daemon(listener, reply);

        let err = exec_in_daemon(&socket_path, &simple_request()).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "unexpected error: {}",
            err
        );

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
    }

    #[test]
    fn test_client_rejects_truncated_response_payload() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("fake.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        // Valid frame, but only 4 payload bytes where 10 are required.
        let mut reply = frame_header(TEST_MAGIC, TEST_VERSION, MessageType::ExecResponse as u8, 4);
        reply.extend_from_slice(&0u32.to_le_bytes());
        let (server, stop) = spawn_fake_daemon(listener, reply);

        let err = exec_in_daemon(&socket_path, &simple_request()).unwrap_err();
        assert!(
            err.to_string().contains("Malformed payload"),
            "unexpected error: {}",
            err
        );

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
    }

    // ========================================================================
    // Daemon lifecycle tests
    // ========================================================================

    /// Bind then drop a listener, leaving a socket file nobody is listening on.
    fn create_stale_socket(path: &Path) {
        let listener = UnixListener::bind(path).expect("Failed to bind stale socket");
        drop(listener);
        assert!(path.exists(), "stale socket file should remain");
    }

    #[test]
    fn test_stale_socket_is_replaced_on_startup() {
        let (temp_dir, socket_path) = setup_test_env("test_stale_socket");
        let rootfs = create_test_rootfs(&temp_dir);
        create_stale_socket(&socket_path);

        let daemon = WarmDaemon::new(create_test_config(socket_path.clone(), rootfs))
            .expect("a stale socket must be replaced, not treated as fatal");

        let handle = start_daemon_background_thread(daemon);
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");
        assert!(
            ping_daemon(&socket_path).unwrap(),
            "daemon should be pingable"
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

    #[test]
    fn test_live_daemon_socket_is_not_clobbered() {
        let (temp_dir, socket_path) = setup_test_env("test_live_socket");
        let rootfs = create_test_rootfs(&temp_dir);

        let daemon = WarmDaemon::new(create_test_config(socket_path.clone(), rootfs.clone()))
            .expect("Failed to create daemon");
        let handle = start_daemon_background_thread(daemon);
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // A second daemon must refuse to unlink a socket that is still serving.
        let second = WarmDaemon::new(create_test_config(socket_path.clone(), rootfs));
        let err = match second {
            Ok(_) => panic!("second daemon must not clobber a live socket"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("already listening"),
            "unexpected error: {}",
            err
        );

        // The original daemon is still reachable.
        assert!(ping_daemon(&socket_path).unwrap());

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

    #[test]
    fn test_daemon_survives_malformed_exec_payload() {
        let (temp_dir, socket_path) = setup_test_env("test_malformed_exec");
        let rootfs = create_test_rootfs(&temp_dir);

        let daemon = WarmDaemon::new(create_test_config(socket_path.clone(), rootfs))
            .expect("Failed to create daemon");
        let handle = start_daemon_background_thread(daemon);
        wait_for_socket(&socket_path, 1000).expect("Socket should be available");

        // Command length claims 16 bytes but the payload ends immediately.
        let msg = Message::new(MessageType::Exec, vec![16, 0]);
        let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write_message(&mut stream, &msg).expect("Failed to send malformed request");

        let response = read_message(&mut stream).expect("daemon should answer with an error frame");
        assert_eq!(response.msg_type, MessageType::Error);
        let text = String::from_utf8_lossy(&response.payload);
        assert!(
            text.contains("Malformed payload"),
            "unexpected error payload: {}",
            text
        );

        // The daemon must still be alive and serving after the bad frame.
        let response = send_exec_request(&socket_path, "/bin/true", vec![])
            .expect("daemon should keep serving after a malformed frame");
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

    #[test]
    fn test_ping_daemon_returns_false_without_socket() {
        let temp_dir = TempDir::new().unwrap();
        let missing = temp_dir.path().join("missing.sock");

        assert!(!ping_daemon(&missing).expect("ping should not fail for a missing socket"));
    }
}
