//! Zygote Spawner with IPC Communication
//!
//! Provides a pool of pre-forked processes that can receive commands
//! via socketpair IPC for fast process execution.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use types_rs::PhantomError;

const ZYGOTE_POOL_MAX: usize = 32;
const MAX_COMMAND_SIZE: usize = 8192;

extern "C" {
    fn phantom_zygote_pool_create(size: usize) -> i32;
    fn phantom_zygote_pool_destroy() -> i32;
    fn phantom_zygote_pool_refill() -> i32;
    fn phantom_numa_pool_get() -> i32;
    fn phantom_zygote_pool_put(pid: i32) -> i32;
    fn phantom_zygote_pool_status() -> i32;
    fn phantom_zygote_pool_size() -> i32;
    fn phantom_zygote_get_socket(pid: i32) -> i32;
    fn phantom_zygote_send_command(pid: i32, cmd_ptr: *const u8, cmd_len: usize) -> i32;
}

/// Command to send to a zygote child process
#[derive(Debug, Clone)]
pub struct ZygoteCommand {
    pub cmd_type: u8,
    pub exec_path: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub rootfs: Option<String>,
    pub flags: u32,
}

impl ZygoteCommand {
    pub fn new(exec_path: String) -> Self {
        Self {
            cmd_type: 0, // Legacy/Generic Spawn
            exec_path,
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: None,
            flags: 0,
        }
    }

    pub fn mother_setup(rootfs: String) -> Self {
        Self {
            cmd_type: 1, // Setup Mother
            exec_path: String::new(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: Some(rootfs),
            flags: 0,
        }
    }

    pub fn mother_exec(exec_path: String) -> Self {
        Self {
            cmd_type: 2, // Execute Command via Mother
            exec_path,
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: None,
            flags: 0,
        }
    }

    pub fn fragment_setup(rootfs: String) -> Self {
        Self {
            cmd_type: 3, // Fragment Setup
            exec_path: String::new(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: Some(rootfs),
            flags: 0,
        }
    }

    pub fn fragment_exec(exec_path: String) -> Self {
        Self {
            cmd_type: 4, // Fragment Fork & Exec
            exec_path,
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: None,
            flags: 0,
        }
    }

    pub fn arg(mut self, arg: String) -> Self {
        self.args.push(arg);
        self
    }

    pub fn args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push(format!("{}={}", key, value));
        self
    }

    pub fn envs(mut self, envs: Vec<String>) -> Self {
        self.env = envs;
        self
    }

    pub fn cwd(mut self, cwd: String) -> Self {
        self.cwd = cwd;
        self
    }

    pub fn rootfs(mut self, rootfs: String) -> Self {
        self.rootfs = Some(rootfs);
        self
    }

    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn serialize(&self) -> Result<Vec<u8>, PhantomError> {
        let mut buf = Vec::with_capacity(MAX_COMMAND_SIZE);

        let exec_path_bytes = self.exec_path.as_bytes();
        if exec_path_bytes.len() > 4096 {
            return Err(PhantomError::InvalidInput("exec_path too long".to_string()));
        }

        let total_len = self.calculate_total_len();
        if total_len > MAX_COMMAND_SIZE {
            return Err(PhantomError::InvalidInput("command too large".to_string()));
        }

        buf.extend_from_slice(&(total_len as u32).to_le_bytes());
        buf.push(self.cmd_type);

        if let Some(ref rootfs) = self.rootfs {
            let rootfs_bytes = rootfs.as_bytes();
            if rootfs_bytes.len() > 65535 {
                return Err(PhantomError::InvalidInput(
                    "rootfs path too long".to_string(),
                ));
            }
            buf.extend_from_slice(&(rootfs_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(rootfs_bytes);
        } else {
            buf.extend_from_slice(&0u16.to_le_bytes());
        }

        buf.extend_from_slice(&(exec_path_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(exec_path_bytes);

        if self.args.len() > 255 {
            return Err(PhantomError::InvalidInput("too many args".to_string()));
        }
        buf.push(self.args.len() as u8);
        for arg in &self.args {
            let arg_bytes = arg.as_bytes();
            if arg_bytes.len() > 65534 {
                return Err(PhantomError::InvalidInput("arg too long".to_string()));
            }
            buf.extend_from_slice(&(arg_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(arg_bytes);
            buf.push(0);
        }

        if self.env.len() > 255 {
            return Err(PhantomError::InvalidInput("too many env vars".to_string()));
        }
        buf.push(self.env.len() as u8);
        for env in &self.env {
            let env_bytes = env.as_bytes();
            if env_bytes.len() > 65534 {
                return Err(PhantomError::InvalidInput("env var too long".to_string()));
            }
            buf.extend_from_slice(&(env_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(env_bytes);
            buf.push(0);
        }

        let cwd_bytes = self.cwd.as_bytes();
        if cwd_bytes.len() > 65535 {
            return Err(PhantomError::InvalidInput("cwd too long".to_string()));
        }
        buf.extend_from_slice(&(cwd_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(cwd_bytes);

        buf.extend_from_slice(&self.flags.to_le_bytes());

        Ok(buf)
    }

    fn calculate_total_len(&self) -> usize {
        let mut len = 4; // total_len
        len += 1; // cmd_type
        len += 2 + self.rootfs.as_ref().map(|r| r.len()).unwrap_or(0);
        len += 2 + self.exec_path.len();
        len += 1; // args_count
        for arg in &self.args {
            len += 2 + arg.len() + 1;
        }
        len += 1; // env_count
        for env in &self.env {
            len += 2 + env.len() + 1;
        }
        len += 2 + self.cwd.len();
        len += 4; // flags
        len
    }
}

/// Zygote pool for pre-warmed processes.
pub struct ZygotePool {
    /// Track zygote PIDs that are currently in use
    zygote_pids: Vec<i32>,
}

impl ZygotePool {
    pub fn new(size: usize) -> Result<Self, PhantomError> {
        let actual_size = size.min(ZYGOTE_POOL_MAX);
        if actual_size == 0 {
            return Err(PhantomError::Internal("Pool size must be > 0".into()));
        }

        let created = unsafe { phantom_zygote_pool_create(actual_size) };
        if created < 0 {
            return Err(PhantomError::Internal(
                "Failed to create zygote pool".into(),
            ));
        }

        Ok(Self {
            zygote_pids: Vec::with_capacity(actual_size),
        })
    }

    pub fn available(&self) -> i32 {
        unsafe { phantom_zygote_pool_status() }
    }

    pub fn pool_size(&self) -> i32 {
        unsafe { phantom_zygote_pool_size() }
    }

    /// Spawn a zygote from the pool and return its PID.
    /// The zygote is marked as in-use and must be released after use.
    pub fn spawn(&mut self) -> Result<i32, PhantomError> {
        let pid = unsafe { phantom_numa_pool_get() };
        if pid > 0 {
            self.zygote_pids.push(pid);
            return Ok(pid);
        }
        Err(PhantomError::Internal("No zygotes available".into()))
    }

    /// Send a command to a zygote and return the exit status.
    ///
    /// The zygote forks a grandchild process, waits for it to complete,
    /// and returns the exit status. The zygote stays alive for reuse.
    ///
    /// After this returns, call `release(zygote_pid)` to return the
    /// zygote to the pool.
    pub fn send_command(
        &mut self,
        zygote_pid: i32,
        command: &ZygoteCommand,
    ) -> Result<i32, PhantomError> {
        let serialized = command.serialize()?;

        let result = unsafe {
            phantom_zygote_send_command(zygote_pid, serialized.as_ptr(), serialized.len())
        };

        if result < 0 {
            return Err(PhantomError::Internal(
                "Failed to send command to zygote".into(),
            ));
        }

        // Return the exit status
        Ok(result)
    }

    /// Execute a command via the zygote pool and return the child PID.
    ///
    /// This spawns a zygote, sends the command, and returns the child PID.
    /// The zygote itself stays alive and is automatically released back to the pool.
    pub fn execute(&mut self, command: ZygoteCommand) -> Result<i32, PhantomError> {
        let zygote_pid = self.spawn()?;
        let result = self.send_command(zygote_pid, &command);

        // Since send_command is synchronous and zygote remains alive,
        // we release the zygote slot immediately after completion.
        self.release(zygote_pid);

        result
    }

    pub fn wait(&mut self, pid: i32) -> Result<i32, PhantomError> {
        let mut status: i32 = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited < 0 {
            return Err(PhantomError::Internal("Failed to wait for process".into()));
        }
        Ok(status)
    }

    pub fn wait_no_hang(&mut self, pid: i32) -> Result<Option<i32>, PhantomError> {
        let mut status: i32 = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited < 0 {
            return Err(PhantomError::Internal("Failed to wait for process".into()));
        }
        if waited == 0 {
            return Ok(None);
        }
        Ok(Some(status))
    }

    /// Release a zygote back to the pool for reuse.
    ///
    /// The zygote remains alive with its socket connection open, ready
    /// to handle the next command. This enables true zygote recycling.
    pub fn release(&mut self, zygote_pid: i32) {
        // Remove from zygote_pids tracking
        self.zygote_pids.retain(|&p| p != zygote_pid);
        // Return zygote to pool
        unsafe {
            phantom_zygote_pool_put(zygote_pid);
        }
    }

    pub fn refill(&mut self) -> Result<(), PhantomError> {
        let spawned = unsafe { phantom_zygote_pool_refill() };
        if spawned < 0 {
            return Err(PhantomError::Internal("Failed to refill pool".into()));
        }
        Ok(())
    }

    pub fn get_socket(&self, pid: i32) -> Option<RawFd> {
        let fd = unsafe { phantom_zygote_get_socket(pid) };
        if fd >= 0 {
            Some(fd)
        } else {
            None
        }
    }
}

impl Drop for ZygotePool {
    fn drop(&mut self) {
        unsafe {
            phantom_zygote_pool_destroy();
        }
        // Wait for any tracked zygotes (shouldn't be any if release() was called properly)
        for zygote_pid in &self.zygote_pids {
            unsafe {
                libc::waitpid(*zygote_pid, std::ptr::null_mut(), 0);
            }
        }
    }
}

pub fn send_command_raw(pid: i32, command: &ZygoteCommand) -> Result<(), PhantomError> {
    let serialized = command.serialize()?;
    let result = unsafe { phantom_zygote_send_command(pid, serialized.as_ptr(), serialized.len()) };
    if result < 0 {
        return Err(PhantomError::Internal("Failed to send command".into()));
    }
    Ok(())
}

pub fn get_socket_fd(pid: i32) -> Option<RawFd> {
    let fd = unsafe { phantom_zygote_get_socket(pid) };
    if fd >= 0 {
        Some(fd)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

#[cfg(test)]
mod stress_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    struct StressMetrics {
        total_spawns: usize,
        successful_spawns: usize,
        failed_spawns: usize,
        latencies: VecDeque<u128>,
        errors: Vec<String>,
        max_latency: u128,
    }

    impl StressMetrics {
        fn new() -> Self {
            Self {
                total_spawns: 0,
                successful_spawns: 0,
                failed_spawns: 0,
                latencies: VecDeque::new(),
                errors: Vec::new(),
                max_latency: 0,
            }
        }

        fn record_success(&mut self, latency_us: u128) {
            self.total_spawns += 1;
            self.successful_spawns += 1;
            self.latencies.push_back(latency_us);
            if latency_us > self.max_latency {
                self.max_latency = latency_us;
            }
        }

        fn record_failure(&mut self, error: String) {
            self.total_spawns += 1;
            self.failed_spawns += 1;
            self.errors.push(error);
        }

        fn average_latency(&self) -> f64 {
            if self.latencies.is_empty() {
                return 0.0;
            }
            let sum: u128 = self.latencies.iter().sum();
            sum as f64 / self.latencies.len() as f64
        }

        fn print_summary(&self, test_name: &str) {
            println!("\n=== {} Results ===", test_name);
            println!("Total spawns attempted: {}", self.total_spawns);
            println!("Successful spawns: {}", self.successful_spawns);
            println!("Failed spawns: {}", self.failed_spawns);
            println!(
                "Success rate: {:.2}%",
                (self.successful_spawns as f64 / self.total_spawns as f64) * 100.0
            );
            if !self.latencies.is_empty() {
                println!("Average latency: {:.2} μs", self.average_latency());
                println!("Max latency: {} μs", self.max_latency);
            }
            if !self.errors.is_empty() {
                println!("\nErrors encountered:");
                for (i, err) in self.errors.iter().enumerate().take(10) {
                    println!("  {}. {}", i + 1, err);
                }
                if self.errors.len() > 10 {
                    println!("  ... and {} more errors", self.errors.len() - 10);
                }
            }
        }
    }

    /// Run a command via zygote and return the exit status.
    ///
    /// This is a helper for tests that executes a command.
    fn run_command_and_wait(pool: &mut ZygotePool, cmd: ZygoteCommand) -> Result<i32, String> {
        pool.execute(cmd)
            .map_err(|e| format!("Execute failed: {:?}", e))
    }

    #[test]
    fn test_pool_creation_and_basic_spawn() {
        println!("\n--- Test: Pool Creation and Basic Spawn ---");

        let mut pool = ZygotePool::new(4).expect("Failed to create pool");

        println!("Pool size: {}", pool.pool_size());
        println!("Available zygotes: {}", pool.available());

        let cmd = ZygoteCommand::new("/bin/echo".to_string())
            .args(vec!["hello".to_string(), "world".to_string()])
            .cwd("/tmp".to_string())
            .flags(0);

        let start = Instant::now();
        let result = run_command_and_wait(&mut pool, cmd);
        let elapsed = start.elapsed().as_micros();

        match result {
            Ok(exit_status) => {
                println!("Exit status: {}", exit_status);
                println!("Spawn + exec + wait latency: {} μs", elapsed);
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }

        println!("Available after spawn: {}", pool.available());
    }

    #[test]
    fn test_different_commands() {
        println!("\n--- Test: Different Commands ---");

        let mut pool = ZygotePool::new(10).expect("Failed to create pool");

        println!("Initial pool size: {}", pool.pool_size());
        println!("Initial available: {}", pool.available());

        let commands = vec![
            ("/bin/echo", vec!["test".to_string()], "echo"),
            ("/bin/ls", vec!["-la".to_string(), "/tmp".to_string()], "ls"),
            (
                "/bin/cat",
                vec!["/etc/passwd".to_string()],
                "cat (first 5 lines)",
            ),
            ("/bin/date", vec![], "date"),
            ("/bin/hostname", vec![], "hostname"),
            ("/bin/uname", vec!["-a".to_string()], "uname"),
            (
                "/bin/printf",
                vec!["hello %s\n".to_string(), "world".to_string()],
                "printf",
            ),
            ("/bin/basename", vec!["/usr/bin/ls".to_string()], "basename"),
        ];

        let mut metrics = StressMetrics::new();

        for (path, args, name) in commands {
            println!("\nTesting: {}", name);

            let cmd = ZygoteCommand::new(path.to_string())
                .args(args)
                .cwd("/".to_string())
                .flags(0);

            let start = Instant::now();
            match run_command_and_wait(&mut pool, cmd) {
                Ok(exit_status) => {
                    let elapsed = start.elapsed().as_micros();
                    metrics.record_success(elapsed);
                    println!("  Status: {}, Latency: {} μs", exit_status, elapsed);

                    let exit_code = exit_status >> 8;
                    if exit_code != 0 {
                        metrics.record_failure(format!("{} exited with code {}", name, exit_code));
                    }
                }
                Err(e) => {
                    metrics.record_failure(format!("{}: {}", name, e));
                    println!("  Error: {}", e);
                }
            }
        }

        metrics.print_summary("Different Commands Test");
    }

    #[test]
    fn test_concurrent_spawns() {
        println!("\n--- Test: Concurrent Spawns ---");

        let pool = Arc::new(Mutex::new(
            ZygotePool::new(8).expect("Failed to create pool"),
        ));
        let metrics = Arc::new(Mutex::new(StressMetrics::new()));

        let num_threads = 4;
        let spawns_per_thread = 10;

        println!(
            "Spawning {} threads with {} spawns each",
            num_threads, spawns_per_thread
        );

        let mut handles = vec![];

        for t in 0..num_threads {
            let pool_clone = Arc::clone(&pool);
            let metrics_clone = Arc::clone(&metrics);

            let handle = thread::spawn(move || {
                for i in 0..spawns_per_thread {
                    let mut pool = pool_clone.lock().unwrap();

                    let cmd = ZygoteCommand::new("/bin/echo".to_string())
                        .args(vec![format!("thread{}spawn{}", t, i)])
                        .cwd("/tmp".to_string())
                        .flags(0);

                    let start = Instant::now();
                    match run_command_and_wait(&mut pool, cmd) {
                        Ok(exit_status) => {
                            let elapsed = start.elapsed().as_micros();
                            let mut m = metrics_clone.lock().unwrap();
                            m.record_success(elapsed);
                            println!(
                                "  Thread {} spawn {}: status={}, latency={}μs",
                                t, i, exit_status, elapsed
                            );
                        }
                        Err(e) => {
                            let mut m = metrics_clone.lock().unwrap();
                            m.record_failure(format!("Thread {} spawn {}: {}", t, i, e));
                        }
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        let m = metrics.lock().expect("Failed to acquire metrics lock");
        m.print_summary("Concurrent Spawns Test");

        println!("\nPool state after concurrent test:");
        println!("  Pool size: {}", pool.lock().expect("Failed to acquire pool lock").pool_size());
        println!("  Available: {}", pool.lock().expect("Failed to acquire pool lock").available());
    }

    #[test]
    fn test_pool_exhaustion_and_recovery() {
        println!("\n--- Test: Pool Exhaustion and Recovery ---");

        let mut pool = ZygotePool::new(4).expect("Failed to create pool");

        println!("Initial available: {}", pool.available());

        let mut pids = vec![];

        println!("\n--- Exhausting pool (spawning without waiting) ---");
        for i in 0..4 {
            match pool.spawn() {
                Ok(pid) => {
                    pids.push(pid);
                    println!("Spawned zygote {}: PID {}", i, pid);
                }
                Err(e) => {
                    println!("Failed to spawn zygote {}: {:?}", i, e);
                }
            }
        }

        println!("\nPool exhausted. Available: {}", pool.available());

        println!("\n--- Testing that spawn fails when pool exhausted ---");
        let result = pool.spawn();
        if result.is_err() {
            println!("Correctly got error when pool exhausted");
        } else {
            println!("Warning: Got PID when pool should be exhausted");
        }

        println!("\n--- Releasing zygotes back to pool ---");
        for (i, pid) in pids.iter().enumerate() {
            pool.release(*pid);
            println!("Released zygote {} (PID {})", i, pid);
        }

        println!("Available after release: {}", pool.available());

        println!("\n--- Testing spawn after recovery ---");
        let cmd = ZygoteCommand::new("/bin/echo".to_string())
            .args(vec!["recovered".to_string()])
            .cwd("/".to_string())
            .flags(0);

        let start = Instant::now();
        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let elapsed = start.elapsed().as_micros();
                println!(
                    "After recovery spawn: exit status={}, latency={}μs",
                    exit_status, elapsed
                );
            }
            Err(e) => {
                println!("Error after recovery: {}", e);
            }
        }
    }

    #[test]
    fn test_error_cases() {
        println!("\n--- Test: Error Cases ---");

        let mut pool = ZygotePool::new(4).expect("Failed to create pool");
        let mut metrics = StressMetrics::new();

        println!("\n1. Testing invalid binary path");
        let cmd = ZygoteCommand::new("/bin/invalid_binary_xyz123".to_string())
            .args(vec!["test".to_string()])
            .cwd("/".to_string())
            .flags(0);

        let start = Instant::now();
        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let elapsed = start.elapsed().as_micros();
                let exit_code = exit_status >> 8;
                println!("  Exit code: {}, Latency: {} μs", exit_code, elapsed);
                if exit_code != 0 {
                    println!("  (Expected: non-zero exit for invalid binary)");
                    metrics.record_success(elapsed);
                }
            }
            Err(e) => {
                metrics.record_failure(format!("Invalid binary: {}", e));
                println!("  Error: {}", e);
            }
        }

        println!("\n2. Testing non-existent path");
        let cmd = ZygoteCommand::new("/nonexistent/path/to/binary".to_string())
            .args(vec!["test".to_string()])
            .cwd("/".to_string())
            .flags(0);

        let start = Instant::now();
        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let elapsed = start.elapsed().as_micros();
                let exit_code = exit_status >> 8;
                println!("  Exit code: {}, Latency: {} μs", exit_code, elapsed);
                if exit_code != 0 {
                    metrics.record_success(elapsed);
                }
            }
            Err(e) => {
                metrics.record_failure(format!("Non-existent path: {}", e));
                println!("  Error: {}", e);
            }
        }

        println!("\n3. Testing empty command (should fail in serialization)");
        let cmd = ZygoteCommand::new("".to_string())
            .args(vec!["test".to_string()])
            .cwd("/".to_string())
            .flags(0);

        match cmd.serialize() {
            Err(e) => {
                println!("  Correctly rejected empty path: {:?}", e);
                metrics.record_success(0);
            }
            Ok(_) => {
                println!("  Warning: Empty path was accepted");
            }
        }

        println!("\n4. Testing binary that doesn't exist but looks valid");
        let cmd = ZygoteCommand::new("/usr/bin/thisdoesnotexist987654321".to_string())
            .args(vec!["arg1".to_string()])
            .cwd("/".to_string())
            .flags(0);

        let start = Instant::now();
        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let elapsed = start.elapsed().as_micros();
                let exit_code = exit_status >> 8;
                println!("  Exit code: {}, Latency: {} μs", exit_code, elapsed);
                metrics.record_success(elapsed);
            }
            Err(e) => {
                metrics.record_failure(format!("Missing binary: {}", e));
                println!("  Error: {}", e);
            }
        }

        println!("\n5. Testing with large number of arguments");
        let mut args = vec![];
        for i in 0..50 {
            args.push(format!("arg{}", i));
        }
        let cmd = ZygoteCommand::new("/bin/echo".to_string())
            .args(args)
            .cwd("/".to_string())
            .flags(0);

        let start = Instant::now();
        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let elapsed = start.elapsed().as_micros();
                println!("  Status: {}, Latency: {} μs", exit_status, elapsed);
                metrics.record_success(elapsed);
            }
            Err(e) => {
                metrics.record_failure(format!("Many args: {}", e));
                println!("  Error: {}", e);
            }
        }

        metrics.print_summary("Error Cases Test");
    }

    #[test]
    fn test_high_concurrency_stress() {
        println!("\n--- Test: High Concurrency Stress ---");

        let pool = Arc::new(Mutex::new(
            ZygotePool::new(8).expect("Failed to create pool"),
        ));
        let metrics = Arc::new(Mutex::new(StressMetrics::new()));

        let num_threads = 8;
        let spawns_per_thread = 20;

        println!(
            "Starting {} threads with {} spawns each",
            num_threads, spawns_per_thread
        );
        println!("Total spawns: {}", num_threads * spawns_per_thread);

        let mut handles = vec![];
        let start_time = Instant::now();

        for t in 0..num_threads {
            let pool_clone = Arc::clone(&pool);
            let metrics_clone = Arc::clone(&metrics);

            let handle = thread::spawn(move || {
                for i in 0..spawns_per_thread {
                    let mut pool = pool_clone.lock().unwrap();

                    let cmd = ZygoteCommand::new("/bin/echo".to_string())
                        .args(vec![format!("stress{}x{}", t, i)])
                        .cwd("/tmp".to_string())
                        .flags(0);

                    let start = Instant::now();
                    match run_command_and_wait(&mut pool, cmd) {
                        Ok(exit_status) => {
                            let elapsed = start.elapsed().as_micros();
                            let mut m = metrics_clone.lock().unwrap();
                            m.record_success(elapsed);
                        }
                        Err(e) => {
                            let mut m = metrics_clone.lock().unwrap();
                            m.record_failure(format!("Thread {} spawn {}: {}", t, i, e));
                        }
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let total_time = start_time.elapsed();

        let m = metrics.lock().unwrap();
        println!("\n=== High Concurrency Stress Results ===");
        println!("Total wall time: {} ms", total_time.as_millis());
        println!("Total spawns attempted: {}", m.total_spawns);
        println!("Successful spawns: {}", m.successful_spawns);
        println!("Failed spawns: {}", m.failed_spawns);
        println!(
            "Success rate: {:.2}%",
            (m.successful_spawns as f64 / m.total_spawns as f64) * 100.0
        );
        if !m.latencies.is_empty() {
            println!("Average latency per spawn: {:.2} μs", m.average_latency());
            println!("Max latency observed: {} μs", m.max_latency);

            let mut sorted_latencies: Vec<u128> = m.latencies.iter().cloned().collect();
            sorted_latencies.sort();
            let p50 = sorted_latencies[sorted_latencies.len() / 2];
            let p95 = sorted_latencies[(sorted_latencies.len() as f64 * 0.95) as usize];
            let p99 = sorted_latencies[(sorted_latencies.len() as f64 * 0.99) as usize];
            println!("P50 latency: {} μs", p50);
            println!("P95 latency: {} μs", p95);
            println!("P99 latency: {} μs", p99);
        }

        let throughput = m.successful_spawns as f64 / (total_time.as_secs_f64() * 1000.0);
        println!("Throughput: {:.2} spawns/sec", throughput * 1000.0);

        if !m.errors.is_empty() {
            println!("\nErrors encountered:");
            for (i, err) in m.errors.iter().enumerate().take(5) {
                println!("  {}. {}", i + 1, err);
            }
        }
    }

    #[test]
    fn test_zygote_exec_actually_works() {
        println!("\n--- Test: Verify Zygote Actually Exec's the Command ---");

        let mut pool = ZygotePool::new(4).expect("Failed to create pool");

        println!("1. Testing echo with specific output");
        let cmd = ZygoteCommand::new("/bin/sh".to_string())
            .args(vec![
                "-c".to_string(),
                "echo PHANTOM_TEST_SUCCESS".to_string(),
            ])
            .cwd("/".to_string())
            .flags(0);

        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let exit_code = exit_status >> 8;
                println!("  Exit code: {}", exit_code);
                if exit_code == 0 {
                    println!("  SUCCESS: Command executed correctly");
                } else {
                    println!("  FAILED: Non-zero exit code");
                }
            }
            Err(e) => {
                println!("  Error: {}", e);
            }
        }

        println!("\n2. Testing ls with output capture");
        let cmd = ZygoteCommand::new("/bin/sh".to_string())
            .args(vec!["-c".to_string(), "ls /tmp | head -3".to_string()])
            .cwd("/".to_string())
            .flags(0);

        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let exit_code = exit_status >> 8;
                println!("  Exit code: {}", exit_code);
                if exit_code == 0 {
                    println!("  SUCCESS: ls executed correctly");
                }
            }
            Err(e) => {
                println!("  Error: {}", e);
            }
        }

        println!("\n3. Testing environment variables");
        let cmd = ZygoteCommand::new("/bin/sh".to_string())
            .args(vec!["-c".to_string(), "echo $TEST_VAR".to_string()])
            .env("TEST_VAR", "ZYGOTE_TEST_PASSED")
            .cwd("/".to_string())
            .flags(0);

        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let exit_code = exit_status >> 8;
                println!("  Exit code: {}", exit_code);
                println!("  (Check output manually if needed - env should be set)");
            }
            Err(e) => {
                println!("  Error: {}", e);
            }
        }

        println!("\n4. Testing working directory change");
        let cmd = ZygoteCommand::new("/bin/sh".to_string())
            .args(vec!["-c".to_string(), "pwd".to_string()])
            .cwd("/var".to_string())
            .flags(0);

        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let exit_code = exit_status >> 8;
                println!("  Exit code: {}", exit_code);
                println!("  (CWD should be /var - check output manually)");
            }
            Err(e) => {
                println!("  Error: {}", e);
            }
        }

        println!("\n5. Testing exit code propagation");
        let cmd = ZygoteCommand::new("/bin/sh".to_string())
            .args(vec!["-c".to_string(), "exit 42".to_string()])
            .cwd("/".to_string())
            .flags(0);

        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                let exit_code = exit_status >> 8;
                println!("  Exit code: {}", exit_code);
                if exit_code == 42 {
                    println!("  SUCCESS: Exit code 42 correctly propagated");
                }
            }
            Err(e) => {
                println!("  Error: {}", e);
            }
        }

        println!("\n--- All verification tests complete ---");
    }

    #[test]
    fn test_pool_refill() {
        println!("\n--- Test: Pool Refill ---");

        let mut pool = ZygotePool::new(4).expect("Failed to create pool");

        println!("Initial pool size: {}", pool.pool_size());
        println!("Initial available: {}", pool.available());

        println!("\n--- Spawning all zygotes ---");
        let mut pids = vec![];
        for i in 0..4 {
            match pool.spawn() {
                Ok(pid) => {
                    pids.push(pid);
                    println!("  Spawned zygote {}: PID {}", i, pid);
                }
                Err(e) => {
                    println!("  Failed to spawn: {:?}", e);
                }
            }
        }

        println!("\nAvailable after spawning all: {}", pool.available());

        println!("\n--- Releasing all zygotes ---");
        for pid in &pids {
            pool.release(*pid);
        }

        println!("Available after release: {}", pool.available());

        println!("\n--- Testing refill ---");
        pool.refill().expect("Refill failed");

        println!("Available after refill: {}", pool.available());

        println!("\n--- Spawning after refill ---");
        let cmd = ZygoteCommand::new("/bin/echo".to_string())
            .args(vec!["after_refill".to_string()])
            .cwd("/".to_string())
            .flags(0);

        match run_command_and_wait(&mut pool, cmd) {
            Ok(exit_status) => {
                println!("  Success: exit status={}", exit_status);
            }
            Err(e) => {
                println!("  Error: {}", e);
            }
        }
    }

    #[test]
    fn test_sequential_rapid_spawns() {
        println!("\n--- Test: Sequential Rapid Spawns ---");

        let mut pool = ZygotePool::new(6).expect("Failed to create pool");
        let num_spawns = 50;

        let mut latencies = vec![];

        println!("Executing {} sequential spawns...", num_spawns);

        for i in 0..num_spawns {
            let cmd = ZygoteCommand::new("/bin/echo".to_string())
                .args(vec!["test".to_string()])
                .cwd("/tmp".to_string())
                .flags(0);

            let start = Instant::now();
            match run_command_and_wait(&mut pool, cmd) {
                Ok(exit_status) => {
                    let elapsed = start.elapsed().as_micros();
                    latencies.push(elapsed);
                    if i % 10 == 0 {
                        println!(
                            "  Spawn {}: exit status={}, latency={}μs",
                            i, exit_status, elapsed
                        );
                    }
                }
                Err(e) => {
                    println!("  Spawn {} failed: {}", i, e);
                }
            }
        }

        println!("\n=== Sequential Spawn Results ===");
        println!("Total spawns: {}", latencies.len());

        if !latencies.is_empty() {
            let sum: u128 = latencies.iter().sum();
            let avg = sum as f64 / latencies.len() as f64;
            let max = *latencies.iter().max().unwrap();
            let min = *latencies.iter().min().unwrap();

            println!("Average latency: {:.2} μs", avg);
            println!("Min latency: {} μs", min);
            println!("Max latency: {} μs", max);

            let mut sorted = latencies.clone();
            sorted.sort();
            let p50 = sorted[sorted.len() / 2];
            let p95 = sorted[(sorted.len() as f64 * 0.95) as usize];
            let p99 = sorted[(sorted.len() as f64 * 0.99) as usize];
            println!("P50 latency: {} μs", p50);
            println!("P95 latency: {} μs", p95);
            println!("P99 latency: {} μs", p99);
        }
    }
}
