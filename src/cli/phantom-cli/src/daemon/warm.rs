//! Socket-based Warm Fragment Daemon
//!
//! This module implements a secure, socket-based daemon for warm fragment execution.
//! It replaces the insecure shell-script based daemon with proper:
//! - Unix socket IPC (no polling, event-driven)
//! - Safe command execution (no eval/command injection)
//! - Proper cgroup integration (applied before exec)
//! - Resource cleanup (cgroups removed on exit)
//!
//! Architecture:
//! ```text
//! ┌─────────────────┐     Unix Socket      ┌──────────────────┐
//! │  Client        │ ◄──────────────────► │  Warm Daemon     │
//! │  (phantom run) │  [length:4][type:1]  │  (this module)   │
//! └─────────────────┘  [payload...]        └──────────────────┘
//!                                              │
//!                                              ▼
//!                                   ┌──────────────────┐
//!                                   │  Child Process   │
//!                                   │  (with cgroups)  │
//!                                   └──────────────────┘
//! ```

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cgroups_rs::CgroupManager;
use execution_rs::HardwareProfile;
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;

// SAFETY: libc is required for signal masking before fork to prevent race conditions
// where signals are delivered to the child before it can set up signal handlers.
use libc;

/// Magic number for protocol validation
const PROTOCOL_MAGIC: u32 = 0x50484E54; // "PHNT"
/// Protocol version
const PROTOCOL_VERSION: u8 = 1;

/// Message types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Exec = 0x01,
    ExecResponse = 0x02,
    Shutdown = 0x03,
    HealthCheck = 0x04,
    HealthResponse = 0x05,
    GetMetrics = 0x06,
    MetricsResponse = 0x07,
    Error = 0xFF,
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => MessageType::Exec,
            0x02 => MessageType::ExecResponse,
            0x03 => MessageType::Shutdown,
            0x04 => MessageType::HealthCheck,
            0x05 => MessageType::HealthResponse,
            0x06 => MessageType::GetMetrics,
            0x07 => MessageType::MetricsResponse,
            0xFF => MessageType::Error,
            _ => MessageType::Error,
        }
    }
}

/// Execution request payload
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    pub hardware_profile: Option<HardwareProfile>,
}

/// Execution response payload
#[derive(Debug, Clone)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub pid: u32,
    pub error: Option<String>,
}

/// Health status for the warm daemon
/// Tracks daemon uptime, request metrics, and cgroup status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Daemon uptime in seconds
    pub uptime_secs: u64,
    /// Total requests handled since startup
    pub total_requests: u64,
    /// Number of failed requests
    pub failed_requests: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Current number of active child processes
    pub active_children: usize,
    /// Cgroup status (true if cgroups are active and functioning)
    pub cgroup_active: bool,
    /// Daemon PID
    pub daemon_pid: u32,
}

impl HealthStatus {
    pub fn new() -> Self {
        Self {
            uptime_secs: 0,
            total_requests: 0,
            failed_requests: 0,
            avg_response_time_ms: 0.0,
            active_children: 0,
            cgroup_active: false,
            daemon_pid: 0,
        }
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics response payload for GetMetrics request
/// Contains detailed metrics in a format suitable for Prometheus export
#[derive(Debug, Clone)]
pub struct MetricsResponse {
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Total requests handled
    pub total_requests: u64,
    /// Failed requests count
    pub failed_requests: u64,
    /// Successful requests count
    pub successful_requests: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Current active children count
    pub active_children: usize,
    /// Cgroup active status
    pub cgroup_active: bool,
    /// Prometheus-formatted metrics string
    pub prometheus_metrics: String,
}

/// Binary message format:
/// [magic:4][version:1][type:1][length:4][payload:length]
#[derive(Debug, Clone)]
pub struct Message {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(10 + self.payload.len());
        buf.extend_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
        buf.push(PROTOCOL_VERSION);
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 10 {
            anyhow::bail!("Message too short");
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != PROTOCOL_MAGIC {
            anyhow::bail!("Invalid protocol magic");
        }

        let version = data[4];
        if version != PROTOCOL_VERSION {
            anyhow::bail!("Unsupported protocol version: {}", version);
        }

        let msg_type = MessageType::from(data[5]);
        let length = u32::from_le_bytes([data[6], data[7], data[8], data[9]]) as usize;

        if data.len() < 10 + length {
            anyhow::bail!("Incomplete message payload");
        }

        let payload = data[10..10 + length].to_vec();
        Ok(Self { msg_type, payload })
    }
}

/// Warm fragment daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub hardware_profile: Option<HardwareProfile>,
    /// Port for Prometheus metrics endpoint (default: 9090)
    pub metrics_port: u16,
}

/// Running child process tracking
struct ChildProcess {
    cgroup: Option<CgroupManager>,
}

/// Socket-based warm fragment daemon
pub struct WarmDaemon {
    config: DaemonConfig,
    listener: UnixListener,
    running: Arc<AtomicBool>,
    children: Arc<Mutex<HashMap<u32, ChildProcess>>>,
    daemon_id: u64,
    /// Start time for uptime calculation
    start_time: Instant,
    /// Total requests handled
    total_requests: Arc<AtomicU64>,
    /// Failed requests count
    failed_requests: Arc<AtomicU64>,
    /// Sum of all response times in milliseconds (for averaging)
    total_response_time_ms: Arc<AtomicU64>,
    /// Cgroup active status
    cgroup_active: Arc<AtomicBool>,
    /// Metrics port for Prometheus scraping
    metrics_port: u16,
    /// Handle to the metrics server thread
    metrics_server_handle: Option<std::thread::JoinHandle<()>>,
}

impl WarmDaemon {
    /// Create a new warm daemon
    pub fn new(config: DaemonConfig) -> Result<Self> {
        // Create socket directory if needed
        if let Some(parent) = config.socket_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create socket directory: {:?}", parent))?;
        }

        // Remove existing socket file
        if config.socket_path.exists() {
            fs::remove_file(&config.socket_path).ok();
        }

        // Bind to socket
        let listener = UnixListener::bind(&config.socket_path)
            .with_context(|| format!("Failed to bind to socket: {:?}", config.socket_path))?;

        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&config.socket_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&config.socket_path, perms)?;
        }

        // Set non-blocking
        listener
            .set_nonblocking(true)
            .context("Failed to set socket non-blocking")?;

        let daemon_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let metrics_port = config.metrics_port;

        let mut daemon = Self {
            config,
            listener,
            running: Arc::new(AtomicBool::new(true)),
            children: Arc::new(Mutex::new(HashMap::new())),
            daemon_id,
            start_time: Instant::now(),
            total_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            total_response_time_ms: Arc::new(AtomicU64::new(0)),
            cgroup_active: Arc::new(AtomicBool::new(false)),
            metrics_port,
            metrics_server_handle: None,
        };

        // Start the metrics HTTP server in a background thread
        daemon.start_metrics_server()?;

        Ok(daemon)
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    /// Get the daemon PID
    pub fn pid(&self) -> u32 {
        std::process::id()
    }

    /// Start the metrics HTTP server in a background thread
    fn start_metrics_server(&mut self) -> Result<()> {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let metrics_port = self.metrics_port;
        let running = Arc::clone(&self.running);
        let total_requests = Arc::clone(&self.total_requests);
        let failed_requests = Arc::clone(&self.failed_requests);
        let total_response_time_ms = Arc::clone(&self.total_response_time_ms);
        let cgroup_active = Arc::clone(&self.cgroup_active);
        let start_time = self.start_time;

        let handle = std::thread::spawn(move || {
            let addr = format!("0.0.0.0:{}", metrics_port);
            let listener = match TcpListener::bind(&addr) {
                Ok(l) => {
                    log::info!("Metrics server listening on http://{}", addr);
                    l
                }
                Err(e) => {
                    log::warn!("Failed to start metrics server on {}: {}", addr, e);
                    return;
                }
            };

            // Set non-blocking for graceful shutdown
            listener.set_nonblocking(true).ok();

            for stream in listener.incoming() {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                // Set read timeout
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok();

                // Read HTTP request
                let mut buffer = [0u8; 1024];
                if stream.read(&mut buffer).is_err() {
                    continue;
                }

                // Check if it's a GET request to /metrics
                let request = String::from_utf8_lossy(&buffer);
                if request.starts_with("GET /metrics") {
                    // Build metrics response
                    let uptime_secs = start_time.elapsed().as_secs();
                    let total_reqs = total_requests.load(Ordering::Relaxed);
                    let failed_reqs = failed_requests.load(Ordering::Relaxed);
                    let total_resp_time = total_response_time_ms.load(Ordering::Relaxed);
                    let cgroup = cgroup_active.load(Ordering::Relaxed);

                    let avg_response_time_ms = if total_reqs > 0 {
                        total_resp_time as f64 / total_reqs as f64
                    } else {
                        0.0
                    };

                    let mut metrics = String::new();
                    metrics.push_str(
                        "# HELP phantom_daemon_uptime_seconds Daemon uptime in seconds\n",
                    );
                    metrics.push_str("# TYPE phantom_daemon_uptime_seconds gauge\n");
                    metrics.push_str(&format!("phantom_daemon_uptime_seconds {}\n", uptime_secs));

                    metrics.push_str("# HELP phantom_requests_total Total requests handled\n");
                    metrics.push_str("# TYPE phantom_requests_total counter\n");
                    metrics.push_str(&format!("phantom_requests_total {}\n", total_reqs));

                    metrics.push_str("# HELP phantom_requests_failed Total failed requests\n");
                    metrics.push_str("# TYPE phantom_requests_failed counter\n");
                    metrics.push_str(&format!("phantom_requests_failed {}\n", failed_reqs));

                    metrics.push_str("# HELP phantom_avg_response_time_ms Average response time in milliseconds\n");
                    metrics.push_str("# TYPE phantom_avg_response_time_ms gauge\n");
                    metrics.push_str(&format!(
                        "phantom_avg_response_time_ms {:.3}\n",
                        avg_response_time_ms
                    ));

                    metrics.push_str("# HELP phantom_cgroup_active Whether cgroups are active\n");
                    metrics.push_str("# TYPE phantom_cgroup_active gauge\n");
                    metrics.push_str(&format!(
                        "phantom_cgroup_active {}\n",
                        if cgroup { 1 } else { 0 }
                    ));

                    // Add metrics from metrics-rs
                    use metrics_rs::MetricsCollector;
                    let collector = MetricsCollector::new();
                    if let Ok(collected) = collector.export() {
                        metrics.push_str(&collected);
                    }

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                        metrics.len(),
                        metrics
                    );

                    let _ = stream.write_all(response.as_bytes());
                } else if request.starts_with("GET /health") {
                    // Health check endpoint
                    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK";
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    // 404 for other paths
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
                    let _ = stream.write_all(response.as_bytes());
                }

                let _ = stream.flush();
            }
        });

        self.metrics_server_handle = Some(handle);
        Ok(())
    }

    /// Run the daemon main loop
    pub fn run(&mut self) -> Result<()> {
        log::info!(
            "Warm daemon started (PID: {}, socket: {:?})",
            self.pid(),
            self.socket_path()
        );

        // Apply cgroup to daemon itself if profile specified
        if let Some(ref profile) = self.config.hardware_profile {
            if let Err(e) = self.apply_daemon_cgroup(profile) {
                log::warn!("Failed to apply daemon cgroup: {:?}", e);
            }
        }

        // Set up signal handling
        let running = Arc::clone(&self.running);
        ctrlc_handler(move || {
            log::info!("Received shutdown signal");
            running.store(false, Ordering::SeqCst);
        })?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            self.listener.set_nonblocking(true).unwrap();
            let async_listener =
                tokio::net::UnixListener::from_std(self.listener.try_clone().unwrap()).unwrap();
            let mut prune_interval = tokio::time::interval(std::time::Duration::from_secs(1));

            loop {
                tokio::select! {
                    accept_result = async_listener.accept() => {
                        match accept_result {
                            Ok((stream, _addr)) => {
                                if !self.running.load(Ordering::SeqCst) {
                                    break;
                                }

                                let std_stream = stream.into_std().unwrap();
                                std_stream.set_nonblocking(false).unwrap();

                                // To avoid changing the entire function signature to be static (borrow checker issues),
                                // we can't easily spawn a task for handle_client since it takes &mut self.
                                // Instead, we do it inline via block_in_place so Tokio's thread pool isn't stalled.
                                tokio::task::block_in_place(|| {
                                    let mut s = std_stream;
                                    if let Err(e) = self.handle_client(&mut s) {
                                        log::error!("Client handler error: {:?}", e);
                                        let _ = self.send_error(&mut s, &e.to_string());
                                    }

                                    // If connection dropped prematurely, the socket gets closed here.
                                    // We can prune immediately as a proactive measure in case the client disconnected while handling an exec request.
                                    let _ = self.prune_dead_children();
                                });
                            }
                            Err(e) => {
                                log::error!("Accept error: {:?}", e);
                            }
                        }
                    }
                    _ = prune_interval.tick() => {
                        let pruned = self.prune_dead_children();
                        if pruned > 0 {
                            log::debug!("Pruned {} dead children", pruned);
                        }
                    }
                }
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }
            }
        });

        // Cleanup
        self.cleanup()?;
        Ok(())
    }

    /// Handle a client connection
    fn handle_client(&mut self, stream: &mut UnixStream) -> Result<()> {
        // Set 5-second socket read and write timeouts to prevent hanging indefinitely under IPC load
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();

        // Verify peer credentials (SO_PEERCRED) to ensure only authorized users can connect
        #[cfg(unix)]
        {
            use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
            use nix::unistd::getuid;
            let cred =
                getsockopt(&*stream, PeerCredentials).context("Failed to get peer credentials")?;
            let current_uid = getuid().as_raw();

            // Only allow connections from same user or root (UID 0)
            if cred.uid() != current_uid && cred.uid() != 0 {
                anyhow::bail!(
                    "Connection rejected: peer UID {} does not match current UID {} (expected same user or root)",
                    cred.uid(),
                    current_uid
                );
            }
        }

        // Read message header
        let mut header = [0u8; 10];
        stream
            .read_exact(&mut header)
            .context("Failed to read message header")?;

        // Parse header to get payload length
        let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;

        // Read payload
        let mut payload = vec![0u8; length];
        stream
            .read_exact(&mut payload)
            .context("Failed to read message payload")?;

        let msg = Message::deserialize(&[&header[..], &payload[..]].concat())?;

        match msg.msg_type {
            MessageType::Exec => self.handle_exec(stream, &msg.payload),
            MessageType::HealthCheck => self.handle_health_check(stream),
            MessageType::GetMetrics => self.handle_get_metrics(stream),
            MessageType::Shutdown => {
                self.running.store(false, Ordering::SeqCst);
                self.send_response(
                    stream,
                    MessageType::ExecResponse,
                    &ExecResponse {
                        exit_code: 0,
                        pid: 0,
                        error: None,
                    },
                )
            }
            _ => {
                let error = format!("Unknown message type: {:?}", msg.msg_type);
                self.send_error(stream, &error)
            }
        }
    }

    /// Handle execution request
    fn handle_exec(
        &mut self,
        stream: &mut std::os::unix::net::UnixStream,
        payload: &[u8],
    ) -> Result<()> {
        let start = Instant::now();

        // Parse request: [cmd_len:2][cmd][args_count:1][args...][env_count:1][env...][cwd_len:2][cwd][profile:1]
        let mut offset = 0;

        // Read command
        let cmd_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        let command = String::from_utf8_lossy(&payload[offset..offset + cmd_len]).to_string();
        offset += cmd_len;

        // Read args
        let args_count = payload[offset] as usize;
        offset += 1;
        let mut args = Vec::with_capacity(args_count);
        for _ in 0..args_count {
            let arg_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            let arg = String::from_utf8_lossy(&payload[offset..offset + arg_len]).to_string();
            offset += arg_len;
            args.push(arg);
        }

        // Read env
        let env_count = payload[offset] as usize;
        offset += 1;
        let mut env = HashMap::new();
        for _ in 0..env_count {
            let key_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            let key = String::from_utf8_lossy(&payload[offset..offset + key_len]).to_string();
            offset += key_len;
            let val_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            let val = String::from_utf8_lossy(&payload[offset..offset + val_len]).to_string();
            offset += val_len;
            env.insert(key, val);
        }

        // Read cwd
        let cwd_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        let cwd = if cwd_len > 0 {
            Some(String::from_utf8_lossy(&payload[offset..offset + cwd_len]).to_string())
        } else {
            None
        };
        offset += cwd_len;

        // Read hardware profile flag
        let has_profile = payload[offset] != 0;
        offset += 1;
        let hardware_profile = if has_profile {
            // Read profile: [cpu_count:4][memory_mb:4]
            let cpu_count = u32::from_le_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]) as usize;
            offset += 4;
            let memory_mb = u32::from_le_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]) as usize;
            Some(HardwareProfile {
                cpu_affinity: None,
                numa_node: None,
                cpu_count,
                memory_mb,
            })
        } else {
            None
        };

        let request = ExecRequest {
            command,
            args,
            env,
            cwd,
            hardware_profile,
        };

        // Execute the command and record metrics
        let (response, success) = match self.execute_command(&request) {
            Ok(response) => (response, true),
            Err(e) => {
                let response = ExecResponse {
                    exit_code: 127,
                    pid: 0,
                    error: Some(e.to_string()),
                };
                (response, false)
            }
        };

        // Record request metrics
        let latency_ms = start.elapsed().as_millis() as u64;
        self.record_request(latency_ms, success);

        self.send_response(stream, MessageType::ExecResponse, &response)
    }

    /// Execute a command with proper isolation and cgroups
    ///
    /// SECURITY FIX: Uses fork-exec pattern to apply cgroups BETWEEN fork and exec.
    /// This eliminates the race condition where the child process could run unrestricted
    /// between spawn() and cgroup application.
    ///
    /// Previous vulnerable pattern:
    /// ```rust
    /// let child = cmd.spawn()?;  // Child starts executing (unrestricted)
    /// let pid = child.id();
    /// cgroup.add_process(pid)?;  // Too late - child already running
    /// ```
    ///
    /// New secure pattern:
    /// ```rust
    /// fork() -> child process
    ///   -> apply cgroup to child (PID 0 = self)
    ///   -> execvp() - child is already restricted when command runs
    /// ```
    fn execute_command(&mut self, request: &ExecRequest) -> Result<ExecResponse> {
        // Validate command - whitelist allowed characters to prevent injection
        if !is_safe_command(&request.command) {
            anyhow::bail!("Invalid command: contains unsafe characters");
        }

        // Prepare command and arguments for execvp
        // Note: c_cmd is created after path validation below
        let mut c_args: Vec<CString> = Vec::with_capacity(request.args.len() + 2);
        for arg in &request.args {
            let c_arg = CString::new(arg.as_str())
                .with_context(|| format!("Invalid argument string: {}", arg))?;
            c_args.push(c_arg);
        }
        // execvp requires null-terminated array - empty string is safe (cannot contain null)
        c_args.push(CString::new("").expect("Empty string cannot contain null bytes"));

        // Prepare environment variables for execve
        let mut env_vars: Vec<CString> = Vec::new();

        // Add custom environment from request
        for (key, val) in &request.env {
            let env_str = format!("{}={}", key, val);
            let c_env = CString::new(env_str)
                .with_context(|| format!("Invalid environment variable: {}", key))?;
            env_vars.push(c_env);
        }

        // Add Phantom-specific environment variables
        // These are internally generated and safe (cannot contain null bytes)
        env_vars
            .push(CString::new("PHANTOM_WARM=1").expect("Static string cannot contain null bytes"));
        env_vars.push(
            CString::new(format!("PHANTOM_DAEMON_ID={}", self.daemon_id))
                .expect("Generated daemon ID cannot contain null bytes"),
        );

        let rootfs_str = self.config.rootfs_path.to_string_lossy();
        if !rootfs_str.is_empty() && rootfs_str != "/" {
            env_vars.push(
                CString::new(format!("PHANTOM_ROOTFS={}", rootfs_str))
                    .expect("Generated rootfs path cannot contain null bytes"),
            );
        }

        // Preserve current environment and merge with custom vars
        let mut final_env: Vec<CString> = std::env::vars()
            .filter_map(|(k, v)| CString::new(format!("{}={}", k, v)).ok())
            .collect();
        final_env.extend(env_vars);

        // Determine and validate working directory
        let target_cwd = if let Some(ref cwd) = request.cwd {
            let cwd_path = PathBuf::from(cwd);

            // Canonicalize to resolve symlinks and ..
            let canonical_cwd = cwd_path.canonicalize().unwrap_or_else(|_| cwd_path.clone());

            // Ensure cwd is within rootfs boundary
            if !canonical_cwd.starts_with(&self.config.rootfs_path) {
                anyhow::bail!("cwd escapes rootfs boundary: {}", cwd);
            }

            cwd.clone()
        } else {
            self.config.rootfs_path.to_string_lossy().to_string()
        };

        // Validate command path - ensure it exists within rootfs
        let validated_command = {
            let cmd_path = PathBuf::from(&request.command);

            // Check for path traversal attempts
            let cmd_str = &request.command;
            if cmd_str.contains("..") {
                anyhow::bail!("command contains path traversal: {}", request.command);
            }

            // Build the full path within rootfs
            let full_path = if cmd_path.is_absolute() {
                self.config
                    .rootfs_path
                    .join(cmd_path.strip_prefix("/").unwrap_or(&cmd_path))
            } else {
                self.config.rootfs_path.join(&cmd_path)
            };

            // Verify the command exists within rootfs
            if !full_path.exists() {
                anyhow::bail!(
                    "command not found in rootfs: {} (looked at {:?})",
                    request.command,
                    full_path
                );
            }

            // Return the original command - it will be resolved in the chroot
            request.command.clone()
        };

        // Create CString for command after validation
        let c_cmd = CString::new(validated_command.as_str())
            .with_context(|| format!("Invalid command string: {}", validated_command))?;

        // Insert command at the beginning of args (execvp expects argv[0] to be the command)
        let mut c_args_with_cmd: Vec<CString> = Vec::with_capacity(c_args.len() + 1);
        c_args_with_cmd.push(c_cmd.clone());
        c_args_with_cmd.append(&mut c_args);

        // Create cgroup in parent BEFORE fork so we can destroy it after child exits
        let cgroup: Option<CgroupManager> = if let Some(ref profile) = request.hardware_profile {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0) as u64;

            let cgroup_name = format!("phantom_warm_{}_{}", self.daemon_id, timestamp);
            let cgroup = CgroupManager::new(&cgroup_name);

            // Create cgroup
            if let Err(e) = cgroup.create() {
                log::warn!("Failed to create cgroup {}: {:?}", cgroup_name, e);
                None
            } else {
                // Apply memory limit
                if profile.memory_mb > 0 {
                    if let Err(e) = cgroup.set_memory_limit(profile.memory_mb as u64) {
                        log::warn!("Failed to set memory limit: {:?}", e);
                    }
                }

                // Apply CPU limit
                if profile.cpu_count > 0 {
                    if let Err(e) = cgroup.set_cpu_limit(profile.cpu_count as u64) {
                        log::warn!("Failed to set CPU limit: {:?}", e);
                    }
                }

                Some(cgroup)
            }
        } else {
            None
        };

        // Fork-exec pattern: apply cgroup BETWEEN fork and exec
        // SAFETY: Signal masking is critical before fork to prevent race conditions.
        // In multi-threaded programs, signals could be delivered to the child process
        // before it can establish its own signal handlers, causing undefined behavior.
        let pid = unsafe {
            let mut sigmask: libc::sigset_t = std::mem::zeroed();
            let mut old_sigmask: libc::sigset_t = std::mem::zeroed();

            // Initialize sigset to block all signals
            libc::sigfillset(&mut sigmask);

            // Block all signals before fork
            let mask_ret = libc::pthread_sigmask(libc::SIG_SETMASK, &sigmask, &mut old_sigmask);
            if mask_ret != 0 {
                return Err(anyhow::anyhow!(
                    "Failed to block signals before fork: errno {}",
                    mask_ret
                ));
            }

            let fork_result = fork();

            // Restore signal mask in both parent and child immediately after fork
            let restore_ret =
                libc::pthread_sigmask(libc::SIG_SETMASK, &old_sigmask, std::ptr::null_mut());

            match fork_result {
                Ok(ForkResult::Child) => {
                    // CRITICAL: Child must restore signals before any non-async-signal-safe operations
                    if restore_ret != 0 {
                        // Use _exit(127) which is async-signal-safe, NOT exit()
                        libc::_exit(127);
                    }
                    // === IN CHILD PROCESS ===
                    // At this point, we are a copy of the parent but before exec.
                    // This is the ONLY safe place to apply cgroups.

                    // Apply cgroup limits BEFORE exec - child is still just our code
                    // The cgroup was already created by the parent; we just need to add ourselves
                    if let Some(ref _profile) = request.hardware_profile {
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0) as u64;

                        let cgroup_name = format!("phantom_warm_{}_{}", self.daemon_id, timestamp);
                        let cgroup = CgroupManager::new(&cgroup_name);

                        // CRITICAL: Add current process (PID 0) to cgroup BEFORE exec
                        // PID 0 means "current process" in the cgroup API
                        if let Err(e) = cgroup.add_process(0) {
                            eprintln!("Failed to add self to cgroup: {:?}", e);
                            // Continue execution without cgroup - don't fail completely
                        }
                    }

                    // ENFORCE NAMESPACE PURITY
                    // Unshare mount namespace
                    if libc::unshare(libc::CLONE_NEWNS) == 0 {
                        // Make all mounts private so they don't propagate to parent
                        let c_none = std::ffi::CString::new("none").unwrap();
                        libc::mount(
                            c_none.as_ptr(),
                            std::ptr::null(),
                            c_none.as_ptr(),
                            libc::MS_PRIVATE | libc::MS_REC,
                            std::ptr::null(),
                        );

                        let c_tmp = std::ffi::CString::new("/tmp").unwrap();
                        let c_tmpfs = std::ffi::CString::new("tmpfs").unwrap();
                        libc::mount(
                            c_tmpfs.as_ptr(),
                            c_tmp.as_ptr(),
                            c_tmpfs.as_ptr(),
                            0,
                            std::ptr::null(),
                        );

                        let c_devshm = std::ffi::CString::new("/dev/shm").unwrap();
                        libc::mount(
                            c_tmpfs.as_ptr(),
                            c_devshm.as_ptr(),
                            c_tmpfs.as_ptr(),
                            0,
                            std::ptr::null(),
                        );
                    }

                    // Change to target directory
                    if nix::unistd::chdir(target_cwd.as_str()).is_err() {
                        eprintln!("Failed to change directory to {}", target_cwd);
                        std::process::exit(127);
                    }

                    // Set environment variables using libc::setenv
                    for env_var in &final_env {
                        let env_str = match env_var.to_str() {
                            Ok(s) => s,
                            Err(_) => {
                                eprintln!("Invalid environment variable encoding");
                                std::process::exit(127);
                            }
                        };
                        if let Some(eq_pos) = env_str.find('=') {
                            let key = &env_str[..eq_pos];
                            let val = &env_str[eq_pos + 1..];
                            let c_key = match CString::new(key) {
                                Ok(c) => c,
                                Err(_) => {
                                    eprintln!("Invalid environment variable key");
                                    std::process::exit(127);
                                }
                            };
                            let c_val = match CString::new(val) {
                                Ok(c) => c,
                                Err(_) => {
                                    eprintln!("Invalid environment variable value");
                                    std::process::exit(127);
                                }
                            };
                            libc::setenv(c_key.as_ptr(), c_val.as_ptr(), 1);
                        }
                    }

                    // Redirect I/O: stdin from /dev/null, stdout/stderr inherited
                    if let Ok(null_fd) = nix::fcntl::open(
                        "/dev/null",
                        nix::fcntl::OFlag::O_RDONLY,
                        nix::sys::stat::Mode::empty(),
                    ) {
                        let _ = nix::unistd::dup2(null_fd, 0);
                        let _ = nix::unistd::close(null_fd);
                    }

                    // NOW exec - child is already restricted by cgroup
                    // This is the key security fix: cgroup is applied BEFORE the target
                    // command ever starts executing
                    let exec_result = execvp(&c_cmd, &c_args_with_cmd);

                    // If execvp returns, it failed
                    // SAFETY: Use _exit(127) instead of exit() to avoid flushing stdio buffers
                    // twice (once in child, once in parent), which could cause duplicate output.
                    eprintln!("Failed to exec {}: {:?}", request.command, exec_result);
                    libc::_exit(127);
                }
                Ok(ForkResult::Parent { child }) => {
                    // === IN PARENT PROCESS ===
                    // child is the PID of the forked process

                    // Log if signal restoration failed (only safe to do in parent)
                    if restore_ret != 0 {
                        log::warn!(
                            "Failed to restore signal mask after fork: errno {}",
                            restore_ret
                        );
                    }

                    child.as_raw() as u32
                }
                Err(e) => {
                    // Signal restoration already attempted above, but fork failed
                    return Err(anyhow::anyhow!("Fork failed: {:?}", e));
                }
            }
        };

        // Parent continues here with the child PID
        // Track child with its cgroup for later cleanup
        self.children
            .lock()
            .unwrap()
            .insert(pid, ChildProcess { cgroup });

        // Wait for child to complete (synchronous execution)
        let wait_result = nix::sys::wait::waitpid(Pid::from_raw(pid as i32), None);

        let exit_code = match wait_result {
            Ok(status) => match status {
                nix::sys::wait::WaitStatus::Exited(_, code) => code,
                nix::sys::wait::WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
                _ => 127,
            },
            Err(_) => 127,
        };

        // Clean up cgroup BEFORE removing from tracking
        let mut locked_children = self.children.lock().unwrap();
        if let Some(child) = locked_children.get(&pid) {
            if let Some(ref cgroup) = child.cgroup {
                if let Err(e) = cgroup.destroy() {
                    log::warn!("Failed to destroy cgroup for PID {}: {:?}", pid, e);
                }
            }
        }

        // Clean up tracking
        locked_children.remove(&pid);

        Ok(ExecResponse {
            exit_code,
            pid,
            error: None,
        })
    }

    /// Apply cgroup to the daemon itself
    fn apply_daemon_cgroup(&self, profile: &HardwareProfile) -> Result<()> {
        let cgroup_name = format!("phantom_daemon_{}", self.daemon_id);
        let cgroup = CgroupManager::new(&cgroup_name);
        cgroup.create()?;

        if profile.memory_mb > 0 {
            cgroup.set_memory_limit(profile.memory_mb as u64)?;
        }
        if profile.cpu_count > 0 {
            cgroup.set_cpu_limit(profile.cpu_count as u64)?;
        }

        cgroup.add_process(self.pid() as i32)?;
        self.set_cgroup_active(true);
        Ok(())
    }

    /// Handle health check
    fn handle_health_check(&self, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
        let response = format!(
            "OK pid={} children={}",
            self.pid(),
            self.children.lock().unwrap().len()
        );
        let msg = Message::new(MessageType::HealthResponse, response.into_bytes());
        let data = msg.serialize()?;
        stream.write_all(&data)?;
        Ok(())
    }

    /// Handle GetMetrics request
    fn handle_get_metrics(&self, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
        let health = self.get_health_status();
        let prometheus = self.export_prometheus_metrics();

        let response = MetricsResponse {
            uptime_secs: health.uptime_secs,
            total_requests: health.total_requests,
            failed_requests: health.failed_requests,
            successful_requests: health.total_requests.saturating_sub(health.failed_requests),
            avg_response_time_ms: health.avg_response_time_ms,
            active_children: health.active_children,
            cgroup_active: health.cgroup_active,
            prometheus_metrics: prometheus,
        };

        // Serialize: [uptime:8][total:8][failed:8][successful:8][avg_ms:8][children:4][cgroup:1][prometheus_len:2][prometheus]
        let mut payload = Vec::new();
        payload.extend_from_slice(&response.uptime_secs.to_le_bytes());
        payload.extend_from_slice(&response.total_requests.to_le_bytes());
        payload.extend_from_slice(&response.failed_requests.to_le_bytes());
        payload.extend_from_slice(&response.successful_requests.to_le_bytes());
        payload.extend_from_slice(&(response.avg_response_time_ms.to_bits() as u64).to_le_bytes());
        payload.extend_from_slice(&(response.active_children as u32).to_le_bytes());
        payload.push(if response.cgroup_active { 1 } else { 0 });

        let prometheus_bytes = response.prometheus_metrics.as_bytes();
        payload.extend_from_slice(&(prometheus_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(prometheus_bytes);

        let msg = Message::new(MessageType::MetricsResponse, payload);
        let data = msg.serialize()?;
        stream.write_all(&data)?;
        Ok(())
    }

    /// Get current health status
    pub fn get_health_status(&self) -> HealthStatus {
        let uptime = self.start_time.elapsed().as_secs();
        let total = self.total_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);
        let total_time = self.total_response_time_ms.load(Ordering::Relaxed);

        let avg_response_time = if total > 0 {
            total_time as f64 / total as f64
        } else {
            0.0
        };

        HealthStatus {
            uptime_secs: uptime,
            total_requests: total,
            failed_requests: failed,
            avg_response_time_ms: avg_response_time,
            active_children: self.children.lock().unwrap().len(),
            cgroup_active: self.cgroup_active.load(Ordering::Relaxed),
            daemon_pid: self.pid(),
        }
    }

    /// Record a request with its latency and success status
    pub fn record_request(&self, latency_ms: u64, success: bool) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_ms
            .fetch_add(latency_ms, Ordering::Relaxed);

        if !success {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Prune dead/zombie child processes
    /// Returns the number of pruned children
    pub fn prune_dead_children(&self) -> usize {
        let mut pruned = 0;
        let mut to_remove = Vec::new();

        let mut locked_children = self.children.lock().unwrap();
        for (pid, _child) in locked_children.iter() {
            // Check if process is still running using nix
            match nix::sys::signal::kill(nix::unistd::Pid::from_raw(*pid as i32), None) {
                Ok(_) => {
                    // Process is still alive
                }
                Err(nix::errno::Errno::ESRCH) => {
                    // Process doesn't exist, mark for removal
                    to_remove.push(*pid);
                }
                Err(_) => {
                    // Other error, process likely dead
                    to_remove.push(*pid);
                }
            }
        }

        for pid in to_remove {
            if let Some(child) = locked_children.remove(&pid) {
                // Clean up cgroup if present
                if let Some(cgroup) = child.cgroup {
                    if let Err(e) = cgroup.destroy() {
                        log::warn!("Failed to destroy cgroup for PID {}: {:?}", pid, e);
                    }
                    log::debug!("Removed dead child PID {} with cgroup", pid);
                } else {
                    log::debug!("Removed dead child PID {}", pid);
                }
                pruned += 1;
            }
        }

        pruned
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus_metrics(&self) -> String {
        let health = self.get_health_status();
        let successful = health.total_requests.saturating_sub(health.failed_requests);

        format!(
            "# HELP phantom_warm_uptime_seconds Daemon uptime in seconds\n\
             # TYPE phantom_warm_uptime_seconds counter\n\
             phantom_warm_uptime_seconds {}\n\
             # HELP phantom_warm_requests_total Total requests handled\n\
             # TYPE phantom_warm_requests_total counter\n\
             phantom_warm_requests_total {}\n\
             # HELP phantom_warm_requests_failed Total failed requests\n\
             # TYPE phantom_warm_requests_failed counter\n\
             phantom_warm_requests_failed {}\n\
             # HELP phantom_warm_requests_successful Total successful requests\n\
             # TYPE phantom_warm_requests_successful counter\n\
             phantom_warm_requests_successful {}\n\
             # HELP phantom_warm_response_time_ms Average response time in milliseconds\n\
             # TYPE phantom_warm_response_time_ms gauge\n\
             phantom_warm_response_time_ms {}\n\
             # HELP phantom_warm_active_children Current active child processes\n\
             # TYPE phantom_warm_active_children gauge\n\
             phantom_warm_active_children {}\n\
             # HELP phantom_warm_cgroup_active Cgroup status (1=active, 0=inactive)\n\
             # TYPE phantom_warm_cgroup_active gauge\n\
             phantom_warm_cgroup_active {}\n\
             # HELP phantom_warm_daemon_pid Daemon process ID\n\
             # TYPE phantom_warm_daemon_pid gauge\n\
             phantom_warm_daemon_pid {}\n",
            health.uptime_secs,
            health.total_requests,
            health.failed_requests,
            successful,
            health.avg_response_time_ms,
            health.active_children,
            if health.cgroup_active { 1 } else { 0 },
            health.daemon_pid,
        )
    }

    /// Set cgroup active status
    pub fn set_cgroup_active(&self, active: bool) {
        self.cgroup_active.store(active, Ordering::Relaxed);
    }

    /// Send response
    fn send_response(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        msg_type: MessageType,
        response: &ExecResponse,
    ) -> Result<()> {
        // Serialize response: [exit_code:4][pid:4][error_len:2][error]
        let mut payload =
            Vec::with_capacity(10 + response.error.as_ref().map(|e| e.len()).unwrap_or(0));
        payload.extend_from_slice(&response.exit_code.to_le_bytes());
        payload.extend_from_slice(&response.pid.to_le_bytes());

        if let Some(ref error) = response.error {
            payload.extend_from_slice(&(error.len() as u16).to_le_bytes());
            payload.extend_from_slice(error.as_bytes());
        } else {
            payload.extend_from_slice(&0u16.to_le_bytes());
        }

        let msg = Message::new(msg_type, payload);
        let data = msg.serialize()?;
        stream.write_all(&data)?;
        Ok(())
    }

    /// Send error
    fn send_error(&self, stream: &mut std::os::unix::net::UnixStream, error: &str) -> Result<()> {
        let response = ExecResponse {
            exit_code: 127,
            pid: 0,
            error: Some(error.to_string()),
        };
        self.send_response(stream, MessageType::Error, &response)
    }

    /// Cleanup resources
    fn cleanup(&mut self) -> Result<()> {
        log::info!("Cleaning up warm daemon resources");

        // Remove socket file
        if self.config.socket_path.exists() {
            fs::remove_file(&self.config.socket_path).ok();
        }

        // Clean up any remaining children
        let mut locked_children = self.children.lock().unwrap();
        for (pid, child) in locked_children.drain() {
            // Kill child if still running
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::SIGTERM,
            );

            // Destroy cgroup
            if let Some(cgroup) = child.cgroup {
                if let Err(e) = cgroup.destroy() {
                    log::warn!("Failed to destroy cgroup for PID {}: {:?}", pid, e);
                }
            }
        }

        Ok(())
    }

    /// Run the daemon main loop without signal handler (for testing)
    #[cfg(test)]
    pub fn run_test_loop(&mut self) -> Result<()> {
        log::info!(
            "Warm daemon test loop started (PID: {}, socket: {:?})",
            self.pid(),
            self.socket_path()
        );

        // Apply cgroup to daemon itself if profile specified
        if let Some(ref profile) = self.config.hardware_profile {
            if let Err(e) = self.apply_daemon_cgroup(profile) {
                log::warn!("Failed to apply daemon cgroup: {:?}", e);
            }
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            self.listener.set_nonblocking(true).unwrap();
            let async_listener =
                tokio::net::UnixListener::from_std(self.listener.try_clone().unwrap()).unwrap();
            let mut prune_interval = tokio::time::interval(std::time::Duration::from_millis(100)); // faster prune for tests

            loop {
                tokio::select! {
                    accept_result = async_listener.accept() => {
                        match accept_result {
                            Ok((stream, _addr)) => {
                                if !self.running.load(Ordering::SeqCst) {
                                    break;
                                }
                                let std_stream = stream.into_std().unwrap();
                                std_stream.set_nonblocking(false).unwrap();
                                tokio::task::block_in_place(|| {
                                    let mut s = std_stream;
                                    if let Err(e) = self.handle_client(&mut s) {
                                        log::error!("Client handler error: {:?}", e);
                                        let _ = self.send_error(&mut s, &e.to_string());
                                    }

                                    // If connection dropped prematurely, the socket gets closed here.
                                    // We can prune immediately as a proactive measure in case the client disconnected while handling an exec request.
                                    let _ = self.prune_dead_children();
                                });
                            }
                            Err(e) => {
                                log::error!("Accept error: {:?}", e);
                            }
                        }
                    }
                    _ = prune_interval.tick() => {
                        let pruned = self.prune_dead_children();
                        if pruned > 0 {
                            log::debug!("Pruned {} dead children", pruned);
                        }
                    }
                }
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }
            }
        });

        // Cleanup
        self.cleanup()?;
        Ok(())
    }
}

impl Drop for WarmDaemon {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Validate command string for safety
/// Only allows alphanumeric, space, dash, underscore, dot, slash, colon
pub fn is_safe_command(cmd: &str) -> bool {
    if cmd.is_empty() {
        return false;
    }

    // Whitelist allowed characters
    cmd.chars().all(|c| {
        c.is_alphanumeric()
            || c == ' '
            || c == '-'
            || c == '_'
            || c == '.'
            || c == '/'
            || c == ':'
            || c == '+'
            || c == '='
    })
}

/// Set up Ctrl+C handler
fn ctrlc_handler<F>(f: F) -> Result<()>
where
    F: FnMut() + Send + 'static,
{
    ctrlc::set_handler(f).context("Failed to set Ctrl+C handler")
}

/// Start daemon in background
pub fn start_daemon_background(config: DaemonConfig) -> Result<u32> {
    use std::process::Stdio;

    let socket_path = config.socket_path.clone();
    let rootfs_path = config.rootfs_path.clone();

    // Fork the daemon process
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("--internal-warm-daemon");
    cmd.arg("--socket");
    cmd.arg(&socket_path);
    cmd.arg("--rootfs");
    cmd.arg(&rootfs_path);

    if let Some(ref profile) = config.hardware_profile {
        cmd.arg("--cpu-count");
        cmd.arg(profile.cpu_count.to_string());
        cmd.arg("--memory-mb");
        cmd.arg(profile.memory_mb.to_string());
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let child = cmd.spawn().context("Failed to spawn daemon")?;
    let pid = child.id();

    // Wait for socket to be ready
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        if socket_path.exists() {
            // Try to connect
            if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
                return Ok(pid);
            }
        }
    }

    anyhow::bail!("Daemon failed to start (socket not ready)");
}

/// Ping a running daemon via Unix socket to verify it is responsive
pub fn ping_daemon(socket_path: &Path) -> Result<bool> {
    let stream = match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(1)))
        .ok();

    let mut stream = stream;
    let msg = Message::new(MessageType::HealthCheck, vec![]);
    let data = msg.serialize()?;
    if stream.write_all(&data).is_err() {
        return Ok(false);
    }

    let mut header = [0u8; 10];
    if stream.read_exact(&mut header).is_err() {
        return Ok(false);
    }

    let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;
    let mut payload = vec![0u8; length];
    if stream.read_exact(&mut payload).is_err() {
        return Ok(false);
    }

    let msg = Message::deserialize(&[&header[..], &payload[..]].concat())?;
    Ok(msg.msg_type == MessageType::HealthResponse)
}

/// Connect to running daemon and send exec request with auto-reconnect retries and timeouts
pub fn exec_in_daemon(socket_path: &Path, request: &ExecRequest) -> Result<ExecResponse> {
    let mut last_err = None;

    // Retry up to 3 times before failing back to cold execution
    for attempt in 1..=3 {
        let stream = match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(anyhow::anyhow!(
                    "Failed to connect to daemon at {:?}: {}",
                    socket_path,
                    e
                ));
                std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
                continue;
            }
        };

        // Set 5-second socket read and write timeouts
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();

        let mut stream = stream;

        // Serialize request: [cmd_len:2][cmd][args_count:1][args...][env_count:1][env...][cwd_len:2][cwd][profile:1][cpu:4][mem:4]
        let mut payload = Vec::new();

        // Command
        payload.extend_from_slice(&(request.command.len() as u16).to_le_bytes());
        payload.extend_from_slice(request.command.as_bytes());

        // Args
        payload.push(request.args.len() as u8);
        for arg in &request.args {
            payload.extend_from_slice(&(arg.len() as u16).to_le_bytes());
            payload.extend_from_slice(arg.as_bytes());
        }

        // Env
        payload.push(request.env.len() as u8);
        for (key, val) in &request.env {
            payload.extend_from_slice(&(key.len() as u16).to_le_bytes());
            payload.extend_from_slice(key.as_bytes());
            payload.extend_from_slice(&(val.len() as u16).to_le_bytes());
            payload.extend_from_slice(val.as_bytes());
        }

        // Cwd
        let cwd_bytes = request.cwd.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        payload.extend_from_slice(&(cwd_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(cwd_bytes);

        // Hardware profile
        if let Some(ref profile) = request.hardware_profile {
            payload.push(1);
            payload.extend_from_slice(&(profile.cpu_count as u32).to_le_bytes());
            payload.extend_from_slice(&(profile.memory_mb as u32).to_le_bytes());
        } else {
            payload.push(0);
            payload.extend_from_slice(&0u32.to_le_bytes());
            payload.extend_from_slice(&0u32.to_le_bytes());
        }

        // Send request
        let msg = Message::new(MessageType::Exec, payload);
        let data = match msg.serialize() {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        if let Err(e) = stream.write_all(&data) {
            last_err = Some(anyhow::anyhow!("Failed to send request to daemon: {}", e));
            std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
            continue;
        }

        // Read response
        let mut header = [0u8; 10];
        if let Err(e) = stream.read_exact(&mut header) {
            last_err = Some(anyhow::anyhow!(
                "Failed to read response header from daemon: {}",
                e
            ));
            std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
            continue;
        }

        let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;
        let mut response_data = vec![0u8; length];
        if let Err(e) = stream.read_exact(&mut response_data) {
            last_err = Some(anyhow::anyhow!(
                "Failed to read response payload from daemon: {}",
                e
            ));
            std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
            continue;
        }

        // Parse response: [exit_code:4][pid:4][error_len:2][error]
        let exit_code = i32::from_le_bytes([
            response_data[0],
            response_data[1],
            response_data[2],
            response_data[3],
        ]);
        let pid = u32::from_le_bytes([
            response_data[4],
            response_data[5],
            response_data[6],
            response_data[7],
        ]);
        let error_len = u16::from_le_bytes([response_data[8], response_data[9]]) as usize;

        let error = if error_len > 0 {
            Some(String::from_utf8_lossy(&response_data[10..10 + error_len]).to_string())
        } else {
            None
        };

        return Ok(ExecResponse {
            exit_code,
            pid,
            error,
        });
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!("Failed to communicate with daemon after 3 attempts")
    }))
}

/// Connect to running daemon and get metrics
pub fn get_metrics_from_daemon(socket_path: &Path) -> Result<MetricsResponse> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to daemon at {:?}", socket_path))?;

    // Send GetMetrics request (empty payload)
    let msg = Message::new(MessageType::GetMetrics, vec![]);
    let data = msg.serialize()?;
    stream.write_all(&data)?;

    // Read response
    let mut header = [0u8; 10];
    stream.read_exact(&mut header)?;
    let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;
    let mut response_data = vec![0u8; length];
    stream.read_exact(&mut response_data)?;

    // Parse MetricsResponse: [uptime:8][total:8][failed:8][successful:8][avg_ms:8][children:4][cgroup:1][prometheus_len:2][prometheus]
    let mut offset = 0;

    let uptime_secs = u64::from_le_bytes([
        response_data[offset],
        response_data[offset + 1],
        response_data[offset + 2],
        response_data[offset + 3],
        response_data[offset + 4],
        response_data[offset + 5],
        response_data[offset + 6],
        response_data[offset + 7],
    ]);
    offset += 8;

    let total_requests = u64::from_le_bytes([
        response_data[offset],
        response_data[offset + 1],
        response_data[offset + 2],
        response_data[offset + 3],
        response_data[offset + 4],
        response_data[offset + 5],
        response_data[offset + 6],
        response_data[offset + 7],
    ]);
    offset += 8;

    let failed_requests = u64::from_le_bytes([
        response_data[offset],
        response_data[offset + 1],
        response_data[offset + 2],
        response_data[offset + 3],
        response_data[offset + 4],
        response_data[offset + 5],
        response_data[offset + 6],
        response_data[offset + 7],
    ]);
    offset += 8;

    let successful_requests = u64::from_le_bytes([
        response_data[offset],
        response_data[offset + 1],
        response_data[offset + 2],
        response_data[offset + 3],
        response_data[offset + 4],
        response_data[offset + 5],
        response_data[offset + 6],
        response_data[offset + 7],
    ]);
    offset += 8;

    let avg_bits = u64::from_le_bytes([
        response_data[offset],
        response_data[offset + 1],
        response_data[offset + 2],
        response_data[offset + 3],
        response_data[offset + 4],
        response_data[offset + 5],
        response_data[offset + 6],
        response_data[offset + 7],
    ]);
    let avg_response_time_ms = f64::from_bits(avg_bits);
    offset += 8;

    let active_children = u32::from_le_bytes([
        response_data[offset],
        response_data[offset + 1],
        response_data[offset + 2],
        response_data[offset + 3],
    ]) as usize;
    offset += 4;

    let cgroup_active = response_data[offset] != 0;
    offset += 1;

    let prometheus_len =
        u16::from_le_bytes([response_data[offset], response_data[offset + 1]]) as usize;
    offset += 2;

    let prometheus_metrics =
        String::from_utf8_lossy(&response_data[offset..offset + prometheus_len]).to_string();

    Ok(MetricsResponse {
        uptime_secs,
        total_requests,
        failed_requests,
        successful_requests,
        avg_response_time_ms,
        active_children,
        cgroup_active,
        prometheus_metrics,
    })
}

/// Entry point for running as a warm daemon
/// Called when --internal-warm-daemon flag is detected in main()
pub async fn run_daemon_mode(args: &[String]) -> anyhow::Result<()> {
    use clap::Parser;

    #[derive(Parser)]
    struct DaemonArgs {
        #[arg(long, hide = true)]
        internal_warm_daemon: bool,

        #[arg(long)]
        socket: String,

        #[arg(long)]
        rootfs: String,

        #[arg(long, default_value = "1")]
        cpu_count: usize,

        #[arg(long, default_value = "512")]
        memory_mb: usize,
    }

    let args = DaemonArgs::parse_from(args);

    let config = DaemonConfig {
        socket_path: PathBuf::from(args.socket),
        rootfs_path: PathBuf::from(args.rootfs),
        hardware_profile: Some(HardwareProfile {
            cpu_affinity: None,
            numa_node: None,
            cpu_count: args.cpu_count,
            memory_mb: args.memory_mb,
        }),
        metrics_port: 9090,
    };

    let mut daemon = WarmDaemon::new(config)?;
    daemon.run()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
