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

/// Size of the fixed message header: [magic:4][version:1][type:1][length:4]
const HEADER_SIZE: usize = 10;

/// Reserved environment variable that carries the security-profile name.
///
/// `ExecRequest` has no profile field and the v1 wire format must not change,
/// so the client piggybacks the name on the existing env map. The daemon reads
/// it, strips it from the child environment and resolves it through
/// `crate::config`. This is a temporary v1-compatible carrier; `ExecV2` gets a
/// real field (see `docs/architecture/components/warm-exec-v2.md`).
pub const PROFILE_ENV: &str = "PHANTOM_PROFILE";

/// Profile applied when a request does not carry [`PROFILE_ENV`].
///
/// Matches the `--profile` default in `commands::run`, so a warm exec without an
/// explicit profile enforces the same policy as the cold path.
const DEFAULT_PROFILE: &str = "sandbox";

/// Landlock access flags understood by `landlock-rs`'s rule encoding
/// (`0x2` = write, `0x4` = execute; read is always implied).
const LL_ACCESS_WRITE: u64 = 0x2;
const LL_ACCESS_EXECUTE: u64 = 0x4;

/// `prctl(2)` options that `libc` does not export for linux-gnu.
const PR_SET_PDEATHSIG: libc::c_int = 1;
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

/// `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words per capability set.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Upper bound for a single message payload.
///
/// The length field is attacker-controlled, so it must never be trusted when
/// allocating a buffer. 1 MiB is far above anything the warm daemon needs
/// (exec requests are a few KiB at most) while keeping a malformed or
/// malicious peer from forcing a multi-gigabyte allocation.
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

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
        if self.payload.len() > MAX_MESSAGE_SIZE {
            anyhow::bail!(
                "Message payload too large: {} bytes (max {})",
                self.payload.len(),
                MAX_MESSAGE_SIZE
            );
        }

        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
        buf.push(PROTOCOL_VERSION);
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    /// Decode a message from an in-memory buffer.
    ///
    /// Kept for protocol completeness and tests; the daemon and client read
    /// frames through [`read_message`], which validates before allocating.
    #[allow(dead_code)]
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
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

        if length > MAX_MESSAGE_SIZE {
            anyhow::bail!(
                "Message payload length {} exceeds maximum {}",
                length,
                MAX_MESSAGE_SIZE
            );
        }

        if data.len() < HEADER_SIZE + length {
            anyhow::bail!("Incomplete message payload");
        }

        let payload = data[HEADER_SIZE..HEADER_SIZE + length].to_vec();
        Ok(Self { msg_type, payload })
    }
}

/// Read and validate a complete message from a stream.
///
/// This is the single framing entry point used by both the daemon and the
/// client. The header is validated (magic, version, bounded length) *before*
/// the payload buffer is allocated, so a truncated header, a protocol
/// mismatch, or an absurd length can never trigger a huge allocation or an
/// out-of-bounds read. `read_exact` loops internally, so partial reads are
/// handled correctly.
pub fn read_message<R: Read>(reader: &mut R) -> Result<Message> {
    let mut header = [0u8; HEADER_SIZE];
    reader
        .read_exact(&mut header)
        .context("Failed to read message header")?;

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != PROTOCOL_MAGIC {
        anyhow::bail!("Invalid protocol magic: 0x{:08X}", magic);
    }

    if header[4] != PROTOCOL_VERSION {
        anyhow::bail!("Unsupported protocol version: {}", header[4]);
    }

    let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if length > MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "Message payload length {} exceeds maximum {}",
            length,
            MAX_MESSAGE_SIZE
        );
    }

    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .context("Failed to read message payload")?;

    Ok(Message {
        msg_type: MessageType::from(header[5]),
        payload,
    })
}

/// Write a framed message to a stream.
///
/// `write_all` loops internally, so short writes are handled correctly.
pub fn write_message<W: Write>(writer: &mut W, message: &Message) -> Result<()> {
    let data = message.serialize()?;
    writer.write_all(&data).context("Failed to write message")?;
    Ok(())
}

/// Bounds-checked reader for the length-prefixed exec payload.
///
/// Every field is validated against the remaining payload before it is
/// sliced, so malformed input produces an `Err` instead of a panic.
struct PayloadReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, len: usize, what: &str) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .context("Payload field length overflow")?;
        if end > self.data.len() {
            anyhow::bail!(
                "Malformed payload: {} needs {} byte(s) at offset {} but only {} remain",
                what,
                len,
                self.offset,
                self.data.len().saturating_sub(self.offset)
            );
        }
        let slice = &self.data[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn read_u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    fn read_u16(&mut self, what: &str) -> Result<u16> {
        let bytes = self.take(2, what)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self, what: &str) -> Result<u32> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self, what: &str) -> Result<u64> {
        let bytes = self.take(8, what)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_string(&mut self, what: &str) -> Result<String> {
        let len = self.read_u16(&format!("{} length", what))? as usize;
        let bytes = self.take(len, what)?;
        Ok(String::from_utf8_lossy(bytes).to_string())
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

/// Security policy enforced by the warm child, resolved from a config profile.
#[derive(Debug, Clone, Copy)]
struct ChildPolicy {
    /// Whether the profile allows writes under the rootfs.
    file_write: bool,
    /// `seccomp-rs` filter to install before exec.
    seccomp: &'static str,
}

/// Resolve a profile name through the same config the CLI uses.
///
/// An unknown name is a hard error: silently running the command unconfined
/// when the caller asked for a profile would defeat the point of the profile.
fn resolve_child_policy(name: &str) -> Result<ChildPolicy> {
    let config = crate::config::Config::load().unwrap_or_else(|e| {
        log::warn!(
            "Failed to load phantom config while resolving warm profile '{}': {}",
            name,
            e
        );
        crate::config::Config::default()
    });

    let profile = config
        .get_profile(name)
        .ok_or_else(|| anyhow::anyhow!("unknown security profile: {}", name))?;

    Ok(ChildPolicy {
        file_write: profile.file_write,
        seccomp: seccomp_profile_for(profile),
    })
}

/// Map a config profile to the `seccomp-rs` filter for its isolation level,
/// mirroring the mode → profile mapping in `execution-rs`.
fn seccomp_profile_for(profile: &crate::config::Profile) -> &'static str {
    match profile.to_execution_mode() {
        execution_rs::ExecutionMode::Sandbox => "default",
        execution_rs::ExecutionMode::Hardened => "hardened",
        execution_rs::ExecutionMode::Wasm => "strict",
    }
}

/// Confine the calling process (the forked warm child) with Landlock.
///
/// Rules use paths as seen *after* `chroot(2)`, i.e. `/` is the image root and
/// `/tmp` / `/dev/shm` are the tmpfs mounts created just before this call. A
/// rule on `/` does not cover a separate mount, so the tmpfs roots get their own
/// rule.
fn apply_child_landlock(file_write: bool) -> std::result::Result<(), String> {
    let ctx = match landlock_rs::LandlockContext::new() {
        Some(ctx) => ctx,
        None => {
            // Kernel without Landlock (< 5.13): nothing can be enforced, but
            // that must not stop the command from running.
            log::warn!("Landlock unavailable; warm child runs without filesystem confinement");
            return Ok(());
        }
    };

    let access = if file_write {
        LL_ACCESS_WRITE | LL_ACCESS_EXECUTE
    } else {
        LL_ACCESS_EXECUTE
    };

    for path in ["/", "/tmp", "/dev/shm"] {
        if !Path::new(path).is_dir() {
            continue;
        }
        ctx.add_rule(path, access)
            .map_err(|e| format!("Landlock rule for {} failed: {}", path, e))?;
    }

    ctx.apply()
        .map_err(|e| format!("Landlock restrict_self failed: {}", e))
}

/// Drop the capability bounding set and clear the capability sets, then set
/// `no_new_privs`.
///
/// Defence in depth: the child is already unprivileged in the parent namespace,
/// so a kernel or namespace that refuses these calls must not fail the exec.
fn drop_child_capabilities() {
    /// `struct __user_cap_header_struct`
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    /// `struct __user_cap_data_struct`
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // A capability dropped from the bounding set cannot be regained across
    // execve. EINVAL (unknown to this kernel) and EPERM (already absent) are
    // both expected and harmless.
    let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<libc::c_int>().ok())
        .unwrap_or(63);
    for cap in 0..=last_cap {
        // SAFETY: prctl with PR_CAPBSET_DROP takes the capability number as arg2.
        unsafe { libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) };
    }

    // Clear the calling thread's sets. The child is single-threaded here, so a
    // per-thread capset covers the whole process.
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset takes a header and an array of two data words, matching
    // _LINUX_CAPABILITY_VERSION_3.
    let ret =
        unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if ret != 0 {
        log::warn!("capset(clear) failed: {}", std::io::Error::last_os_error());
    }

    // no_new_privs is what makes the drop stick across execve.
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes the flag value as arg2.
    if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        log::warn!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            std::io::Error::last_os_error()
        );
    }
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

        // Remove a stale socket file, but never clobber a live daemon.
        //
        // Previously this unconditionally unlinked the path, so starting a
        // second daemon (or a duplicate supervisor) silently stole the socket
        // from the running one, leaving the first daemon unreachable.
        if config.socket_path.exists() {
            if UnixStream::connect(&config.socket_path).is_ok() {
                anyhow::bail!(
                    "A warm daemon is already listening on {:?}; refusing to replace its socket",
                    config.socket_path
                );
            }

            // Nothing is listening: the socket is stale, safe to remove.
            fs::remove_file(&config.socket_path).with_context(|| {
                format!("Failed to remove stale socket: {:?}", config.socket_path)
            })?;
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
                    // The listener is non-blocking, so `incoming()` reports
                    // WouldBlock whenever no connection is pending. Sleep
                    // briefly instead of spinning (this previously burned a
                    // full CPU core for the daemon's whole lifetime).
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
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

        // Leave the launcher's session before accepting anything, so a Ctrl+C
        // aimed at the shell that ran `phantom warm create` cannot signal the
        // daemon or its children.
        detach_daemon_session();

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
            // The listener must be registered from inside the runtime: tokio's
            // `from_std` requires an active reactor.
            let listener = self
                .listener
                .try_clone()
                .context("Failed to clone daemon listener")?;
            let async_listener = tokio::net::UnixListener::from_std(listener)
                .context("Failed to register daemon listener with tokio")?;
            let mut prune_interval = tokio::time::interval(std::time::Duration::from_secs(1));

            loop {
                tokio::select! {
                    accept_result = async_listener.accept() => {
                        match accept_result {
                            Ok((stream, _addr)) => {
                                if !self.running.load(Ordering::SeqCst) {
                                    break;
                                }

                                let std_stream = match stream.into_std() {
                                    Ok(s) => s,
                                    Err(e) => {
                                        log::error!("Failed to convert client stream: {:?}", e);
                                        continue;
                                    }
                                };
                                if let Err(e) = std_stream.set_nonblocking(false) {
                                    log::error!("Failed to set client stream to blocking: {:?}", e);
                                    continue;
                                }

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

            Ok::<(), anyhow::Error>(())
        })?;

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

        // Read and validate the framed request. Header validation (magic,
        // version, bounded length) happens before any payload allocation.
        let msg = read_message(stream)?;

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

        // Parse request: [cmd_len:2][cmd][args_count:1][args...][env_count:1][env...][cwd_len:2][cwd][profile:1][cpu:4][mem:4]
        //
        // All reads go through PayloadReader: a truncated or malformed payload
        // is rejected with an error rather than panicking on slice indexing.
        let mut reader = PayloadReader::new(payload);

        let command = reader.read_string("command")?;

        let args_count = reader.read_u8("args count")? as usize;
        let mut args = Vec::with_capacity(args_count);
        for _ in 0..args_count {
            args.push(reader.read_string("argument")?);
        }

        let env_count = reader.read_u8("env count")? as usize;
        let mut env = HashMap::new();
        for _ in 0..env_count {
            let key = reader.read_string("env key")?;
            let val = reader.read_string("env value")?;
            env.insert(key, val);
        }

        let cwd = {
            let cwd = reader.read_string("cwd")?;
            if cwd.is_empty() {
                None
            } else {
                Some(cwd)
            }
        };

        let has_profile = reader.read_u8("profile flag")? != 0;
        let hardware_profile = if has_profile {
            // Read profile: [cpu_count:4][memory_mb:4]
            let cpu_count = reader.read_u32("cpu count")? as usize;
            let memory_mb = reader.read_u32("memory mb")? as usize;
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

        // Resolve the security profile before forking. An unknown profile is a
        // normal exec error, not a child setup failure.
        let profile_name = request
            .env
            .get(PROFILE_ENV)
            .map(String::as_str)
            .unwrap_or(DEFAULT_PROFILE);
        let child_policy = resolve_child_policy(profile_name)?;

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
            // `PHANTOM_PROFILE` is the v1 carrier for the profile name: the
            // daemon consumes it, the child must never see it.
            if key == PROFILE_ENV {
                continue;
            }
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
            .filter(|(k, _)| k != PROFILE_ENV)
            .filter_map(|(k, v)| CString::new(format!("{}={}", k, v)).ok())
            .collect();
        final_env.extend(env_vars);

        // Determine and validate working directory.
        //
        // `request.cwd` arrives as a host path under the rootfs, but the child
        // chdir()s after chroot(2), where that host prefix no longer exists.
        // Strip it so the stored value is absolute inside the new root.
        let chroot_cwd = if let Some(ref cwd) = request.cwd {
            let cwd_path = PathBuf::from(cwd);

            // Canonicalize to resolve symlinks and ..
            let canonical_cwd = cwd_path.canonicalize().unwrap_or_else(|_| cwd_path.clone());

            // Ensure cwd is within rootfs boundary
            if !canonical_cwd.starts_with(&self.config.rootfs_path) {
                anyhow::bail!("cwd escapes rootfs boundary: {}", cwd);
            }

            let relative = canonical_cwd
                .strip_prefix(&self.config.rootfs_path)
                .expect("cwd boundary checked above");

            if relative.as_os_str().is_empty() {
                "/".to_string()
            } else {
                format!("/{}", relative.display())
            }
        } else {
            "/".to_string()
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
            } else if request.command.contains('/') {
                self.config.rootfs_path.join(&cmd_path)
            } else {
                // Bare name: the child resolves it with execvp inside the
                // chroot, so validate against a standard PATH here too.
                ["bin", "usr/bin", "sbin", "usr/sbin"]
                    .iter()
                    .map(|dir| self.config.rootfs_path.join(dir).join(&cmd_path))
                    // Rootfs binaries are absolute symlinks (`/bin/echo ->
                    // /bin/busybox`) that only resolve after the chroot, so
                    // `exists()` would reject them; lstat the link itself.
                    .find(|candidate| candidate.symlink_metadata().is_ok())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "command not found in rootfs PATH: {} (searched {:?})",
                            request.command,
                            self.config.rootfs_path
                        )
                    })?
            };

            // Verify the command exists within rootfs
            if full_path.symlink_metadata().is_err() {
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

        // Create cgroup in parent BEFORE fork so we can destroy it after child exits.
        //
        // The name is computed exactly once, here in the parent, and the child
        // reuses it. Previously the child recomputed the timestamp after fork,
        // producing a *different* name: it tried to join a cgroup that did not
        // exist (so limits were never applied) while the parent destroyed its
        // empty cgroup. That silently disabled cgroup enforcement.
        let cgroup_name: Option<String> = request.hardware_profile.as_ref().map(|_| {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0) as u64;

            format!("phantom_warm_{}_{}", self.daemon_id, timestamp)
        });

        let cgroup: Option<CgroupManager> = if let (Some(profile), Some(name)) =
            (request.hardware_profile.as_ref(), cgroup_name.as_deref())
        {
            let cgroup = CgroupManager::new(name);

            // Create cgroup
            if let Err(e) = cgroup.create() {
                log::warn!("Failed to create cgroup {}: {:?}", name, e);
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

        // Fail-closed status pipe.
        //
        // The daemon is spawned with `Stdio::null()`, so anything the child
        // prints is lost. The child reports setup/exec failures through this
        // pipe instead. The write end is CLOEXEC, so the parent reads EOF with
        // no bytes only when execvp() actually succeeded.
        let (status_read, status_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .context("Failed to create exec status pipe")?;

        // Build child-only paths before fork to keep the post-fork window small.
        let c_rootfs = CString::new(self.config.rootfs_path.to_string_lossy().as_bytes())
            .context("rootfs path contains a NUL byte")?;
        let c_chroot_cwd =
            CString::new(chroot_cwd.as_str()).context("working directory contains a NUL byte")?;

        // Fork-exec pattern: apply cgroup BETWEEN fork and exec
        // SAFETY: Signal masking is critical before fork to prevent race conditions.
        // In multi-threaded programs, signals could be delivered to the child process
        // before it can establish its own signal handlers, causing undefined behavior.
        let (pid, exec_error) = unsafe {
            let mut sigmask: libc::sigset_t = std::mem::zeroed();
            let mut old_sigmask: libc::sigset_t = std::mem::zeroed();

            // Initialize sigset to block all signals
            libc::sigfillset(&mut sigmask);

            // Block all signals before fork
            let mask_ret = libc::pthread_sigmask(libc::SIG_SETMASK, &sigmask, &mut old_sigmask);
            if mask_ret != 0 {
                let _ = nix::unistd::close(status_read);
                let _ = nix::unistd::close(status_write);
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
                    // === IN CHILD PROCESS ===
                    // At this point, we are a copy of the parent but before exec.
                    // This is the ONLY safe place to apply cgroups.

                    // Only the parent consumes the status pipe.
                    let _ = nix::unistd::close(status_read);

                    // Report a setup failure to the parent and fail closed.
                    // `_exit` is async-signal-safe and skips atexit handlers.
                    let fail = |msg: String| -> ! {
                        let _ = nix::unistd::write(status_write, msg.as_bytes());
                        libc::_exit(127);
                    };

                    // CRITICAL: Child must restore signals before any non-async-signal-safe operations
                    if restore_ret != 0 {
                        fail(format!(
                            "Failed to restore signal mask after fork: errno {}",
                            restore_ret
                        ));
                    }

                    // Apply cgroup limits BEFORE exec - child is still just our code
                    // The cgroup was already created by the parent; we just need to add ourselves
                    // using the SAME name the parent created.
                    if let Some(ref name) = cgroup_name {
                        let cgroup = CgroupManager::new(name);

                        // CRITICAL: Add current process (PID 0) to cgroup BEFORE exec
                        // PID 0 means "current process" in the cgroup API
                        if let Err(e) = cgroup.add_process(0) {
                            eprintln!("Failed to add self to cgroup: {:?}", e);
                            // Continue execution without cgroup - don't fail completely
                        }
                    }

                    // Capture credentials before entering the user namespace:
                    // the mapping itself is written with the caller's host ids.
                    let uid = libc::getuid();
                    let gid = libc::getgid();

                    // ENFORCE NAMESPACE PURITY
                    // A user namespace is required first: without it the daemon
                    // (unprivileged uid 1000) has no CAP_SYS_CHROOT/CAP_SYS_ADMIN
                    // and both chroot(2) and mount(2) would fail with EPERM.
                    // The mount namespace is owned by the new user namespace.
                    if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                        fail(format!(
                            "unshare(CLONE_NEWUSER|CLONE_NEWNS) failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }

                    // `setgroups` does not exist on older kernels; anything else
                    // is fatal because gid_map would then be unusable.
                    if let Err(e) = write_proc_file("/proc/self/setgroups", b"deny") {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            fail(format!("Failed to write /proc/self/setgroups: {}", e));
                        }
                    }
                    if let Err(e) = write_proc_file(
                        "/proc/self/uid_map",
                        format!("{} {} 1", uid, uid).as_bytes(),
                    ) {
                        fail(format!("Failed to write /proc/self/uid_map: {}", e));
                    }
                    if let Err(e) = write_proc_file(
                        "/proc/self/gid_map",
                        format!("{} {} 1", gid, gid).as_bytes(),
                    ) {
                        fail(format!("Failed to write /proc/self/gid_map: {}", e));
                    }

                    // Make all mounts private so they don't propagate to parent
                    let c_root =
                        CString::new("/").expect("Static string cannot contain null bytes");
                    if libc::mount(
                        std::ptr::null(),
                        c_root.as_ptr(),
                        std::ptr::null(),
                        libc::MS_PRIVATE | libc::MS_REC,
                        std::ptr::null(),
                    ) != 0
                    {
                        fail(format!(
                            "mount(/, MS_PRIVATE|MS_REC) failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }

                    // The image may not have a usable /dev/null, so open the
                    // host's before the root switch.
                    let null_fd = match nix::fcntl::open(
                        "/dev/null",
                        nix::fcntl::OFlag::O_RDONLY,
                        nix::sys::stat::Mode::empty(),
                    ) {
                        Ok(fd) => fd,
                        Err(e) => fail(format!("Failed to open /dev/null: {}", e)),
                    };

                    // Enter the image. Everything from here on runs inside the
                    // rootfs, so the command validated above is now the file
                    // execvp() will actually execute.
                    if libc::chroot(c_rootfs.as_ptr()) != 0 {
                        fail(format!(
                            "chroot({}) failed: {}",
                            self.config.rootfs_path.display(),
                            std::io::Error::last_os_error()
                        ));
                    }

                    // Change to target directory inside the new root
                    if libc::chdir(c_chroot_cwd.as_ptr()) != 0 {
                        fail(format!(
                            "chdir({}) failed: {}",
                            chroot_cwd,
                            std::io::Error::last_os_error()
                        ));
                    }

                    // tmpfs hygiene inside the new root. These mounts are not a
                    // security boundary; failures are ignored.
                    for dir in ["/tmp", "/dev/shm"] {
                        if !Path::new(dir).is_dir() {
                            continue;
                        }
                        let c_dir = match CString::new(dir) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let c_tmpfs =
                            CString::new("tmpfs").expect("Static string cannot contain null bytes");
                        libc::mount(
                            c_tmpfs.as_ptr(),
                            c_dir.as_ptr(),
                            c_tmpfs.as_ptr(),
                            0,
                            std::ptr::null(),
                        );
                    }

                    // Redirect stdin from the host's /dev/null opened above.
                    // stdout/stderr stay inherited.
                    let _ = nix::unistd::dup2(null_fd, 0);
                    if null_fd != 0 {
                        let _ = nix::unistd::close(null_fd);
                    }

                    // === Security stack ===
                    // Order: landlock -> caps/no_new_privs -> seccomp -> exec.
                    // Landlock and the capability drop need no privileges; the
                    // seccomp filter goes last so it cannot block our own setup
                    // syscalls.
                    if let Err(e) = apply_child_landlock(child_policy.file_write) {
                        // Fail closed: the profile's filesystem policy could
                        // not be enforced, so the command must not run.
                        fail(e);
                    }

                    // Defence in depth only: the child is already unprivileged
                    // in the parent namespace, so this never fails the exec.
                    drop_child_capabilities();

                    // Fail closed: a profile that asks for a filter must not
                    // run without one.
                    if let Err(e) = seccomp_rs::apply_profile(child_policy.seccomp) {
                        fail(format!(
                            "seccomp profile '{}' could not be installed: {}",
                            child_policy.seccomp, e
                        ));
                    }

                    // Set environment variables using libc::setenv
                    for env_var in &final_env {
                        let env_str = match env_var.to_str() {
                            Ok(s) => s,
                            Err(_) => {
                                fail("Invalid environment variable encoding".to_string());
                            }
                        };
                        if let Some(eq_pos) = env_str.find('=') {
                            let key = &env_str[..eq_pos];
                            let val = &env_str[eq_pos + 1..];
                            let c_key = match CString::new(key) {
                                Ok(c) => c,
                                Err(_) => fail("Invalid environment variable key".to_string()),
                            };
                            let c_val = match CString::new(val) {
                                Ok(c) => c,
                                Err(_) => fail("Invalid environment variable value".to_string()),
                            };
                            libc::setenv(c_key.as_ptr(), c_val.as_ptr(), 1);
                        }
                    }

                    // NOW exec - child is already restricted by cgroup
                    // This is the key security fix: cgroup is applied BEFORE the target
                    // command ever starts executing
                    let exec_result = execvp(&c_cmd, &c_args_with_cmd);

                    // If execvp returns, it failed.
                    // SAFETY: Use _exit(127) instead of exit() to avoid flushing stdio buffers
                    // twice (once in child, once in parent), which could cause duplicate output.
                    fail(format!(
                        "execvp({}) failed: {:?}",
                        validated_command, exec_result
                    ));
                }
                Ok(ForkResult::Parent { child }) => {
                    // === IN PARENT PROCESS ===
                    // child is the PID of the forked process

                    // Close the write end or the read below would never see EOF.
                    let _ = nix::unistd::close(status_write);

                    // Log if signal restoration failed (only safe to do in parent)
                    if restore_ret != 0 {
                        log::warn!(
                            "Failed to restore signal mask after fork: errno {}",
                            restore_ret
                        );
                    }

                    // Read to EOF: bytes mean the child failed before exec,
                    // while a clean EOF means execvp() succeeded.
                    let mut status = Vec::new();
                    let mut chunk = [0u8; 256];
                    loop {
                        match nix::unistd::read(status_read, &mut chunk) {
                            Ok(0) => break,
                            Ok(n) => status.extend_from_slice(&chunk[..n]),
                            Err(nix::errno::Errno::EINTR) => continue,
                            Err(_) => break,
                        }
                    }
                    let _ = nix::unistd::close(status_read);

                    let error = if status.is_empty() {
                        None
                    } else {
                        Some(String::from_utf8_lossy(&status).into_owned())
                    };

                    (child.as_raw() as u32, error)
                }
                Err(e) => {
                    // Signal restoration already attempted above, but fork failed
                    let _ = nix::unistd::close(status_read);
                    let _ = nix::unistd::close(status_write);
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
            error: exec_error,
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
        payload.extend_from_slice(&response.avg_response_time_ms.to_bits().to_le_bytes());
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
    ///
    /// A zombie child is still visible to `kill(pid, 0)`, so a pure liveness
    /// probe never reaps anything. Reap with `waitpid(WNOHANG)` first and drop
    /// entries that were reaped or are no longer our children. Returns the
    /// number of pruned children.
    pub fn prune_dead_children(&self) -> usize {
        let mut locked_children = self.children.lock().unwrap();
        let pids: Vec<u32> = locked_children.keys().copied().collect();
        let mut to_remove = Vec::new();

        for pid in pids {
            match nix::sys::wait::waitpid(
                nix::unistd::Pid::from_raw(pid as i32),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG),
            ) {
                // Child is still running: keep tracking it.
                Ok(nix::sys::wait::WaitStatus::StillAlive) => {}
                // Child exited or was signalled and has now been reaped.
                Ok(_) => to_remove.push(pid),
                // Not our child anymore (already reaped elsewhere or the PID
                // was reused): drop the stale tracking entry.
                Err(nix::errno::Errno::ECHILD) => to_remove.push(pid),
                // Transient error: retry on the next tick.
                Err(_) => {}
            }
        }

        let mut pruned = 0;
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
            let raw_pid = nix::unistd::Pid::from_raw(pid as i32);

            // Kill child if still running
            let _ = nix::sys::signal::kill(raw_pid, nix::sys::signal::Signal::SIGTERM);

            // Reap the child so it does not linger as a zombie. Give it a short
            // grace period, then force-kill and wait for it.
            let mut reaped = false;
            for _ in 0..20 {
                match nix::sys::wait::waitpid(raw_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Ok(_) => {
                        reaped = true;
                        break;
                    }
                    Err(nix::errno::Errno::ECHILD) => {
                        reaped = true;
                        break;
                    }
                    Err(_) => {}
                }
            }
            if !reaped {
                let _ = nix::sys::signal::kill(raw_pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(raw_pid, None);
            }

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

        // Same detachment as the production loop; the test harness process is
        // the "daemon", so this is observable via /proc/<pid>/stat.
        detach_daemon_session();

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
            let listener = self
                .listener
                .try_clone()
                .context("Failed to clone daemon listener")?;
            let async_listener = tokio::net::UnixListener::from_std(listener)
                .context("Failed to register daemon listener with tokio")?;
            let mut prune_interval = tokio::time::interval(std::time::Duration::from_millis(100)); // faster prune for tests

            loop {
                tokio::select! {
                    accept_result = async_listener.accept() => {
                        match accept_result {
                            Ok((stream, _addr)) => {
                                if !self.running.load(Ordering::SeqCst) {
                                    break;
                                }
                                let std_stream = match stream.into_std() {
                                    Ok(s) => s,
                                    Err(e) => {
                                        log::error!("Failed to convert client stream: {:?}", e);
                                        continue;
                                    }
                                };
                                if let Err(e) = std_stream.set_nonblocking(false) {
                                    log::error!("Failed to set client stream to blocking: {:?}", e);
                                    continue;
                                }
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

            Ok::<(), anyhow::Error>(())
        })?;

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

/// Write a single value to a procfs control file.
///
/// Used for `/proc/self/{setgroups,uid_map,gid_map}` after entering a user
/// namespace. The kernel requires the mapping to be written in one call.
fn write_proc_file(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(data)
}

/// Set up Ctrl+C handler
fn ctrlc_handler<F>(f: F) -> Result<()>
where
    F: FnMut() + Send + 'static,
{
    ctrlc::set_handler(f).context("Failed to set Ctrl+C handler")
}

/// Detach the daemon from the session of the process that launched it.
///
/// `start_daemon_background` spawns the daemon with a plain `Command`, so it
/// inherits the launcher's session and process group: a `Ctrl+C` in the shell
/// that ran `phantom warm create` would signal the daemon and every warm child.
fn detach_daemon_session() {
    // SAFETY: setsid(2) takes no arguments.
    if unsafe { libc::setsid() } < 0 {
        let err = std::io::Error::last_os_error();
        // EPERM means the caller already leads a session: nothing to detach.
        if err.raw_os_error() != Some(libc::EPERM) {
            log::warn!("setsid() failed: {}", err);
        }
    }

    // A detached daemon has no controlling terminal, but an explicit SIGHUP
    // (supervisor restart, shell job cleanup) must not take it down.
    // SAFETY: signal(2) with SIG_IGN and a valid signal number.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    // The launcher exits as soon as the socket is ready; clear any inherited
    // parent-death signal so that does not kill the daemon.
    // SAFETY: prctl with PR_SET_PDEATHSIG takes the signal number (0 = none).
    if unsafe { libc::prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) } != 0 {
        log::warn!(
            "PR_SET_PDEATHSIG(0) failed: {}",
            std::io::Error::last_os_error()
        );
    }
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

    let mut child = cmd.spawn().context("Failed to spawn daemon")?;
    let pid = child.id();

    // Wait for socket to be ready
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(20));

        // If the daemon exited early, reap it and report the failure instead of
        // waiting the full timeout and leaving a zombie behind.
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("Daemon exited during startup with status: {}", status);
        }

        if socket_path.exists() {
            // Try to connect
            if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
                return Ok(pid);
            }
        }
    }

    // Startup timed out: do not leave an orphaned daemon or zombie process.
    let _ = child.kill();
    let _ = child.wait();

    anyhow::bail!("Daemon failed to start (socket not ready)");
}

/// Ping a running daemon via Unix socket to verify it is responsive
pub fn ping_daemon(socket_path: &Path) -> Result<bool> {
    let mut stream = match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(1)))
        .ok();

    let msg = Message::new(MessageType::HealthCheck, vec![]);
    if write_message(&mut stream, &msg).is_err() {
        return Ok(false);
    }

    // read_message validates magic, version and the length bound, so a broken
    // or malicious peer cannot make us allocate an absurd buffer.
    match read_message(&mut stream) {
        Ok(response) => Ok(response.msg_type == MessageType::HealthResponse),
        Err(_) => Ok(false),
    }
}

/// Connect to running daemon and send exec request with auto-reconnect retries and timeouts
pub fn exec_in_daemon(socket_path: &Path, request: &ExecRequest) -> Result<ExecResponse> {
    // Reject requests whose length-prefixed fields cannot be represented by the
    // wire format instead of silently truncating them with `as u16`/`as u8`.
    validate_exec_request(request)?;

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
        if let Err(e) = write_message(&mut stream, &msg) {
            last_err = Some(anyhow::anyhow!("Failed to send request to daemon: {}", e));
            std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
            continue;
        }

        // Read response
        let response = match read_message(&mut stream) {
            Ok(msg) => msg,
            Err(e) => {
                last_err = Some(anyhow::anyhow!(
                    "Failed to read response from daemon: {}",
                    e
                ));
                std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
                continue;
            }
        };

        if !matches!(
            response.msg_type,
            MessageType::ExecResponse | MessageType::Error
        ) {
            return Err(anyhow::anyhow!(
                "Unexpected response type from daemon: {:?}",
                response.msg_type
            ));
        }

        return parse_exec_response(&response.payload);
    }

    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("Failed to communicate with daemon after 3 attempts")))
}

/// Validate that an exec request fits the wire format.
fn validate_exec_request(request: &ExecRequest) -> Result<()> {
    if request.command.len() > u16::MAX as usize {
        anyhow::bail!("Command too long: {} bytes", request.command.len());
    }
    if request.args.len() > u8::MAX as usize {
        anyhow::bail!("Too many arguments: {}", request.args.len());
    }
    for arg in &request.args {
        if arg.len() > u16::MAX as usize {
            anyhow::bail!("Argument too long: {} bytes", arg.len());
        }
    }
    if request.env.len() > u8::MAX as usize {
        anyhow::bail!("Too many environment variables: {}", request.env.len());
    }
    for (key, val) in &request.env {
        if key.len() > u16::MAX as usize || val.len() > u16::MAX as usize {
            anyhow::bail!("Environment entry too long: {}={}", key, val);
        }
    }
    if let Some(ref cwd) = request.cwd {
        if cwd.len() > u16::MAX as usize {
            anyhow::bail!("Working directory too long: {} bytes", cwd.len());
        }
    }
    Ok(())
}

/// Parse an `ExecResponse` payload: [exit_code:4][pid:4][error_len:2][error]
fn parse_exec_response(payload: &[u8]) -> Result<ExecResponse> {
    let mut reader = PayloadReader::new(payload);

    let exit_code = reader.read_u32("exit code")? as i32;
    let pid = reader.read_u32("pid")?;
    let error_len = reader.read_u16("error length")? as usize;
    let error = if error_len > 0 {
        let bytes = reader.take(error_len, "error message")?;
        Some(String::from_utf8_lossy(bytes).to_string())
    } else {
        None
    };

    Ok(ExecResponse {
        exit_code,
        pid,
        error,
    })
}

/// Connect to running daemon and get metrics
pub fn get_metrics_from_daemon(socket_path: &Path) -> Result<MetricsResponse> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to daemon at {:?}", socket_path))?;

    // Without timeouts a wedged daemon makes this call hang forever.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();

    // Send GetMetrics request (empty payload)
    let msg = Message::new(MessageType::GetMetrics, vec![]);
    write_message(&mut stream, &msg)?;

    // Read response
    let response = read_message(&mut stream).context("Failed to read metrics response")?;
    if response.msg_type != MessageType::MetricsResponse {
        anyhow::bail!(
            "Unexpected response type from daemon: {:?}",
            response.msg_type
        );
    }

    // Parse MetricsResponse: [uptime:8][total:8][failed:8][successful:8][avg_ms:8][children:4][cgroup:1][prometheus_len:2][prometheus]
    let mut reader = PayloadReader::new(&response.payload);

    let uptime_secs = reader.read_u64("uptime")?;
    let total_requests = reader.read_u64("total requests")?;
    let failed_requests = reader.read_u64("failed requests")?;
    let successful_requests = reader.read_u64("successful requests")?;
    let avg_response_time_ms = f64::from_bits(reader.read_u64("avg response time")?);
    let active_children = reader.read_u32("active children")? as usize;
    let cgroup_active = reader.read_u8("cgroup active")? != 0;
    let prometheus_len = reader.read_u16("prometheus length")? as usize;
    let prometheus_metrics =
        String::from_utf8_lossy(reader.take(prometheus_len, "prometheus metrics")?).to_string();

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
///
/// `WarmDaemon::run` builds its own Tokio runtime and blocks on it, which
/// panics with "Cannot start a runtime from within a runtime" when called from
/// `#[tokio::main]`. Run it on a dedicated OS thread so it owns a fresh runtime.
pub fn run_daemon_mode(args: &[String]) -> anyhow::Result<()> {
    let args = args.to_vec();
    std::thread::Builder::new()
        .name("warm-daemon".to_string())
        .spawn(move || daemon_main(&args))
        .context("Failed to spawn warm daemon thread")?
        .join()
        .map_err(|_| anyhow::anyhow!("Warm daemon thread panicked"))?
}

fn daemon_main(args: &[String]) -> anyhow::Result<()> {
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
