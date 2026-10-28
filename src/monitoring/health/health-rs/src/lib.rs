//! Health Checker
//!
//! Monitors component health and system readiness.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Warm-daemon wire protocol constants.
//
// Source of truth: `src/cli/phantom-cli/src/daemon/warm.rs`
// (`PROTOCOL_MAGIC`, `PROTOCOL_VERSION`, `HEADER_SIZE`, `MAX_MESSAGE_SIZE`,
// `MessageType`, and `Message::serialize`). They are duplicated here because
// `phantom-cli` depends on `health-rs`, not the other way around.
const PROTOCOL_MAGIC: u32 = 0x50484E54; // "PHNT"
const PROTOCOL_VERSION: u8 = 1;
/// [magic:4][version:1][type:1][length:4]
const HEADER_SIZE: usize = 10;
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const MSG_TYPE_HEALTH_CHECK: u8 = 0x04;
const MSG_TYPE_HEALTH_RESPONSE: u8 = 0x05;

/// Serialize a `HealthCheck` frame exactly like `warm.rs::Message::serialize`:
/// `[magic:4 LE][version:1][type:1][payload length:4 LE][payload]`.
fn health_check_frame() -> [u8; HEADER_SIZE] {
    let mut frame = [0u8; HEADER_SIZE];
    frame[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
    frame[4] = PROTOCOL_VERSION;
    frame[5] = MSG_TYPE_HEALTH_CHECK;
    frame[6..10].copy_from_slice(&0u32.to_le_bytes()); // empty payload
    frame
}

/// Read and validate the daemon's reply frame.
///
/// Mirrors `warm.rs::read_message`: the header is validated (magic, version,
/// bounded length) before the payload is allocated, then the full payload is
/// read. Returns `true` only for a well-formed `HealthResponse` whose payload
/// starts with `OK` (see `warm.rs::handle_health_check`). An `Error` frame, a
/// wrong version, a truncated read, or any other frame is not healthy.
fn read_health_reply(stream: &mut UnixStream) -> std::io::Result<bool> {
    let mut header = [0u8; HEADER_SIZE];
    stream.read_exact(&mut header)?;

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != PROTOCOL_MAGIC {
        return Ok(false);
    }
    if header[4] != PROTOCOL_VERSION {
        return Ok(false);
    }

    let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if length > MAX_MESSAGE_SIZE {
        return Ok(false);
    }

    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;

    if header[5] != MSG_TYPE_HEALTH_RESPONSE {
        return Ok(false);
    }

    Ok(payload.starts_with(b"OK"))
}

/// Check if a process is alive by checking /proc/{pid}
pub fn is_process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

/// Health status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResult {
    pub status: HealthStatus,
    pub message: String,
    pub timestamp: u64,
}

/// Health configuration
#[derive(Debug, Clone, Default)]
pub struct HealthConfig {
    /// Health check timeout in milliseconds
    pub timeout_ms: u64,
    /// Enable verbose logging
    pub verbose: bool,
}

/// Health Monitor - centralized health checking for daemon supervision
pub struct HealthMonitor {
    config: HealthConfig,
    components: Arc<Mutex<HashMap<String, HealthResult>>>,
    last_check: Arc<Mutex<Option<Instant>>>,
}

impl HealthMonitor {
    /// Create a new HealthMonitor with default configuration
    pub fn new() -> Self {
        Self {
            config: HealthConfig::default(),
            components: Arc::new(Mutex::new(HashMap::new())),
            last_check: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new HealthMonitor with custom configuration
    pub fn with_config(config: HealthConfig) -> Self {
        Self {
            config,
            components: Arc::new(Mutex::new(HashMap::new())),
            last_check: Arc::new(Mutex::new(None)),
        }
    }

    /// Check health of a Unix socket endpoint (e.g., daemon socket)
    pub fn check_health(&self, socket_path: &Path) -> Result<HealthStatus, std::io::Error> {
        let timeout = Duration::from_millis(self.config.timeout_ms);

        if !socket_path.exists() {
            return Ok(HealthStatus::Unhealthy);
        }

        // Try to connect to the socket with timeout using std::thread
        let socket_path = socket_path.to_path_buf();
        let (tx, rx): (
            std::sync::mpsc::Sender<std::io::Result<std::os::unix::net::UnixStream>>,
            _,
        ) = std::sync::mpsc::channel();

        let _connect_handle = std::thread::spawn(move || {
            let result = std::os::unix::net::UnixStream::connect(&socket_path);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(Ok(mut stream)) => {
                // Set read timeout
                stream.set_read_timeout(Some(timeout)).ok();

                // Send a real HealthCheck frame (see `health_check_frame`)
                if stream.write_all(&health_check_frame()).is_err() {
                    self.update_component("socket", HealthStatus::Degraded, "Socket write failed");
                    return Ok(HealthStatus::Degraded);
                }

                // Read and validate the full reply frame
                match read_health_reply(&mut stream) {
                    Ok(true) => {
                        self.update_component("socket", HealthStatus::Healthy, "Socket responsive");
                        *self.last_check.lock().unwrap() = Some(Instant::now());
                        Ok(HealthStatus::Healthy)
                    }
                    Ok(false) => {
                        self.update_component(
                            "socket",
                            HealthStatus::Unhealthy,
                            "Unexpected health response",
                        );
                        Ok(HealthStatus::Unhealthy)
                    }
                    Err(_) => {
                        self.update_component(
                            "socket",
                            HealthStatus::Unhealthy,
                            "Socket not responding",
                        );
                        Ok(HealthStatus::Unhealthy)
                    }
                }
            }
            Ok(Err(_)) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.update_component("socket", HealthStatus::Unhealthy, "Connection timeout");
                Ok(HealthStatus::Unhealthy)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.update_component("socket", HealthStatus::Unhealthy, "Connection failed");
                Ok(HealthStatus::Unhealthy)
            }
        }
    }

    /// Check if a process is alive
    pub fn check_process(&self, pid: u32) -> HealthStatus {
        if is_process_alive(pid) {
            self.update_component(
                "process",
                HealthStatus::Healthy,
                &format!("Process {} alive", pid),
            );
            HealthStatus::Healthy
        } else {
            self.update_component(
                "process",
                HealthStatus::Unhealthy,
                &format!("Process {} not found", pid),
            );
            HealthStatus::Unhealthy
        }
    }

    /// Register a health update for a component
    pub fn update(&self, component: &str, status: HealthStatus, message: &str) {
        self.update_component(component, status, message);
    }

    fn update_component(&self, component: &str, status: HealthStatus, message: &str) {
        let mut map = self.components.lock().unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        map.insert(
            component.to_string(),
            HealthResult {
                status,
                message: message.to_string(),
                timestamp,
            },
        );
    }

    /// Check overall system health
    pub fn check_system(&self) -> HealthStatus {
        let map = self.components.lock().unwrap();
        let mut system_status = HealthStatus::Healthy;

        for result in map.values() {
            match result.status {
                HealthStatus::Unhealthy => return HealthStatus::Unhealthy,
                HealthStatus::Degraded => system_status = HealthStatus::Degraded,
                HealthStatus::Healthy => {}
            }
        }

        system_status
    }

    /// Get detailed health report
    pub fn get_report(&self) -> HashMap<String, HealthResult> {
        self.components.lock().unwrap().clone()
    }

    /// Get time since last health check
    pub fn time_since_last_check(&self) -> Option<Duration> {
        self.last_check
            .lock()
            .unwrap()
            .map(|instant| instant.elapsed())
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_SOCKET_ID: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn test_health_aggregation() {
        let monitor = HealthMonitor::new();

        monitor.update("storage", HealthStatus::Healthy, "OK");
        monitor.update("network", HealthStatus::Healthy, "OK");
        assert_eq!(monitor.check_system(), HealthStatus::Healthy);

        monitor.update("memory", HealthStatus::Degraded, "High usage");
        assert_eq!(monitor.check_system(), HealthStatus::Degraded);

        monitor.update("security", HealthStatus::Unhealthy, "Policy failure");
        assert_eq!(monitor.check_system(), HealthStatus::Unhealthy);
    }

    #[test]
    fn test_health_monitor() {
        let monitor = HealthMonitor::new();
        assert_eq!(monitor.check_system(), HealthStatus::Healthy);

        monitor.update("test", HealthStatus::Healthy, "Test passed");
        assert_eq!(monitor.check_system(), HealthStatus::Healthy);
    }

    /// The probe request must match `Message::new(MessageType::HealthCheck,
    /// vec![]).serialize()` in `src/cli/phantom-cli/src/daemon/warm.rs`:
    /// magic 0x50484E54 little-endian, version 1, type 0x04, length 0.
    #[test]
    fn test_health_check_frame_bytes() {
        let expected = [
            0x54, 0x4E, 0x48, 0x50, // 0x50484E54 as little-endian ("PHNT")
            0x01, // PROTOCOL_VERSION
            0x04, // MessageType::HealthCheck
            0x00, 0x00, 0x00, 0x00, // empty payload length
        ];
        assert_eq!(health_check_frame(), expected);
    }

    /// Build a reply frame by hand, mirroring `warm.rs::Message::serialize`.
    fn reply_frame(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x54, 0x4E, 0x48, 0x50]); // 0x50484E54 LE
        frame.push(0x01); // PROTOCOL_VERSION
        frame.push(msg_type);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Start a one-shot server that reads the probe request and writes `reply`.
    /// Returns the temp directory, the socket path, and the server thread.
    fn spawn_reply_server(reply: Vec<u8>) -> (PathBuf, PathBuf, std::thread::JoinHandle<()>) {
        let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("health-rs-test-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let socket_path = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind unix listener");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut request = [0u8; HEADER_SIZE];
            stream.read_exact(&mut request).expect("read probe request");
            assert_eq!(
                request,
                health_check_frame(),
                "probe must send a real HealthCheck frame"
            );
            stream.write_all(&reply).expect("write reply");
        });

        (dir, socket_path, handle)
    }

    fn monitor() -> HealthMonitor {
        HealthMonitor::with_config(HealthConfig {
            timeout_ms: 2000,
            verbose: false,
        })
    }

    #[test]
    fn test_probe_accepts_health_response() {
        let (dir, socket_path, handle) =
            spawn_reply_server(reply_frame(0x05, b"OK pid=1234 children=0"));

        let status = monitor().check_health(&socket_path).expect("probe runs");
        handle.join().expect("server thread");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(status, HealthStatus::Healthy);
    }

    #[test]
    fn test_probe_rejects_error_frame() {
        let (dir, socket_path, handle) =
            spawn_reply_server(reply_frame(0xFF, b"Invalid protocol magic"));

        let status = monitor().check_health(&socket_path).expect("probe runs");
        handle.join().expect("server thread");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_probe_rejects_non_ok_payload() {
        let (dir, socket_path, handle) = spawn_reply_server(reply_frame(0x05, b"BUSY"));

        let status = monitor().check_health(&socket_path).expect("probe runs");
        handle.join().expect("server thread");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_probe_rejects_garbage_reply() {
        let (dir, socket_path, handle) = spawn_reply_server(vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        ]);

        let status = monitor().check_health(&socket_path).expect("probe runs");
        handle.join().expect("server thread");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_probe_rejects_truncated_reply() {
        // Valid magic/version but the frame ends after four header bytes.
        let (dir, socket_path, handle) = spawn_reply_server(vec![0x54, 0x4E, 0x48, 0x50]);

        let status = monitor().check_health(&socket_path).expect("probe runs");
        handle.join().expect("server thread");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(status, HealthStatus::Unhealthy);
    }
}
