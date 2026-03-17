//! Health Checker
//!
//! Monitors component health and system readiness.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

                // Send a simple health check probe (empty message)
                let probe = b"\x00\x00\x00\x00\x01\x04\x00\x00\x00\x00";
                if stream.write_all(probe).is_err() {
                    self.update_component("socket", HealthStatus::Degraded, "Socket write failed");
                    return Ok(HealthStatus::Degraded);
                }

                // Try to read response
                let mut header = [0u8; 10];
                match stream.read_exact(&mut header) {
                    Ok(_) => {
                        self.update_component("socket", HealthStatus::Healthy, "Socket responsive");
                        *self.last_check.lock().unwrap() = Some(Instant::now());
                        Ok(HealthStatus::Healthy)
                    }
                    Err(_) => {
                        self.update_component(
                            "socket",
                            HealthStatus::Degraded,
                            "Socket not responding",
                        );
                        Ok(HealthStatus::Degraded)
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

// Required imports for UnixStream operations
use std::io::{Read, Write};

#[cfg(test)]
mod tests {
    use super::*;

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
}
