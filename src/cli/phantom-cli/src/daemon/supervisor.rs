//! Daemon Supervisor Module
//!
//! Provides automatic restart functionality for the warm fragment daemon.
//! Monitors daemon health and restarts it if it crashes or becomes unresponsive.
//!
//! Features:
//! - Automatic restart on crash
//! - Health check integration with health-rs
//! - Exponential backoff to prevent rapid restart loops
//! - Maximum retry limiting
//! - Comprehensive logging

use anyhow::{Context, Result};
use health_rs::{HealthConfig, HealthMonitor, HealthStatus as HealthRsStatus};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::daemon::warm::start_daemon_background;
use crate::daemon::warm::DaemonConfig;

/// Maximum number of restart attempts before giving up
const MAX_RESTART_ATTEMPTS: u32 = 10;

/// Initial backoff duration between restart attempts
const INITIAL_BACKOFF_MS: u64 = 100;

/// Maximum backoff duration (cap for exponential backoff)
const MAX_BACKOFF_MS: u64 = 30000; // 30 seconds

/// Health check interval
const HEALTH_CHECK_INTERVAL_MS: u64 = 5000;

/// Connection timeout for health checks
const HEALTH_CHECK_TIMEOUT_MS: u64 = 2000;

/// Supervisor state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    /// Supervisor is starting the daemon
    Starting,
    /// Daemon is running and healthy
    Running,
    /// Daemon crashed, waiting to restart
    Restarting,
    /// Supervisor is stopped
    Stopped,
    /// Maximum retries exceeded, supervisor gave up
    Failed,
}

/// Statistics about daemon restarts
#[derive(Debug, Clone, Default)]
pub struct SupervisorStats {
    /// Total number of restarts performed
    pub total_restarts: u32,
    /// Number of times max retries was exceeded
    pub max_retries_exceeded: u32,
    /// Total uptime in seconds (accumulated across restarts)
    pub total_uptime_secs: u64,
    /// Last restart timestamp (Unix epoch seconds)
    pub last_restart_timestamp: u64,
    /// Number of health check failures
    pub health_check_failures: u32,
    /// Number of successful health checks
    pub health_check_successes: u32,
}

/// Daemon supervisor configuration
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Base daemon configuration
    pub daemon_config: DaemonConfig,
    /// Enable automatic restarts (default: true)
    pub auto_restart: bool,
    /// Maximum number of restart attempts (default: 10)
    pub max_restart_attempts: u32,
    /// Maximum backoff in milliseconds (default: 30000)
    pub max_backoff_ms: u64,
    /// Health check interval in milliseconds (default: 5000)
    pub health_check_interval_ms: u64,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            daemon_config: DaemonConfig {
                socket_path: PathBuf::from("/tmp/phantom-warm.sock"),
                rootfs_path: PathBuf::from("/"),
                hardware_profile: None,
                metrics_port: 9090,
            },
            auto_restart: true,
            max_restart_attempts: MAX_RESTART_ATTEMPTS,
            max_backoff_ms: MAX_BACKOFF_MS,
            health_check_interval_ms: HEALTH_CHECK_INTERVAL_MS,
            verbose: false,
        }
    }
}

/// Daemon Supervisor
///
/// Monitors the warm daemon process and automatically restarts it
/// if it crashes or becomes unresponsive.
pub struct DaemonSupervisor {
    /// Configuration
    config: SupervisorConfig,
    /// Current daemon PID (if running)
    daemon_pid: Option<u32>,
    /// Current state
    state: SupervisorState,
    /// Running flag for the supervisor loop
    running: Arc<AtomicBool>,
    /// Current restart attempt count
    restart_attempts: Arc<AtomicU32>,
    /// Current backoff duration in milliseconds
    current_backoff_ms: Arc<AtomicU64>,
    /// Statistics
    stats: Arc<SupervisorStatsWrapper>,
    /// Start time of current daemon instance
    daemon_start_time: Option<Instant>,
    /// Total accumulated uptime
    total_uptime_secs: u64,
    /// Health monitor for centralized health checking
    health_monitor: HealthMonitor,
}

/// Thread-safe wrapper for stats
struct SupervisorStatsWrapper {
    inner: RwLock<SupervisorStats>,
}

impl SupervisorStatsWrapper {
    fn new() -> Self {
        Self {
            inner: RwLock::new(SupervisorStats::default()),
        }
    }

    fn update<F>(&self, f: F)
    where
        F: FnOnce(&mut SupervisorStats),
    {
        let mut stats = self.inner.write().unwrap();
        f(&mut *stats);
    }

    fn get(&self) -> SupervisorStats {
        self.inner.read().unwrap().clone()
    }
}

impl DaemonSupervisor {
    /// Create a new daemon supervisor
    pub fn new(config: SupervisorConfig) -> Self {
        let health_config = HealthConfig {
            timeout_ms: HEALTH_CHECK_TIMEOUT_MS,
            verbose: config.verbose,
        };
        Self {
            config,
            daemon_pid: None,
            state: SupervisorState::Stopped,
            running: Arc::new(AtomicBool::new(false)),
            restart_attempts: Arc::new(AtomicU32::new(0)),
            current_backoff_ms: Arc::new(AtomicU64::new(INITIAL_BACKOFF_MS)),
            stats: Arc::new(SupervisorStatsWrapper::new()),
            daemon_start_time: None,
            total_uptime_secs: 0,
            health_monitor: HealthMonitor::with_config(health_config),
        }
    }

    /// Get the current state
    pub fn state(&self) -> SupervisorState {
        self.state
    }

    /// Get supervisor statistics
    pub fn get_stats(&self) -> SupervisorStats {
        self.stats.get()
    }

    /// Start the supervisor and begin monitoring the daemon
    /// This runs in the current thread and blocks until stopped
    pub fn run(&mut self) -> Result<()> {
        log::info!("Starting daemon supervisor");
        self.running.store(true, Ordering::SeqCst);
        self.state = SupervisorState::Starting;

        // Start the daemon initially
        if let Err(e) = self.start_daemon() {
            log::error!("Failed to start initial daemon: {:?}", e);
            if !self.config.auto_restart {
                return Err(e);
            }
        }

        // Main monitoring loop
        while self.running.load(Ordering::SeqCst) {
            match self.state {
                SupervisorState::Starting | SupervisorState::Running => {
                    // Check daemon health
                    match self.check_daemon_health() {
                        Ok(healthy) => {
                            if healthy {
                                self.state = SupervisorState::Running;
                                if self.config.verbose {
                                    log::debug!("Daemon health check passed");
                                }
                            } else {
                                log::warn!("Daemon health check failed - daemon is unhealthy");
                                self.handle_daemon_crash();
                            }
                        }
                        Err(e) => {
                            log::warn!("Daemon health check error: {:?}", e);
                            self.stats.update(|s| s.health_check_failures += 1);
                            self.handle_daemon_crash();
                        }
                    }
                }
                SupervisorState::Restarting => {
                    // Wait for backoff period
                    let backoff_ms = self.current_backoff_ms.load(Ordering::Relaxed);
                    log::info!("Waiting {}ms before restart attempt", backoff_ms);

                    // Sleep in small increments to allow for stop signal
                    let sleep_interval = Duration::from_millis(100);
                    let mut elapsed = 0;
                    while elapsed < backoff_ms && self.running.load(Ordering::SeqCst) {
                        thread::sleep(sleep_interval);
                        elapsed += 100;
                    }

                    if !self.running.load(Ordering::SeqCst) {
                        break;
                    }

                    // Attempt restart
                    match self.start_daemon() {
                        Ok(_) => {
                            log::info!("Daemon restarted successfully");
                            self.state = SupervisorState::Running;
                            // Reset backoff on successful restart
                            self.current_backoff_ms
                                .store(INITIAL_BACKOFF_MS, Ordering::Relaxed);
                        }
                        Err(e) => {
                            log::error!("Failed to restart daemon: {:?}", e);
                            self.handle_restart_failure();
                        }
                    }
                }
                SupervisorState::Stopped | SupervisorState::Failed => {
                    // Exit the loop
                    break;
                }
            }

            // Sleep between health checks
            thread::sleep(Duration::from_millis(self.config.health_check_interval_ms));
        }

        // Cleanup
        self.stop();
        Ok(())
    }

    /// Start the supervisor in a background thread
    /// Returns a handle to control the supervisor
    pub fn start_background(&mut self) -> Result<SupervisorHandle> {
        let running = Arc::clone(&self.running);
        let restart_attempts = Arc::clone(&self.restart_attempts);
        let current_backoff_ms = Arc::clone(&self.current_backoff_ms);
        let stats = Arc::clone(&self.stats);

        // Create a channel for communication
        let (tx, rx) = std::sync::mpsc::channel();

        let config = self.config.clone();
        let socket_path = self.config.daemon_config.socket_path.clone();

        let handle = thread::spawn(move || {
            let mut supervisor = DaemonSupervisor::new(config);
            supervisor.running = running;
            supervisor.restart_attempts = restart_attempts;
            supervisor.current_backoff_ms = current_backoff_ms;
            supervisor.stats = stats;

            // Run the supervisor
            let result = supervisor.run();

            // Send final state back
            let _ = tx.send((
                supervisor.daemon_pid,
                supervisor.state,
                supervisor.get_stats(),
            ));

            result
        });

        // Wait briefly for daemon to start
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(20));
            if socket_path.exists() {
                if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
                    break;
                }
            }
        }

        Ok(SupervisorHandle {
            _thread: handle,
            _receiver: rx,
        })
    }

    /// Stop the supervisor
    pub fn stop(&mut self) {
        log::info!("Stopping daemon supervisor");
        self.running.store(false, Ordering::SeqCst);
        self.state = SupervisorState::Stopped;

        // Kill the daemon if running
        if let Some(pid) = self.daemon_pid.take() {
            let _ = kill_process(pid);
            log::info!("Killed daemon process {}", pid);
        }

        // Clean up socket file
        if self.config.daemon_config.socket_path.exists() {
            let _ = std::fs::remove_file(&self.config.daemon_config.socket_path);
        }
    }

    /// Start the daemon process
    fn start_daemon(&mut self) -> Result<()> {
        log::info!("Starting warm daemon");
        self.state = SupervisorState::Starting;

        // Clean up any existing socket
        if self.config.daemon_config.socket_path.exists() {
            let _ = std::fs::remove_file(&self.config.daemon_config.socket_path);
        }

        // Start the daemon
        let pid = start_daemon_background(self.config.daemon_config.clone())
            .context("Failed to start daemon process")?;

        self.daemon_pid = Some(pid);
        self.daemon_start_time = Some(Instant::now());

        self.stats.update(|s| {
            s.last_restart_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            s.total_restarts += 1;
        });

        log::info!("Daemon started with PID {}", pid);
        Ok(())
    }

    /// Check daemon health using health-rs HealthMonitor
    fn check_daemon_health(&self) -> Result<bool> {
        let socket_path = &self.config.daemon_config.socket_path;

        // Use health-rs for centralized health checking
        match self.health_monitor.check_health(socket_path) {
            Ok(HealthRsStatus::Healthy) => {
                self.stats.update(|s| s.health_check_successes += 1);
                Ok(true)
            }
            Ok(HealthRsStatus::Degraded) => {
                // Degraded is still considered "running" but with issues
                self.stats.update(|s| s.health_check_failures += 1);
                Ok(true)
            }
            Ok(HealthRsStatus::Unhealthy) => {
                self.stats.update(|s| s.health_check_failures += 1);
                Ok(false)
            }
            Err(e) => {
                log::warn!("Health check error: {:?}", e);
                self.stats.update(|s| s.health_check_failures += 1);
                Ok(false)
            }
        }
    }

    /// Handle daemon crash - transition to restart state
    fn handle_daemon_crash(&mut self) {
        log::warn!("Daemon crashed or became unresponsive");

        // Update uptime stats
        if let Some(start_time) = self.daemon_start_time.take() {
            self.total_uptime_secs += start_time.elapsed().as_secs();
            self.stats
                .update(|s| s.total_uptime_secs = self.total_uptime_secs);
        }

        // Check if we've exceeded max restart attempts
        let attempts = self.restart_attempts.load(Ordering::Relaxed);
        if attempts >= self.config.max_restart_attempts {
            log::error!(
                "Maximum restart attempts ({}) exceeded, giving up",
                self.config.max_restart_attempts
            );
            self.stats.update(|s| s.max_retries_exceeded += 1);
            self.state = SupervisorState::Failed;
            self.daemon_pid = None;
            return;
        }

        // Calculate exponential backoff
        let backoff_ms = self.current_backoff_ms.load(Ordering::Relaxed);
        log::info!(
            "Restart attempt {}/{} with {}ms backoff",
            attempts + 1,
            self.config.max_restart_attempts,
            backoff_ms
        );

        // Increase backoff for next time (exponential with cap)
        let next_backoff = (backoff_ms * 2).min(self.config.max_backoff_ms);
        self.current_backoff_ms
            .store(next_backoff, Ordering::Relaxed);

        // Increment restart attempts
        self.restart_attempts.fetch_add(1, Ordering::Relaxed);

        // Clean up old PID
        self.daemon_pid = None;

        // Transition to restarting state
        self.state = SupervisorState::Restarting;
    }

    /// Handle restart failure (when start_daemon fails)
    fn handle_restart_failure(&mut self) {
        let attempts = self.restart_attempts.load(Ordering::Relaxed);

        if attempts >= self.config.max_restart_attempts {
            log::error!(
                "Maximum restart attempts ({}) exceeded after start failures",
                self.config.max_restart_attempts
            );
            self.stats.update(|s| s.max_retries_exceeded += 1);
            self.state = SupervisorState::Failed;
        } else {
            // Increase backoff and try again
            let backoff_ms = self.current_backoff_ms.load(Ordering::Relaxed);
            let next_backoff = (backoff_ms * 2).min(self.config.max_backoff_ms);
            self.current_backoff_ms
                .store(next_backoff, Ordering::Relaxed);
            self.restart_attempts.fetch_add(1, Ordering::Relaxed);
            self.state = SupervisorState::Restarting;
        }
    }
}

impl Drop for DaemonSupervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Handle for controlling a background supervisor
pub struct SupervisorHandle {
    _thread: thread::JoinHandle<Result<()>>,
    _receiver: std::sync::mpsc::Receiver<(Option<u32>, SupervisorState, SupervisorStats)>,
}

/// Kill a process
fn kill_process(pid: u32) -> Result<()> {
    Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .output()
        .context(format!("Failed to kill process {}", pid))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_supervisor_creation() {
        let config = SupervisorConfig::default();
        let supervisor = DaemonSupervisor::new(config);

        assert_eq!(supervisor.state(), SupervisorState::Stopped);
        assert!(supervisor.daemon_pid().is_none());
    }

    #[test]
    fn test_exponential_backoff() {
        let config = SupervisorConfig {
            max_backoff_ms: 1000,
            ..Default::default()
        };

        // Simulate exponential backoff
        let mut backoff = 100u64;
        for _ in 0..10 {
            backoff = (backoff * 2).min(config.max_backoff_ms);
        }

        // Should be capped at max
        assert_eq!(backoff, config.max_backoff_ms);
    }

    #[test]
    fn test_is_process_alive() {
        // Current process should be alive
        let current_pid = std::process::id();
        assert!(is_process_alive(current_pid));

        // Non-existent PID should not be alive
        assert!(!is_process_alive(99999999));
    }

    #[test]
    fn test_supervisor_state_transitions() {
        let config = SupervisorConfig::default();
        let mut supervisor = DaemonSupervisor::new(config);

        assert_eq!(supervisor.state(), SupervisorState::Stopped);

        supervisor.state = SupervisorState::Starting;
        assert_eq!(supervisor.state(), SupervisorState::Starting);

        supervisor.state = SupervisorState::Running;
        assert_eq!(supervisor.state(), SupervisorState::Running);

        supervisor.state = SupervisorState::Restarting;
        assert_eq!(supervisor.state(), SupervisorState::Restarting);

        supervisor.state = SupervisorState::Failed;
        assert_eq!(supervisor.state(), SupervisorState::Failed);
    }

    #[test]
    fn test_supervisor_stats_update() {
        let config = SupervisorConfig::default();
        let supervisor = DaemonSupervisor::new(config);

        supervisor.stats.update(|s| {
            s.total_restarts = 5;
            s.health_check_successes = 10;
        });

        let stats = supervisor.get_stats();
        assert_eq!(stats.total_restarts, 5);
        assert_eq!(stats.health_check_successes, 10);
    }

    #[test]
    fn test_handle_daemon_crash_max_retries() {
        let config = SupervisorConfig {
            max_restart_attempts: 3,
            ..Default::default()
        };
        let mut supervisor = DaemonSupervisor::new(config);

        // Simulate 3 attempts
        supervisor.restart_attempts.store(3, Ordering::SeqCst);
        supervisor.handle_daemon_crash();

        assert_eq!(supervisor.state(), SupervisorState::Failed);
        assert_eq!(supervisor.get_stats().max_retries_exceeded, 1);
    }

    #[test]
    fn test_handle_daemon_crash_incremental() {
        let config = SupervisorConfig {
            max_restart_attempts: 10,
            ..Default::default()
        };
        let mut supervisor = DaemonSupervisor::new(config);

        supervisor.restart_attempts.store(0, Ordering::SeqCst);
        supervisor.handle_daemon_crash();

        assert_eq!(supervisor.state(), SupervisorState::Restarting);
        assert_eq!(supervisor.restart_attempts.load(Ordering::SeqCst), 1);
        // Initial backoff was 100, now should be 200
        assert_eq!(supervisor.current_backoff_ms.load(Ordering::SeqCst), 200);
    }
}
