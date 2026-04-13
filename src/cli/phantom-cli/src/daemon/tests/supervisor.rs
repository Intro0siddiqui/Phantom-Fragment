//! Tests for the Daemon Supervisor Module

use crate::daemon::supervisor::*;
use health_rs::is_process_alive;
use std::sync::atomic::Ordering;

#[test]
fn test_supervisor_creation() {
    let config = SupervisorConfig::default();
    let supervisor = DaemonSupervisor::new(config);

    assert_eq!(supervisor.state(), SupervisorState::Stopped);
    assert!(supervisor.daemon_pid.is_none());
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
