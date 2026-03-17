//! Unit tests for the debug library

use super::*;
use chrono::Utc;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fragment_inspector_creation() {
        let _inspector = FragmentInspector::new();
        // Test passes if it compiles and creates successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_log_analyzer_creation() {
        let _analyzer = LogAnalyzer::new();
        // Test passes if it compiles and creates successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_resource_monitor_creation() {
        let _monitor = ResourceMonitor::new();
        // Test passes if it compiles and creates successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_resource_monitor_with_history_creation() {
        let _monitor = ResourceMonitorWithHistory::new(100);
        // Test passes if it compiles and creates successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_fragment_profiler_creation() {
        let _profiler = FragmentProfiler::new();
        // Test passes if it compiles and creates successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_fragment_attacher_creation() {
        let _attacher = FragmentAttacher::new();
        // Test passes if it compiles and creates successfully
        assert!(true);
    }

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry {
            timestamp: Utc::now(),
            level: "INFO".to_string(),
            message: "Test message".to_string(),
            source: "test".to_string(),
            fragment_id: "test-fragment".to_string(),
            thread_id: 123,
            file: "test.rs".to_string(),
            line: 42,
        };

        assert_eq!(entry.level, "INFO");
        assert_eq!(entry.message, "Test message");
        assert_eq!(entry.thread_id, 123);
    }

    #[test]
    fn test_fragment_state_creation() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());

        let mut command_line = Vec::new();
        command_line.push("test".to_string());

        let state = FragmentState {
            fragment_id: "test-fragment".to_string(),
            pid: 1234,
            ppid: 1,
            state: "running".to_string(),
            threads: Vec::new(),
            memory: MemoryInfo::default(),
            files: Vec::new(),
            network: Vec::new(),
            namespaces: NamespaceInfo::default(),
            system_calls: Vec::new(),
            environment: env,
            command_line,
            start_time: Utc::now(),
            cpu_time: std::time::Duration::from_secs(10),
        };

        assert_eq!(state.fragment_id, "test-fragment");
        assert_eq!(state.pid, 1234);
        assert_eq!(state.ppid, 1);
        assert_eq!(state.state, "running");
        assert_eq!(state.environment.get("PATH"), Some(&"/usr/bin".to_string()));
        assert_eq!(state.command_line[0], "test");
    }

    #[test]
    fn test_resource_metrics_creation() {
        let metrics = ResourceMetrics {
            timestamp: Utc::now(),
            fragment_id: "test-fragment".to_string(),
            cpu_usage: 45.5,
            memory_usage: MemoryInfo::default(),
            io_stats: IOStats::default(),
            network_stats: NetworkStats::default(),
        };

        assert_eq!(metrics.fragment_id, "test-fragment");
        assert_eq!(metrics.cpu_usage, 45.5);
    }

    #[test]
    fn test_fragment_profile_creation() {
        let profile = FragmentProfile {
            fragment_id: "test-fragment".to_string(),
            profile_type: "cpu".to_string(),
            duration: 30,
            sample_count: 300,
            start_time: Utc::now(),
            end_time: Utc::now(),
            peak_cpu: 75.5,
            peak_memory: 128.5,
            total_cpu: 45.2,
            total_memory: 96.3,
            io_read_bytes: 1024 * 1024,
            io_write_bytes: 512 * 1024,
            syscalls: 1500,
            context_switches: 250,
            raw_data: vec![1, 2, 3, 4],
        };

        assert_eq!(profile.fragment_id, "test-fragment");
        assert_eq!(profile.profile_type, "cpu");
        assert_eq!(profile.duration, 30);
        assert_eq!(profile.sample_count, 300);
        assert_eq!(profile.peak_cpu, 75.5);
        assert_eq!(profile.raw_data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_debug_error_creation() {
        let err = DebugError::fragment_not_found("test-fragment");
        match err {
            DebugError::FragmentNotFound(id) => assert_eq!(id, "test-fragment"),
            _ => panic!("Wrong error type"),
        }

        let err = DebugError::invalid_argument("bad arg");
        match err {
            DebugError::InvalidArgument(msg) => assert_eq!(msg, "bad arg"),
            _ => panic!("Wrong error type"),
        }

        let err = DebugError::unsupported("feature");
        match err {
            DebugError::Unsupported(msg) => assert_eq!(msg, "feature"),
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_memory_info_default() {
        let mem = MemoryInfo::default();
        assert_eq!(mem.rss, 0);
        assert_eq!(mem.vms, 0);
        assert_eq!(mem.data, 0);
        assert_eq!(mem.stack, 0);
        assert_eq!(mem.swap, 0);
        assert_eq!(mem.page_faults, 0);
        assert_eq!(mem.minor_faults, 0);
        assert_eq!(mem.peak_rss, 0);
        assert_eq!(mem.peak_vms, 0);
    }

    #[test]
    fn test_io_stats_default() {
        let io = IOStats::default();
        assert_eq!(io.read_bytes_per_sec, 0.0);
        assert_eq!(io.write_bytes_per_sec, 0.0);
        assert_eq!(io.read_ops_per_sec, 0.0);
        assert_eq!(io.write_ops_per_sec, 0.0);
        assert!(io.read_latency.is_zero());
        assert!(io.write_latency.is_zero());
    }

    #[test]
    fn test_network_stats_default() {
        let net = NetworkStats::default();
        assert_eq!(net.bytes_sent_per_sec, 0.0);
        assert_eq!(net.bytes_recv_per_sec, 0.0);
        assert_eq!(net.packets_sent_per_sec, 0.0);
        assert_eq!(net.packets_recv_per_sec, 0.0);
    }

    #[test]
    fn test_namespace_info_default() {
        let ns = NamespaceInfo::default();
        assert_eq!(ns.pid, 0);
        assert_eq!(ns.mount, "");
        assert_eq!(ns.uts, "");
        assert_eq!(ns.ipc, "");
        assert_eq!(ns.network, "");
        assert_eq!(ns.user, "");
        assert_eq!(ns.cgroups, "");
    }

    #[test]
    fn test_thread_info_creation() {
        let thread = ThreadInfo {
            id: 123,
            state: "running".to_string(),
            cpu_usage: 25.5,
            stack: vec![0, 1, 2, 3],
        };

        assert_eq!(thread.id, 123);
        assert_eq!(thread.state, "running");
        assert_eq!(thread.cpu_usage, 25.5);
        assert_eq!(thread.stack, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_file_info_creation() {
        let file = FileInfo {
            fd: 3,
            path: "/tmp/test".to_string(),
            file_type: "file".to_string(),
            position: 1024,
            flags: "rw".to_string(),
        };

        assert_eq!(file.fd, 3);
        assert_eq!(file.path, "/tmp/test");
        assert_eq!(file.file_type, "file");
        assert_eq!(file.position, 1024);
        assert_eq!(file.flags, "rw");
    }

    #[test]
    fn test_network_connection_creation() {
        let conn = NetworkConnection {
            protocol: "tcp".to_string(),
            local_addr: "127.0.0.1:8080".to_string(),
            remote_addr: "127.0.0.1:9090".to_string(),
            state: "ESTABLISHED".to_string(),
            send_queue: 0,
            recv_queue: 0,
        };

        assert_eq!(conn.protocol, "tcp");
        assert_eq!(conn.local_addr, "127.0.0.1:8080");
        assert_eq!(conn.remote_addr, "127.0.0.1:9090");
        assert_eq!(conn.state, "ESTABLISHED");
        assert_eq!(conn.send_queue, 0);
        assert_eq!(conn.recv_queue, 0);
    }

    #[test]
    fn test_syscall_info_creation() {
        let syscall = SyscallInfo {
            name: "read".to_string(),
            count: 150,
            total_time: std::time::Duration::from_millis(10),
            errors: 0,
        };

        assert_eq!(syscall.name, "read");
        assert_eq!(syscall.count, 150);
        assert_eq!(syscall.total_time, std::time::Duration::from_millis(10));
        assert_eq!(syscall.errors, 0);
    }
}
