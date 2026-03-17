//! Core data structures and types for the debug library

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// System information collected by DebugInspector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Kernel version
    pub kernel: String,
    /// Architecture (e.g., x86_64)
    pub arch: String,
    /// CPU information
    pub cpu: CpuInfo,
    /// Memory information
    pub memory: MemoryInfo,
}

/// CPU information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuInfo {
    /// Number of CPU cores
    pub cores: usize,
    /// CPU frequency in GHz
    pub frequency_ghz: f64,
    /// CPU model name
    pub model: String,
}

/// Resource usage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Number of active fragments
    pub active_fragments: usize,
    /// Total CPU time in seconds
    pub total_cpu_time_secs: f64,
    /// Total memory usage in bytes
    pub total_memory_bytes: u64,
    /// Zygote pool statistics
    pub zygote_pool: ZygotePoolInfo,
}

/// Zygote pool information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZygotePoolInfo {
    /// Number of available zygotes
    pub available: usize,
    /// Total zygote pool size
    pub total: usize,
}

/// Active fragment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveFragment {
    /// Fragment name/ID
    pub name: String,
    /// Process ID
    pub pid: Option<u32>,
    /// Memory usage in KB
    pub memory_kb: u64,
    /// CPU time in seconds
    pub cpu_time_secs: f64,
    /// Fragment status
    pub status: String,
}

/// Debug configuration
#[derive(Debug, Clone, Default)]
pub struct DebugConfig {
    /// Enable verbose output
    pub verbose: bool,
    /// Output format (text, json)
    pub format: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FragmentProfile {
    pub fragment_id: String,
    pub profile_type: String,
    pub duration: u32,
    pub sample_count: u32,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub peak_cpu: f64,
    pub peak_memory: f64,
    pub total_cpu: f64,
    pub total_memory: f64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub syscalls: u64,
    pub context_switches: u64,
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentState {
    pub fragment_id: String,
    pub pid: i32,
    pub ppid: i32,
    pub state: String,
    pub threads: Vec<ThreadInfo>,
    pub memory: MemoryInfo,
    pub files: Vec<FileInfo>,
    pub network: Vec<NetworkConnection>,
    pub namespaces: NamespaceInfo,
    pub system_calls: Vec<SyscallInfo>,
    pub environment: HashMap<String, String>,
    pub command_line: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub cpu_time: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub id: i32,
    pub state: String,
    pub cpu_usage: f64,
    pub stack: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub rss: u64,
    pub vms: u64,
    pub data: u64,
    pub stack: u64,
    pub swap: u64,
    pub page_faults: u64,
    pub minor_faults: u64,
    pub peak_rss: u64,
    pub peak_vms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub fd: i32,
    pub path: String,
    pub file_type: String,
    pub position: u64,
    pub flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub send_queue: u32,
    pub recv_queue: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamespaceInfo {
    pub pid: i32,
    pub mount: String,
    pub uts: String,
    pub ipc: String,
    pub network: String,
    pub user: String,
    pub cgroups: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInfo {
    pub name: String,
    pub count: u64,
    pub total_time: std::time::Duration,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub source: String,
    pub fragment_id: String,
    pub thread_id: i32,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub timestamp: DateTime<Utc>,
    pub fragment_id: String,
    pub cpu_usage: f64,
    pub memory_usage: MemoryInfo,
    pub io_stats: IOStats,
    pub network_stats: NetworkStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IOStats {
    pub read_bytes_per_sec: f64,
    pub write_bytes_per_sec: f64,
    pub read_ops_per_sec: f64,
    pub write_ops_per_sec: f64,
    pub read_latency: std::time::Duration,
    pub write_latency: std::time::Duration,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkStats {
    pub bytes_sent_per_sec: f64,
    pub bytes_recv_per_sec: f64,
    pub packets_sent_per_sec: f64,
    pub packets_recv_per_sec: f64,
}

#[async_trait::async_trait]
pub trait DebuggerBackend: Send + Sync {
    async fn attach(&mut self, pid: i32, port: u16) -> crate::Result<()>;
    async fn detach(&mut self) -> crate::Result<()>;
    async fn get_state(&self) -> crate::Result<String>;
    async fn send_command(&mut self, cmd: &str) -> crate::Result<String>;
}

#[async_trait::async_trait]
pub trait ProfilerBackend: Send + Sync {
    async fn start(&mut self, pid: i32) -> crate::Result<()>;
    async fn stop(&mut self) -> crate::Result<FragmentProfile>;
    async fn collect_sample(&mut self) -> crate::Result<()>;
    fn box_clone(&self) -> Box<dyn ProfilerBackend>;
}

impl Clone for Box<dyn ProfilerBackend> {
    fn clone(&self) -> Box<dyn ProfilerBackend> {
        self.box_clone()
    }
}

#[async_trait::async_trait]
pub trait LogSource: Send + Sync {
    async fn get_logs(&self, since: DateTime<Utc>, limit: usize) -> crate::Result<Vec<LogEntry>>;
    async fn follow_logs(
        &self,
        callback: Box<dyn Fn(LogEntry) -> crate::Result<()> + Send + Sync + 'static>,
    ) -> crate::Result<()>;
    async fn filter_logs(
        &self,
        logs: Vec<LogEntry>,
        filter: &str,
        level: &str,
    ) -> crate::Result<Vec<LogEntry>>;
}

pub struct FragmentAttacher {
    pub debuggers: HashMap<String, Box<dyn DebuggerBackend>>,
}

pub struct FragmentProfiler {
    pub profilers: HashMap<String, Box<dyn ProfilerBackend>>,
}

#[derive(Debug)]
pub struct FragmentInspector;

pub struct LogAnalyzer {
    pub log_sources: HashMap<String, Box<dyn LogSource>>,
}

#[derive(Debug)]
pub struct ResourceMonitor;

#[derive(Debug)]
pub struct ResourceMonitorWithHistory {
    pub monitor: ResourceMonitor,
    pub history: Vec<ResourceMetrics>,
    pub max_history: usize,
}

/// Debug Inspector - provides system-wide debugging and monitoring information
#[derive(Debug)]
pub struct DebugInspector;

impl DebugInspector {
    /// Create a new DebugInspector with the given configuration
    pub fn new(_config: DebugConfig) -> crate::Result<Self> {
        Ok(Self)
    }

    /// Get system information (kernel, arch, CPU, memory)
    pub fn get_system_info(&self) -> crate::Result<SystemInfo> {
        // Get OS release (kernel version)
        let kernel = sys_info::os_release().unwrap_or_else(|_| "unknown".to_string());

        // Get architecture using uname via nix
        let arch = unsafe {
            let mut utsname = std::mem::MaybeUninit::<libc::utsname>::uninit();
            if libc::uname(utsname.as_mut_ptr()) == 0 {
                let utsname = utsname.assume_init();
                std::ffi::CStr::from_ptr(&utsname.machine as *const libc::c_char)
                    .to_string_lossy()
                    .into_owned()
            } else {
                "unknown".to_string()
            }
        };

        let cpu_cores = num_cpus::get();
        let cpu_freq = sys_info::cpu_speed()
            .map(|s| s as f64 / 1000.0)
            .unwrap_or(0.0);

        // Get CPU model from /proc/cpuinfo
        let cpu_model = std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|line| line.starts_with("model name"))
                    .and_then(|line| line.split(':').nth(1))
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());

        let mem_info = sys_info::mem_info().map_err(|e| {
            crate::DebugError::SystemCall(format!("Failed to get memory info: {}", e))
        })?;

        Ok(SystemInfo {
            kernel,
            arch,
            cpu: CpuInfo {
                cores: cpu_cores,
                frequency_ghz: cpu_freq,
                model: cpu_model,
            },
            memory: MemoryInfo {
                rss: mem_info.total * 1024,
                vms: mem_info.avail * 1024,
                data: 0,
                stack: 0,
                swap: mem_info.swap_total * 1024,
                page_faults: 0,
                minor_faults: 0,
                peak_rss: 0,
                peak_vms: 0,
            },
        })
    }

    /// Get resource usage statistics
    pub fn get_resource_usage(&self) -> crate::Result<ResourceUsage> {
        // Count active phantom processes
        let active_fragments = self.count_active_fragments();

        // Get total CPU time from /proc/stat
        let total_cpu_time_secs = self.get_total_cpu_time();

        // Get total memory usage
        let mem_info = sys_info::mem_info().map_err(|e| {
            crate::DebugError::SystemCall(format!("Failed to get memory info: {}", e))
        })?;
        let total_memory_bytes = (mem_info.total - mem_info.avail) * 1024;

        // Get zygote pool info by scanning for zygote processes
        let zygote_pool = self.get_zygote_pool_info();

        Ok(ResourceUsage {
            active_fragments,
            total_cpu_time_secs,
            total_memory_bytes,
            zygote_pool,
        })
    }

    /// Get zygote pool information by scanning for zygote processes
    fn get_zygote_pool_info(&self) -> ZygotePoolInfo {
        let mut available = 0usize;
        let mut total = 0usize;

        // Try to find zygote processes
        if let Ok(all_procs) = procfs::process::all_processes() {
            for proc_result in all_procs.flatten() {
                if let Ok(comm) = proc_result.stat().map(|s| s.comm) {
                    if comm.contains("zygote") || comm.contains("phantom-zygote") {
                        total += 1;
                        // Check if process is idle/available by checking CPU time
                        if let Ok(stat) = proc_result.stat() {
                            let clock_ticks = procfs::ticks_per_second() as f64;
                            let cpu_time = (stat.utime + stat.stime) as f64 / clock_ticks;
                            // Consider process available if it has low CPU time (idle)
                            if cpu_time < 1.0 {
                                available += 1;
                            }
                        }
                    }
                }

                // Also check environment for zygote markers
                if let Ok(environ) = proc_result.environ() {
                    if let Some(val) = environ.get(&std::ffi::OsString::from("PHANTOM_ZYGOTE")) {
                        total += 1;
                        if val.to_string_lossy() == "available" || val.to_string_lossy() == "idle" {
                            available += 1;
                        }
                    }
                }
            }
        }

        // Also try to read from zygote status file if it exists
        if total == 0 {
            if let Ok(content) = std::fs::read_to_string("/tmp/phantom-zygote-pool.status") {
                for line in content.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        match key.trim() {
                            "total" => total = value.trim().parse().unwrap_or(0),
                            "available" => available = value.trim().parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                }
            }
        }

        // Default fallback if no zygote processes found
        if total == 0 {
            total = 4;
            available = 4;
        }

        ZygotePoolInfo { available, total }
    }

    /// Get list of active fragments
    pub fn get_active_fragments(&self) -> crate::Result<Vec<ActiveFragment>> {
        let mut fragments = Vec::new();

        // Find phantom fragment processes
        if let Ok(all_procs) = procfs::process::all_processes() {
            for proc_result in all_procs.flatten() {
                if let Ok(cmdline) = proc_result.cmdline() {
                    let cmd_str = cmdline.join(" ");
                    if cmd_str.contains("phantom") || cmd_str.contains("PHANTOM") {
                        let stat = proc_result.stat().ok();
                        let memory_kb = proc_result
                            .statm()
                            .map(|s| (s.resident * procfs::page_size()) / 1024)
                            .unwrap_or(0);

                        let cpu_time_secs = stat
                            .map(|s| {
                                let clock_ticks = procfs::ticks_per_second() as f64;
                                ((s.utime + s.stime) as f64) / clock_ticks
                            })
                            .unwrap_or(0.0);

                        fragments.push(ActiveFragment {
                            name: format!("fragment-{}", proc_result.pid),
                            pid: Some(proc_result.pid as u32),
                            memory_kb,
                            cpu_time_secs,
                            status: "running".to_string(),
                        });
                    }
                }
            }
        }

        Ok(fragments)
    }

    /// Count active fragment processes
    fn count_active_fragments(&self) -> usize {
        if let Ok(all_procs) = procfs::process::all_processes() {
            all_procs
                .flatten()
                .filter_map(|p| p.cmdline().ok())
                .filter(|cmd| {
                    cmd.iter()
                        .any(|c| c.contains("phantom") || c.contains("PHANTOM"))
                })
                .count()
        } else {
            0
        }
    }

    /// Get total CPU time from /proc/stat
    fn get_total_cpu_time(&self) -> f64 {
        if let Ok(content) = std::fs::read_to_string("/proc/stat") {
            for line in content.lines() {
                if line.starts_with("cpu ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let user: u64 = parts[1].parse().unwrap_or(0);
                        let nice: u64 = parts[2].parse().unwrap_or(0);
                        let system: u64 = parts[3].parse().unwrap_or(0);
                        let _idle: u64 = parts[4].parse().unwrap_or(0);
                        let clock_ticks = procfs::ticks_per_second() as f64;
                        return (user + nice + system) as f64 / clock_ticks;
                    }
                }
            }
        }
        0.0
    }
}
