//! Performance profiling module for fragments

use chrono::Utc;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout};

use crate::error::{DebugError, Result};
use crate::types::*;

impl FragmentProfiler {
    pub fn new() -> Self {
        Self {
            profilers: HashMap::new(),
        }
    }

    pub async fn profile(
        &mut self,
        fragment_id: &str,
        profile_type: &str,
        duration_secs: u32,
    ) -> Result<FragmentProfile> {
        let pid = self.find_fragment_pid(fragment_id).await?;

        let backend = self.get_profiler_backend(profile_type)?;

        let start_time = Utc::now();
        backend.start(pid).await?;

        let sample_interval = Duration::from_millis(100);
        let sample_count = (duration_secs as u64 * 1000) / 100;

        let (tx, mut rx) = mpsc::channel(100);

        let mut backend_clone = backend.clone();
        tokio::spawn(async move {
            let mut interval = interval(sample_interval);
            for _ in 0..sample_count {
                interval.tick().await;
                if backend_clone.collect_sample().await.is_err() {
                    break;
                }
            }
            let _ = tx.send(()).await;
        });

        let timeout_duration = Duration::from_secs(duration_secs as u64 + 1);
        let _ = timeout(timeout_duration, rx.recv()).await;

        let end_time = Utc::now();
        let mut profile = backend.stop().await?;

        profile.fragment_id = fragment_id.to_string();
        profile.duration = duration_secs;
        profile.sample_count = sample_count as u32;
        profile.start_time = start_time;
        profile.end_time = end_time;

        self.enrich_profile(&mut profile, pid).await?;

        Ok(profile)
    }

    pub async fn save_profile(&self, profile: &FragmentProfile, filename: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(profile).map_err(DebugError::Serialization)?;

        tokio::fs::write(filename, json)
            .await
            .map_err(DebugError::Io)?;

        Ok(())
    }

    async fn find_fragment_pid(&self, fragment_id: &str) -> Result<i32> {
        let all_procs = procfs::process::all_processes()
            .map_err(|e| DebugError::SystemCall(format!("failed to read processes: {}", e)))?;

        for proc in all_procs.flatten() {
            if let Ok(cmdline) = proc.cmdline() {
                if cmdline.iter().any(|arg| arg.contains(fragment_id)) {
                    return Ok(proc.pid);
                }
            }

            if let Ok(comm) = proc.stat().map(|s| s.comm) {
                if comm.contains(fragment_id) {
                    return Ok(proc.pid);
                }
            }

            if let Ok(environ) = proc.environ() {
                if let Some(frag_id) = environ.get(&std::ffi::OsString::from("PHANTOM_FRAGMENT_ID"))
                {
                    if frag_id.to_string_lossy() == fragment_id {
                        return Ok(proc.pid);
                    }
                }
            }
        }

        Err(DebugError::fragment_not_found(fragment_id))
    }

    fn get_profiler_backend(
        &mut self,
        profile_type: &str,
    ) -> Result<&mut Box<dyn ProfilerBackend>> {
        if !self.profilers.contains_key(profile_type) {
            let backend: Box<dyn ProfilerBackend> = match profile_type {
                "cpu" => Box::new(CPUProfiler::new()),
                "memory" => Box::new(MemoryProfiler::new()),
                "io" => Box::new(IOProfiler::new()),
                "all" => Box::new(CombinedProfiler::new()),
                _ => {
                    return Err(DebugError::unsupported(format!(
                        "profile type: {}",
                        profile_type
                    )))
                }
            };
            self.profilers.insert(profile_type.to_string(), backend);
        }

        self.profilers
            .get_mut(profile_type)
            .ok_or_else(|| DebugError::debugger(format!("Profiler '{}' not found", profile_type)))
    }

    async fn enrich_profile(&self, profile: &mut FragmentProfile, pid: i32) -> Result<()> {
        if let Ok(stat) = self.get_process_stat(pid).await {
            profile.total_cpu = stat.cpu_usage;
            profile.total_memory = stat.rss as f64 / 1024.0 / 1024.0;
            profile.syscalls = stat.syscalls;
            profile.context_switches = stat.context_switches;
        }

        if let Ok(io_stat) = self.get_io_stat(pid).await {
            profile.io_read_bytes = io_stat.read_bytes;
            profile.io_write_bytes = io_stat.write_bytes;
        }

        // Collect raw profile data
        profile.raw_data = self.collect_raw_profile_data(pid).await?;

        Ok(())
    }

    async fn get_process_stat(&self, pid: i32) -> Result<ProcessStat> {
        let proc = procfs::process::Process::new(pid)
            .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

        let stat = proc
            .stat()
            .map_err(|e| DebugError::SystemCall(format!("failed to read stat: {}", e)))?;

        let utime = stat.utime;
        let stime = stat.stime;
        let clock_ticks = 100;
        let total_time = (utime + stime) * 1000 / clock_ticks;

        let rss_pages = stat.rss;
        let page_size = procfs::page_size();
        let rss_bytes = rss_pages * page_size;

        // Get context switches and voluntary/involuntary switches from /proc/[pid]/status
        let (voluntary_switches, involuntary_switches) = self.get_context_switches(pid).await?;

        // Get syscall count from /proc/[pid]/syscall (if available)
        let syscalls = self.get_syscall_count(pid).await?;

        Ok(ProcessStat {
            cpu_usage: total_time as f64 / 1000.0,
            rss: rss_bytes,
            syscalls,
            context_switches: voluntary_switches + involuntary_switches,
        })
    }

    async fn get_context_switches(&self, pid: i32) -> Result<(u64, u64)> {
        let status_path = format!("/proc/{}/status", pid);
        let content = tokio::fs::read_to_string(&status_path)
            .await
            .map_err(DebugError::Io)?;

        let mut voluntary = 0u64;
        let mut involuntary = 0u64;

        for line in content.lines() {
            if let Some(value) = line.strip_prefix("voluntary_ctxt_switches:") {
                voluntary = value.trim().parse().unwrap_or(0);
            } else if let Some(value) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
                involuntary = value.trim().parse().unwrap_or(0);
            }
        }

        Ok((voluntary, involuntary))
    }

    async fn get_syscall_count(&self, pid: i32) -> Result<u64> {
        // Try to read from /proc/[pid]/syscall
        let syscall_path = format!("/proc/{}/syscall", pid);
        if let Ok(_content) = tokio::fs::read_to_string(&syscall_path).await {
            // The syscall file contains current syscall info, not count
            // We estimate based on process stats
            if let Ok(stat) = procfs::process::Process::new(pid).and_then(|p| p.stat()) {
                // Estimate syscalls based on CPU time (rough heuristic)
                // ~100 syscalls per second of CPU time is a reasonable estimate
                let clock_ticks = procfs::ticks_per_second();
                let cpu_time_secs = (stat.utime + stat.stime) as f64 / clock_ticks as f64;
                return Ok((cpu_time_secs * 100.0) as u64);
            }
        }

        // Fallback estimate
        Ok(0)
    }

    async fn collect_raw_profile_data(&self, pid: i32) -> Result<Vec<u8>> {
        let mut raw_data = Vec::new();

        // Collect process stat as raw binary data
        if let Ok(stat) = procfs::process::Process::new(pid).and_then(|p| p.stat()) {
            // Serialize key stats as JSON for raw data
            let stat_data = serde_json::json!({
                "pid": stat.pid,
                "comm": stat.comm,
                "state": format!("{:?}", stat.state),
                "ppid": stat.ppid,
                "utime": stat.utime,
                "stime": stat.stime,
                "num_threads": stat.num_threads,
                "rss": stat.rss,
                "start_time": stat.starttime,
            });
            let stat_bytes = serde_json::to_vec(&stat_data).unwrap_or_default();
            raw_data.extend(stat_bytes);
        }

        // Collect memory maps summary
        if let Ok(maps) = tokio::fs::read_to_string(format!("/proc/{}/maps", pid)).await {
            let map_count = maps.lines().count();
            let map_summary = serde_json::json!({
                "map_count": map_count,
                "sample": maps.lines().take(5).collect::<Vec<_>>().join("\n")
            });
            let map_bytes = serde_json::to_vec(&map_summary).unwrap_or_default();
            raw_data.extend(map_bytes);
        }

        // Collect open file descriptors count
        if let Ok(mut entries) = tokio::fs::read_dir(format!("/proc/{}/fd", pid)).await {
            let mut fd_count = 0;
            while let Ok(Some(_)) = entries.next_entry().await {
                fd_count += 1;
            }
            let fd_data = serde_json::json!({ "fd_count": fd_count });
            let fd_bytes = serde_json::to_vec(&fd_data).unwrap_or_default();
            raw_data.extend(fd_bytes);
        }

        Ok(raw_data)
    }

    async fn get_io_stat(&self, pid: i32) -> Result<IOStat> {
        let io_path = format!("/proc/{}/io", pid);
        let content = tokio::fs::read_to_string(&io_path)
            .await
            .map_err(DebugError::Io)?;

        let mut io_stat = IOStat::default();

        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let value = parts[1].trim();

                match key {
                    "read_bytes" => {
                        if let Ok(bytes) = value.parse::<u64>() {
                            io_stat.read_bytes = bytes;
                        }
                    }
                    "write_bytes" => {
                        if let Ok(bytes) = value.parse::<u64>() {
                            io_stat.write_bytes = bytes;
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(io_stat)
    }
}

#[derive(Debug, Clone)]
struct ProcessStat {
    cpu_usage: f64,
    rss: u64,
    syscalls: u64,
    context_switches: u64,
}

#[derive(Debug, Clone, Default)]
struct IOStat {
    read_bytes: u64,
    write_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct CPUProfiler {
    pid: Option<i32>,
    profile: FragmentProfile,
}

impl CPUProfiler {
    pub fn new() -> Self {
        Self {
            pid: None,
            profile: FragmentProfile {
                fragment_id: String::new(),
                profile_type: "cpu".to_string(),
                duration: 0,
                sample_count: 0,
                start_time: Utc::now(),
                end_time: Utc::now(),
                peak_cpu: 0.0,
                peak_memory: 0.0,
                total_cpu: 0.0,
                total_memory: 0.0,
                io_read_bytes: 0,
                io_write_bytes: 0,
                syscalls: 0,
                context_switches: 0,
                raw_data: Vec::new(),
            },
        }
    }
}

#[async_trait::async_trait]
impl ProfilerBackend for CPUProfiler {
    async fn start(&mut self, pid: i32) -> Result<()> {
        self.pid = Some(pid);
        Ok(())
    }

    async fn stop(&mut self) -> Result<FragmentProfile> {
        if let Some(pid) = self.pid {
            let proc = procfs::process::Process::new(pid)
                .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

            if let Ok(stat) = proc.stat() {
                let clock_ticks = procfs::ticks_per_second();
                let total_time = (stat.utime + stat.stime) as f64 / clock_ticks as f64;
                self.profile.total_cpu = total_time;
                self.profile.peak_cpu = total_time;
            }
        }
        Ok(std::mem::take(&mut self.profile))
    }

    async fn collect_sample(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            let proc = procfs::process::Process::new(pid)
                .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

            if let Ok(stat) = proc.stat() {
                let clock_ticks = procfs::ticks_per_second();
                let cpu_time = (stat.utime + stat.stime) as f64 / clock_ticks as f64;
                if cpu_time > self.profile.peak_cpu {
                    self.profile.peak_cpu = cpu_time;
                }
            }
        }
        Ok(())
    }

    fn box_clone(&self) -> Box<dyn ProfilerBackend> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct MemoryProfiler {
    pid: Option<i32>,
    profile: FragmentProfile,
}

impl MemoryProfiler {
    pub fn new() -> Self {
        Self {
            pid: None,
            profile: FragmentProfile {
                fragment_id: String::new(),
                profile_type: "memory".to_string(),
                duration: 0,
                sample_count: 0,
                start_time: Utc::now(),
                end_time: Utc::now(),
                peak_cpu: 0.0,
                peak_memory: 0.0,
                total_cpu: 0.0,
                total_memory: 0.0,
                io_read_bytes: 0,
                io_write_bytes: 0,
                syscalls: 0,
                context_switches: 0,
                raw_data: Vec::new(),
            },
        }
    }
}

#[async_trait::async_trait]
impl ProfilerBackend for MemoryProfiler {
    async fn start(&mut self, pid: i32) -> Result<()> {
        self.pid = Some(pid);
        Ok(())
    }

    async fn stop(&mut self) -> Result<FragmentProfile> {
        if let Some(pid) = self.pid {
            let proc = procfs::process::Process::new(pid)
                .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

            if let Ok(statm) = proc.statm() {
                let page_size = procfs::page_size();
                let rss = (statm.resident * page_size) as f64 / 1024.0 / 1024.0;
                self.profile.total_memory = rss;
                self.profile.peak_memory = rss;
            }
        }
        Ok(std::mem::take(&mut self.profile))
    }

    async fn collect_sample(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            let proc = procfs::process::Process::new(pid)
                .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

            if let Ok(statm) = proc.statm() {
                let page_size = procfs::page_size();
                let rss = (statm.resident * page_size) as f64 / 1024.0 / 1024.0;
                if rss > self.profile.peak_memory {
                    self.profile.peak_memory = rss;
                }
            }
        }
        Ok(())
    }

    fn box_clone(&self) -> Box<dyn ProfilerBackend> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct IOProfiler {
    pid: Option<i32>,
    profile: FragmentProfile,
    initial_read: u64,
    initial_write: u64,
}

impl IOProfiler {
    pub fn new() -> Self {
        Self {
            pid: None,
            profile: FragmentProfile {
                fragment_id: String::new(),
                profile_type: "io".to_string(),
                duration: 0,
                sample_count: 0,
                start_time: Utc::now(),
                end_time: Utc::now(),
                peak_cpu: 0.0,
                peak_memory: 0.0,
                total_cpu: 0.0,
                total_memory: 0.0,
                io_read_bytes: 0,
                io_write_bytes: 0,
                syscalls: 0,
                context_switches: 0,
                raw_data: Vec::new(),
            },
            initial_read: 0,
            initial_write: 0,
        }
    }

    async fn read_io_stats(&self, pid: i32) -> Result<(u64, u64)> {
        let io_path = format!("/proc/{}/io", pid);
        let content = tokio::fs::read_to_string(&io_path)
            .await
            .map_err(DebugError::Io)?;

        let mut read_bytes = 0u64;
        let mut write_bytes = 0u64;

        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let value = parts[1].trim();
                match key {
                    "read_bytes" => {
                        read_bytes = value.parse().unwrap_or(0);
                    }
                    "write_bytes" => {
                        write_bytes = value.parse().unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }

        Ok((read_bytes, write_bytes))
    }
}

#[async_trait::async_trait]
impl ProfilerBackend for IOProfiler {
    async fn start(&mut self, pid: i32) -> Result<()> {
        self.pid = Some(pid);
        let (read, write) = self.read_io_stats(pid).await?;
        self.initial_read = read;
        self.initial_write = write;
        Ok(())
    }

    async fn stop(&mut self) -> Result<FragmentProfile> {
        if let Some(pid) = self.pid {
            let (read, write) = self.read_io_stats(pid).await?;
            self.profile.io_read_bytes = read.saturating_sub(self.initial_read);
            self.profile.io_write_bytes = write.saturating_sub(self.initial_write);
        }
        Ok(std::mem::take(&mut self.profile))
    }

    async fn collect_sample(&mut self) -> Result<()> {
        Ok(())
    }

    fn box_clone(&self) -> Box<dyn ProfilerBackend> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct CombinedProfiler {
    cpu_profiler: CPUProfiler,
    memory_profiler: MemoryProfiler,
    io_profiler: IOProfiler,
    profile: FragmentProfile,
}

impl CombinedProfiler {
    pub fn new() -> Self {
        Self {
            cpu_profiler: CPUProfiler::new(),
            memory_profiler: MemoryProfiler::new(),
            io_profiler: IOProfiler::new(),
            profile: FragmentProfile {
                fragment_id: String::new(),
                profile_type: "all".to_string(),
                duration: 0,
                sample_count: 0,
                start_time: Utc::now(),
                end_time: Utc::now(),
                peak_cpu: 0.0,
                peak_memory: 0.0,
                total_cpu: 0.0,
                total_memory: 0.0,
                io_read_bytes: 0,
                io_write_bytes: 0,
                syscalls: 0,
                context_switches: 0,
                raw_data: Vec::new(),
            },
        }
    }
}

#[async_trait::async_trait]
impl ProfilerBackend for CombinedProfiler {
    async fn start(&mut self, pid: i32) -> Result<()> {
        self.cpu_profiler.start(pid).await?;
        self.memory_profiler.start(pid).await?;
        self.io_profiler.start(pid).await?;
        Ok(())
    }

    async fn stop(&mut self) -> Result<FragmentProfile> {
        let cpu_profile = self.cpu_profiler.stop().await?;
        let memory_profile = self.memory_profiler.stop().await?;
        let io_profile = self.io_profiler.stop().await?;

        self.profile.peak_cpu = cpu_profile.peak_cpu;
        self.profile.total_cpu = cpu_profile.total_cpu;
        self.profile.peak_memory = memory_profile.peak_memory;
        self.profile.total_memory = memory_profile.total_memory;
        self.profile.io_read_bytes = io_profile.io_read_bytes;
        self.profile.io_write_bytes = io_profile.io_write_bytes;

        Ok(std::mem::take(&mut self.profile))
    }

    async fn collect_sample(&mut self) -> Result<()> {
        self.cpu_profiler.collect_sample().await?;
        self.memory_profiler.collect_sample().await?;
        self.io_profiler.collect_sample().await?;
        Ok(())
    }

    fn box_clone(&self) -> Box<dyn ProfilerBackend> {
        Box::new(self.clone())
    }
}
