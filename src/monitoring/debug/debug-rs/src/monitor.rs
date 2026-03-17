//! Resource monitoring module for real-time performance tracking

use chrono::Utc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::error::{DebugError, Result};
use crate::types::*;

impl ResourceMonitor {
    pub fn new() -> Self {
        Self
    }

    pub async fn start_monitoring(
        &self,
        fragment_id: &str,
        interval_secs: u32,
        duration_secs: Option<u32>,
    ) -> Result<()> {
        let pid = self.find_fragment_pid(fragment_id).await?;

        println!(
            "Starting resource monitoring for fragment {} (PID: {})",
            fragment_id, pid
        );
        println!("Interval: {} seconds", interval_secs);
        if let Some(duration) = duration_secs {
            println!("Duration: {} seconds", duration);
        }
        println!();

        let (metrics_tx, mut metrics_rx) = mpsc::channel(100);
        let (error_tx, mut error_rx) = mpsc::channel(1);

        let monitor_task = tokio::spawn(async move {
            Self::collect_metrics_task(pid, interval_secs, metrics_tx, error_tx).await;
        });

        let duration_timeout = duration_secs.map(|d| Duration::from_secs(d as u64));

        self.display_header();

        let mut metrics_count = 0;

        loop {
            tokio::select! {
                Some(metrics) = metrics_rx.recv() => {
                    self.display_metrics(&metrics);
                    metrics_count += 1;
                }

                Some(error) = error_rx.recv() => {
                    return Err(error);
                }

                _ = async {
                    if let Some(duration) = duration_timeout {
                        tokio::time::sleep(duration).await;
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Some(duration) = duration_secs {
                        println!("\nMonitoring completed after {} seconds ({} samples collected)",
                                duration, metrics_count);
                    }
                    break;
                }
            }
        }

        monitor_task.abort();
        Ok(())
    }

    async fn collect_current_metrics(&self, pid: i32) -> Result<ResourceMetrics> {
        let mut metrics = ResourceMetrics {
            timestamp: Utc::now(),
            fragment_id: format!("fragment-{}", pid),
            cpu_usage: 0.0,
            memory_usage: MemoryInfo::default(),
            io_stats: IOStats::default(),
            network_stats: NetworkStats::default(),
        };

        metrics.cpu_usage = self.get_cpu_usage(pid).await?;
        metrics.memory_usage = self.get_memory_info(pid).await?;
        metrics.io_stats = self.get_io_stats(pid).await?;
        metrics.network_stats = self.get_network_stats(pid).await?;

        Ok(metrics)
    }

    async fn get_cpu_usage(&self, pid: i32) -> Result<f64> {
        let proc = procfs::process::Process::new(pid)
            .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

        let stat = proc
            .stat()
            .map_err(|e| DebugError::SystemCall(format!("failed to read stat: {}", e)))?;

        let clock_ticks = procfs::ticks_per_second();
        let total_time = (stat.utime + stat.stime) as f64 / clock_ticks as f64;

        Ok(total_time.min(100.0).max(0.0))
    }

    async fn get_memory_info(&self, pid: i32) -> Result<MemoryInfo> {
        let proc = procfs::process::Process::new(pid)
            .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

        let statm = proc
            .statm()
            .map_err(|e| DebugError::SystemCall(format!("failed to read statm: {}", e)))?;

        let page_size = procfs::page_size();

        let mut mem_info = MemoryInfo {
            rss: (statm.resident * page_size) as u64,
            vms: (statm.size * page_size) as u64,
            ..Default::default()
        };

        if let Ok(status) = proc.status() {
            if let Some(vm_peak) = status.vmpeak {
                mem_info.peak_rss = vm_peak * 1024;
            }
            if let Some(vm_swap) = status.vmswap {
                mem_info.swap = vm_swap * 1024;
            }
        }

        Ok(mem_info)
    }

    async fn get_io_stats(&self, pid: i32) -> Result<IOStats> {
        let io_path = format!("/proc/{}/io", pid);
        let content = tokio::fs::read_to_string(&io_path)
            .await
            .map_err(DebugError::Io)?;

        let mut io_stats = IOStats::default();
        let mut read_bytes = 0u64;
        let mut write_bytes = 0u64;
        let mut read_ops = 0u64;
        let mut write_ops = 0u64;

        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let value = parts[1].trim();

                match key {
                    "read_bytes" => {
                        if let Ok(bytes) = value.parse::<u64>() {
                            read_bytes = bytes;
                            io_stats.read_bytes_per_sec = bytes as f64 / 1024.0 / 1024.0;
                        }
                    }
                    "write_bytes" => {
                        if let Ok(bytes) = value.parse::<u64>() {
                            write_bytes = bytes;
                            io_stats.write_bytes_per_sec = bytes as f64 / 1024.0 / 1024.0;
                        }
                    }
                    "read_chars" => {
                        if let Ok(ops) = value.parse::<u64>() {
                            read_ops = ops;
                            io_stats.read_ops_per_sec = ops as f64;
                        }
                    }
                    "write_chars" => {
                        if let Ok(ops) = value.parse::<u64>() {
                            write_ops = ops;
                            io_stats.write_ops_per_sec = ops as f64;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Estimate IO latency based on operation count and bytes
        // This is a heuristic - real latency would require tracing
        let total_ops = read_ops + write_ops;
        if total_ops > 0 {
            // Assume average latency of 0.1-1ms per operation based on throughput
            let avg_latency_ms = if (read_bytes + write_bytes) > 1024 * 1024 {
                // High throughput - lower latency
                std::time::Duration::from_millis(1)
            } else {
                // Low throughput - higher latency
                std::time::Duration::from_millis(5)
            };
            io_stats.read_latency = avg_latency_ms;
            io_stats.write_latency = avg_latency_ms;
        }

        Ok(io_stats)
    }

    async fn get_network_stats(&self, pid: i32) -> Result<NetworkStats> {
        let mut stats = NetworkStats::default();

        // Read network statistics from /proc/[pid]/net/dev
        let net_dev_path = format!("/proc/{}/net/dev", pid);
        if let Ok(content) = tokio::fs::read_to_string(&net_dev_path).await {
            for line in content.lines().skip(2) {
                // Skip header lines
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 2 {
                    let values: Vec<&str> = parts[1].split_whitespace().collect();
                    if values.len() >= 10 {
                        // Format: bytes packets errs drop fifo frame compressed multicast | bytes packets errs drop fifo colls carrier compressed
                        // RX: values[0]=bytes, values[1]=packets
                        // TX: values[8]=bytes, values[9]=packets
                        if let Ok(rx_bytes) = values[0].parse::<u64>() {
                            stats.bytes_recv_per_sec = rx_bytes as f64;
                        }
                        if let Ok(rx_packets) = values[1].parse::<u64>() {
                            stats.packets_recv_per_sec = rx_packets as f64;
                        }
                        if let Ok(tx_bytes) = values[8].parse::<u64>() {
                            stats.bytes_sent_per_sec = tx_bytes as f64;
                        }
                        if let Ok(tx_packets) = values[9].parse::<u64>() {
                            stats.packets_sent_per_sec = tx_packets as f64;
                        }
                    }
                }
            }
        }

        // If no network stats found in namespace, try system-wide
        if stats.bytes_recv_per_sec == 0.0 {
            if let Ok(content) = tokio::fs::read_to_string("/proc/net/dev").await {
                for line in content.lines().skip(2) {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() == 2 {
                        let values: Vec<&str> = parts[1].split_whitespace().collect();
                        if values.len() >= 10 && !parts[0].trim().starts_with("lo") {
                            if let Ok(rx_bytes) = values[0].parse::<u64>() {
                                stats.bytes_recv_per_sec += rx_bytes as f64;
                            }
                            if let Ok(rx_packets) = values[1].parse::<u64>() {
                                stats.packets_recv_per_sec += rx_packets as f64;
                            }
                            if let Ok(tx_bytes) = values[8].parse::<u64>() {
                                stats.bytes_sent_per_sec += tx_bytes as f64;
                            }
                            if let Ok(tx_packets) = values[9].parse::<u64>() {
                                stats.packets_sent_per_sec += tx_packets as f64;
                            }
                        }
                    }
                }
            }
        }

        Ok(stats)
    }

    fn display_header(&self) {
        println!("RESOURCE MONITORING");
        println!("===================");
        println!(
            "{:<12} {:<8} {:<10} {:<10} {:<10} {:<10}",
            "TIME", "CPU%", "RSS(MB)", "VMS(MB)", "READ(MB)", "WRITE(MB)"
        );
        println!("{}", "=".repeat(66));
    }

    fn display_metrics(&self, metrics: &ResourceMetrics) {
        let timestamp = metrics.timestamp.format("%H:%M:%S");

        println!(
            "{:<12} {:<8.1} {:<10.1} {:<10.1} {:<10.2} {:<10.2}",
            timestamp,
            metrics.cpu_usage,
            metrics.memory_usage.rss as f64 / 1024.0 / 1024.0,
            metrics.memory_usage.vms as f64 / 1024.0 / 1024.0,
            metrics.io_stats.read_bytes_per_sec,
            metrics.io_stats.write_bytes_per_sec,
        );
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

    async fn collect_metrics_task(
        pid: i32,
        interval_secs: u32,
        metrics_tx: mpsc::Sender<ResourceMetrics>,
        error_tx: mpsc::Sender<DebugError>,
    ) {
        let mut interval = interval(Duration::from_secs(interval_secs as u64));
        let monitor = Self::new();

        loop {
            interval.tick().await;

            match monitor.collect_current_metrics(pid).await {
                Ok(metrics) => {
                    if metrics_tx.send(metrics).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = error_tx.send(e).await;
                    break;
                }
            }
        }
    }
}

impl ResourceMonitorWithHistory {
    pub fn new(max_history: usize) -> Self {
        Self {
            monitor: ResourceMonitor::new(),
            history: Vec::new(),
            max_history,
        }
    }

    pub async fn start_monitoring_with_history(
        &mut self,
        fragment_id: &str,
        interval_secs: u32,
        duration_secs: Option<u32>,
    ) -> Result<()> {
        let pid = self.monitor.find_fragment_pid(fragment_id).await?;

        println!(
            "Starting resource monitoring with history for fragment {}",
            fragment_id
        );

        let (metrics_tx, mut metrics_rx) = mpsc::channel(100);
        let (error_tx, mut error_rx) = mpsc::channel(1);

        let monitor_task = tokio::spawn(async move {
            ResourceMonitor::collect_metrics_task(pid, interval_secs, metrics_tx, error_tx).await;
        });

        let duration_timeout = duration_secs.map(|d| Duration::from_secs(d as u64));

        self.monitor.display_header();

        let mut metrics_count = 0;

        loop {
            tokio::select! {
                Some(metrics) = metrics_rx.recv() => {
                    self.add_to_history(metrics.clone());
                    self.monitor.display_metrics(&metrics);
                    metrics_count += 1;
                }

                Some(error) = error_rx.recv() => {
                    return Err(error);
                }

                _ = async {
                    if let Some(duration) = duration_timeout {
                        tokio::time::sleep(duration).await;
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Some(duration) = duration_secs {
                        println!("\nMonitoring completed after {} seconds ({} samples collected)",
                                duration, metrics_count);
                    }
                    self.display_summary();
                    break;
                }
            }
        }

        monitor_task.abort();
        Ok(())
    }

    fn add_to_history(&mut self, metrics: ResourceMetrics) {
        self.history.push(metrics);

        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    fn display_summary(&self) {
        if self.history.is_empty() {
            return;
        }

        println!("\nMONITORING SUMMARY");
        println!("=================");

        let mut total_cpu = 0.0;
        let mut peak_cpu = 0.0;
        let mut total_memory: u64 = 0;
        let mut peak_memory: u64 = 0;
        let mut total_read = 0.0;
        let mut peak_read = 0.0;
        let mut total_write = 0.0;
        let mut peak_write = 0.0;

        for metrics in &self.history {
            total_cpu += metrics.cpu_usage;
            if metrics.cpu_usage > peak_cpu {
                peak_cpu = metrics.cpu_usage;
            }

            let memory = metrics.memory_usage.rss;
            total_memory += memory;
            if memory > peak_memory {
                peak_memory = memory;
            }

            let read_rate = metrics.io_stats.read_bytes_per_sec;
            total_read += read_rate;
            if read_rate > peak_read {
                peak_read = read_rate;
            }

            let write_rate = metrics.io_stats.write_bytes_per_sec;
            total_write += write_rate;
            if write_rate > peak_write {
                peak_write = write_rate;
            }
        }

        let count = self.history.len() as f64;
        println!("Total Samples: {}", self.history.len());
        println!("Average CPU: {:.1}%", total_cpu / count);
        println!("Peak CPU: {:.1}%", peak_cpu);
        println!(
            "Average Memory: {:.1} MB",
            total_memory as f64 / count / 1024.0 / 1024.0
        );
        println!(
            "Peak Memory: {:.1} MB",
            peak_memory as f64 / 1024.0 / 1024.0
        );
        println!("Average Read Rate: {:.2} MB/s", total_read / count);
        println!("Peak Read Rate: {:.2} MB/s", peak_read);
        println!("Average Write Rate: {:.2} MB/s", total_write / count);
        println!("Peak Write Rate: {:.2} MB/s", peak_write);
    }

    pub fn get_history(&self) -> &[ResourceMetrics] {
        &self.history
    }
}
