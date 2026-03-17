//! Log analysis and filtering module

use chrono::{DateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::error::{DebugError, Result};
use crate::types::*;

/// Log analyzer for log analysis and filtering
impl LogAnalyzer {
    /// Create a new log analyzer
    pub fn new() -> Self {
        Self {
            log_sources: HashMap::new(),
        }
    }

    /// Get logs from a fragment with filtering
    pub async fn get_logs(
        &mut self,
        fragment_id: &str,
        lines: usize,
        filter: Option<&str>,
        level: Option<&str>,
    ) -> Result<Vec<LogEntry>> {
        // Find the fragment's PID
        let pid = self.find_fragment_pid(fragment_id).await?;

        // Get log source for this fragment
        let source = self.get_log_source(fragment_id, pid).await?;

        // Get recent logs
        let since = Utc::now() - chrono::Duration::hours(1); // Get last hour by default
        let mut logs = source.get_logs(since, lines * 2).await?; // Get more to account for filtering

        // Apply filters
        self.filter_logs(&mut logs, filter, level);

        // Sort by timestamp (most recent first)
        logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Return requested number of lines
        if lines > 0 && logs.len() > lines {
            logs.truncate(lines);
        }

        Ok(logs)
    }

    /// Follow logs in real-time
    pub async fn follow_logs(
        &mut self,
        fragment_id: &str,
        filter: Option<&str>,
        level: Option<&str>,
    ) -> Result<()> {
        // Find the fragment's PID
        let pid = self.find_fragment_pid(fragment_id).await?;

        // Get log source for this fragment
        let source = self.get_log_source(fragment_id, pid).await?;

        // Create context for cancellation
        let (tx, _rx) = mpsc::channel(1);

        // Handle interrupt signal (simplified)
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await; // Auto-stop after 30 seconds
            let _ = tx.send(()).await;
        });

        println!(
            "Following logs for fragment {} (press Ctrl+C to stop)...",
            fragment_id
        );

        // Clone filter and level for the closure
        let filter = filter.map(|s| s.to_string());
        let level = level.map(|s| s.to_string());

        // Follow logs
        let result = timeout(
            Duration::from_secs(30),
            source.follow_logs(Box::new(move |entry| {
                // Apply filters
                if LogAnalyzer::matches_filter(&entry, filter.as_deref(), level.as_deref()) {
                    LogAnalyzer::display_log_entry(&entry);
                }
                Ok(())
            })),
        )
        .await;

        match result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(()), // Timeout is not an error for follow_logs
        }
    }

    /// Display logs in a formatted way
    pub fn display_logs(&self, logs: &[LogEntry]) -> Result<()> {
        if logs.is_empty() {
            println!("No logs found.");
            return Ok(());
        }

        // Display logs with colors and formatting
        for entry in logs {
            LogAnalyzer::display_log_entry(entry);
        }

        Ok(())
    }

    /// Find the PID of a fragment
    async fn find_fragment_pid(&self, fragment_id: &str) -> Result<i32> {
        // Use procfs to find processes matching the fragment ID

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

            // Check environment variables
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

    /// Get or create a log source for a fragment
    async fn get_log_source(
        &mut self,
        fragment_id: &str,
        pid: i32,
    ) -> Result<&mut Box<dyn LogSource>> {
        if !self.log_sources.contains_key(fragment_id) {
            let source = Box::new(FragmentLogSource::new(pid)) as Box<dyn LogSource>;
            self.log_sources.insert(fragment_id.to_string(), source);
        }

        self.log_sources
            .get_mut(fragment_id)
            .ok_or_else(|| DebugError::fragment_not_found(fragment_id))
    }

    /// Apply filtering to log entries
    fn filter_logs(&self, logs: &mut Vec<LogEntry>, filter: Option<&str>, level: Option<&str>) {
        logs.retain(|entry| LogAnalyzer::matches_filter(entry, filter, level));
    }

    /// Check if a log entry matches the filter criteria
    fn matches_filter(entry: &LogEntry, filter: Option<&str>, level: Option<&str>) -> bool {
        // Level filter
        if let Some(lvl) = level {
            if !entry.level.eq_ignore_ascii_case(lvl) {
                return false;
            }
        }

        // Pattern filter
        if let Some(pattern) = filter {
            // Try to compile as regex first
            if let Ok(regex) = Regex::new(pattern) {
                if !regex.is_match(&entry.message) {
                    return false;
                }
            } else {
                // Fall back to literal string matching
                if !entry.message.contains(pattern) {
                    return false;
                }
            }
        }

        true
    }

    /// Display a single log entry with formatting
    fn display_log_entry(entry: &LogEntry) {
        // Color coding based on level
        let (color_code, reset_code) = match entry.level.to_uppercase().as_str() {
            "ERROR" | "FATAL" | "CRITICAL" => ("\x1b[31m", "\x1b[0m"), // Red
            "WARN" | "WARNING" => ("\x1b[33m", "\x1b[0m"),             // Yellow
            "INFO" => ("\x1b[32m", "\x1b[0m"),                         // Green
            "DEBUG" => ("\x1b[36m", "\x1b[0m"),                        // Cyan
            _ => ("\x1b[37m", "\x1b[0m"),                              // White
        };

        // Format timestamp
        let timestamp = entry.timestamp.format("%Y-%m-%d %H:%M:%S%.3f");

        // Format output
        print!(
            "{}{}{} [{}] {}",
            color_code, timestamp, reset_code, entry.level, entry.message
        );

        if !entry.source.is_empty() {
            print!(" ({})", entry.source);
        }

        if entry.thread_id != 0 {
            print!(" [TID:{}]", entry.thread_id);
        }

        println!();
    }
}

/// Fragment log source implementation
pub struct FragmentLogSource {
    pid: i32,
    log_files: Vec<String>,
    last_read: HashMap<String, DateTime<Utc>>,
}

impl FragmentLogSource {
    /// Create a new fragment log source
    pub fn new(pid: i32) -> Self {
        Self {
            pid,
            log_files: Self::discover_log_files(pid),
            last_read: HashMap::new(),
        }
    }

    /// Discover potential log files for a fragment
    fn discover_log_files(pid: i32) -> Vec<String> {
        let mut log_files = Vec::new();

        // Common log file locations
        let locations = vec![
            format!("/proc/{}/fd/1", pid), // stdout
            format!("/proc/{}/fd/2", pid), // stderr
            format!("/tmp/fragment-{}.log", pid),
            format!("/var/log/phantom/fragment-{}.log", pid),
            format!("/var/log/containers/fragment-{}.log", pid),
        ];

        for location in locations {
            if std::fs::metadata(&location).is_ok() {
                log_files.push(location);
            }
        }

        log_files
    }

    /// Read logs from a specific file
    fn read_log_file(
        &mut self,
        filename: &str,
        since: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<LogEntry>> {
        let file = File::open(filename).map_err(|e| DebugError::Io(e))?;

        let reader = BufReader::new(file);
        let mut logs = Vec::new();
        let mut line_count = 0;

        for line_result in reader.lines() {
            let line = line_result.map_err(|e| DebugError::Io(e))?;
            if line.is_empty() {
                continue;
            }

            // Parse log entry
            if let Ok(entry) = self.parse_log_line(&line, filename) {
                // Check if entry is recent enough
                if entry.timestamp >= since {
                    logs.push(entry);
                    line_count += 1;
                }

                // Apply limit
                if limit > 0 && line_count >= limit {
                    break;
                }
            }
        }

        // Update last read position
        if let Ok(metadata) = std::fs::metadata(filename) {
            if let Ok(modified) = metadata.modified() {
                self.last_read
                    .insert(filename.to_string(), DateTime::from(modified));
            }
        }

        Ok(logs)
    }

    /// Parse a single log line into a LogEntry
    fn parse_log_line(&self, line: &str, filename: &str) -> Result<LogEntry> {
        let mut entry = LogEntry {
            timestamp: Utc::now(),
            level: "INFO".to_string(),
            message: line.to_string(),
            source: filename.to_string(),
            fragment_id: format!("fragment-{}", self.pid),
            thread_id: 0,
            file: String::new(),
            line: 0,
        };

        // Try to parse timestamp and level from common log formats
        // Format 1: [2023-12-01 10:30:45] [INFO] Message
        if let Some(captures) =
            Regex::new(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(\w+)\] (.+)$")
                .ok()
                .and_then(|re| re.captures(line))
        {
            if let (Some(timestamp_str), Some(level_str), Some(message)) =
                (captures.get(1), captures.get(2), captures.get(3))
            {
                if let Ok(timestamp) = DateTime::parse_from_str(
                    &format!("{} +0000", timestamp_str.as_str()),
                    "%Y-%m-%d %H:%M:%S %z",
                ) {
                    entry.timestamp = timestamp.with_timezone(&Utc);
                }
                entry.level = level_str.as_str().to_string();
                entry.message = message.as_str().to_string();
            }
        } else {
            // Extract thread ID if present (format: [TID:123])
            if let Some(tid_capture) = Regex::new(r"\[TID:(\d+)\]")
                .ok()
                .and_then(|re| re.captures(line).and_then(|c| c.get(1)))
            {
                if let Ok(tid) = tid_capture.as_str().parse::<i32>() {
                    entry.thread_id = tid;
                }
            }
        }

        Ok(entry)
    }
}

#[async_trait::async_trait]
impl LogSource for FragmentLogSource {
    async fn get_logs(&self, since: DateTime<Utc>, limit: usize) -> Result<Vec<LogEntry>> {
        let mut all_logs = Vec::new();

        for log_file in &self.log_files {
            // We need to make this mutable to update last_read, but the trait method takes &self
            // For now, we'll skip the last_read optimization in this implementation
            let mut source = FragmentLogSource::new(self.pid);
            if let Ok(logs) = source.read_log_file(log_file, since, limit) {
                all_logs.extend(logs);
            }
        }

        // Sort by timestamp
        all_logs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Apply limit
        if limit > 0 && all_logs.len() > limit {
            all_logs.truncate(limit);
        }

        Ok(all_logs)
    }

    async fn follow_logs(
        &self,
        callback: Box<dyn Fn(LogEntry) -> Result<()> + Send + Sync + 'static>,
    ) -> Result<()> {
        // For real-time following, we'd typically use inotify or similar
        // For now, we'll poll the log files periodically

        let mut interval = tokio::time::interval(Duration::from_millis(500));
        let mut last_check = Utc::now();

        loop {
            interval.tick().await;

            let since = last_check;
            last_check = Utc::now();

            if let Ok(logs) = self.get_logs(since, 100).await {
                for entry in logs {
                    callback(entry)?;
                }
            }
        }
    }

    async fn filter_logs(
        &self,
        mut logs: Vec<LogEntry>,
        filter: &str,
        level: &str,
    ) -> Result<Vec<LogEntry>> {
        let analyzer = LogAnalyzer::new();
        analyzer.filter_logs(&mut logs, Some(filter), Some(level));
        Ok(logs)
    }
}

/// Log statistics and analysis functions
impl LogAnalyzer {
    /// Get statistics about the logs
    pub fn get_log_stats(&self, logs: &[LogEntry]) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();

        if logs.is_empty() {
            return stats;
        }

        // Count by level
        let mut level_counts = HashMap::new();
        let mut earliest = logs[0].timestamp;
        let mut latest = logs[0].timestamp;

        for entry in logs {
            *level_counts.entry(entry.level.clone()).or_insert(0) += 1;

            if entry.timestamp < earliest {
                earliest = entry.timestamp;
            }
            if entry.timestamp > latest {
                latest = entry.timestamp;
            }
        }

        stats.insert("total_entries".to_string(), logs.len().into());
        stats.insert(
            "level_counts".to_string(),
            serde_json::to_value(level_counts).unwrap_or_default(),
        );
        stats.insert("earliest_entry".to_string(), earliest.to_rfc3339().into());
        stats.insert("latest_entry".to_string(), latest.to_rfc3339().into());
        stats.insert(
            "timespan".to_string(),
            (latest - earliest).to_string().into(),
        );

        // Calculate rate (entries per minute)
        if let Ok(duration) = (latest - earliest).to_std() {
            if duration.as_secs() > 0 {
                let rate = logs.len() as f64 / duration.as_secs_f64() * 60.0;
                stats.insert("entries_per_minute".to_string(), rate.into());
            }
        }

        stats
    }

    /// Find error patterns in logs
    pub fn find_errors(&self, logs: &[LogEntry]) -> Vec<LogEntry> {
        let error_patterns = [
            "error",
            "Error",
            "ERROR",
            "exception",
            "Exception",
            "EXCEPTION",
            "failed",
            "Failed",
            "FAILED",
            "fatal",
            "Fatal",
            "FATAL",
            "panic",
            "Panic",
            "PANIC",
        ];

        logs.iter()
            .filter(|entry| {
                error_patterns
                    .iter()
                    .any(|pattern| entry.message.contains(pattern))
            })
            .cloned()
            .collect()
    }

    /// Find warning patterns in logs
    pub fn find_warnings(&self, logs: &[LogEntry]) -> Vec<LogEntry> {
        let warning_patterns = [
            "warning",
            "Warning",
            "WARNING",
            "warn",
            "Warn",
            "WARN",
            "deprecated",
            "Deprecated",
            "DEPRECATED",
        ];

        logs.iter()
            .filter(|entry| {
                warning_patterns
                    .iter()
                    .any(|pattern| entry.message.contains(pattern))
            })
            .cloned()
            .collect()
    }
}
