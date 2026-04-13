//! Cgroup Management for Phantom Fragment
//!
//! This crate provides cgroup v2 resource management.
//! Note: Interactive prompts have been moved to the CLI layer for unified permission handling.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone, Default)]
pub struct IoLimits {
    pub read_bps: Option<u64>,
    pub write_bps: Option<u64>,
    pub read_iops: Option<u64>,
    pub write_iops: Option<u64>,
}

#[derive(Error, Debug)]
pub enum CgroupError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid path")]
    InvalidPath,
    #[error("Parse error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}

pub struct CgroupManager {
    full_path: PathBuf,
}

impl CgroupManager {
    pub fn new(path: &str) -> Self {
        let mut full_path = PathBuf::from("/sys/fs/cgroup");
        if path.starts_with("/") {
            full_path = PathBuf::from(path);
        } else {
            full_path.push(path);
        }
        Self { full_path }
    }

    pub fn create(&self) -> Result<(), CgroupError> {
        if !self.full_path.exists() {
            fs::create_dir_all(&self.full_path)?;
        }
        Ok(())
    }

    pub fn set_memory_limit(&self, limit_mb: u64) -> Result<(), CgroupError> {
        let limit_bytes = limit_mb * 1024 * 1024;
        let path = self.full_path.join("memory.max");

        if !path.exists() {
            return Err(
                std::io::Error::new(std::io::ErrorKind::NotFound, "memory.max not found").into(),
            );
        }

        let mut file = File::create(path)?;
        write!(file, "{}", limit_bytes)?;
        Ok(())
    }

    pub fn set_cpu_limit(&self, cpu_count: u64) -> Result<(), CgroupError> {
        let path = self.full_path.join("cpu.max");

        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cpu.max not found (cgroup v2 cpu controller missing)",
            )
            .into());
        }

        if cpu_count == 0 {
            let mut file = File::create(path)?;
            write!(file, "max")?;
            return Ok(());
        }

        let period = 100000u64;
        let quota = cpu_count * period;
        let mut file = File::create(path)?;
        write!(file, "{} {}", quota, period)?;
        Ok(())
    }

    pub fn set_cpu_weight(&self, weight: u64) -> Result<(), CgroupError> {
        let path = self.full_path.join("cpu.weight");

        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cpu.weight not found (cgroup v2 cpu controller missing)",
            )
            .into());
        }

        let weight = weight.clamp(1, 10000);
        let mut file = File::create(path)?;
        write!(file, "{}", weight)?;
        Ok(())
    }

    pub fn add_process(&self, pid: i32) -> Result<(), CgroupError> {
        let path = self.full_path.join("cgroup.procs");
        let mut file = File::options().write(true).open(path)?;
        write!(file, "{}", pid)?;
        Ok(())
    }

    pub fn get_oom_count(&self) -> Result<u64, CgroupError> {
        let path = self.full_path.join("memory.events");
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        for line in content.lines() {
            if line.starts_with("oom ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Ok(parts[1].parse()?);
                }
            }
        }
        Ok(0)
    }

    pub fn set_pid_limit(&self, max_pids: u32) -> Result<(), CgroupError> {
        let path = self.full_path.join("pids.max");

        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "pids.max not found (cgroup v2 pids controller missing)",
            )
            .into());
        }

        let mut file = File::create(path)?;
        write!(file, "{}", max_pids)?;
        Ok(())
    }

    pub fn set_io_limit(
        &self,
        major: u32,
        minor: u32,
        limits: IoLimits,
    ) -> Result<(), CgroupError> {
        let path = self.full_path.join("io.max");

        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "io.max not found (cgroup v2 io controller missing)",
            )
            .into());
        }

        let mut parts = Vec::new();
        if let Some(bps) = limits.read_bps {
            parts.push(format!("rbps={}", bps));
        }
        if let Some(bps) = limits.write_bps {
            parts.push(format!("wbps={}", bps));
        }
        if let Some(iops) = limits.read_iops {
            parts.push(format!("riops={}", iops));
        }
        if let Some(iops) = limits.write_iops {
            parts.push(format!("wiops={}", iops));
        }

        if parts.is_empty() {
            return Ok(());
        }

        let limit_str = format!("{}:{} {}", major, minor, parts.join(" "));
        let mut file = File::create(path)?;
        write!(file, "{}", limit_str)?;
        Ok(())
    }

    /// Destroy the cgroup - removes the cgroup directory
    ///
    /// This is critical for preventing resource leaks. Every cgroup created
    /// must be destroyed when the process exits.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The cgroup directory doesn't exist
    /// - The cgroup still contains processes
    /// - Permission is denied
    pub fn destroy(&self) -> Result<(), CgroupError> {
        if !self.full_path.exists() {
            // Already destroyed - not an error
            return Ok(());
        }

        // Check if cgroup is empty (no processes)
        let procs_path = self.full_path.join("cgroup.procs");
        if procs_path.exists() {
            let mut file = File::open(&procs_path)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;

            // If there are still processes, we can't destroy
            // Filter out empty lines
            let has_processes = content.lines().any(|line| !line.trim().is_empty());
            if has_processes {
                return Err(CgroupError::Io(std::io::Error::other(
                    "Cannot destroy cgroup: processes still attached",
                )));
            }
        }

        // Remove the cgroup directory
        fs::remove_dir(&self.full_path)?;
        Ok(())
    }

    /// Get the cgroup path
    pub fn path(&self) -> &Path {
        &self.full_path
    }
}

// ============ Automatic Systemd User Slice Setup ============

/// Result of checking user slice availability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSliceStatus {
    /// User slice exists and is writable
    Available,
    /// User slice doesn't exist but can be created
    CanCreate,
    /// User slice exists but not writable
    NotWritable,
    /// Cannot create user slice (requires root or delegation)
    Unavailable,
}

/// Check if systemd user slice exists and is accessible
pub fn check_user_slice_status() -> UserSliceStatus {
    let uid = unsafe { libc::getuid() };
    let slice_path = format!("/sys/fs/cgroup/user.slice/user-{}.slice", uid);
    let path = Path::new(&slice_path);

    if !path.exists() {
        // Check if parent directory exists and is writable
        let parent = Path::new("/sys/fs/cgroup/user.slice");
        if parent.exists()
            && parent
                .metadata()
                .map(|m| m.permissions().readonly() == false)
                .unwrap_or(false)
        {
            return UserSliceStatus::CanCreate;
        }
        return UserSliceStatus::Unavailable;
    }

    // Check if writable
    let test_file = path.join("cgroup.subtree_control");
    if test_file.exists() {
        // Try to open for writing to verify access
        match File::options().write(true).open(&test_file) {
            Ok(_) => UserSliceStatus::Available,
            Err(_) => UserSliceStatus::NotWritable,
        }
    } else {
        // cgroup.subtree_control might not exist, check cgroup.procs instead
        let procs_file = path.join("cgroup.procs");
        if procs_file.exists() {
            match File::options().write(true).open(&procs_file) {
                Ok(_) => UserSliceStatus::Available,
                Err(_) => UserSliceStatus::NotWritable,
            }
        } else {
            UserSliceStatus::NotWritable
        }
    }
}

/// Detect cgroup version (1 or 2)
pub fn detect_cgroup_version() -> u8 {
    // cgroup v2: unified hierarchy, single mount point
    let v2_mount = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if v2_mount.exists() {
        return 2;
    }

    // cgroup v1: separate hierarchies
    let v1_memory = Path::new("/sys/fs/cgroup/memory");
    if v1_memory.exists() {
        return 1;
    }

    0 // Unknown
}

/// Attempt to setup user cgroup slice automatically
///
/// Tries multiple approaches in order:
/// 1. systemd-run --user --scope (cleanest, requires systemd user session)
/// 2. Manual cgroup v2 directory creation with proper ownership
/// 3. Direct cgroup fs manipulation (if already delegated)
///
/// Returns Ok(()) if setup succeeded or is not needed
pub fn setup_user_cgroup_slice() -> Result<(), CgroupError> {
    // First, check if we already have access
    match check_user_slice_status() {
        UserSliceStatus::Available => {
            log::debug!("User slice already available");
            return Ok(());
        }
        UserSliceStatus::NotWritable => {
            log::debug!("User slice exists but not writable, attempting setup");
        }
        UserSliceStatus::CanCreate | UserSliceStatus::Unavailable => {
            log::debug!("User slice needs creation");
        }
    }

    // Try systemd-run --user --scope first (preferred method)
    if try_systemd_run_user_scope() {
        log::info!("Successfully setup user slice via systemd-run");
        return Ok(());
    }

    // Fallback: try manual cgroup v2 setup
    match setup_cgroup_v2_user_slice() {
        Ok(_) => {
            log::info!("Successfully setup user slice via manual cgroup v2");
            return Ok(());
        }
        Err(e) => {
            log::warn!("Manual cgroup v2 setup failed: {}", e);
        }
    }

    // Final fallback: try cgroup v1 setup
    if detect_cgroup_version() == 1 {
        if let Ok(_) = setup_cgroup_v1_user_slice() {
            log::info!("Successfully setup user slice via cgroup v1");
            return Ok(());
        }
    }

    // All methods failed
    Err(CgroupError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "Failed to setup user cgroup slice: all methods exhausted",
    )))
}

/// Try systemd-run --user --scope approach
///
/// This is the cleanest method as it properly integrates with systemd
/// and automatically handles cgroup delegation.
fn try_systemd_run_user_scope() -> bool {
    // First check if systemd --user is available
    let check_output = Command::new("systemctl")
        .args(["--user", "is-system-running"])
        .output();

    let systemd_user_available = match check_output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    };

    if !systemd_user_available {
        log::debug!("systemd --user not available");
        return false;
    }

    // Try to create a transient scope using systemd-run
    // This will automatically place us in the user slice
    let output = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--unit=phantom-fragment-cgroup-check",
            "true",
        ])
        .output();

    match output {
        Ok(result) => {
            if result.status.success() {
                // The scope was created successfully
                // Clean up the transient unit
                let _ = Command::new("systemctl")
                    .args(["--user", "stop", "phantom-fragment-cgroup-check.scope"])
                    .output();
                let _ = Command::new("systemctl")
                    .args([
                        "--user",
                        "reset-failed",
                        "phantom-fragment-cgroup-check.scope",
                    ])
                    .output();
                return true;
            }
            log::debug!(
                "systemd-run failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        Err(e) => {
            log::debug!("systemd-run command failed: {}", e);
        }
    }

    false
}

/// Setup cgroup v2 user slice manually
///
/// Attempts to create the user slice directory with proper ownership.
/// This requires either root access or pre-existing delegation.
fn setup_cgroup_v2_user_slice() -> Result<(), CgroupError> {
    let uid = unsafe { libc::getuid() };
    let slice_path = format!("/sys/fs/cgroup/user.slice/user-{}.slice", uid);
    let path = Path::new(&slice_path);

    // Check if cgroup v2 is mounted
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Err(CgroupError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cgroup v2 not mounted",
        )));
    }

    // Check if user.slice parent exists
    let parent = Path::new("/sys/fs/cgroup/user.slice");
    if !parent.exists() {
        // Try to create user.slice (requires root or delegation)
        fs::create_dir_all(parent).map_err(|e| {
            CgroupError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Cannot create user.slice: {}. Requires root or cgroup delegation.",
                    e
                ),
            ))
        })?;
    }

    // Try to create user slice directory
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| {
            CgroupError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Cannot create user slice: {}. Requires root or delegation.",
                    e
                ),
            ))
        })?;
    }

    // Enable controllers for the slice (optional but recommended)
    let subtree_control = path.join("cgroup.subtree_control");
    if !subtree_control.exists() {
        // Controllers might already be enabled at parent level
        log::debug!("cgroup.subtree_control not available, using parent settings");
    } else {
        // Try to enable common controllers
        let _ =
            File::create(&subtree_control).and_then(|mut f| write!(f, "+cpu +memory +pids +io"));
    }

    // Set ownership to current user (requires root)
    #[cfg(target_os = "linux")]
    {
        // Note: chown requires root, so this may fail
        // If it fails, the slice might still be usable if delegation exists
        let _ = Command::new("chown")
            .args([format!("{}", uid), format!("{}", uid), slice_path.clone()])
            .output();
    }

    Ok(())
}

/// Setup cgroup v1 user slice (legacy support)
fn setup_cgroup_v1_user_slice() -> Result<(), CgroupError> {
    let uid = unsafe { libc::getuid() };

    // cgroup v1 has separate hierarchies for each controller
    let controllers = ["memory", "cpu", "pids", "blkio"];
    let slice_name = format!("user-{}", uid);

    for controller in &controllers {
        let controller_path = format!("/sys/fs/cgroup/{}/{}", controller, slice_name);
        let path = Path::new(&controller_path);

        if !path.exists() {
            // Try to create (requires root or delegation)
            if let Err(e) = fs::create_dir_all(path) {
                log::warn!("Cannot create cgroup v1 {} slice: {}", controller, e);
                // Continue with other controllers
            }
        }

        // Try to set ownership
        let _ = Command::new("chown")
            .args([
                format!("{}", uid),
                format!("{}", uid),
                controller_path.clone(),
            ])
            .output();
    }

    Ok(())
}

/// Get the current user's cgroup slice path
pub fn get_user_slice_path() -> String {
    let uid = unsafe { libc::getuid() };
    format!("/sys/fs/cgroup/user.slice/user-{}.slice", uid)
}

/// Check if running inside a user slice
pub fn is_in_user_slice() -> bool {
    // Read current process cgroup
    let cgroup_path = Path::new("/proc/self/cgroup");
    if let Ok(content) = fs::read_to_string(cgroup_path) {
        let uid = unsafe { libc::getuid() };
        let user_slice_marker = format!("user-{}.slice", uid);
        return content.contains(&user_slice_marker);
    }
    false
}

