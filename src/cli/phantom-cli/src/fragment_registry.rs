//! Fragment Registry - Persistent tracking of active fragments
//!
//! This module provides a simple file-based registry for tracking active Phantom Fragment
//! containers. It allows listing, querying, and managing fragment lifecycle.

use anyhow::{Context, Result};
use log::{info, warn};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::config::PhantomPaths;

/// Fragment metadata stored in the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentInfo {
    pub name: String,
    pub profile: String,
    pub pid: Option<u32>,
    pub created_at: u64,
    pub status: FragmentStatus,
    pub components: Vec<String>,
    pub memory_kb: u64,
    pub cpu_count: Option<u32>,
    pub mode: String,
    /// Timestamp of last successful PID validation (Unix epoch seconds)
    /// Added for stale fragment detection - defaults to None for backward compatibility
    #[serde(default)]
    pub last_validated: Option<u64>,
    /// Optional rootfs image name associated with this fragment
    /// Added for dependency tracking - defaults to None for backward compatibility
    #[serde(default)]
    pub image: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FragmentStatus {
    Running,
    Stopped,
    Failed,
}

/// Fragment Registry - manages persistent fragment tracking
pub struct FragmentRegistry {
    registry_path: PathBuf,
    fragments: HashMap<String, FragmentInfo>,
}

impl FragmentRegistry {
    /// Create a new registry with default path
    pub fn new() -> Result<Self> {
        let registry_path = Self::default_registry_path()?;
        Self::with_path(registry_path)
    }

    /// Create a registry with a custom path
    pub fn with_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let registry_path = path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = registry_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create registry directory: {:?}", parent))?;
        }

        // Load existing fragments if file exists
        let fragments = if registry_path.exists() {
            let data = fs::read_to_string(&registry_path)
                .with_context(|| format!("Failed to read registry: {:?}", registry_path))?;
            serde_json::from_str(&data).with_context(|| "Failed to parse registry JSON")?
        } else {
            HashMap::new()
        };

        Ok(Self {
            registry_path,
            fragments,
        })
    }

    /// Get default registry path: ~/.phantom/registry.json
    fn default_registry_path() -> Result<PathBuf> {
        let paths = PhantomPaths::new();
        Ok(paths.registry())
    }

    /// Register a new fragment
    pub fn register(&mut self, info: FragmentInfo) -> Result<()> {
        self.fragments.insert(info.name.clone(), info);
        self.save()
    }

    /// Get fragment info by name
    pub fn get(&self, name: &str) -> Option<&FragmentInfo> {
        self.fragments.get(name)
    }

    /// List all fragments
    pub fn list(&self) -> Vec<&FragmentInfo> {
        self.fragments.values().collect()
    }

    /// List fragments by status
    pub fn list_by_status(&self, status: FragmentStatus) -> Vec<&FragmentInfo> {
        self.fragments
            .values()
            .filter(|f| f.status == status)
            .collect()
    }

    /// Update fragment status
    pub fn update_status(&mut self, name: &str, status: FragmentStatus) -> Result<()> {
        if let Some(fragment) = self.fragments.get_mut(name) {
            fragment.status = status;
            self.save()
        } else {
            anyhow::bail!("Fragment not found: {}", name)
        }
    }

    pub fn update_pid(&mut self, name: &str, pid: u32) -> Result<()> {
        if let Some(fragment) = self.fragments.get_mut(name) {
            fragment.pid = Some(pid);
            self.save()
        } else {
            anyhow::bail!("Fragment not found: {}", name)
        }
    }

    pub fn update_validated(&mut self, name: &str, timestamp: u64) -> Result<()> {
        if let Some(fragment) = self.fragments.get_mut(name) {
            fragment.last_validated = Some(timestamp);
            self.save()
        } else {
            anyhow::bail!("Fragment not found: {}", name)
        }
    }

    /// Remove a fragment from the registry
    pub fn remove(&mut self, name: &str) -> Result<()> {
        self.fragments
            .remove(name)
            .context(format!("Fragment not found: {}", name))?;
        self.save()
    }

    /// Check if fragment exists
    pub fn exists(&self, name: &str) -> bool {
        self.fragments.contains_key(name)
    }

    /// Validate if a PID is still alive by sending SIGCONT signal
    ///
    /// Uses `nix::sys::signal::kill()` with `Signal::SIGCONT` to check process existence.
    /// - Returns `true` if the process exists (kill succeeds or returns EPERM)
    /// - Returns `false` if the process doesn't exist (ESRCH)
    ///
    /// # Arguments
    /// * `pid` - The process ID to validate
    ///
    /// # Returns
    /// * `bool` - `true` if process exists, `false` otherwise
    pub fn validate_pid(pid: u32) -> bool {
        let pid = Pid::from_raw(pid as i32);
        match signal::kill(pid, Signal::SIGCONT) {
            Ok(_) => true,                          // Process exists and we can signal it
            Err(nix::errno::Errno::ESRCH) => false, // No such process - definitely dead
            Err(nix::errno::Errno::EPERM) => true,  // Permission denied but process exists
            Err(_) => false,                        // Other errors - assume dead
        }
    }

    /// Get all stale fragments (running status but dead PID)
    ///
    /// # Returns
    /// Vector of references to stale fragment info
    pub fn get_stale_fragments(&self) -> Vec<&FragmentInfo> {
        self.fragments
            .values()
            .filter(|info| {
                info.status == FragmentStatus::Running
                    && info.pid.is_some()
                    && !Self::validate_pid(info.pid.unwrap())
            })
            .collect()
    }

    /// Prune stale fragments by marking dead processes as Stopped
    ///
    /// Iterates through all fragments with Running status and validates their PIDs.
    /// Dead processes are marked as Stopped and logged.
    ///
    /// # Returns
    /// Vector of fragment names that were pruned (marked as stopped)
    ///
    /// # Errors
    /// Returns error if saving the registry fails
    pub fn prune_stale(&mut self) -> Result<Vec<String>> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut pruned = Vec::new();

        for (name, fragment) in self.fragments.iter_mut() {
            if fragment.status == FragmentStatus::Running {
                if let Some(pid) = fragment.pid {
                    if !Self::validate_pid(pid) {
                        warn!(
                            "Stale fragment detected: '{}' (PID {}) - marking as Stopped",
                            name, pid
                        );
                        fragment.status = FragmentStatus::Stopped;
                        fragment.last_validated = Some(now);
                        pruned.push(name.clone());
                    } else {
                        // Update validation timestamp for alive fragments
                        fragment.last_validated = Some(now);
                    }
                }
            }
        }

        if !pruned.is_empty() {
            info!("Pruned {} stale fragment(s): {:?}", pruned.len(), pruned);
            self.save()?;
        }

        Ok(pruned)
    }

    /// Validate all running fragments and update their validation timestamps
    ///
    /// Unlike `prune_stale`, this method only validates and updates timestamps
    /// without changing fragment status.
    ///
    /// # Returns
    /// Number of fragments validated
    ///
    /// # Errors
    /// Returns error if saving the registry fails
    pub fn validate_all(&mut self) -> Result<usize> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut validated_count = 0;

        for fragment in self.fragments.values_mut() {
            if fragment.status == FragmentStatus::Running {
                if let Some(pid) = fragment.pid {
                    let is_alive = Self::validate_pid(pid);
                    fragment.last_validated = Some(now);

                    if is_alive {
                        validated_count += 1;
                    } else {
                        warn!(
                            "Fragment '{}' (PID {}) validation failed - process may be dead",
                            fragment.name, pid
                        );
                    }
                }
            }
        }

        info!("Validated {} running fragment(s)", validated_count);
        self.save()?;

        Ok(validated_count)
    }

    /// Save registry to disk
    fn save(&self) -> Result<()> {
        let data = serde_json::to_string_pretty(&self.fragments)
            .context("Failed to serialize registry")?;
        fs::write(&self.registry_path, data)
            .with_context(|| format!("Failed to write registry: {:?}", self.registry_path))
    }
}

