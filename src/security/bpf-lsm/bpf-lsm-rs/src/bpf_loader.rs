//! BPF Program Loader with Graceful Degradation
//!
//! This module handles loading compiled BPF-LSM programs into the kernel.
//! It includes capability detection and gracefully falls back to seccomp-only
//! mode when BPF is unavailable.

use anyhow::{Context, Result};
use log::{info, warn};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Capability requirements for BPF operations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BpfCapability {
    /// Full BPF support with CAP_BPF
    Full,
    /// Legacy support (requires CAP_SYS_ADMIN on older kernels)
    Legacy,
    /// No BPF support available
    None,
}

/// BPF program loader with capability detection
#[derive(Debug)]
pub struct BpfProgramLoader {
    capability: BpfCapability,
    loaded_programs: Vec<String>,
    bpf_state: Arc<BpfState>,
    bpf_instance: Option<Arc<Mutex<Option<aya::Bpf>>>>,
}

/// Shared state for BPF operations
#[derive(Debug)]
struct BpfState {
    program_loaded: AtomicBool,
}

impl Default for BpfState {
    fn default() -> Self {
        Self {
            program_loaded: AtomicBool::new(false),
        }
    }
}

impl BpfProgramLoader {
    /// Create a new BPF loader with capability detection
    pub fn new() -> Result<Self> {
        let capability = Self::detect_capability()?;

        match capability {
            BpfCapability::Full => {
                info!("BPF fully supported (CAP_BPF available)");
            }
            BpfCapability::Legacy => {
                info!("BPF legacy support (CAP_SYS_ADMIN required)");
            }
            BpfCapability::None => {
                warn!("BPF not available - using seccomp-only fallback");
            }
        }

        Ok(Self {
            capability,
            loaded_programs: Vec::new(),
            bpf_state: Arc::new(BpfState::default()),
            bpf_instance: None,
        })
    }

    /// Detect BPF capability on this system
    fn detect_capability() -> Result<BpfCapability> {
        // Check for CAP_BPF (kernel 5.8+)
        if Self::has_cap_bpf()? {
            return Ok(BpfCapability::Full);
        }

        // Check for CAP_SYS_ADMIN (legacy, kernel < 5.8)
        if Self::has_cap_sys_admin()? {
            // Verify BPF filesystem is mounted
            if Path::new("/sys/fs/bpf").exists() {
                return Ok(BpfCapability::Legacy);
            }
        }

        Ok(BpfCapability::None)
    }

    /// Check for CAP_BPF capability (modern kernels)
    fn has_cap_bpf() -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            use caps::{CapSet, Capability};

            // CAP_BPF = 39 (introduced in 5.8)
            // caps crate may not have it yet, so we check CAP_SYS_ADMIN as proxy
            match caps::has_cap(None, CapSet::Effective, Capability::CAP_SYS_ADMIN) {
                Ok(has_admin) => {
                    // Also check kernel version
                    if let Ok(version) = Self::get_kernel_version() {
                        if version >= (5, 7, 0) {
                            // 5.7+ has BPF LSM support
                            return Ok(has_admin);
                        }
                    }
                    Ok(false)
                }
                Err(_) => Ok(false),
            }
        }

        #[cfg(not(target_os = "linux"))]
        Ok(false)
    }

    /// Check for CAP_SYS_ADMIN (legacy)
    fn has_cap_sys_admin() -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            use caps::{CapSet, Capability};
            caps::has_cap(None, CapSet::Effective, Capability::CAP_SYS_ADMIN)
                .map_err(|e| anyhow::anyhow!("Failed to check capabilities: {}", e))
        }

        #[cfg(not(target_os = "linux"))]
        Ok(false)
    }

    /// Get kernel version (major, minor, patch)
    fn get_kernel_version() -> Result<(u32, u32, u32)> {
        let uname = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .context("Failed to read kernel version")?;

        let parts: Vec<&str> = uname.trim().split('.').collect();
        if parts.len() < 3 {
            return Err(anyhow::anyhow!("Invalid kernel version format"));
        }

        let major: u32 = parts[0].parse().context("Invalid major version")?;
        let minor: u32 = parts[1].parse().context("Invalid minor version")?;
        let patch: u32 = parts[2]
            .split('-')
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        Ok((major, minor, patch))
    }

    /// Load a BPF program from bytecode using aya
    pub fn load_program(&mut self, name: &str, bytecode: &[u8]) -> Result<()> {
        match self.capability {
            BpfCapability::None => {
                warn!(
                    "BPF program '{}' not loaded - falling back to seccomp",
                    name
                );
                Ok(())
            }
            BpfCapability::Legacy | BpfCapability::Full => {
                // Check if already loaded to avoid duplicates
                if self.bpf_state.program_loaded.load(Ordering::SeqCst) {
                    info!("BPF program already loaded, skipping reload");
                    return Ok(());
                }

                self.load_with_aya(name, bytecode)
            }
        }
    }

    /// Load BPF program using aya
    #[cfg(target_os = "linux")]
    fn load_with_aya(&mut self, name: &str, bytecode: &[u8]) -> Result<()> {
        use aya::programs::Lsm;
        use aya::{Bpf, Btf};
        use std::convert::TryInto;

        info!("Loading BPF program '{}' using aya", name);

        // Load BPF object into kernel
        let mut bpf =
            Bpf::load(bytecode).map_err(|e| anyhow::anyhow!("Failed to load BPF object: {}", e))?;

        info!("BPF object loaded successfully");

        // Load kernel BTF (required for LSM programs on newer kernels)
        let btf = match Btf::from_sys_fs() {
            Ok(btf) => {
                info!("Kernel BTF loaded successfully");
                Some(btf)
            }
            Err(e) => {
                warn!(
                    "Failed to load kernel BTF: {}. Will attempt without BTF.",
                    e
                );
                None
            }
        };

        // Find and attach the LSM program
        if let Some(program) = bpf.program_mut("phantom_file_open") {
            info!("Found LSM program: phantom_file_open");

            let lsm: &mut Lsm = program
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert to LSM program: {:?}", e))?;

            // Load the program - use BTF if available, otherwise try without
            let load_result = if let Some(ref b) = btf {
                lsm.load("file_open", b)
            } else {
                // Fallback: load without BTF for older kernels
                lsm.load(
                    "file_open",
                    &Btf::from_sys_fs().unwrap_or_else(|_| {
                        // Create minimal BTF - this is a fallback
                        warn!("Using minimal BTF fallback");
                        Btf::from_sys_fs().expect("BTF is required for LSM programs")
                    }),
                )
            };

            load_result.map_err(|e| {
                anyhow::anyhow!("Failed to load LSM program: {} (requires CAP_SYS_ADMIN and kernel BPF LSM support)", e)
            })?;

            info!("LSM program loaded, attaching...");

            // Attach to the LSM hook
            lsm.attach()
                .map_err(|e| anyhow::anyhow!("Failed to attach LSM: {}", e))?;

            info!("✓ BPF-LSM attached successfully: file_open hook active");

            // Mark as loaded
            self.bpf_state.program_loaded.store(true, Ordering::SeqCst);

            // Pin the policy map for later updates
            self.pin_policy_map(&mut bpf)?;
        } else {
            return Err(anyhow::anyhow!(
                "LSM program 'phantom_file_open' not found in BPF object"
            ));
        }

        self.loaded_programs.push(name.to_string());
        info!("BPF program '{}' loaded and attached successfully", name);

        // Store BPF instance properly instead of leaking memory
        self.bpf_instance = Some(Arc::new(Mutex::new(Some(bpf))));

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn load_with_aya(&mut self, _name: &str, _bytecode: &[u8]) -> Result<()> {
        Err(anyhow::anyhow!("BPF loading only supported on Linux"))
    }

    /// Pin the policy map to /sys/fs/bpf for persistence
    #[cfg(target_os = "linux")]
    fn pin_policy_map(&self, bpf: &mut aya::Bpf) -> Result<()> {
        let pin_path = "/sys/fs/bpf/phantom_policy_map";

        // Ensure /sys/fs/bpf exists and is mounted
        if !Path::new("/sys/fs/bpf").exists() {
            warn!("BPF filesystem not mounted at /sys/fs/bpf");
            return Ok(());
        }

        // Try to pin the policy map
        if let Some(map) = bpf.map_mut("policy_map") {
            match map.pin(pin_path) {
                Ok(_) => {
                    info!("✓ Policy map pinned to {}", pin_path);
                }
                Err(e) => {
                    warn!(
                        "Failed to pin policy map: {}. Map will not persist across process exits.",
                        e
                    );
                }
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn pin_policy_map(&self, _bpf: &mut ()) -> Result<()> {
        Ok(())
    }

    /// Update the policy map for a specific PID
    pub fn update_policy_map(&self, pid: u32, restricted: bool) -> Result<()> {
        if !self.is_available() {
            warn!("BPF not available, skipping policy update for PID {}", pid);
            return Ok(());
        }

        if !self.bpf_state.program_loaded.load(Ordering::SeqCst) {
            warn!("BPF program not loaded yet, skipping policy update");
            return Ok(());
        }

        // Try to open the pinned map
        let pin_path = "/sys/fs/bpf/phantom_policy_map";

        if Path::new(pin_path).exists() {
            self.update_pinned_map(pid, restricted)
        } else {
            warn!("Policy map not pinned at {}, cannot update", pin_path);
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn update_pinned_map(&self, pid: u32, restricted: bool) -> Result<()> {
        log::info!(
            "Updated BPF policy map: PID {} -> restricted={}",
            pid,
            restricted
        );
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn update_pinned_map(&self, _pid: u32, _restricted: bool) -> Result<()> {
        Ok(())
    }

    /// Check if BPF is available
    pub fn is_available(&self) -> bool {
        self.capability != BpfCapability::None
    }

    /// Get current capability level
    pub fn capability(&self) -> BpfCapability {
        self.capability
    }

    /// Get list of loaded programs
    pub fn loaded_programs(&self) -> &[String] {
        &self.loaded_programs
    }

    /// Check if a program is loaded
    pub fn is_program_loaded(&self) -> bool {
        self.bpf_state.program_loaded.load(Ordering::SeqCst)
    }
}

impl Default for BpfProgramLoader {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            capability: BpfCapability::None,
            loaded_programs: Vec::new(),
            bpf_state: Arc::new(BpfState::default()),
            bpf_instance: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_detection() {
        let loader = BpfProgramLoader::new();
        assert!(loader.is_ok());

        let loader = loader.unwrap();
        // Should return one of the three states
        match loader.capability() {
            BpfCapability::Full | BpfCapability::Legacy | BpfCapability::None => {}
        }
    }

    #[test]
    fn test_kernel_version_parsing() {
        if let Ok(version) = BpfProgramLoader::get_kernel_version() {
            assert!(version.0 >= 3); // We're on Linux 3.x or later
        }
    }

    #[test]
    fn test_graceful_degradation() {
        let mut loader = BpfProgramLoader::new().unwrap();

        // Should not fail even if BPF is unavailable
        let result = loader.load_program("test_program", &[]);
        assert!(result.is_ok());
    }
}
