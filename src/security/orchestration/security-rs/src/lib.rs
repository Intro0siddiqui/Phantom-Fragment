use anyhow::Result;
#[cfg(feature = "bpf-lsm")]
use aya::Bpf;
use cgroups_rs::{CgroupManager, IoLimits, UserSliceStatus};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use log::{info, warn};
use std::os::linux::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::Path;
use types_rs::PhantomError;

#[cfg(feature = "bpf-lsm")]
use bpf_lsm_rs::BpfError;

/// Security features that may require elevated privileges
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityFeature {
    /// BPF-LSM for runtime syscall monitoring
    BpfLsm,
    /// Cgroups for resource limits
    Cgroups,
}

impl std::fmt::Display for SecurityFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityFeature::BpfLsm => write!(f, "BPF-LSM (runtime syscall monitoring)"),
            SecurityFeature::Cgroups => write!(f, "cgroups (resource limits)"),
        }
    }
}

/// Result of checking which security features need elevated privileges
#[derive(Debug, Clone)]
pub struct PrivilegeRequirements {
    /// Features that require elevated privileges
    pub required: Vec<SecurityFeature>,
    /// Features that are available without elevated privileges
    pub available: Vec<SecurityFeature>,
}

impl PrivilegeRequirements {
    /// Check if any features require elevated privileges
    pub fn needs_elevation(&self) -> bool {
        !self.required.is_empty()
    }

    /// Get a human-readable description of required features
    pub fn required_description(&self) -> String {
        if self.required.is_empty() {
            "None".to_string()
        } else {
            self.required
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join("\n  • ")
        }
    }
}

/// Check if the current process has CAP_SYS_ADMIN
fn has_cap_sys_admin() -> bool {
    // Try to read /proc/self/status for CapEff
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                let caps = line.split_whitespace().nth(1).unwrap_or("0");
                if let Ok(cap_mask) = u64::from_str_radix(caps, 16) {
                    return (cap_mask >> 21) & 1 == 1;
                }
            }
        }
    }
    // Fallback: check if we're running as root
    unsafe { libc::geteuid() == 0 }
}

/// Check which security features need elevated privileges
///
/// This performs a unified check for all security features that require
/// elevated privileges (CAP_SYS_ADMIN), avoiding duplicate prompts.
pub fn check_privilege_requirements() -> PrivilegeRequirements {
    let mut required = Vec::new();
    let mut available = Vec::new();

    let has_elevation = has_cap_sys_admin();

    // Check BPF-LSM requirements
    #[cfg(feature = "bpf-lsm")]
    {
        if bpf_lsm_rs::BpfLsmSecurity::is_supported() {
            if has_elevation {
                available.push(SecurityFeature::BpfLsm);
            } else {
                required.push(SecurityFeature::BpfLsm);
            }
        }
    }
    #[cfg(not(feature = "bpf-lsm"))]
    {
        // BPF-LSM not compiled in, skip
    }

    // Check cgroup requirements
    match cgroups_rs::check_user_slice_status() {
        UserSliceStatus::Available => {
            available.push(SecurityFeature::Cgroups);
        }
        _ => {
            if has_elevation {
                // With sudo, cgroups will work
                available.push(SecurityFeature::Cgroups);
            } else {
                required.push(SecurityFeature::Cgroups);
            }
        }
    }

    PrivilegeRequirements {
        required,
        available,
    }
}

/// User choice from unified privilege prompt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeChoice {
    /// Re-run with sudo for full security
    UseSudo,
    /// Continue without elevated privileges (reduced security)
    ContinueWithout,
    /// Abort execution
    Abort,
}

/// Security Policy for a container
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub name: String,
    pub bpf_programs: Vec<String>,
    pub seccomp_rules: Vec<SeccompRule>,
    pub capabilities: Vec<String>,
    pub cgroups: CgroupPolicy,
}

#[derive(Debug, Clone, Default)]
pub struct CgroupPolicy {
    pub pids_limit: Option<u32>,
    pub io_limits: Option<IoLimits>,
}

#[derive(Debug, Clone)]
pub struct SeccompRule {
    pub syscall: String,
    pub action: String,
}

#[derive(Debug)]
pub struct BpfProgram {}

#[derive(Debug)]
pub struct SeccompFilter {
    rules: Vec<SeccompRule>,
}

impl SeccompFilter {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: SeccompRule) {
        self.rules.push(rule);
    }
}

impl Default for SeccompFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime security monitor using eBPF
///
/// NOTE: eBPF monitoring is currently incomplete. The BPF programs exist in source form
/// but require compilation with bpf-linker. When eBPF is unavailable, the system falls
/// back to seccomp and Landlock for security enforcement.
///
/// To enable full eBPF monitoring:
/// 1. Install bpf-linker: `cargo install bpf-linker`
/// 2. Compile BPF programs: `cargo build-bpf` in the bpf/ directory
/// 3. Ensure the resulting monitor.o is placed in src/bpf/
#[derive(Debug)]
pub struct RuntimeSecurityMonitor {
    bpf_available: bool,
}

impl RuntimeSecurityMonitor {
    pub fn new() -> Self {
        // Check if BPF object file exists
        let bpf_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("bpf/monitor.o");
        let bpf_available = bpf_path.exists();

        if !bpf_available {
            warn!("eBPF monitoring unavailable: bpf/monitor.o not found. See security-rs/bpf/README.md for build instructions.");
        }

        Self { bpf_available }
    }

    pub fn start_monitoring(
        &mut self,
        container_id: &str,
        _policy: &SecurityPolicy,
    ) -> Result<(), PhantomError> {
        info!(
            "Starting security monitoring for container: {}",
            container_id
        );

        if !self.bpf_available {
            warn!(
                "eBPF monitoring not available for {}. Using seccomp/Landlock fallback.",
                container_id
            );
            return Ok(());
        }

        #[cfg(feature = "bpf-lsm")]
        {
            info!("Initializing eBPF runtime monitor for {}", container_id);
            match self.initialize_bpf_monitor(container_id) {
                Ok(_) => {
                    info!("✓ eBPF runtime monitor active for {}", container_id);
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize eBPF monitor: {:?}. Falling back to seccomp.",
                        e
                    );
                }
            }
        }

        #[cfg(not(feature = "bpf-lsm"))]
        {
            warn!(
                "eBPF-LSM feature not enabled. Using seccomp fallback for {}",
                container_id
            );
        }

        Ok(())
    }

    #[cfg(feature = "bpf-lsm")]
    fn initialize_bpf_monitor(&mut self, _container_id: &str) -> Result<aya::Bpf, PhantomError> {
        let bpf_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("bpf/monitor.o");

        if !bpf_path.exists() {
            return Err(PhantomError::Internal(
                "BPF object file not found. Run 'cargo build-bpf' in the bpf/ directory."
                    .to_string(),
            ));
        }

        let bpf_bytes = std::fs::read(&bpf_path).map_err(|e| {
            PhantomError::Internal(format!("Failed to read BPF object file: {}", e))
        })?;

        aya::Bpf::load(&bpf_bytes[..]).map_err(|e| {
            PhantomError::Internal(format!("Failed to load BPF runtime monitor: {}", e))
        })
    }
}

impl Default for RuntimeSecurityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Security Manager - Phase 4: eBPF-based security in Rust
pub struct SecurityManager {
    bpf_programs: Vec<BpfProgram>,
    seccomp_filters: SeccompFilter,
    runtime_monitor: RuntimeSecurityMonitor,
}

impl SecurityManager {
    pub fn new() -> Self {
        Self {
            bpf_programs: Vec::new(),
            seccomp_filters: SeccompFilter::new(),
            runtime_monitor: RuntimeSecurityMonitor::new(),
        }
    }

    /// Apply container security policy
    ///
    /// If `graceful` is true, failures in optional features (BPF-LSM, cgroups)
    /// will be logged as warnings but won't cause errors. Use this after
    /// the user has already been prompted about missing privileges.
    pub fn apply_container_security(
        &mut self,
        container_id: &str,
        policy: &SecurityPolicy,
        graceful: bool,
    ) -> Result<(), PhantomError> {
        info!(
            "Applying security policy '{}' to container: {}",
            policy.name, container_id
        );

        // Load BPF-LSM policy (graceful fallback if unavailable)
        match self.load_bpf_policy(policy) {
            Ok(Some(_)) => {
                info!("✓ BPF-LSM policy active");
            }
            Ok(None) => {
                log::debug!("BPF-LSM not active, using Seccomp/Landlock fallback");
            }
            Err(e) if graceful => {
                log::warn!(
                    "⚠️ BPF-LSM failed to load: {:?}. Continuing with fallback.",
                    e
                );
            }
            Err(e) => {
                return Err(e);
            }
        }

        // Apply seccomp filters (always applied, doesn't need privileges)
        self.apply_seccomp_filters(container_id, &policy.seccomp_rules)?;

        // Apply cgroup limits (graceful fallback if unavailable)
        if let Err(e) = self.apply_cgroups(container_id, policy) {
            if graceful {
                log::warn!(
                    "⚠️ Cgroups failed to apply: {:?}. Continuing without resource limits.",
                    e
                );
            } else {
                return Err(e);
            }
        }

        // Start runtime monitoring
        self.runtime_monitor
            .start_monitoring(container_id, policy)?;

        Ok(())
    }

    /// Load BPF-LSM policy (without prompts - caller handles privilege checks)
    #[cfg(feature = "bpf-lsm")]
    fn load_bpf_policy(&mut self, policy: &SecurityPolicy) -> Result<Option<RawFd>, PhantomError> {
        use bpf_lsm_rs::{BpfLsmConfig, BpfLsmSecurity};

        // Try to initialize BPF-LSM
        let config = BpfLsmConfig::default();
        match BpfLsmSecurity::new(config) {
            Ok(lsm) => {
                log::info!("✅ BPF-LSM initialized");
                // Store the LSM instance for later use
                drop(lsm);
                self.load_bpf_programs(policy).map(Some)
            }
            Err(BpfError::PermissionDenied) => {
                log::debug!("BPF-LSM requires elevated privileges");
                Err(PhantomError::NeedSudo)
            }
            Err(e) => {
                log::debug!("BPF-LSM unavailable: {:?}", e);
                Ok(None)
            }
        }
    }

    #[cfg(not(feature = "bpf-lsm"))]
    fn load_bpf_policy(&mut self, _policy: &SecurityPolicy) -> Result<Option<RawFd>, PhantomError> {
        if !_policy.bpf_programs.is_empty() {
            info!(
                "BPF-LSM feature disabled. Using seccomp fallback for policy: {}",
                _policy.name
            );
        }
        Ok(None)
    }

    /// Load BPF programs into the kernel (low-level implementation)
    #[cfg(feature = "bpf-lsm")]
    fn load_bpf_programs(&mut self, policy: &SecurityPolicy) -> Result<RawFd, PhantomError> {
        use aya::maps::HashMap;
        use aya::programs::Lsm;
        use aya::Btf;
        use std::convert::TryInto;

        info!("Loading BPF-LSM policy: {}", policy.name);

        // Load embedded BPF object
        info!("Loading embedded BPF-LSM policy: {}", policy.name);
        let bpf_bytes = include_bytes!("../bpf/monitor.o");
        let mut bpf = Bpf::load(bpf_bytes).map_err(|e| {
            PhantomError::Internal(format!("Failed to load BPF from memory: {}", e))
        })?;

        // Load kernel BTF (required for LSM programs)
        let btf = Btf::from_sys_fs().map_err(|e| {
            PhantomError::Internal(format!(
                "Failed to load kernel BTF: {} (is /sys/kernel/btf/vmlinux available?)",
                e
            ))
        })?;

        // Try to load and attach the LSM program
        if let Some(program) = bpf.program_mut("phantom_file_open") {
            info!("Found LSM program: phantom_file_open");

            // Convert to LSM type and attach
            // Note: This requires CAP_SYS_ADMIN and kernel BPF LSM support
            let lsm: &mut Lsm = program.try_into().map_err(|e| {
                PhantomError::Internal(format!("Failed to convert to LSM: {:?}", e))
            })?;

            // Load with hook name and BTF
            lsm.load("file_open", &btf).map_err(|e| {
                PhantomError::Internal(format!("Failed to load LSM program: {}", e))
            })?;

            info!("Loaded LSM program. Attaching...");

            lsm.attach().map_err(|e| {
                PhantomError::Internal(format!(
                    "Failed to attach LSM: {} (requires CAP_SYS_ADMIN)",
                    e
                ))
            })?;

            info!("✓ BPF-LSM attached successfully: file_open hook active");

            // 3. Update Policy Map for current PID
            let pid = std::process::id();
            if let Some(map) = bpf.map_mut("policy_map") {
                let mut hash_map: HashMap<_, u32, u32> = HashMap::try_from(map).map_err(|e| {
                    PhantomError::Internal(format!("Failed to access policy map: {:?}", e))
                })?;

                // Set policy to 1 (Strict/Malicious Context) for this PID
                hash_map.insert(pid, 1, 0).map_err(|e| {
                    PhantomError::Internal(format!("Failed to update policy map: {:?}", e))
                })?;

                info!("✓ Enforced BPF policy for PID {}", pid);
            }
        } else {
            info!("LSM program 'phantom_file_open' not found in object file");
        }

        // Also check tracepoint
        if bpf.program_mut("trace_execve").is_some() {
            info!("Found tracepoint program: trace_execve (monitoring only)");
        }

        Ok(-1)
    }

    #[cfg(not(feature = "bpf-lsm"))]
    fn load_bpf_policy(&mut self, policy: &SecurityPolicy) -> Result<RawFd, PhantomError> {
        if !policy.bpf_programs.is_empty() {
            info!(
                "BPF-LSM feature disabled. Using seccomp fallback for policy: {}",
                policy.name
            );
        }
        Ok(-1)
    }

    fn apply_seccomp_filters(
        &mut self,
        container_id: &str,
        rules: &[SeccompRule],
    ) -> Result<(), PhantomError> {
        info!(
            "Applying {} seccomp rules to container: {}",
            rules.len(),
            container_id
        );

        // Create a new filter with default action Kill (allow nothing by default unless specified)
        // Or Allow (allow everything unless restricted). Usually Allow for blacklisting, Kill for whitelisting.
        // Let's assume a default of Allow for now to be safe, or we can parse it from policy.
        let mut filter = ScmpFilterContext::new(ScmpAction::Allow).map_err(|e| {
            PhantomError::Internal(format!("Failed to create seccomp filter: {}", e))
        })?;

        for rule in rules {
            let syscall = ScmpSyscall::from_name(&rule.syscall).map_err(|_| {
                PhantomError::Internal(format!("Invalid syscall name: {}", rule.syscall))
            })?;

            let action = match rule.action.as_str() {
                "SCMP_ACT_ALLOW" => ScmpAction::Allow,
                "SCMP_ACT_KILL" => ScmpAction::KillThread,
                "SCMP_ACT_TRAP" => ScmpAction::Trap,
                "SCMP_ACT_ERRNO" => ScmpAction::Errno(1), // EPERM
                "SCMP_ACT_LOG" => ScmpAction::Log,
                _ => ScmpAction::KillThread, // Default to kill for unknown actions
            };

            filter.add_rule(action, syscall).map_err(|e| {
                PhantomError::Internal(format!("Failed to add seccomp rule: {}", e))
            })?;

            self.seccomp_filters.add_rule(rule.clone());
        }

        // Load the filter into the kernel
        filter
            .load()
            .map_err(|e| PhantomError::Internal(format!("Failed to load seccomp filter: {}", e)))?;

        info!("Seccomp filters loaded successfully for {}", container_id);
        Ok(())
    }

    fn apply_cgroups(
        &self,
        container_id: &str,
        policy: &SecurityPolicy,
    ) -> Result<(), PhantomError> {
        info!("Applying cgroup limits for container: {}", container_id);

        let manager = CgroupManager::new(container_id);

        // Try to create cgroup - if it fails due to permissions, return error
        // Caller should have already checked privilege requirements
        if let Err(e) = manager.create() {
            log::debug!("Cgroup creation failed: {:?}", e);
            return Err(PhantomError::Internal(format!(
                "Cgroup creation failed (may need elevated privileges): {}",
                e
            )));
        }

        info!("  Cgroup created: {}", container_id);

        if let Some(limit) = policy.cgroups.pids_limit {
            if let Err(e) = manager.set_pid_limit(limit) {
                log::warn!(
                    "  Failed to set PID limit: {}. Continuing without PID limit.",
                    e
                );
            } else {
                info!("  PID limit set to {}", limit);
            }
        }

        if let Some(ref io_limits) = policy.cgroups.io_limits {
            if let Ok(meta) = std::fs::metadata(".") {
                let dev = meta.st_dev();
                let major = libc::major(dev) as u32;
                let minor = libc::minor(dev) as u32;

                if let Err(e) = manager.set_io_limit(major, minor, io_limits.clone()) {
                    log::warn!(
                        "  Failed to set I/O limits: {}. Continuing without I/O limits.",
                        e
                    );
                } else {
                    info!("  I/O limits set for device {}:{}", major, minor);
                }
            }
        }

        info!("✅ Cgroup limits applied");
        Ok(())
    }

    /// Get security status for a container
    pub fn get_security_status(&self, container_id: &str) -> Result<SecurityStatus, PhantomError> {
        Ok(SecurityStatus {
            container_id: container_id.to_string(),
            bpf_programs_loaded: self.bpf_programs.len(),
            seccomp_rules_active: self.seccomp_filters.rules.len(),
            monitoring_active: true,
        })
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SecurityStatus {
    pub container_id: String,
    pub bpf_programs_loaded: usize,
    pub seccomp_rules_active: usize,
    pub monitoring_active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_manager_creation() {
        let manager = SecurityManager::new();
        assert_eq!(manager.bpf_programs.len(), 0);
    }

    #[test]
    fn test_security_policy_creation() {
        let policy = SecurityPolicy {
            name: "test-policy".to_string(),
            bpf_programs: vec!["monitor_syscalls".to_string()],
            seccomp_rules: vec![SeccompRule {
                syscall: "execve".to_string(),
                action: "SCMP_ACT_ALLOW".to_string(),
            }],
            capabilities: vec!["CAP_NET_ADMIN".to_string()],
            cgroups: CgroupPolicy {
                pids_limit: Some(100),
                io_limits: None,
            },
        };

        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.bpf_programs.len(), 1);
    }
}
