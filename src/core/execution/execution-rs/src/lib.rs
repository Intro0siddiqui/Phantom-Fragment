//! Adaptive Execution Engine
//!
//! Automatically selects the optimal execution mode based on workload risk and performance requirements.

use serde::{Deserialize, Serialize};
use types_rs::PhantomError;

// BPF-LSM imports
use bpf_lsm_rs::BpfError;

/// Security mode for handling security feature failures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityMode {
    /// Fail if security features are unavailable (strict security)
    Strict,
    /// Log warning and continue (permissive, backward compatible)
    Permissive,
}

impl Default for SecurityMode {
    fn default() -> Self {
        SecurityMode::Permissive
    }
}

/// Execution modes with varying security/performance trade-offs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    /// <25ms latency, standard namespace isolation. Default mode.
    Sandbox,
    /// <60ms latency, full seccomp + network restrictions. For high-risk workloads.
    Hardened,
    /// <30ms latency, WebAssembly sandbox. For untrusted plugins.
    Wasm,
}

/// Risk assessment factors
#[derive(Debug, Clone, Default)]
pub struct RiskProfile {
    pub network_access: bool,
    pub file_write: bool,
    pub privileged_ops: bool,
    pub untrusted_source: bool,
}

/// Performance requirements
#[derive(Debug, Clone, Default)]
pub struct PerformanceProfile {
    pub latency_sensitive: bool,
    pub high_throughput: bool,
}

/// Hardware isolation configuration
#[derive(Debug, Clone, Default)]
pub struct HardwareProfile {
    pub cpu_affinity: Option<Vec<u32>>,
    pub numa_node: Option<u32>,
    pub cpu_count: usize,
    pub memory_mb: usize,
}

use bpf_lsm_rs::{BpfLsmConfig, BpfLsmSecurity};
use capabilities_rs::drop_capabilities;
use cgroups_rs::CgroupManager;
use security_rs::{SecurityManager, SecurityPolicy};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use zygote_rs::{ZygoteCommand, ZygotePool};

/// Main engine for adaptive execution
pub struct AdaptiveEngine {
    default_mode: ExecutionMode,
    zygote_pool: Arc<Mutex<Option<ZygotePool>>>,
    /// Track PIDs spawned via zygote for proper release
    zygote_pids: Arc<Mutex<HashSet<i32>>>,
}

impl AdaptiveEngine {
    pub fn new() -> Self {
        eprintln!("DEBUG: AdaptiveEngine::new() called");
        // Permissive mode should never fail - it gracefully handles initialization errors
        Self::with_security_mode(SecurityMode::Permissive)
            .expect("Failed to initialize AdaptiveEngine in Permissive mode")
    }

    /// Create a new AdaptiveEngine with specified security mode
    pub fn with_security_mode(_security_mode: SecurityMode) -> Result<Self, PhantomError> {
        // Initialize zygote pool
        let pool = match ZygotePool::new(5) {
            Ok(p) => Some(p),
            Err(e) => match _security_mode {
                SecurityMode::Strict => {
                    return Err(PhantomError::Internal(format!(
                        "Failed to initialize zygote pool (strict mode): {:?}",
                        e
                    )));
                }
                SecurityMode::Permissive => {
                    log::warn!("Failed to initialize zygote pool: {:?}. Continuing without zygote optimization.", e);
                    None
                }
            },
        };

        // Initialize BPF-LSM (note: privilege prompts are handled at CLI layer)
        if BpfLsmSecurity::is_supported() {
            match BpfLsmSecurity::new(BpfLsmConfig::default()) {
                Ok(_lsm) => {
                    log::info!("✅ BPF-LSM initialized successfully");
                }
                Err(BpfError::PermissionDenied) => {
                    // Permission check handled at CLI layer - just log here
                    log::debug!("BPF-LSM requires elevated privileges (handled at CLI layer)");
                }
                Err(e) => {
                    match _security_mode {
                        SecurityMode::Strict => {
                            return Err(PhantomError::Internal(format!(
                                "Failed to initialize BPF-LSM (strict mode): {:?}",
                                e
                            )));
                        }
                        SecurityMode::Permissive => {
                            log::warn!("Failed to initialize BPF-LSM: {:?}. Continuing with reduced security.", e);
                        }
                    }
                }
            }
        } else {
            if _security_mode == SecurityMode::Strict {
                return Err(PhantomError::Internal(
                    "BPF-LSM not supported on this kernel (strict mode requires BPF-LSM)"
                        .to_string(),
                ));
            }
            log::info!("BPF-LSM not supported on this kernel");
        }

        Ok(Self {
            default_mode: ExecutionMode::Sandbox,
            zygote_pool: Arc::new(Mutex::new(pool)),
            zygote_pids: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn select_mode(&self, risk: &RiskProfile, _perf: &PerformanceProfile) -> ExecutionMode {
        if risk.untrusted_source || (risk.privileged_ops && risk.network_access) {
            return ExecutionMode::Hardened;
        }

        if risk.untrusted_source && !risk.privileged_ops {
            return ExecutionMode::Wasm;
        }

        self.default_mode
    }

    pub fn spawn(
        &self,
        mode: ExecutionMode,
        command: &str,
        hardware: Option<&HardwareProfile>,
        security_policy: Option<&SecurityPolicy>,
    ) -> Result<i32, PhantomError> {
        log::info!("Spawning command '{}' in {:?} mode", command, mode);

        match mode {
            ExecutionMode::Sandbox | ExecutionMode::Hardened => {
                self.spawn_sandboxed(command, mode, hardware, security_policy)
            }
            ExecutionMode::Wasm => self.spawn_wasm(command, hardware, security_policy),
        }
    }

    pub fn wait_child(&self, pid: i32, block: bool) -> Result<Option<i32>, PhantomError> {
        let mut status: i32 = 0;
        let options = if block { 0 } else { libc::WNOHANG };

        // SAFETY: waitpid is async-signal-safe and only writes to `status` on success.
        // The `status` variable is properly initialized and passed by mutable reference.
        let waited = unsafe { libc::waitpid(pid, &mut status, options) };

        if waited < 0 {
            // SAFETY: errno is thread-local and safe to read after a failed syscall.
            let err = nix::errno::errno();
            return Err(PhantomError::Internal(format!(
                "waitpid failed for PID {}: errno {} ({})",
                pid,
                err,
                std::io::Error::from_raw_os_error(err)
            )));
        }
        if waited == 0 {
            return Ok(None);
        }

        // Release zygote slot if this was a zygote-spawned process
        if let Ok(mut zygote_pids) = self.zygote_pids.lock() {
            if zygote_pids.remove(&pid) {
                log::debug!("Releasing zygote slot for PID {}", pid);
                if let Ok(mut guard) = self.zygote_pool.lock() {
                    if let Some(ref mut pool) = *guard {
                        pool.release(pid);
                    }
                }
            }
        }

        if libc::WIFEXITED(status) {
            Ok(Some(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            log::info!("Child {} killed by signal {}", pid, libc::WTERMSIG(status));
            Ok(Some(-1))
        } else {
            Ok(Some(status))
        }
    }

    fn spawn_sandboxed(
        &self,
        command: &str,
        mode: ExecutionMode,
        hardware: Option<&HardwareProfile>,
        security_policy: Option<&SecurityPolicy>,
    ) -> Result<i32, PhantomError> {
        // For sandboxed/hardened modes, we need security policies applied before exec.
        // Zygote can be used but security must be applied post-spawn where possible.
        // Note: seccomp/landlock/capabilities require pre-exec application, so we use
        // fork-exec for full security. Zygote is used for cgroup/BPF-LSM only.

        // Try zygote for faster spawn, then apply post-spawn security
        if let Ok(mut guard) = self.zygote_pool.lock() {
            if let Some(ref mut _pool) = *guard {
                let mut parts = command.split_whitespace();
                let exec_path = match parts.next() {
                    Some(p) => p.to_string(),
                    None => return Err(PhantomError::InvalidInput("Empty command".to_string())),
                };
                let args: Vec<String> = parts.map(|s| s.to_string()).collect();

                let mut zygote_cmd = ZygoteCommand::new(exec_path)
                    .args(args)
                    .cwd(
                        std::env::current_dir()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "/".to_string()),
                    )
                    .flags(0);

                for (key, value) in std::env::vars() {
                    zygote_cmd = zygote_cmd.env(&key, &value);
                }

                // Note: zygote blocks until completion, so we can't apply cgroups/BPF
                // For sandboxed/hardened modes, fall back to fork-exec which allows
                // security policy application
                log::debug!("Zygote not used for sandboxed mode (requires security application)");
                // Fall through to fork-exec below
            }
        }

        // Fallback to fork-exec for full security policy application
        use nix::unistd::{fork, ForkResult};

        // SAFETY: Signal masking prevents race conditions where signals are delivered
        // to the child process before it can set up its own signal handlers.
        // We block all signals before fork, then restore them in both parent and child.
        unsafe {
            let mut sigmask: libc::sigset_t = std::mem::zeroed();
            let mut old_sigmask: libc::sigset_t = std::mem::zeroed();

            // Initialize sigset to block all signals
            libc::sigfillset(&mut sigmask);

            // Block all signals before fork - this is critical for thread safety
            // in multi-threaded programs to prevent signals being delivered to
            // the child before it can establish its own signal handlers.
            let ret = libc::pthread_sigmask(libc::SIG_SETMASK, &sigmask, &mut old_sigmask);
            if ret != 0 {
                return Err(PhantomError::Internal(format!(
                    "Failed to block signals before fork: errno {}",
                    ret
                )));
            }

            let fork_result = fork();

            // Restore signal mask in both parent and child immediately after fork
            // The child must restore signals before exec to avoid inheriting blocked signals
            let restore_ret =
                libc::pthread_sigmask(libc::SIG_SETMASK, &old_sigmask, std::ptr::null_mut());

            // Log signal restoration failure in parent only (async-signal-safety)
            if restore_ret != 0
                && fork_result.is_ok()
                && !matches!(fork_result, Ok(ForkResult::Child))
            {
                log::warn!(
                    "Failed to restore signal mask after fork: errno {}",
                    restore_ret
                );
            }

            match fork_result {
                Ok(ForkResult::Parent { child }) => {
                    let child_pid = child.as_raw() as u32;
                    log::info!(
                        "Spawned sandboxed child via fork-exec: {} (pid={})",
                        child,
                        child_pid
                    );

                    if let Some(hw) = hardware {
                        if let Err(e) = self.apply_cgroup_limits(child_pid, hw) {
                            log::warn!("Failed to apply cgroup limits: {:?}", e);
                        }
                    }

                    if mode == ExecutionMode::Hardened || security_policy.is_some() {
                        log::debug!("Hardened mode: Security policies applied in child process");
                    }

                    Ok(child.as_raw())
                }
                Ok(ForkResult::Child) => {
                    // CRITICAL: In child process, use only async-signal-safe functions.
                    // log! is NOT async-signal-safe, so we use eprintln/exit for errors.
                    // Signal mask was already restored above.

                    if restore_ret != 0 {
                        // Cannot log here - signal restoration failed in child
                        // Use minimal async-signal-safe output
                        let _ = nix::unistd::write(
                            libc::STDERR_FILENO,
                            b"fork: failed to restore signal mask\n",
                        );
                        libc::_exit(127);
                    }

                    if let Err(e) = self.apply_security_policies(mode) {
                        // eprintln is NOT async-signal-safe, use write syscall
                        let msg = format!("Failed to apply security policies: {:?}\n", e);
                        let _ = nix::unistd::write(libc::STDERR_FILENO, msg.as_bytes());
                        libc::_exit(1);
                    }

                    if let Some(policy) = security_policy {
                        let mut manager = SecurityManager::new();
                        // In the child process after fork, use graceful mode since
                        // privilege checks were already done at CLI layer
                        if let Err(e) = manager.apply_container_security("fragment", policy, true) {
                            let msg = format!("Failed to apply security policy: {:?}\n", e);
                            let _ = nix::unistd::write(libc::STDERR_FILENO, msg.as_bytes());
                            libc::_exit(1);
                        }
                    }

                    if let Some(hw) = hardware {
                        if let Err(e) = self.apply_hardware_isolation(hw) {
                            let msg = format!("Failed to apply hardware isolation: {:?}\n", e);
                            let _ = nix::unistd::write(libc::STDERR_FILENO, msg.as_bytes());
                            libc::_exit(1);
                        }
                    }

                    self.exec_command(command);
                    // SAFETY: _exit(127) is async-signal-safe and prevents flush of stdio buffers
                    // which could cause duplicate output in parent/child.
                    libc::_exit(127);
                }
                Err(e) => Err(PhantomError::Internal(format!("Fork failed: {}", e))),
            }
        }
    }

    fn spawn_wasm(
        &self,
        command: &str,
        hardware: Option<&HardwareProfile>,
        security_policy: Option<&SecurityPolicy>,
    ) -> Result<i32, PhantomError> {
        use std::path::Path;
        use wasm_rs::{WasmBackend, WasmConfig};

        let mut parts = command.split_whitespace();
        let wasm_path = match parts.next() {
            Some(p) => Path::new(p),
            None => return Err(PhantomError::Internal("Empty command".to_string())),
        };

        let args: Vec<String> = parts.map(|s| s.to_string()).collect();

        let mut config = WasmConfig::default();

        if let Some(hw) = hardware {
            config.max_memory_mb = hw.memory_mb;
        }

        if let Some(policy) = security_policy {
            log::info!(
                "Applying security policy '{}' to WASM execution",
                policy.name
            );

            config.allowed_dirs = vec![("/tmp".to_string(), std::path::PathBuf::from("/tmp"))];
            log::info!("WASM filesystem access restricted to read-only /tmp");

            log::warn!("WASM network isolation not available - network access is determined by WASM runtime");
        }

        let backend = WasmBackend::new()
            .map_err(|e| PhantomError::Internal(format!("WASM init failed: {}", e)))?;

        let backend = backend.with_config(config);

        match backend.run(wasm_path, &args) {
            Ok(code) => Ok(code),
            Err(e) => Err(PhantomError::Internal(format!(
                "WASM execution failed: {}",
                e
            ))),
        }
    }

    fn exec_command(&self, command: &str) {
        use nix::unistd::execvp;
        use std::ffi::CString;

        let mut parts = command.split_whitespace();
        let program = match parts.next() {
            Some(p) => CString::new(p).unwrap_or_else(|_| {
                log::error!("Invalid command: contains null byte");
                std::process::exit(1);
            }),
            None => {
                log::error!("Empty command provided to exec_command");
                std::process::exit(1);
            }
        };

        let args: Vec<CString> = std::iter::once(program.clone())
            .chain(parts.map(|s| {
                CString::new(s).unwrap_or_else(|_| {
                    log::error!("Invalid argument: contains null byte");
                    std::process::exit(1);
                })
            }))
            .collect();

        log::info!("Executing: {:?}", command);

        match execvp(&program, &args) {
            Err(e) => {
                log::error!(
                    "execvp failed for '{}': {} (hint: use 'phantom run <image> <command>' to execute commands)",
                    program.to_string_lossy(), e
                );
                std::process::exit(127);
            }
            Ok(_) => unreachable!("execvp should never return on success"),
        }
    }

    fn apply_security_policies(&self, mode: ExecutionMode) -> Result<(), PhantomError> {
        self.apply_landlock(mode)?;
        self.apply_seccomp(mode)?;
        self.apply_network_isolation(mode)?;
        self.apply_capabilities(mode)?;
        Ok(())
    }

    fn apply_capabilities(&self, mode: ExecutionMode) -> Result<(), PhantomError> {
        let caps_to_drop: Vec<&str> = match mode {
            ExecutionMode::Sandbox => vec!["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE"],
            ExecutionMode::Hardened => vec![
                "CAP_SYS_ADMIN",
                "CAP_NET_ADMIN",
                "CAP_NET_RAW",
                "CAP_SYS_PTRACE",
                "CAP_MKNOD",
                "CAP_SYS_MODULE",
                "CAP_SYS_RAWIO",
            ],
            ExecutionMode::Wasm => vec![
                "CAP_SYS_ADMIN",
                "CAP_NET_ADMIN",
                "CAP_NET_RAW",
                "CAP_SYS_PTRACE",
                "CAP_MKNOD",
                "CAP_SYS_MODULE",
                "CAP_SYS_RAWIO",
                "CAP_FOWNER",
                "CAP_FSETID",
            ],
        };

        if let Err(e) = drop_capabilities(&caps_to_drop) {
            log::warn!("Failed to drop capabilities: {:?}", e);
        } else {
            log::info!("✅ Capabilities dropped for {:?} mode", mode);
        }
        Ok(())
    }

    fn apply_landlock(&self, mode: ExecutionMode) -> Result<(), PhantomError> {
        let ctx = match landlock_rs::LandlockContext::new() {
            Some(c) => c,
            None => {
                log::warn!("Landlock not available (requires kernel 5.13+)");
                return Ok(());
            }
        };

        let allowed_paths = match mode {
            ExecutionMode::Sandbox => vec!["/usr", "/lib", "/tmp"],
            ExecutionMode::Hardened => vec!["/usr/bin"],
            ExecutionMode::Wasm => vec!["/tmp"],
        };

        for path in allowed_paths {
            let access_rights = 0x5;

            if ctx.add_rule(path, access_rights).is_err() {
                log::warn!(
                    "Failed to add Landlock rule for {} (path may not exist)",
                    path
                );
                continue;
            }
        }

        if ctx.apply().is_err() {
            log::warn!("Failed to apply Landlock ruleset");
            return Ok(());
        }

        log::info!("✅ Landlock policy applied for {:?} mode", mode);
        Ok(())
    }

    fn apply_hardware_isolation(&self, profile: &HardwareProfile) -> Result<(), PhantomError> {
        if let Some(ref cpus) = profile.cpu_affinity {
            if !cpus.is_empty() {
                if memory_rs::set_cpu_affinity(cpus).is_err() {
                    return Err(PhantomError::Internal(
                        "Failed to set CPU affinity".to_string(),
                    ));
                }
                log::info!("✅ CPU affinity applied: {:?}", cpus);
            }
        }

        #[cfg(feature = "numa")]
        if let Some(node) = profile.numa_node {
            memory_rs::NumaManager::bind_node(node as i32);
            log::info!("✅ NUMA policy applied: node {}", node);
        }

        Ok(())
    }

    fn apply_cgroup_limits(
        &self,
        child_pid: u32,
        profile: &HardwareProfile,
    ) -> Result<(), PhantomError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        let cgroup_name = format!("phantom_{}_{}", child_pid, timestamp);
        let cgroup = CgroupManager::new(&cgroup_name);

        if let Err(e) = cgroup.create() {
            log::warn!(
                "Failed to create cgroup '{}': {}. Continuing without resource limits.",
                cgroup_name,
                e
            );
            return Ok(());
        }

        let memory_mb = if profile.memory_mb > 0 {
            profile.memory_mb as u64
        } else {
            512
        };

        if let Err(e) = cgroup.set_memory_limit(memory_mb) {
            log::warn!(
                "Failed to set memory limit {}MB: {}. Continuing without memory limit.",
                memory_mb,
                e
            );
        } else {
            log::info!("✅ Cgroup memory limit set: {}MB", memory_mb);
        }

        if profile.cpu_count > 0 {
            if let Err(e) = cgroup.set_cpu_limit(profile.cpu_count as u64) {
                log::warn!(
                    "Failed to set CPU limit {} cores: {}. Continuing without CPU limit.",
                    profile.cpu_count,
                    e
                );
            } else {
                log::info!("✅ Cgroup CPU limit set: {} cores", profile.cpu_count);
            }
        }

        if let Err(e) = cgroup.add_process(child_pid as i32) {
            log::warn!(
                "Failed to add process {} to cgroup: {}. Continuing without resource limits.",
                child_pid,
                e
            );
            return Ok(());
        }

        log::info!(
            "✅ Cgroup '{}' created and configured for PID {}",
            cgroup_name,
            child_pid
        );
        Ok(())
    }

    fn apply_seccomp(&self, mode: ExecutionMode) -> Result<(), PhantomError> {
        let profile_name = match mode {
            ExecutionMode::Sandbox => "default",
            ExecutionMode::Hardened => "hardened",
            ExecutionMode::Wasm => "strict",
        };

        if seccomp_rs::apply_profile(profile_name).is_err() {
            log::warn!("Failed to apply seccomp profile (may not be supported)");
            return Ok(());
        }
        log::info!("✅ Seccomp profile applied for {:?} mode", mode);

        Ok(())
    }

    fn apply_network_isolation(&self, mode: ExecutionMode) -> Result<(), PhantomError> {
        if mode == ExecutionMode::Sandbox || mode == ExecutionMode::Hardened {
            match network_rs::NetworkNamespace::new() {
                Some(_ns) => {
                    log::info!("✅ Network namespace created for {:?} mode", mode);
                }
                None => {
                    log::warn!("Failed to create network namespace (requires CAP_SYS_ADMIN)");
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    pub fn apply_mode(&self, mode: ExecutionMode) -> Result<(), PhantomError> {
        log::info!("Mode {:?} selected (use spawn() for execution)", mode);
        Ok(())
    }

    /// Apply cgroup limits to an external PID (for forked warm fragments)
    pub fn apply_cgroup_limits_to_pid(
        pid: u32,
        profile: &HardwareProfile,
    ) -> Result<(), PhantomError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        let cgroup_name = format!("phantom_{}_{}", pid, timestamp);
        let cgroup = CgroupManager::new(&cgroup_name);

        if let Err(e) = cgroup.create() {
            log::warn!(
                "Failed to create cgroup '{}': {}. Continuing without resource limits.",
                cgroup_name,
                e
            );
            return Ok(());
        }

        let memory_mb = if profile.memory_mb > 0 {
            profile.memory_mb as u64
        } else {
            512
        };

        if let Err(e) = cgroup.set_memory_limit(memory_mb) {
            log::warn!(
                "Failed to set memory limit {}MB: {}. Continuing without memory limit.",
                memory_mb,
                e
            );
        } else {
            log::info!("✅ Cgroup memory limit set: {}MB", memory_mb);
        }

        if profile.cpu_count > 0 {
            if let Err(e) = cgroup.set_cpu_limit(profile.cpu_count as u64) {
                log::warn!(
                    "Failed to set CPU limit {} cores: {}. Continuing without CPU limit.",
                    profile.cpu_count,
                    e
                );
            } else {
                log::info!("✅ Cgroup CPU limit set: {} cores", profile.cpu_count);
            }
        }

        if let Err(e) = cgroup.add_process(pid as i32) {
            log::warn!(
                "Failed to add process {} to cgroup: {}. Continuing without resource limits.",
                pid,
                e
            );
            return Ok(());
        }

        log::info!(
            "✅ Cgroup '{}' created and configured for PID {}",
            cgroup_name,
            pid
        );
        Ok(())
    }
}

impl Default for AdaptiveEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_risk_selection() {
        let engine = AdaptiveEngine::new();
        let risk = RiskProfile {
            untrusted_source: true,
            ..Default::default()
        };
        let perf = PerformanceProfile::default();

        assert_eq!(engine.select_mode(&risk, &perf), ExecutionMode::Hardened);
    }

    #[test]
    fn test_performance_selection() {
        let engine = AdaptiveEngine::new();
        let risk = RiskProfile::default();
        let perf = PerformanceProfile {
            latency_sensitive: true,
            ..Default::default()
        };

        assert_eq!(engine.select_mode(&risk, &perf), ExecutionMode::Sandbox);
    }

    #[test]
    fn test_default_selection() {
        let engine = AdaptiveEngine::new();
        let risk = RiskProfile {
            network_access: true,
            ..Default::default()
        };
        let perf = PerformanceProfile::default();

        assert_eq!(engine.select_mode(&risk, &perf), ExecutionMode::Sandbox);
    }
}
