use crate::commands::CommandContext;
use crate::config::Config;
use crate::config::PhantomPaths;
use crate::io_utils::{chrono_lite_timestamp, parse_run_args};
use crate::permission_prompt::{self, print_continue_without_info, print_sudo_instructions};
use crate::ui;
use anyhow::Context;
use bpf_lsm_rs::{BpfLsmConfig, BpfLsmSecurity};
use colored::*;
use security_rs::{CgroupPolicy, PrivilegeChoice, SeccompRule, SecurityPolicy};
use std::path::{Path, PathBuf};

/// Image configuration stored with built images
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ImageConfig {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub user: String,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            entrypoint: None,
            cmd: None,
            user: "root".to_string(),
        }
    }
}

/// Read image configuration from phantom-config.json
fn read_image_config(image_path: &Path) -> Option<ImageConfig> {
    let config_path = image_path.join("phantom-config.json");
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(config) = serde_json::from_str(&content) {
                return Some(config);
            }
        }
    }
    None
}

/// Get the final command by combining ENTRYPOINT + CMD
fn get_command_for_image(
    image_name: &str,
    user_cmd: Vec<String>,
    paths: &PhantomPaths,
) -> (Vec<String>, Option<String>) {
    // Try to find image in rootfs
    let simple_name = image_name.replace(":", "-").replace("/", "_");
    let image_path = paths.rootfs().join(&simple_name);

    if let Some(config) = read_image_config(&image_path) {
        let mut final_cmd = Vec::new();

        // ENTRYPOINT + user CMD (or image CMD if no user CMD)
        if let Some(entrypoint) = &config.entrypoint {
            final_cmd.extend(entrypoint.clone());
        }

        let cmd_to_use = if !user_cmd.is_empty() {
            user_cmd
        } else if let Some(cmd) = &config.cmd {
            cmd.clone()
        } else {
            vec![]
        };

        final_cmd.extend(cmd_to_use);

        // If no command at all, use shell
        if final_cmd.is_empty() {
            final_cmd = vec!["/bin/sh".to_string()];
        }

        log::info!(
            "Using image config: entrypoint={:?}, cmd={:?}",
            config.entrypoint,
            config.cmd
        );
        return (final_cmd, Some(config.user));
    }

    // Fallback to user command or shell
    let cmd = if user_cmd.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        user_cmd
    };
    (cmd, None)
}

#[derive(clap::Args, Debug, Clone)]
pub struct RunArgs {
    /// Fragment image OR first part of command
    pub image_or_command: Option<String>,

    /// Disable auto-pull (pull is enabled by default)
    #[arg(long)]
    pub no_pull: bool,

    /// Enable strict SHA256 verification of downloaded layers
    #[arg(long)]
    pub verify: bool,

    /// Enable network access
    #[arg(short = 'n', long)]
    pub network: bool,

    /// Run as true root (requires sudo)
    #[arg(short = 'r', long)]
    pub root: bool,

    /// Use Proot for rootless emulation
    #[arg(long)]
    pub proot: bool,

    /// Use Fuse-OverlayFS (experimental)
    #[arg(long)]
    pub overlay: bool,

    /// OCI Runtime to use
    #[arg(long)]
    pub runtime: Option<String>,

    /// Security profile (direct, sandbox, hardened, wasm)
    #[arg(short, long, default_value = "sandbox")]
    pub profile: String,

    /// Run as WebAssembly module
    #[arg(long, help = "Run as WebAssembly module")]
    pub wasm: bool,

    /// Use warm fragment pool (mother fragment) for faster startup (beta/experimental)
    #[arg(
        long,
        help = "Use warm fragment pool for faster startup (beta/experimental - has limitations)"
    )]
    pub warm: bool,

    /// Use zygote pool for ultra-fast spawning (<1ms)
    #[arg(long, help = "Use zygote pool for ultra-fast spawning")]
    pub zygote: bool,

    /// Command and arguments (everything after image)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,

    /// Path to configuration file
    #[arg(long)]
    pub config: Option<String>,
}

pub async fn exec(ctx: CommandContext<'_>, args: RunArgs) -> anyhow::Result<()> {
    // ============ UNIFIED PRIVILEGE CHECK ============
    // Check security feature requirements BEFORE attempting to use them.
    // This ensures we only prompt ONCE for all features needing elevation.
    let privilege_choice = permission_prompt::handle_privilege_requirements();

    match privilege_choice {
        PrivilegeChoice::UseSudo => {
            // User wants to use sudo - trigger re-exec from main.rs
            print_sudo_instructions();
            return Err(anyhow::anyhow!("Permission denied - sudo required"));
        }
        PrivilegeChoice::Abort => {
            println!("{} Aborting.", "✗".red());
            std::process::exit(1);
        }
        PrivilegeChoice::ContinueWithout => {
            // Continue without elevated privileges - security features will gracefully degrade
            log::debug!("Continuing without elevated privileges");
        }
    }

    // Determine if we should use graceful mode for security features
    let graceful_security = privilege_choice == PrivilegeChoice::ContinueWithout;

    let CommandContext {
        config: app_config,
        paths,
        ..
    } = ctx;

    let RunArgs {
        image_or_command,
        no_pull,
        verify,
        network,
        root,
        proot,
        overlay,
        runtime,
        profile,
        wasm,
        warm,
        zygote,
        command,
        config: config_path_opt,
    } = args;

    let app_config = if let Some(config_path) = config_path_opt {
        Config::from_file(&PathBuf::from(&config_path)).unwrap_or_else(|e| {
            eprintln!("Error: Failed to load config from {}: {}", config_path, e);
            std::process::exit(1);
        })
    } else {
        app_config.clone()
    };

    let (final_image, user_command) = parse_run_args(image_or_command, command);
    let pull = !no_pull;

    // Get command from image config if available (ENTRYPOINT + CMD)
    let (mut final_command, image_user) = if let Some(ref image_name) = final_image {
        get_command_for_image(image_name, user_command, &paths)
    } else {
        let cmd = if user_command.is_empty() {
            vec!["/bin/sh".to_string()]
        } else {
            user_command
        };
        (cmd, None)
    };

    // Use image USER if not running as root
    let effective_user = if root { None } else { image_user };

    let profile_name = if wasm {
        "wasm".to_string()
    } else if let Some(ref img) = final_image {
        if img.ends_with(".wasm") {
            "wasm".to_string()
        } else {
            profile
        }
    } else if !final_command.is_empty() && final_command[0].ends_with(".wasm") {
        "wasm".to_string()
    } else {
        profile
    };

    // Get hardware profile from profile settings for cgroup limits
    let hardware_profile = app_config
        .get_profile(&profile_name)
        .and_then(|p| p.to_hardware_profile());

    let security_policy = if let Some(p) = app_config.get_profile(&profile_name) {
        let mut rules = vec![];
        if let Some(config_rules) = &p.seccomp_rules {
            for r in config_rules {
                rules.push(SeccompRule {
                    syscall: r.syscall.clone(),
                    action: r.action.clone(),
                });
            }
        }

        Some(SecurityPolicy {
            name: format!("{}-policy", profile_name),
            bpf_programs: vec![],
            seccomp_rules: rules,
            capabilities: vec![],
            cgroups: CgroupPolicy {
                pids_limit: app_config.security.pids_limit,
                io_limits: None,
            },
        })
    } else if app_config.security.pids_limit.is_some() {
        Some(SecurityPolicy {
            name: "default-policy".to_string(),
            bpf_programs: vec![],
            seccomp_rules: vec![],
            capabilities: vec![],
            cgroups: CgroupPolicy {
                pids_limit: app_config.security.pids_limit,
                io_limits: None,
            },
        })
    } else {
        None
    };

    if let Some(ref image_ref) = final_image {
        if final_command.is_empty() {
            final_command.push("/bin/sh".to_string());
        }

        ui::success_with_prefix("Running in fragment:", image_ref);
        ui::info("Command:", &format!("{:?}", final_command));

        use image_puller::{ImagePuller, PullConfig, RootfsExecutor};

        let config = PullConfig { verify };
        let puller = ImagePuller::with_config(config).context("Failed to create ImagePuller")?;

        let rootfs_path = puller.get_rootfs(image_ref, pull).await?;

        ui::info("Rootfs:", &rootfs_path.display().to_string());

        // Use warm fragment pool if --warm flag is passed
        if warm {
            ui::warn_bold("Warm fragments are an experimental feature with limitations (daemon stability, IPC issues)");
            use crate::fragment_pool::FragmentPool;
            if let Ok(pools) = FragmentPool::list() {
                if let Some(pool_meta) = pools.iter().find(|p| p.image == *image_ref) {
                    if !pool_meta.available_pids.is_empty() {
                        ui::info(
                            "Using warm fragment:",
                            &format!("{} available", pool_meta.available_pids.len()),
                        );

                        match FragmentPool::load(image_ref) {
                            Ok(mut pool) => {
                                if let Some(pid) = pool.acquire_pid() {
                                    let paths = PhantomPaths::new();
                                    let pool_path = paths.fragment_pools().join(image_ref);
                                    match fork_from_daemon(
                                        pid,
                                        &final_command,
                                        &pool_path,
                                        hardware_profile.as_ref(),
                                    ) {
                                        Ok(exit_code) => {
                                            let _ = pool.release_pid(pid);
                                            if exit_code != 0 {
                                                ui::error_with_prefix(
                                                    "✗",
                                                    &format!(
                                                        "Command exited with code: {}",
                                                        exit_code
                                                    ),
                                                );
                                                std::process::exit(exit_code);
                                            }
                                            return Ok(());
                                        }
                                        Err(e) => {
                                            ui::warn(&format!(
                                                "Warm execution failed: {:?}, falling back to cold",
                                                e
                                            ));
                                            let _ = pool.release_pid(pid);
                                        }
                                    }
                                } else {
                                    ui::warn(
                                        "Fragment pool exhausted, falling back to cold execution",
                                    );
                                }
                            }
                            Err(e) => {
                                ui::warn(&format!(
                                    "Failed to load fragment pool: {:?}, falling back to cold",
                                    e
                                ));
                            }
                        }
                    } else {
                        ui::warn("No warm fragment pool found, falling back to cold execution");
                    }
                } else {
                    ui::info("No fragment pool for this image", "using cold execution");
                }
            }
        }

        // Use zygote pool for ultra-fast execution if --zygote flag is passed
        if zygote {
            use zygote_rs::{ZygoteCommand, ZygotePool};

            ui::info("Using zygote pool:", "for ultra-fast execution");

            // Try zygote pool execution
            match ZygotePool::new(4) {
                Ok(mut pool) => {
                    // Build zygote command with rootfs
                    let mut zygote_cmd = ZygoteCommand::new(
                        final_command
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "/bin/sh".to_string()),
                    )
                    .args(final_command.iter().skip(1).cloned().collect())
                    .cwd(
                        std::env::current_dir()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "/".to_string()),
                    )
                    .rootfs(rootfs_path.display().to_string())
                    .flags(0);

                    // Inherit environment from parent
                    for (key, value) in std::env::vars() {
                        zygote_cmd = zygote_cmd.env(&key, &value);
                    }

                    match pool.execute(zygote_cmd) {
                        Ok(exit_status) => {
                            let exit_code = if exit_status >= 0 { exit_status } else { -1 };
                            if exit_code != 0 {
                                ui::error_with_prefix(
                                    "✗",
                                    &format!("Command exited with code: {}", exit_code),
                                );
                                std::process::exit(exit_code);
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            ui::warn(&format!(
                                "Zygote execution failed: {:?}, falling back to normal execution",
                                e
                            ));
                            // Fall through to normal execution below
                        }
                    }
                }
                Err(e) => {
                    ui::warn(&format!(
                        "Zygote pool unavailable: {:?}, falling back to normal execution",
                        e
                    ));
                    // Fall through to normal execution below
                }
            }
        }

        let effective_network = if let Some(p) = app_config.get_profile(&profile_name) {
            if !p.network {
                ui::error_with_prefix(
                    "🔒",
                    &format!(
                        "network isolation enforced by profile '{}'",
                        profile_name.cyan()
                    ),
                );
            }
            p.network
        } else {
            network
        };

        // Initialize BPF-LSM security if supported
        log::debug!("Checking BPF-LSM support...");
        if BpfLsmSecurity::is_supported() {
            log::debug!("BPF-LSM supported, initializing...");
            match BpfLsmSecurity::new(BpfLsmConfig::default()) {
                Ok(_security) => {
                    ui::info("BPF-LSM:", "active (runtime syscall monitoring)");
                }
                Err(e) if graceful_security => {
                    // In graceful mode, log warning but continue
                    log::warn!(
                        "BPF-LSM initialization failed: {}, continuing without it",
                        e
                    );
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("BPF-LSM initialization failed: {}", e));
                }
            }
        } else {
            log::debug!("BPF-LSM not supported on this kernel");
        }

        let mut executor_builder = RootfsExecutor::new(rootfs_path)
            .with_network(effective_network)
            .with_user_ns(!root)
            .with_proot(proot)
            .with_overlay(overlay)
            .with_mounts(root)
            .with_runtime(runtime)
            .with_root(root);

        // Apply USER from image config if specified
        if let Some(user) = &effective_user {
            ui::info("Running as user:", user);
            executor_builder = executor_builder.with_user(user.clone());
        }

        if root {
            ui::error_bold("Running as ROOT (privileged)");
        } else {
            ui::success("Running as Rootless (unprivileged)");
        }

        let log_name = final_image.clone().unwrap_or_else(|| "unknown".to_string());
        let logs_dir = paths.logs();
        let _ = std::fs::create_dir_all(&logs_dir);
        let log_file = logs_dir.join(format!("{}.log", log_name.replace('/', "-")));

        let timestamp = chrono_lite_timestamp();
        let log_entry = format!("{} │ Fragment started: {:?}\n", timestamp, final_command);
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .and_then(|mut f| std::io::Write::write_all(&mut f, log_entry.as_bytes()));

        let exit_code = executor_builder.execute(&final_command).await?;

        let timestamp = chrono_lite_timestamp();
        let exit_entry = format!("{} │ Fragment exited with code: {}\n", timestamp, exit_code);
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .and_then(|mut f| std::io::Write::write_all(&mut f, exit_entry.as_bytes()));

        if exit_code != 0 {
            ui::error_with_prefix("✗", &format!("Command exited with code: {}", exit_code));
            std::process::exit(exit_code);
        }
    } else {
        // Direct command execution (no image)
        ui::success_with_prefix("Running command:", &format!("{:?}", final_command));

        // Show info about reduced security if continuing without privileges
        if graceful_security {
            let reqs = security_rs::check_privilege_requirements();
            if !reqs.required.is_empty() {
                print_continue_without_info(&reqs.required);
            }
        }

        // Use zygote pool for ultra-fast execution if --zygote flag is passed
        if zygote {
            use zygote_rs::{ZygoteCommand, ZygotePool};

            ui::info("Using zygote pool:", "for ultra-fast execution");

            // Try zygote pool execution
            match ZygotePool::new(4) {
                Ok(mut pool) => {
                    // Build zygote command
                    let mut zygote_cmd = ZygoteCommand::new(
                        final_command
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "/bin/sh".to_string()),
                    )
                    .args(final_command.iter().skip(1).cloned().collect())
                    .cwd(
                        std::env::current_dir()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "/".to_string()),
                    )
                    .flags(0);

                    // Inherit environment from parent
                    for (key, value) in std::env::vars() {
                        zygote_cmd = zygote_cmd.env(&key, &value);
                    }

                    match pool.execute(zygote_cmd) {
                        Ok(exit_status) => {
                            let exit_code = if exit_status >= 0 { exit_status } else { -1 };
                            if exit_code != 0 {
                                ui::error_with_prefix(
                                    "✗",
                                    &format!("Command exited with code: {}", exit_code),
                                );
                                std::process::exit(exit_code);
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            ui::warn(&format!(
                                "Zygote execution failed: {:?}, falling back to normal execution",
                                e
                            ));
                            // Fall through to normal execution below
                        }
                    }
                }
                Err(e) => {
                    ui::warn(&format!(
                        "Zygote pool unavailable: {:?}, falling back to normal execution",
                        e
                    ));
                    // Fall through to normal execution below
                }
            }
        }

        use execution_rs::{AdaptiveEngine, PerformanceProfile, RiskProfile};
        use security_rs::SecurityManager;
        let engine = AdaptiveEngine::new()?;

        let (mode, hardware) = if let Some(custom_profile) = app_config.get_profile(&profile_name) {
            let hw = custom_profile.to_hardware_profile();
            if let Some(ref h) = hw {
                if let Some(node) = h.numa_node {
                    ui::info("NUMA Node:", &node.to_string());
                }
            }
            (custom_profile.to_execution_mode(), hw)
        } else {
            let risk = if profile_name == "hardened" {
                RiskProfile {
                    network_access: false,
                    file_write: false,
                    privileged_ops: false,
                    untrusted_source: true,
                }
            } else {
                RiskProfile::default()
            };

            let perf = if profile_name == "direct" {
                PerformanceProfile {
                    latency_sensitive: true,
                    high_throughput: false,
                }
            } else {
                PerformanceProfile::default()
            };

            (engine.select_mode(&risk, &perf), None)
        };

        ui::info("Mode:", &format!("{:?}", mode));

        let cmd_str = final_command.join(" ");

        // Create security manager and apply policy with graceful mode if needed
        let mut security_manager = SecurityManager::new();
        if let Some(ref policy) = security_policy {
            let container_id = format!("phantom-{}", std::process::id());
            if let Err(e) =
                security_manager.apply_container_security(&container_id, policy, graceful_security)
            {
                if !graceful_security {
                    ui::error_with_prefix("✗ Security Error:", &format!("{:?}", e));
                    std::process::exit(1);
                }
                // In graceful mode, warnings were already logged
            }
        }

        match engine.spawn(mode, &cmd_str, hardware.as_ref(), security_policy.as_ref()) {
            Ok(pid) => ui::success_with_prefix("✓", &format!("Executed (PID: {})", pid)),
            Err(e) => {
                ui::error_with_prefix("✗ Error:", &format!("Execution failed: {:?}", e));
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

fn fork_from_daemon(
    _daemon_pid: u32,
    command: &[String],
    pool_path: &std::path::Path,
    hardware_profile: Option<&execution_rs::HardwareProfile>,
) -> anyhow::Result<i32> {
    use crate::daemon::{exec_in_daemon, ExecRequest};
    use std::path::Path;

    // Read socket path from file
    let socket_path_file = pool_path.join("socket.path");
    if !socket_path_file.exists() {
        anyhow::bail!("Socket path file not found - daemon may not be running");
    }

    let socket_path_str =
        std::fs::read_to_string(&socket_path_file).context("Failed to read socket path")?;
    let socket_path = Path::new(socket_path_str.trim());

    if !socket_path.exists() {
        anyhow::bail!("Socket file not found - daemon may have crashed");
    }

    // Build the execution request
    let request = ExecRequest {
        command: command.first().cloned().unwrap_or_default(),
        args: command.iter().skip(1).cloned().collect(),
        env: std::collections::HashMap::new(),
        cwd: None,
        hardware_profile: hardware_profile.cloned(),
    };

    // Send request via socket
    match exec_in_daemon(socket_path, &request) {
        Ok(response) => {
            if let Some(error) = response.error {
                anyhow::bail!("Daemon execution failed: {}", error);
            }
            Ok(response.exit_code)
        }
        Err(e) => {
            anyhow::bail!("Failed to communicate with daemon: {:?}", e);
        }
    }
}
