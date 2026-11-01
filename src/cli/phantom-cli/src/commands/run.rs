use crate::commands::CommandContext;
use crate::config::Config;
use crate::config::PhantomPaths;
use crate::io_utils::{chrono_lite_timestamp, parse_run_args};
use crate::permission_prompt::{self, print_continue_without_info};
use crate::ui;
use anyhow::Context;
use bpf_lsm_rs::BpfLsmSecurity;
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
    ///
    /// `None` means the caller did not choose one. Cold execution then uses
    /// `sandbox`, but the warm path lets the pool's bound profile decide.
    #[arg(short, long)]
    pub profile: Option<String>,

    /// Run as WebAssembly module
    #[arg(long, help = "Run as WebAssembly module")]
    pub wasm: bool,

    /// Use warm fragment pool (mother fragment) for faster startup (beta/experimental)
    #[arg(
        long,
        help = "Use warm fragment pool for faster startup (beta/experimental - has limitations)"
    )]
    pub warm: bool,

    /// Execution engine for image runs
    ///
    /// `auto` uses the native sandbox and falls back to bubblewrap only when the
    /// host cannot provide the namespace primitives. A profile that requires
    /// confinement never falls back.
    #[arg(long, value_enum, default_value_t = crate::engine::EngineChoice::Auto)]
    pub engine: crate::engine::EngineChoice,

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
            permission_prompt::reexec_with_sudo()?;
            unreachable!("exec replaces the process");
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
        engine,
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

    // Distinguish "no profile chosen" from "sandbox chosen explicitly": the
    // warm pool already carries a bound profile, and an explicit request that
    // disagrees with it must fail instead of falling back to another engine.
    let requested_profile = profile.clone();

    let profile_name = if wasm {
        "wasm".to_string()
    } else if let Some(ref img) = final_image {
        if img.ends_with(".wasm") {
            "wasm".to_string()
        } else {
            profile.unwrap_or_else(|| "sandbox".to_string())
        }
    } else if !final_command.is_empty() && final_command[0].ends_with(".wasm") {
        "wasm".to_string()
    } else {
        profile.unwrap_or_else(|| "sandbox".to_string())
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

        // Warm first: a warm fragment already owns its rootfs, so resolving the
        // image (which builds a registry client and opens the image store)
        // would be pure latency. The cold path below does that work only when a
        // warm fragment cannot serve the request.
        if warm {
            ui::warn_bold("Warm fragments are a beta feature: one command per fragment at a time");
            use crate::fragment_pool::FragmentPool;
            if let Ok(pools) = FragmentPool::list() {
                if let Some(pool_meta) = pools.iter().find(|p| p.image == *image_ref) {
                    let pool_rootfs = pool_meta.rootfs_path.clone();
                    // Load even when no slot is currently free: `acquire_pid`
                    // reclaims slots whose client died before releasing (e.g. a
                    // SIGKILLed `run --warm`). Only genuine exhaustion falls
                    // back to cold.
                    {
                        match FragmentPool::load(image_ref) {
                            Ok(mut pool) => {
                                let mut acquired = pool.acquire_pid();
                                if acquired.is_none() {
                                    // A dead daemon's slot is purged, never replaced,
                                    // so a pool that loses its daemons (crash, reboot)
                                    // would silently run cold forever. Rebuild one slot
                                    // and retry once; the first run pays the build, the
                                    // rest are warm again.
                                    if let Some(slot) = pool.missing_slots().first().copied() {
                                        match crate::commands::warm::refill_slot(&pool, slot) {
                                            Ok(pid) => {
                                                let _ = pool.register_pid(pid);
                                                acquired = pool.acquire_pid();
                                            }
                                            Err(e) => ui::warn(&format!(
                                                "Failed to rebuild warm fragment: {:#}",
                                                e
                                            )),
                                        }
                                    }
                                }
                                if let Some(pid) = acquired {
                                    ui::info(
                                        "Using warm fragment:",
                                        &format!(
                                            "{} available",
                                            pool.get_pool().available_pids.len()
                                        ),
                                    );
                                    match pool.socket_path_for_pid(pid) {
                                        Some(socket_path) => {
                                            ui::info("Rootfs:", &pool_rootfs);
                                            match fork_from_daemon(
                                                pid,
                                                &final_command,
                                                &socket_path,
                                                hardware_profile.as_ref(),
                                                requested_profile.as_deref(),
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
                                                    let message = format!("{:#}", e);
                                                    if message.contains(
                                                        crate::daemon::PROFILE_MISMATCH_MARKER,
                                                    ) {
                                                        // The caller named a profile the pool
                                                        // was not built with. Do not purge a
                                                        // healthy daemon and do not answer the
                                                        // request through a different engine.
                                                        // Return the slot so the pool stays
                                                        // usable for matching requests.
                                                        let _ = pool.release_pid(pid);
                                                        ui::error_with_prefix("✗", &message);
                                                        return Err(anyhow::anyhow!(
                                                            "warm pool for '{}' uses a different security profile; \
                                                             create a pool with `phantom warm create {} -p {}` \
                                                             or omit --profile",
                                                            image_ref,
                                                            image_ref,
                                                            profile_name
                                                        ));
                                                    }
                                                    ui::warn(&format!(
                                                        "Warm execution failed: {:?}, falling back to cold",
                                                        e
                                                    ));
                                                    let _ = pool.purge_pid(pid);
                                                }
                                            }
                                        }
                                        None => {
                                            ui::warn(&format!(
                                                "No socket found for warm daemon PID {}, purging and falling back to cold",
                                                pid
                                            ));
                                            let _ = pool.purge_pid(pid);
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
                    }
                } else {
                    ui::info("No fragment pool for this image", "using cold execution");
                }
            }
        }

        use image_puller::{ImagePuller, PullConfig, RootfsExecutor};

        let config = PullConfig { verify };
        let puller = ImagePuller::with_config(config).context("Failed to create ImagePuller")?;

        let rootfs_path = puller.get_rootfs(image_ref, pull).await?;

        ui::info("Rootfs:", &rootfs_path.display().to_string());

        // Use zygote pool for ultra-fast execution if --zygote flag is passed
        if zygote {
            use zygote_rs::{ZygoteCommand, ZygotePool};

            ui::info("Using zygote pool:", "for ultra-fast execution");

            // The zygote child cannot apply seccomp/landlock/capabilities, and
            // applying them here would restrict the CLI itself. Skip the pool
            // and use the normal fork-exec path when a policy is requested.
            if security_policy.is_some() {
                ui::warn(
                    "Security policy requested: zygote cannot apply seccomp/landlock, using normal execution",
                );
            } else {
                // The zygote child uses execve, not execvp: a bare command
                // name would fail with 126 instead of being looked up in PATH.
                let program = final_command
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "/bin/sh".to_string());
                match resolve_in_rootfs(&rootfs_path, &program) {
                    Some(exec_path) => {
                        // Try zygote pool execution
                        match ZygotePool::new(4) {
                            Ok(mut pool) => {
                                // Build zygote command with rootfs
                                let mut zygote_cmd = ZygoteCommand::new(exec_path)
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
                                    Ok(status) => {
                                        // `execute` returns a raw wait status; decode it
                                        // or exit(42) would surface as 10752.
                                        let exit_code = zygote_rs::decode_exit_status(status);
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
                    None => {
                        ui::warn(&format!(
                            "Command '{}' not found in fragment PATH, falling back to normal execution",
                            program
                        ));
                        // Fall through to normal execution below
                    }
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

        // BPF-LSM is not attached to image fragments yet. Creating the handle
        // here only proves the kernel supports it; nothing would be enforced,
        // so do not claim otherwise. Seccomp, Landlock and the capability drop
        // in the execution engine are what actually confine the command.
        log::debug!(
            "BPF-LSM supported: {} (not attached to image fragments)",
            BpfLsmSecurity::is_supported()
        );

        let mut executor_builder = RootfsExecutor::new(rootfs_path.clone())
            .with_network(effective_network)
            .with_user_ns(!root)
            .with_proot(proot)
            .with_overlay(overlay)
            .with_mounts(root)
            .with_runtime(runtime.clone())
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

        // Engine selection: the native sandbox is the default, bubblewrap is a
        // classified fallback. Flags that need a different mechanism (proot,
        // overlayfs, an OCI runtime, real root, wasm) always use the bubblewrap
        // executor, because the native engine does not implement them.
        let native_blocked = proot || overlay || runtime.is_some() || root || wasm;
        if native_blocked && engine == crate::engine::EngineChoice::Native {
            anyhow::bail!(
                "--engine native cannot be combined with --proot, --overlay, --runtime, --root or --wasm"
            );
        }
        let choice = if native_blocked {
            crate::engine::EngineChoice::Bwrap
        } else {
            engine
        };

        let policy = crate::engine::sandbox::resolve_child_policy(&profile_name)?;
        // A profile that asks for confinement the bubblewrap path does not
        // apply must never be answered by the fallback.
        let strict_profile =
            profile_name == "hardened" || !policy.file_write || policy.seccomp != "default";

        let (inside_uid, inside_gid) = match &effective_user {
            Some(user) => match image_puller::resolve_uid_gid(&rootfs_path, user) {
                Some(ids) => ids,
                None => {
                    ui::warn(&format!(
                        "Cannot resolve user '{}' in the image's /etc/passwd or /etc/group; \
                         running as the invoking user",
                        user
                    ));
                    (
                        nix::unistd::getuid().as_raw(),
                        nix::unistd::getgid().as_raw(),
                    )
                }
            },
            None => (0, 0),
        };

        let mut env: Vec<(String, String)> = std::env::vars()
            .filter(|(key, _)| key != crate::daemon::PROFILE_ENV && key != "PATH")
            .collect();
        env.push((
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ));

        // The image's own resolv.conf is kept; with network access a file with
        // public resolvers is bound over it so DNS works without mutating the
        // rootfs (the bubblewrap path rewrites the file instead).
        let resolv_conf = if effective_network {
            let path =
                std::env::temp_dir().join(format!("phantom-resolv-{}.conf", std::process::id()));
            match crate::engine::native::write_resolv_conf(&path) {
                Ok(()) => Some(path),
                Err(e) => {
                    ui::warn(&format!("Could not write DNS configuration: {}", e));
                    None
                }
            }
        } else {
            None
        };

        let exit_code = if choice == crate::engine::EngineChoice::Bwrap {
            executor_builder.execute(&final_command).await?
        } else {
            let spec = crate::engine::native::NativeSpec {
                rootfs: rootfs_path.clone(),
                command: final_command.clone(),
                network: effective_network,
                inside_uid,
                inside_gid,
                policy,
                env,
                resolv_conf: resolv_conf.clone(),
            };
            ui::info("Engine:", "native");
            match crate::engine::native::execute(&spec) {
                Ok(code) => code,
                Err(crate::engine::native::NativeFailure::Unsupported(reason))
                    if choice == crate::engine::EngineChoice::Auto && !strict_profile =>
                {
                    ui::warn(&format!(
                        "Native engine unavailable ({}); falling back to bubblewrap, which applies \
                         namespace isolation only (no seccomp, Landlock or capability drop)",
                        reason
                    ));
                    executor_builder.execute(&final_command).await?
                }
                Err(failure) => {
                    anyhow::bail!("native engine: {}", failure);
                }
            }
        };

        if let Some(path) = &resolv_conf {
            let _ = std::fs::remove_file(path);
        }

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
                    // The zygote child uses execve, not execvp: a bare command
                    // name would fail with 126 instead of being looked up in PATH.
                    let program = final_command
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "/bin/sh".to_string());
                    let mut zygote_cmd = ZygoteCommand::new(resolve_on_host(&program))
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
                        Ok(status) => {
                            // `execute` returns a raw wait status; decode it
                            // or exit(42) would surface as 10752.
                            let exit_code = zygote_rs::decode_exit_status(status);
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

/// Directories searched for a bare command name, matching a typical PATH.
const PATH_DIRS: [&str; 4] = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"];

/// Resolve a bare command name to an absolute path *inside* `rootfs`.
///
/// The cold path execs with `execvp`, which searches `PATH` after the chroot.
/// The zygote child execs with `execve`, so `phantom run --zygote alpine echo`
/// would otherwise fail with 126 instead of finding `/bin/echo`.
fn resolve_in_rootfs(rootfs: &std::path::Path, program: &str) -> Option<String> {
    if program.contains('/') {
        return Some(program.to_string());
    }

    PATH_DIRS
        .iter()
        .map(|dir| format!("{}/{}", dir, program))
        // `exists()` follows symlinks, and rootfs binaries are usually absolute
        // symlinks (`/bin/echo -> /bin/busybox`) that only resolve after the
        // chroot. lstat the link itself instead.
        .find(|candidate| {
            rootfs
                .join(candidate.trim_start_matches('/'))
                .symlink_metadata()
                .is_ok()
        })
}

/// Resolve a bare command name against the host filesystem.
///
/// Used by the zygote path that runs without a fragment rootfs. Falls back to
/// the original name so the failure is reported by `execve` as before.
fn resolve_on_host(program: &str) -> String {
    if program.contains('/') {
        return program.to_string();
    }

    PATH_DIRS
        .iter()
        .map(|dir| format!("{}/{}", dir, program))
        .find(|candidate| std::path::Path::new(candidate).exists())
        .unwrap_or_else(|| program.to_string())
}

fn fork_from_daemon(
    _daemon_pid: u32,
    command: &[String],
    socket_path: &std::path::Path,
    hardware_profile: Option<&execution_rs::HardwareProfile>,
    profile_name: Option<&str>,
) -> anyhow::Result<i32> {
    use crate::daemon::{exec_in_daemon, ExecRequest, PROFILE_ENV};

    if !socket_path.exists() {
        anyhow::bail!("Socket file not found - daemon may have crashed");
    }

    // The v1 wire format has no profile field, so an explicitly chosen profile
    // name rides in the env map under a reserved key. When the caller did not
    // choose one, send nothing and let the pool's bound profile apply.
    let mut env = std::collections::HashMap::new();
    if let Some(name) = profile_name {
        env.insert(PROFILE_ENV.to_string(), name.to_string());
    }

    // Build the execution request
    let request = ExecRequest {
        command: command.first().cloned().unwrap_or_default(),
        args: command.iter().skip(1).cloned().collect(),
        env,
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
