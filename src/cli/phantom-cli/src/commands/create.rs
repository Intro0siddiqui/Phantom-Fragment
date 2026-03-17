use crate::commands::CommandContext;
use crate::fragment_registry::{FragmentInfo, FragmentStatus};
use crate::ui;
use colored::Colorize;
use execution_rs::{AdaptiveEngine, PerformanceProfile, RiskProfile};
use log::{info, warn};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use task_analyzer_rs::{Command as TaskCommand, Component, TaskAnalyzer};
use tokio::time::sleep;

/// Validate if a spawned PID is still alive by sending SIGCONT signal
///
/// Uses `nix::sys::signal::kill()` with `Signal::SIGCONT` to check process existence
/// without affecting the process state.
///
/// # Arguments
/// * `pid` - The process ID to validate
///
/// # Returns
/// * `true` - Process exists and is alive
/// * `false` - Process does not exist (ESRCH error)
fn validate_spawned_pid(pid: i32) -> bool {
    match signal::kill(Pid::from_raw(pid), Signal::SIGCONT) {
        Ok(_) => true,
        Err(nix::errno::Errno::ESRCH) => false, // Process doesn't exist
        Err(_) => true, // Other errors mean process exists but we may not have permission
    }
}

/// Validate spawned PID with retry logic and exponential backoff
///
/// Attempts to validate the PID up to 3 times with delays of 50ms, 100ms, 200ms.
/// This handles race conditions where the process may not be fully initialized.
///
/// # Arguments
/// * `pid` - The process ID to validate
///
/// # Returns
/// * `true` - Process validated successfully
/// * `false` - Process validation failed after all retries
async fn validate_spawned_pid_with_retry(pid: i32) -> bool {
    let delays = [50, 100, 200]; // milliseconds for exponential backoff
    let max_attempts = delays.len();

    for (attempt, &delay_ms) in delays.iter().enumerate() {
        if validate_spawned_pid(pid) {
            return true;
        }

        if attempt < max_attempts - 1 {
            warn!(
                "PID {} validation attempt {} failed, retrying in {}ms...",
                pid,
                attempt + 1,
                delay_ms
            );
            sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    warn!(
        "PID {} validation failed after {} attempts",
        pid, max_attempts
    );
    false
}

/// Kill a process by PID, ignoring errors if process doesn't exist
///
/// # Arguments
/// * `pid` - The process ID to kill
fn kill_process(pid: i32) {
    let pid_raw = Pid::from_raw(pid);
    match signal::kill(pid_raw, Signal::SIGKILL) {
        Ok(_) => info!("Killed orphaned process {}", pid),
        Err(nix::errno::Errno::ESRCH) => {
            // Process already gone, nothing to do
        }
        Err(e) => warn!("Failed to kill process {}: {}", pid, e),
    }
}

#[derive(clap::Args, Debug, Clone)]
pub struct CreateArgs {
    /// Fragment name
    #[arg(short, long, default_value = "myfragment")]
    pub name: String,

    /// Security profile (direct, sandbox, hardened, wasm)
    #[arg(short, long, default_value = "sandbox")]
    pub profile: String,

    /// Persist fragment to storage
    #[arg(long, default_value_t = true)]
    pub persist: bool,

    /// Network configuration (e.g., bridge, host, none)
    #[arg(long)]
    pub network: Option<String>,
}

pub async fn exec(ctx: CommandContext<'_>, args: CreateArgs) -> anyhow::Result<()> {
    let CommandContext {
        config,
        paths,
        registry,
    } = ctx;
    let CreateArgs {
        name,
        profile,
        persist,
        network,
    } = args;

    println!("{} {}", "Creating fragment:".green().bold(), name.cyan());

    if let Some(ref net_config) = network {
        println!("  {} {}", "Network:".yellow(), net_config.cyan());
    }

    if registry.exists(&name) {
        ui::error_with_prefix("Error:", &format!("Fragment '{}' already exists", name));
        std::process::exit(1);
    }

    let analyzer = TaskAnalyzer::new();
    let command = TaskCommand {
        executable: name.clone(),
        args: vec![],
        env: vec![],
        working_dir: None,
    };
    let req_components = analyzer.analyze(&command);
    println!(
        "  {} {} components ({})",
        "Components:".yellow(),
        req_components.components.len(),
        req_components.reason.dimmed()
    );

    let needs_network = req_components.components.contains(&Component::TcpStack);
    let needs_file_io = req_components.components.contains(&Component::FileIo);

    let engine = AdaptiveEngine::new();
    let (mode, _risk, _perf, hardware) = if let Some(custom_profile) = config.get_profile(&profile)
    {
        (
            custom_profile.to_execution_mode(),
            custom_profile.to_risk_profile(),
            custom_profile.to_performance_profile(),
            custom_profile.to_hardware_profile(),
        )
    } else {
        let risk = RiskProfile {
            network_access: needs_network,
            file_write: needs_file_io,
            privileged_ops: false,
            untrusted_source: profile == "hardened",
        };
        let perf = PerformanceProfile {
            latency_sensitive: profile == "direct",
            high_throughput: false,
        };
        (engine.select_mode(&risk, &perf), risk, perf, None)
    };
    println!("  {} {:?}", "Mode:".yellow(), mode);

    let mem_estimate = analyzer.estimate_memory(&req_components);
    println!("  {} {} KB", "Memory:".yellow(), mem_estimate / 1024);

    let init_command = "sleep 999999999";
    match engine.spawn(mode, init_command, hardware.as_ref(), None) {
        Ok(pid) => {
            println!("{} PID {}", "✓ Spawned:".green().bold(), pid);

            // Validate the spawned PID with retry logic before registering
            // Using await directly here since exec is now async
            let validation_result = validate_spawned_pid_with_retry(pid).await;

            if !validation_result {
                // Validation failed - clean up the orphaned process
                kill_process(pid);
                ui::error_with_prefix(
                    "✗ Error:",
                    &format!(
                        "Process validation failed for PID {}. The process may have exited unexpectedly.",
                        pid
                    ),
                );
                std::process::exit(1);
            }

            info!("PID {} validated successfully after spawn", pid);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let fragment_info = FragmentInfo {
                name: name.clone(),
                profile: profile.clone(),
                pid: Some(pid as u32),
                created_at: now,
                status: FragmentStatus::Running,
                components: req_components
                    .components
                    .iter()
                    .map(|c| format!("{:?}", c))
                    .collect(),
                memory_kb: (mem_estimate / 1024) as u64,
                cpu_count: hardware.as_ref().map(|h| h.cpu_count as u32),
                mode: format!("{:?}", mode),
                last_validated: Some(now),
                image: None,
            };

            registry.register(fragment_info)?;
            ui::success("Registered in fragment registry");

            if persist {
                let storage_dir = paths.storage();

                if let Err(e) = std::fs::create_dir_all(&storage_dir) {
                    ui::warn(&format!("Failed to create storage dir: {}", e));
                } else {
                    let state = serde_json::json!({
                        "name": name,
                        "pid": pid,
                        "profile": profile,
                    });
                    let state_path = storage_dir.join(format!("{}.json", name));
                    if let Err(e) = std::fs::write(&state_path, state.to_string()) {
                        ui::warn(&format!("Failed to persist to storage: {}", e));
                    } else {
                        ui::success("Persisted to storage");
                    }
                }
            }
        }
        Err(e) => {
            ui::error_with_prefix("✗ Error:", &format!("Failed to spawn: {:?}", e));
            std::process::exit(1);
        }
    }

    Ok(())
}
