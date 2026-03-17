use crate::commands::CommandContext;
use crate::fragment_registry::FragmentStatus;
use crate::ui::print_header;
use colored::*;
use execution_rs::{AdaptiveEngine, ExecutionMode, PerformanceProfile, RiskProfile};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(clap::Args, Debug, Clone)]
pub struct RestartArgs {
    /// Fragment name
    pub name: String,
    /// Shutdown timeout
    #[arg(long, default_value = "10s")]
    pub timeout: String,
    /// Force restart
    #[arg(short, long)]
    pub force: bool,
}

pub fn exec(ctx: CommandContext<'_>, args: RestartArgs) -> anyhow::Result<()> {
    let CommandContext {
        config, registry, ..
    } = ctx;
    let fragment = registry
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("Fragment '{}' not found", args.name))?
        .clone();

    print_header(&format!("Restarting fragment: {}", args.name));

    let was_running = fragment.status == FragmentStatus::Running;

    if was_running {
        println!("  {} Stopping (timeout: {})...", "→".yellow(), args.timeout);
        if args.force {
            println!("  {} Force stop enabled", "→".yellow());
        }

        if let Some(pid) = fragment.pid {
            let signal = if args.force {
                Signal::SIGKILL
            } else {
                Signal::SIGTERM
            };
            let _ = signal::kill(Pid::from_raw(pid as i32), signal);
        }
    } else {
        println!("  {} Fragment is not running, starting...", "→".yellow());
    }

    let _mode = parse_execution_mode(&fragment.mode);
    let profile = &fragment.profile;

    let (exec_mode, hardware) = if let Some(custom_profile) = config.get_profile(profile) {
        (
            custom_profile.to_execution_mode(),
            custom_profile.to_hardware_profile(),
        )
    } else {
        let risk = RiskProfile::default();
        let perf = PerformanceProfile::default();
        let engine = AdaptiveEngine::new()?;
        (engine.select_mode(&risk, &perf), None)
    };

    let init_command = "sleep 999999999";
    match AdaptiveEngine::new()?.spawn(exec_mode, init_command, hardware.as_ref(), None) {
        Ok(new_pid) => {
            println!("{} New PID {}", "✓ Spawned:".green().bold(), new_pid);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            registry.update_status(&args.name, FragmentStatus::Running)?;
            registry.update_pid(&args.name, new_pid as u32)?;
            registry.update_validated(&args.name, now)?;

            println!("{} Fragment restarted", "✓".green().bold());
        }
        Err(e) => {
            println!("{} Failed to spawn: {:?}", "✗".red().bold(), e);
            registry.update_status(&args.name, FragmentStatus::Failed)?;
        }
    }

    Ok(())
}

fn parse_execution_mode(mode_str: &str) -> ExecutionMode {
    match mode_str.trim() {
        "Sandbox" => ExecutionMode::Sandbox,
        "Hardened" => ExecutionMode::Hardened,
        "Wasm" => ExecutionMode::Wasm,
        _ => ExecutionMode::Sandbox,
    }
}
