use crate::commands::CommandContext;
use crate::fragment_registry::FragmentStatus;
use crate::ui::print_header;
use colored::*;

#[derive(clap::Args, Debug, Clone)]
pub struct StopArgs {
    /// Fragment name
    pub name: String,
    /// Force stop (SIGKILL)
    #[arg(short, long)]
    pub force: bool,
    /// Shutdown timeout
    #[arg(long, default_value = "10s")]
    pub timeout: String,
}

pub fn exec(ctx: CommandContext<'_>, args: StopArgs) -> anyhow::Result<()> {
    let CommandContext { registry, .. } = ctx;
    let fragment = registry
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("Fragment '{}' not found", args.name))?
        .clone();

    print_header(&format!("Stopping fragment: {}", args.name));

    if fragment.status != FragmentStatus::Running {
        println!("  {} Fragment is not running", "Note:".yellow());
        return Ok(());
    }

    if let Some(pid) = fragment.pid {
        println!("  {} Sending SIGTERM to PID {}", "→".yellow(), pid);

        if args.force {
            println!("  {} Force stop (SIGKILL)", "→".yellow());
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        } else {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
    }

    registry.update_status(&args.name, FragmentStatus::Stopped)?;
    println!(
        "{} Fragment stopped (timeout: {})",
        "✓".green().bold(),
        args.timeout
    );
    Ok(())
}
