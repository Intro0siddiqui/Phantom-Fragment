use crate::commands::CommandContext;
use crate::fragment_registry::{FragmentRegistry, FragmentStatus};
use crate::ui::{dimmed, print_divider_full, print_header};
use colored::*;

#[derive(clap::Args, Clone, Debug)]
pub struct ListArgs {
    /// Show all fragments (including stopped)
    #[arg(short, long)]
    pub all: bool,

    /// Prune stale fragments (mark dead processes as Stopped)
    #[arg(long)]
    pub prune: bool,

    /// Validate all running fragments and update timestamps
    #[arg(long)]
    pub validate: bool,
}

pub fn exec(ctx: CommandContext, args: ListArgs) -> anyhow::Result<()> {
    let CommandContext { registry, .. } = ctx;
    print_header("Fragment Registry");
    print_divider_full();

    // Auto-prune stale fragments before displaying
    let pruned = registry.prune_stale()?;
    if !pruned.is_empty() {
        println!(
            "{} Auto-pruned {} stale fragment(s): {}",
            "[PRUNE]".yellow().bold(),
            pruned.len(),
            pruned.join(", ")
        );
        println!();
    }

    // Handle --validate flag (extra validation with timestamp update)
    if args.validate {
        let validated = registry.validate_all()?;
        println!(
            "{} Validated {} running fragment(s)",
            "[VALIDATE]".blue().bold(),
            validated
        );
        println!();
    }

    let fragments = if args.all {
        registry.list()
    } else {
        registry.list_by_status(FragmentStatus::Running)
    };

    // Check for stale fragments and show warning
    let stale_fragments = registry.get_stale_fragments();
    if !stale_fragments.is_empty() && !args.prune {
        println!(
            "{} {} stale fragment(s) detected (PID no longer exists). Use --prune to clean up.",
            "[WARNING]".yellow().bold(),
            stale_fragments.len()
        );
        for stale in &stale_fragments {
            println!(
                "  - {} (PID: {})",
                stale.name,
                stale.pid.map_or("N/A".to_string(), |p| p.to_string())
            );
        }
        println!();
    }

    if fragments.is_empty() {
        dimmed("No fragments found");
        return Ok(());
    }

    println!(
        "{:<20} {:<10} {:<10} {:<12} {:<10} {:<15} {:<12}",
        "NAME".bold(),
        "PID".bold(),
        "STATUS".bold(),
        "PROFILE".bold(),
        "MEMORY".bold(),
        "MODE".bold(),
        "STALE".bold()
    );
    print_divider_full();

    for fragment in fragments {
        let status_colored = match fragment.status {
            FragmentStatus::Running => "Running".green(),
            FragmentStatus::Stopped => "Stopped".yellow(),
            FragmentStatus::Failed => "Failed".red(),
        };

        let pid_str = fragment.pid.map_or("N/A".to_string(), |p| p.to_string());

        // Check if this fragment is stale (running status but dead PID)
        let is_stale = fragment.status == FragmentStatus::Running
            && fragment.pid.is_some()
            && !FragmentRegistry::validate_pid(fragment.pid.unwrap());

        let stale_indicator = if is_stale {
            "YES".red().bold()
        } else {
            "-".dimmed()
        };

        println!(
            "{:<20} {:<10} {:<10} {:<12} {:<10} {:<15} {:<12}",
            fragment.name.cyan(),
            pid_str,
            status_colored,
            fragment.profile,
            format!("{} KB", fragment.memory_kb),
            fragment.mode,
            stale_indicator
        );
    }

    println!();
    let total = registry.list().len();
    let running = registry.list_by_status(FragmentStatus::Running).len();
    let stale_count = stale_fragments.len();

    println!(
        "{} {} total, {} running, {} stale",
        "Summary:".dimmed(),
        total,
        running,
        stale_count
    );

    if stale_count > 0 && !args.prune {
        println!(
            "{} Run with {} to automatically mark stale fragments as Stopped",
            "Hint:".dimmed(),
            "--prune".cyan()
        );
    }

    Ok(())
}
