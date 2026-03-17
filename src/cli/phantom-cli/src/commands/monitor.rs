use crate::commands::CommandContext;
use crate::io_utils::tail_file;
use crate::ui::print_header;
use colored::*;

#[derive(clap::Args, Debug, Clone)]
pub struct MonitorArgs {
    /// Fragment name
    pub name: String,
    /// Show metrics
    #[arg(long)]
    pub metrics: bool,
    /// Show logs
    #[arg(long)]
    pub logs: bool,
    /// Follow output
    #[arg(short, long)]
    pub follow: bool,
}

pub fn exec(ctx: CommandContext<'_>, args: MonitorArgs) -> anyhow::Result<()> {
    let CommandContext {
        registry, paths, ..
    } = ctx;
    let fragment = registry
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("Fragment '{}' not found", args.name))?
        .clone();

    print_header(&format!("Monitoring fragment: {}", args.name));

    if args.metrics || (!args.metrics && !args.logs) {
        println!("{}:", "Metrics".yellow());
        println!(
            "  {:<20} {}",
            "Status:",
            format!("{:?}", fragment.status).green()
        );
        println!("  {:<20} {} KB", "Memory:", fragment.memory_kb);
        println!("  {:<20} {:?}", "PID:", fragment.pid);
        println!("  {:<20} {}", "Mode:", fragment.mode);
        println!();
    }

    if args.logs {
        let log_path = paths.logs().join(format!("{}.log", args.name));

        if log_path.exists() {
            println!("{}:", "Recent Logs".yellow());
            if let Ok(lines) = tail_file(log_path, 10) {
                for line in &lines {
                    println!("  {}", line.dimmed());
                }
            }
            if args.follow {
                println!();
                println!("{} Following logs (Ctrl+C to exit)...", "→".yellow());
            }
        } else {
            println!("{} No logs available", "Note:".yellow());
        }
    }
    Ok(())
}
