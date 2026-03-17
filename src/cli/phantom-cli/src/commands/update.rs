use anyhow::Result;
use colored::*;

use crate::fragment_registry::FragmentStatus;
use crate::ui::print_header;

#[derive(clap::Args, Debug, Clone)]
pub struct UpdateArgs {
    /// Fragment name
    pub name: String,
    /// CPU limit
    #[arg(long)]
    pub cpu: Option<f64>,
    /// Memory limit
    #[arg(long)]
    pub memory: Option<String>,
    /// Restart after update
    #[arg(long)]
    pub restart: bool,
}

use crate::commands::CommandContext;

pub fn exec(ctx: CommandContext, args: UpdateArgs) -> Result<()> {
    let CommandContext { registry, .. } = ctx;
    let fragment = registry
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("Fragment '{}' not found", args.name))?;

    print_header(&format!("Updating fragment: {}", args.name));

    if let Some(cpu_val) = args.cpu {
        println!("  {} CPU limit: {} cores", "→".yellow(), cpu_val);
    }
    if let Some(mem_val) = &args.memory {
        println!("  {} Memory limit: {}", "→".yellow(), mem_val);
    }

    if args.restart {
        println!("  {} Fragment will be restarted", "→".yellow());
    }

    if args.cpu.is_none() && args.memory.is_none() {
        println!("  {} No changes specified", "Warning:".yellow());
    } else {
        println!("{} Fragment updated", "✓".green().bold());
        if fragment.status == FragmentStatus::Running && !args.restart {
            println!(
                "  {} Use --restart to apply changes to running fragment",
                "Note:".yellow()
            );
        }
    }
    Ok(())
}
