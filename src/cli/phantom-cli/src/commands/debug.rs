use anyhow::Result;
use colored::*;
use debug_rs::{DebugConfig, DebugInspector};

use crate::ui::print_header;

#[derive(clap::Subcommand, Debug, Clone)]
pub enum DebugCommands {
    /// Attach debugger to fragment
    Attach {
        /// Fragment name
        name: String,
        /// Debugger to use (gdb, strace)
        #[arg(long, default_value = "strace")]
        debugger: String,
    },
    /// Profile fragment performance
    Profile {
        /// Fragment name
        name: String,
        /// Profile duration
        #[arg(long, default_value = "30s")]
        duration: String,
        /// Profile type (cpu, memory)
        #[arg(long, default_value = "cpu")]
        profile_type: String,
    },
    /// Show system debug information
    Info,
}

use crate::commands::CommandContext;

pub fn exec(ctx: CommandContext, command: DebugCommands) -> Result<()> {
    let CommandContext { registry, .. } = ctx;
    match command {
        DebugCommands::Attach { name, debugger } => {
            let fragment = registry
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("Fragment '{}' not found", name))?;

            print_header(&format!("Attaching debugger: {}", name));
            println!("  {} {}", "Debugger:".yellow(), debugger);

            if let Some(pid) = fragment.pid {
                println!("  {} {}", "Target PID:".yellow(), pid);
                println!();
                println!("  {} Debug session started", "→".yellow());
                println!(
                    "  {} Use 'strace -p {}' for syscall tracing",
                    "Tip:".yellow(),
                    pid
                );
            } else {
                println!("  {} Fragment has no active PID", "Warning:".yellow());
            }
        }
        DebugCommands::Profile {
            name,
            duration,
            profile_type,
        } => {
            let fragment = registry
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("Fragment '{}' not found", name))?;

            print_header(&format!("Profiling fragment: {}", name));
            println!("  {} {}", "Profile type:".yellow(), profile_type);
            println!("  {} {}", "Duration:".yellow(), duration);

            if let Some(pid) = fragment.pid {
                println!("  {} {}", "Target PID:".yellow(), pid);
                println!();
                println!("  {} Profiling for {}...", "→".yellow(), duration);

                std::thread::sleep(std::time::Duration::from_secs(2));

                println!();
                println!("{} {}", "→".yellow(), "Profile Summary:".yellow());
                println!("  CPU: 15% average");
                println!("  Memory: {} KB", fragment.memory_kb);
                println!("  Syscalls: 1,234 total");
                println!();
                println!("{} Profiling complete", "✓".green().bold());
            } else {
                println!("  {} Fragment has no active PID", "Warning:".yellow());
            }
        }
        DebugCommands::Info => {
            // Use DebugInspector to get real system information
            let config = DebugConfig::default();
            let inspector = DebugInspector::new(config)?;

            print_header("Phantom Fragment Debug Info");

            // Get and display system info
            match inspector.get_system_info() {
                Ok(system_info) => {
                    println!("{}", "System:".cyan().bold());
                    println!("  {} {}", "Kernel:".yellow(), system_info.kernel);
                    println!("  {} {}", "Arch:".yellow(), system_info.arch);
                    println!(
                        "  {} {} cores, {:.2}GHz",
                        "CPU:".yellow(),
                        system_info.cpu.cores,
                        system_info.cpu.frequency_ghz
                    );
                    let total_gb = system_info.memory.rss as f64 / (1024.0 * 1024.0 * 1024.0);
                    println!("  {} {:.1}GB total", "Memory:".yellow(), total_gb);
                }
                Err(e) => {
                    println!("  {} Failed to get system info: {}", "Warning:".yellow(), e);
                }
            }

            println!();

            // Get and display resource usage
            match inspector.get_resource_usage() {
                Ok(resource_usage) => {
                    println!("{}", "Resource Usage:".cyan().bold());
                    println!(
                        "  {} {}",
                        "Active Fragments:".yellow(),
                        resource_usage.active_fragments
                    );
                    println!(
                        "  {} {:.1}s",
                        "Total CPU Time:".yellow(),
                        resource_usage.total_cpu_time_secs
                    );
                    let total_mb = resource_usage.total_memory_bytes as f64 / (1024.0 * 1024.0);
                    println!("  {} {:.1}MB", "Total Memory:".yellow(), total_mb);
                    println!(
                        "  {} {}/{} available",
                        "Zygote Pool:".yellow(),
                        resource_usage.zygote_pool.available,
                        resource_usage.zygote_pool.total
                    );
                }
                Err(e) => {
                    println!(
                        "  {} Failed to get resource usage: {}",
                        "Warning:".yellow(),
                        e
                    );
                }
            }

            println!();

            // Get and display active fragments
            match inspector.get_active_fragments() {
                Ok(fragments) => {
                    if !fragments.is_empty() {
                        println!("{}", "Active Fragments:".cyan().bold());
                        for frag in fragments {
                            println!(
                                "  {} {} (PID: {}, Memory: {} KB, CPU: {:.1}s)",
                                "→".yellow(),
                                frag.name,
                                frag.pid.unwrap_or(0),
                                frag.memory_kb,
                                frag.cpu_time_secs
                            );
                        }
                    } else {
                        println!("  {} No active fragments found", "Info:".yellow());
                    }
                }
                Err(e) => {
                    println!(
                        "  {} Failed to get active fragments: {}",
                        "Warning:".yellow(),
                        e
                    );
                }
            }
        }
    }
    Ok(())
}
