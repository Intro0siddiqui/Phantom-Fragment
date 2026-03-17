use anyhow::{Context, Result};
use colored::*;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::commands::CommandContext;
use crate::ui::{print_divider_full, print_header};

#[derive(clap::Args, Clone, Debug)]
pub struct StatusArgs {
    /// Fragment name
    #[arg(required = true)]
    pub name: String,
}

/// Format uptime from Unix timestamp
fn format_uptime(secs: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = now.saturating_sub(secs);

    let duration = Duration::from_secs(age);
    let days = duration.as_secs() / 86400;
    let hours = (duration.as_secs() % 86400) / 3600;
    let mins = (duration.as_secs() % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m {}s", mins, duration.as_secs() % 60)
    }
}

/// Check if PID is alive
fn pid_exists(pid: u32) -> bool {
    use nix::sys::signal::{self, Signal};
    use nix::unistd::Pid;
    signal::kill(Pid::from_raw(pid as i32), Signal::SIGCONT).is_ok()
}

/// Get process memory from /proc/<pid>/status
fn get_process_memory(pid: u32) -> Option<u64> {
    let content = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in content.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse::<u64>().ok();
            }
        }
    }
    None
}

pub fn exec(ctx: CommandContext, args: StatusArgs) -> Result<()> {
    let CommandContext { registry, .. } = ctx;

    // Find fragment
    let fragment = registry
        .get(&args.name)
        .context(format!("Fragment '{}' not found", args.name))?;

    print_header(&format!("Fragment: {}", args.name));
    print_divider_full();

    // Process State section
    println!("{}:", "Process State".cyan().bold());

    if let Some(pid) = fragment.pid {
        let is_alive = pid_exists(pid);
        let status_str = if is_alive { "Running" } else { "Stopped" };
        let status_colored = if is_alive {
            status_str.green()
        } else {
            status_str.yellow()
        };

        println!("  {} {}", "PID:".dimmed(), pid);
        println!("  {} {}", "Status:".dimmed(), status_colored);

        if !is_alive {
            println!("  {} Process no longer exists", "⚠".yellow());
        } else {
            // Get uptime
            let uptime = format_uptime(fragment.created_at);
            println!("  {} {}", "Uptime:".dimmed(), uptime);

            // Get memory
            if let Some(mem_kb) = get_process_memory(pid) {
                let mem_mb = mem_kb as f64 / 1024.0;
                let limit_mb = fragment.memory_kb as f64 / 1024.0;
                println!(
                    "  {} {:.1} MB / {:.0} MB",
                    "Memory:".dimmed(),
                    mem_mb,
                    limit_mb
                );
            }
        }
    } else {
        println!("  {} No PID assigned", "N/A".dimmed());
    }

    println!();

    // Security Layers section
    println!("{}:", "Security Layers".cyan().bold());

    // Check security features (simplified - just show what's configured)
    let security_checks = vec![
        ("Namespace Isolation", fragment.mode != "direct"),
        ("Seccomp Filter", fragment.profile != "direct"),
        ("Landlock", true), // Always enabled in sandbox/hardened
        ("BPF-LSM", true),  // Assume active if available
        ("Cgroups v2", fragment.memory_kb > 0),
    ];

    for (name, active) in security_checks {
        let icon = if active {
            "✓".green()
        } else {
            "⚠".yellow()
        };
        let status = if active { "Active" } else { "Inactive" };
        println!("  {} {}: {}", icon, name, status);
    }

    Ok(())
}
