use anyhow::Result;
use colored::*;
use std::fs;
use std::path::Path;

use crate::ui::{print_divider_full, print_header};

#[derive(clap::Args, Debug, Clone, Default)]
pub struct HealthArgs {}

use crate::commands::CommandContext;

/// Check if a command/tool is available in PATH or a specific directory
fn command_exists(cmd: &str, extra_dir: Option<&Path>) -> bool {
    if which::which(cmd).is_ok() {
        return true;
    }

    if let Some(dir) = extra_dir {
        let path = dir.join(cmd);
        if path.exists() {
            return true;
        }
    }

    false
}

/// Get kernel version as string
fn get_kernel_version() -> String {
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        content.trim().to_string()
    } else {
        "unknown".to_string()
    }
}

/// Check cgroups version
fn get_cgroups_version() -> &'static str {
    if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        "v2"
    } else if Path::new("/sys/fs/cgroup/memory").exists() {
        "v1"
    } else {
        "unavailable"
    }
}

/// Check if BPF-LSM is available
fn check_ebpf_status() -> (&'static str, &'static str) {
    // Check kernel version (BPF-LSM requires 5.7+)
    let kernel = get_kernel_version();
    let kernel_parts: Vec<&str> = kernel.split('.').collect();

    if kernel_parts.len() >= 2 {
        let major: u32 = kernel_parts[0].parse().unwrap_or(0);
        let minor: u32 = kernel_parts[1].parse().unwrap_or(0);

        if major > 5 || (major == 5 && minor >= 7) {
            // Check if BPF is enabled
            if Path::new("/sys/fs/bpf").exists() {
                return ("Available", "✓");
            }
        }
    }

    ("Unavailable", "✗")
}

/// Check if Landlock is available
fn check_landlock_status() -> (&'static str, String) {
    // Landlock requires kernel 5.13+
    let kernel = get_kernel_version();
    let kernel_parts: Vec<&str> = kernel.split('.').collect();

    if kernel_parts.len() >= 2 {
        let major: u32 = kernel_parts[0].parse().unwrap_or(0);
        let minor: u32 = kernel_parts[1].parse().unwrap_or(0);

        if major > 5 || (major == 5 && minor >= 13) {
            return ("Enabled", kernel);
        }
    }

    ("Unavailable", kernel)
}

/// Check if seccomp is available in the kernel and current process status
fn check_seccomp_status() -> (&'static str, &'static str) {
    let kernel_supported = seccomp_rs::is_supported();

    // Check /proc/self/status for Seccomp field for current process status
    let process_status = if let Ok(content) = fs::read_to_string("/proc/self/status") {
        let mut status = "Disabled";
        for line in content.lines() {
            if line.starts_with("Seccomp:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    match parts[1] {
                        "0" => status = "Disabled",
                        "1" | "2" => status = "Enabled",
                        _ => status = "Unknown",
                    }
                }
            }
        }
        status
    } else {
        "Unknown"
    };

    match (kernel_supported, process_status) {
        (true, "Enabled") => ("Enabled (available)", "✓"),
        (true, "Disabled") => ("Available (not active for CLI)", "✓"),
        (true, status) => (status, "✓"),
        (false, _) => ("Unavailable (kernel support missing)", "✗"),
    }
}

pub fn exec(ctx: CommandContext, _args: HealthArgs) -> Result<()> {
    let CommandContext { paths, .. } = ctx;
    print_header("System Health");
    print_divider_full();

    // Overall status (simplified - always show healthy if we get here)
    println!("{} {}", "Status:".yellow(), "Healthy".green());

    // Security Stack section
    println!();
    println!("{}:", "Security Stack".cyan().bold());

    // eBPF status
    let (ebpf_status, ebpf_icon) = check_ebpf_status();
    println!("  {} eBPF: {}", ebpf_icon.green(), ebpf_status);

    // Seccomp status
    let (seccomp_status, seccomp_icon_raw) = check_seccomp_status();
    let seccomp_icon = if seccomp_icon_raw == "✓" {
        seccomp_icon_raw.green()
    } else {
        seccomp_icon_raw.red()
    };
    println!("  {} Seccomp: {}", seccomp_icon, seccomp_status);

    // Landlock status
    let (landlock_status, kernel) = check_landlock_status();
    let landlock_icon = if landlock_status == "Enabled" {
        "✓".green()
    } else {
        "⚠".yellow()
    };
    println!(
        "  {} Landlock: {} (kernel {})",
        landlock_icon, landlock_status, kernel
    );

    // Cgroups status
    let cgroups = get_cgroups_version();
    let cgroups_icon = if cgroups == "v2" {
        "✓".green()
    } else if cgroups == "v1" {
        "⚠".yellow()
    } else {
        "✗".red()
    };
    println!("  {} Cgroups: {}", cgroups_icon, cgroups);

    // Bubblewrap status
    let bwrap = if command_exists("bwrap", None) {
        ("Available", "✓".green())
    } else {
        ("Unavailable", "✗".red())
    };
    println!("  {} Bubblewrap: {}", bwrap.1, bwrap.0);

    // Proot status (fallback)
    let bin_dir = paths.bin();
    let proot = if command_exists("proot", Some(&bin_dir)) {
        if !command_exists("bwrap", None) {
            ("Available (fallback)", "⚠".yellow())
        } else {
            ("Available", "✓".green())
        }
    } else {
        ("Unavailable", "✗".red())
    };
    println!("  {} Proot: {}", proot.1, proot.0);

    Ok(())
}
