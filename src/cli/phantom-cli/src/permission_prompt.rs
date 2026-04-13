//! Unified Security Permission Handling
//!
//! This module provides centralized privilege checking and prompting for
//! security features that require elevated privileges (CAP_SYS_ADMIN).
//!
//! Previously, BPF-LSM and cgroups each had their own prompts, causing users
//! to see multiple prompts for the same underlying permission issue.
//!
//! The unified approach:
//! 1. Check ALL security features at once
//! 2. Show ONE prompt if any need elevated privileges
//! 3. Apply ALL features after getting privileges (or gracefully degrade)

use colored::Colorize;
use security_rs::{PrivilegeChoice, PrivilegeRequirements, SecurityFeature};
use std::io::{self, Write};

/// Check if running in an interactive terminal
fn is_interactive() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// Show unified permission prompt for all security features that need elevation
///
/// Returns the user's choice: UseSudo, ContinueWithout, or Abort
pub fn show_unified_privilege_prompt(requirements: &PrivilegeRequirements) -> PrivilegeChoice {
    if !is_interactive() {
        // Non-interactive mode: continue without elevated privileges
        log::warn!(
            "Non-interactive mode: continuing without elevated privileges. \
             Some security features will be disabled."
        );
        return PrivilegeChoice::ContinueWithout;
    }

    println!();
    println!("{}", "⚠️  Elevated Privileges Required".yellow().bold());
    println!();
    println!("   The following security features require elevated privileges (CAP_SYS_ADMIN):");
    println!();

    for feature in &requirements.required {
        match feature {
            SecurityFeature::BpfLsm => {
                println!("   • BPF-LSM: runtime syscall monitoring");
            }
            SecurityFeature::Cgroups => {
                println!("   • cgroups: resource limits (memory, CPU, I/O)");
            }
        }
    }

    println!();
    println!("   {}", "Your Options:".white().bold());
    println!();
    println!(
        "   {} Re-run with sudo (recommended, full security)",
        "1.".cyan()
    );
    println!("      → All security features will be enabled");
    println!();
    println!("   {} Continue without elevated privileges", "2.".cyan());
    println!("      → Reduced security: seccomp/landlock only, no resource limits");
    println!();
    println!("   {} Abort", "3.".cyan());
    println!();

    print!("   Choose [1/2/3, default=2]: ");
    let _ = io::stdout().flush();

    let mut choice = String::new();
    if io::stdin().read_line(&mut choice).is_err() {
        return PrivilegeChoice::Abort;
    }

    match choice.trim() {
        "1" => PrivilegeChoice::UseSudo,
        "2" | "" => PrivilegeChoice::ContinueWithout,
        "3" => PrivilegeChoice::Abort,
        _ => PrivilegeChoice::Abort,
    }
}

/// Handle privilege requirements with appropriate behavior
///
/// This is the main entry point for unified privilege handling:
/// 1. Checks what features need elevated privileges
/// 2. If none need elevation, returns ContinueWithout immediately
/// 3. If some need elevation and we're not elevated, shows unified prompt
/// 4. Returns the user's choice for the caller to act on
pub fn handle_privilege_requirements() -> PrivilegeChoice {
    let requirements = security_rs::check_privilege_requirements();

    if !requirements.needs_elevation() {
        // No elevated privileges needed, proceed normally
        log::debug!(
            "All security features available: {:?}",
            requirements.available
        );
        return PrivilegeChoice::ContinueWithout;
    }

    log::debug!(
        "Security features requiring elevation: {:?}",
        requirements.required
    );

    // Show unified prompt
    show_unified_privilege_prompt(&requirements)
}

/// Print sudo instructions and return true to indicate re-exec should happen
pub fn print_sudo_instructions() {
    println!();
    println!("{} Re-executing with sudo...", "ℹ️".blue());
    println!();
    println!("   {} sudo phantom <your-command>", "$".dimmed());
    println!();
}

/// Print information about continuing without elevated privileges
pub fn print_continue_without_info(features: &[SecurityFeature]) {
    println!();
    println!("{} Continuing with reduced security:", "⚠️".yellow());
    println!();
    println!("   The following features are disabled:");
    for feature in features {
        match feature {
            SecurityFeature::BpfLsm => {
                println!("   • BPF-LSM runtime monitoring");
            }
            SecurityFeature::Cgroups => {
                println!("   • Resource limits (cgroups)");
            }
        }
    }
    println!();
    println!(
        "   {} Security will use seccomp and Landlock only.",
        "ℹ️".blue()
    );
    println!();
}
