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
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

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
    println!("      → sudo will ask for your password, then re-run phantom elevated");
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

    // Loop guard: if the sudo re-exec did not actually grant CAP_SYS_ADMIN
    // (for example in a restricted container where root lacks the capability),
    // do not prompt and elevate again.
    if std::env::var("PHANTOM_ELEVATED").as_deref() == Ok("1") {
        log::warn!(
            "Already elevated (PHANTOM_ELEVATED=1) but CAP_SYS_ADMIN is still unavailable; \
             continuing without elevated privileges."
        );
        return PrivilegeChoice::ContinueWithout;
    }

    // Show unified prompt
    show_unified_privilege_prompt(&requirements)
}

/// Build the `sudo env ...` command that re-runs this CLI with elevated privileges.
///
/// HOME (and PHANTOM_CONFIG) are passed explicitly through `env` because plain
/// sudo resets HOME to /root, which would hide the invoking user's images,
/// pools and configuration from `PhantomPaths`.
fn build_sudo_command(
    exe: &Path,
    args: &[OsString],
    home: Option<&OsStr>,
    phantom_config: Option<&OsStr>,
) -> Command {
    let mut command = Command::new("sudo");
    command.arg("env");

    if let Some(home) = home {
        let mut assignment = OsString::from("HOME=");
        assignment.push(home);
        command.arg(assignment);
    }

    if let Some(config) = phantom_config {
        let mut assignment = OsString::from("PHANTOM_CONFIG=");
        assignment.push(config);
        command.arg(assignment);
    }

    command.arg("PHANTOM_ELEVATED=1");
    command.arg(exe);
    command.args(args);
    command
}

/// Quote a value for display in a shell command line.
fn shell_quote(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@".contains(c))
    {
        value.into_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Render a command as a copy-pasteable shell command line.
fn render_command(command: &Command) -> String {
    let mut parts = vec![shell_quote(command.get_program())];
    parts.extend(command.get_args().map(shell_quote));
    parts.join(" ")
}

/// Replace the current process with an elevated copy of this CLI via sudo.
///
/// sudo prompts for the password on its own tty; the password is never read,
/// stored or forwarded by phantom. On failure this returns an error containing
/// the exact command the user can run manually.
pub fn reexec_with_sudo() -> anyhow::Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("Failed to determine the phantom executable path: {e}"))?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let home = std::env::var_os("HOME");
    let phantom_config = std::env::var_os("PHANTOM_CONFIG");

    let mut command = build_sudo_command(&exe, &args, home.as_deref(), phantom_config.as_deref());
    let display = render_command(&command);

    println!();
    println!(
        "{} Re-executing with sudo (sudo will ask for your password)...",
        "ℹ️".blue()
    );
    println!("   {} {}", "$".dimmed(), display);
    println!();

    use std::os::unix::process::CommandExt;
    let error = command.exec();

    let reason = if error.kind() == io::ErrorKind::NotFound {
        "sudo was not found on PATH".to_string()
    } else {
        format!("failed to execute sudo: {error}")
    };
    Err(anyhow::anyhow!(
        "Failed to re-execute with elevated privileges ({reason}). \
         Run the following command manually:\n\n    {display}"
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn command_args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn test_build_sudo_command_with_config() {
        let exe = Path::new("/usr/local/bin/phantom");
        let args: Vec<OsString> = [
            "run",
            "--profile",
            "sandbox",
            "alpine",
            "echo",
            "hello world",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();

        let command = build_sudo_command(
            exe,
            &args,
            Some(OsStr::new("/home/alice")),
            Some(OsStr::new("/home/alice/phantom.toml")),
        );

        assert_eq!(command.get_program(), "sudo");

        let args = command_args(&command);
        assert_eq!(args[0], "env");
        assert!(args.contains(&"HOME=/home/alice".to_string()));
        assert!(args.contains(&"PHANTOM_CONFIG=/home/alice/phantom.toml".to_string()));
        assert!(args.contains(&"PHANTOM_ELEVATED=1".to_string()));

        let exe_index = args
            .iter()
            .position(|arg| arg == "/usr/local/bin/phantom")
            .expect("executable must be present");
        for assignment in [
            "HOME=/home/alice",
            "PHANTOM_CONFIG=/home/alice/phantom.toml",
            "PHANTOM_ELEVATED=1",
        ] {
            let assignment_index = args
                .iter()
                .position(|arg| arg == assignment)
                .expect("environment assignment must be present");
            assert!(
                assignment_index < exe_index,
                "{assignment} must come before the executable"
            );
        }
        assert_eq!(
            &args[exe_index + 1..],
            [
                "run",
                "--profile",
                "sandbox",
                "alpine",
                "echo",
                "hello world"
            ]
        );
    }

    #[test]
    fn test_build_sudo_command_without_config() {
        let exe = Path::new("/usr/local/bin/phantom");
        let args: Vec<OsString> = ["run", "alpine", "true"]
            .into_iter()
            .map(OsString::from)
            .collect();

        let command = build_sudo_command(exe, &args, Some(OsStr::new("/home/alice")), None);

        let args = command_args(&command);
        assert_eq!(args[0], "env");
        assert!(args.contains(&"HOME=/home/alice".to_string()));
        assert!(args.contains(&"PHANTOM_ELEVATED=1".to_string()));
        assert!(!args.iter().any(|arg| arg.starts_with("PHANTOM_CONFIG=")));

        let exe_index = args
            .iter()
            .position(|arg| arg == "/usr/local/bin/phantom")
            .expect("executable must be present");
        assert_eq!(&args[exe_index + 1..], ["run", "alpine", "true"]);
    }

    #[test]
    fn test_privilege_choice_variants() {
        // Test that all variants exist and are distinct
        assert_ne!(PrivilegeChoice::UseSudo, PrivilegeChoice::ContinueWithout);
        assert_ne!(PrivilegeChoice::ContinueWithout, PrivilegeChoice::Abort);
        assert_ne!(PrivilegeChoice::UseSudo, PrivilegeChoice::Abort);
    }

    #[test]
    fn test_privilege_requirements() {
        let req = PrivilegeRequirements {
            required: vec![SecurityFeature::BpfLsm],
            available: vec![SecurityFeature::Cgroups],
        };
        assert!(req.needs_elevation());

        let req_empty = PrivilegeRequirements {
            required: vec![],
            available: vec![SecurityFeature::Cgroups, SecurityFeature::BpfLsm],
        };
        assert!(!req_empty.needs_elevation());
    }
}
