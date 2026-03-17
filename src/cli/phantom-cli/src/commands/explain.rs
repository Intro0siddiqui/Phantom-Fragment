use anyhow::Result;
use colored::*;

use crate::ui::{print_divider_full, print_header};

#[derive(clap::Args, Clone, Debug)]
pub struct ExplainArgs {
    /// Show detailed security information
    #[arg(long)]
    pub detailed: bool,
}

pub fn exec(_args: ExplainArgs) -> Result<()> {
    print_header("Phantom Fragment Security Model");
    print_divider_full();

    println!();
    println!(
        "{}",
        "Phantom Fragment uses a layered security approach:".dimmed()
    );
    println!();

    // Layer 1
    println!("{} {}", "1.".yellow().bold(), "Namespace Isolation".cyan());
    println!("   - Process isolation from host system");
    println!("   - Separate network, mount, and PID namespaces");
    println!();

    // Layer 2
    println!("{} {}", "2.".yellow().bold(), "Seccomp Filters".cyan());
    println!("   - Restricts available syscalls");
    println!("   - Default profile: ~150 syscalls allowed");
    println!("   - Hardened profile: ~89 syscalls allowed");
    println!();

    // Layer 3
    println!("{} {}", "3.".yellow().bold(), "Landlock LSM".cyan());
    println!("   - Filesystem sandboxing");
    println!("   - Path-based access control");
    println!("   - Prevents unauthorized file access");
    println!();

    // Layer 4
    println!("{} {}", "4.".yellow().bold(), "BPF-LSM".cyan());
    println!("   - Kernel-level security hooks");
    println!("   - Runtime policy enforcement");
    println!("   - Graceful fallback if unavailable");
    println!();

    // Layer 5
    println!("{} {}", "5.".yellow().bold(), "Cgroups v2".cyan());
    println!("   - Resource limits enforcement");
    println!("   - Prevents resource exhaustion attacks");
    println!();

    // Execution Modes
    println!("{}:", "Execution Modes".cyan().bold());
    println!(
        "  - {}: Standard isolation, default (<25ms)",
        "Sandbox".dimmed()
    );
    println!("  - {}: Maximum isolation (<60ms)", "Hardened".dimmed());
    println!("  - {}: WebAssembly sandbox (<30ms)", "Wasm".dimmed());
    println!();

    if _args.detailed {
        print_divider_full();
        println!();
        println!("{}:", "Detailed Security Information".cyan().bold());
        println!();
        println!("For more information, see:");
        println!("  - Documentation: docs/security/");
        println!("  - CLI Reference: docs/usage/cli-reference.md");
        println!("  - README: README.md");
        println!();
        println!("Security features require:");
        println!("  - Kernel 5.7+ for BPF-LSM");
        println!("  - Kernel 5.13+ for Landlock");
        println!("  - Cgroups v2 support");
        println!("  - bubblewrap or proot for rootless operation");
    } else {
        println!(
            "Run {} for more information.",
            "phantom explain --detailed".cyan()
        );
    }

    Ok(())
}
