use anyhow::Result;
use colored::*;

#[derive(clap::Subcommand, Debug, Clone)]
pub enum ProfileCommands {
    /// List available profiles
    List {
        /// Show performance benchmarks
        #[arg(short, long)]
        benchmark: bool,
        /// Detailed output
        #[arg(short, long)]
        detailed: bool,
    },
    /// Show profile details
    Show {
        /// Profile name
        name: String,
        /// Output as YAML
        #[arg(long)]
        yaml: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

use crate::commands::CommandContext;

pub fn exec(ctx: CommandContext, command: ProfileCommands) -> Result<()> {
    let CommandContext { config, .. } = ctx;
    match command {
        ProfileCommands::List {
            benchmark,
            detailed,
        } => {
            println!("{}", "Available Profiles".cyan().bold());
            println!("{}", "─".repeat(80).dimmed());

            let builtin_profiles = get_builtin_profiles();

            println!(
                "{:<20} {:<15} {:<12} {:<15}",
                "NAME".bold(),
                "ISOLATION".bold(),
                "NETWORK".bold(),
                "MEMORY".bold()
            );
            println!("{}", "─".repeat(80).dimmed());

            for (name, isolation, network, mem) in &builtin_profiles {
                println!(
                    "{:<20} {:<15} {:<12} {:<15}",
                    name.cyan(),
                    isolation.yellow(),
                    if *network {
                        "enabled".green()
                    } else {
                        "disabled".red()
                    },
                    mem.dimmed()
                );

                if detailed {
                    println!(
                        "    {} {}",
                        "→".dimmed(),
                        format!("Isolation level: {}", isolation).dimmed()
                    );
                }
            }

            if !config.profiles.is_empty() {
                println!();
                println!("{}", "Custom Profiles (from config):".yellow());
                for (name, profile) in &config.profiles {
                    println!(
                        "  {} {} ({})",
                        "•".cyan(),
                        name.cyan(),
                        profile.isolation.yellow()
                    );
                    if detailed {
                        println!(
                            "    Network: {}, File Write: {}",
                            profile.network, profile.file_write
                        );
                        if let Some(ref mem) = profile.memory_mb {
                            println!("    Memory: {} MB", mem);
                        }
                    }
                }
            }

            if benchmark {
                println!();
                println!("{}", "Performance Benchmarks:".yellow());
                println!("  {:<15} {:<15} {:<15}", "Profile", "Startup", "Overhead");
                println!("  {:<15} {:<15} {:<15}", "sandbox", "<25ms", "standard");
                println!("  {:<15} {:<15} {:<15}", "hardened", "<60ms", "enhanced");
            }

            println!();
            println!("Use 'phantom profile show <name>' for details");
        }
        ProfileCommands::Show { name, yaml, json } => {
            let builtin_profiles = get_builtin_profiles();
            let builtin = builtin_profiles.iter().find(|p| p.0 == name);

            let profile_info = if let Some((_, isolation, network, mem)) = builtin {
                let mem_val = mem.trim_end_matches(" MB");
                serde_json::json!({
                    "name": name,
                    "isolation": isolation,
                    "network": network,
                    "memory_mb": mem_val.parse::<u64>().unwrap_or(512),
                    "seccomp": if isolation == "hardened" { "strict" } else { "default" },
                    "description": match isolation.as_str() {
                        "sandbox" => "Standard namespace isolation",
                        "hardened" => "Full seccomp + network restrictions",
                        _ => "Custom profile"
                    }
                })
            } else if let Some(profile) = config.get_profile(&name) {
                serde_json::json!({
                    "name": name,
                    "isolation": profile.isolation,
                    "network": profile.network,
                    "memory_mb": profile.memory_mb.unwrap_or(512),
                    "cpu_count": profile.cpu_count.unwrap_or(1),
                    "cpu_affinity": profile.cpu_affinity,
                    "numa_node": profile.numa_node,
                    "seccomp_rules": profile.seccomp_rules
                })
            } else {
                anyhow::bail!("Profile '{}' not found", name);
            };

            if yaml {
                println!("{}", serde_yaml::to_string(&profile_info)?);
            } else if json {
                println!("{}", serde_json::to_string_pretty(&profile_info)?);
            } else {
                println!("{}", "Profile Details".cyan().bold());
                println!("{}", "─".repeat(60).dimmed());
                println!(
                    "  {:<15} {}",
                    "Name:".yellow(),
                    profile_info["name"].as_str().unwrap_or("unknown").cyan()
                );
                println!(
                    "  {:<15} {}",
                    "Isolation:".yellow(),
                    profile_info["isolation"].as_str().unwrap_or("unknown")
                );
                println!(
                    "  {:<15} {}",
                    "Network:".yellow(),
                    profile_info["network"].as_bool().unwrap_or(true)
                );
                println!(
                    "  {:<15} {} MB",
                    "Memory:".yellow(),
                    profile_info["memory_mb"].as_u64().unwrap_or(512)
                );
                if let Some(node) = profile_info["numa_node"].as_u64() {
                    println!("  {:<15} {}", "NUMA Node:".yellow(), node);
                }
                if let Some(desc) = profile_info["description"].as_str() {
                    println!("  {:<15} {}", "Description:".yellow(), desc.dimmed());
                }
            }
        }
    }
    Ok(())
}

fn get_builtin_profiles() -> Vec<(String, String, bool, String)> {
    vec![
        (
            "sandbox".to_string(),
            "sandbox".to_string(),
            true,
            "512 MB".to_string(),
        ),
        (
            "hardened".to_string(),
            "hardened".to_string(),
            false,
            "256 MB".to_string(),
        ),
        (
            "wasm".to_string(),
            "wasm".to_string(),
            false,
            "256 MB".to_string(),
        ),
    ]
}
