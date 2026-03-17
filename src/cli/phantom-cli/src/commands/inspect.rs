use anyhow::Result;
use colored::*;

use crate::commands::CommandContext;
use crate::io_utils::chrono_lite_timestamp;

#[derive(clap::Args, Debug, Clone)]
pub struct InspectArgs {
    /// Fragment name
    pub name: String,
    /// Output format
    #[arg(long, default_value = "pretty")]
    pub format: String,
    /// Type of information (config, network, mounts)
    #[arg(long)]
    pub info_type: Option<String>,
}

pub fn exec(ctx: CommandContext, args: InspectArgs) -> Result<()> {
    let CommandContext { registry, .. } = ctx;
    let fragment = registry
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("Fragment '{}' not found", args.name))?
        .clone();

    let inspect_data = serde_json::json!({
        "name": fragment.name,
        "profile": fragment.profile,
        "pid": fragment.pid,
        "status": format!("{:?}", fragment.status),
        "mode": fragment.mode,
        "memory_kb": fragment.memory_kb,
        "components": fragment.components,
        "created_at": fragment.created_at,
        "created_at_human": chrono_lite_timestamp(),
    });

    match args.info_type.as_deref() {
        Some("config") => {
            let config_json = serde_json::to_string_pretty(&serde_json::json!({
                "name": fragment.name,
                "profile": fragment.profile,
                "mode": fragment.mode,
                "memory_kb": fragment.memory_kb,
            }))?;
            println!("{}", config_json);
        }
        Some("network") => {
            let network_json = serde_json::to_string_pretty(&serde_json::json!({
                "name": fragment.name,
                "network_access": fragment.components.contains(&"TcpStack".to_string()),
                "dns": fragment.components.contains(&"DnsResolver".to_string()),
            }))?;
            println!("{}", network_json);
        }
        Some("mounts") => {
            let mounts_json = serde_json::to_string_pretty(&serde_json::json!({
                "name": fragment.name,
                "binds": [],
                "volumes": [],
            }))?;
            println!("{}", mounts_json);
        }
        _ => {
            if args.format == "json" {
                println!("{}", serde_json::to_string_pretty(&inspect_data)?);
            } else if args.format == "yaml" {
                println!("{}", serde_yaml::to_string(&inspect_data)?);
            } else {
                println!("{}", "Fragment Details".cyan().bold());
                println!("{}", "─".repeat(60).dimmed());
                println!("  {:<15} {}", "Name:".yellow(), fragment.name.cyan());
                println!("  {:<15} {}", "Profile:".yellow(), fragment.profile);
                println!("  {:<15} {:?}", "Status:".yellow(), fragment.status);
                println!("  {:<15} {:?}", "Mode:".yellow(), fragment.mode);
                println!("  {:<15} {:?}", "PID:".yellow(), fragment.pid);
                println!("  {:<15} {} KB", "Memory:".yellow(), fragment.memory_kb);
                println!("  {:<15} {:?}", "Components:".yellow(), fragment.components);
            }
        }
    }
    Ok(())
}
