use anyhow::Result;
use colored::*;

#[derive(clap::Subcommand, Debug, Clone)]
pub enum NetworkCommands {
    /// List all network interfaces
    List,
    /// Bring an interface up
    Up {
        /// Interface name
        name: String,
    },
    /// Add an IP address to an interface
    AddIp {
        /// Interface name
        interface: String,
        /// IP address with prefix (e.g., 192.168.1.10/24)
        ip: String,
    },
    /// Create a VETH pair
    CreateVeth {
        /// Host interface name
        host_name: String,
        /// Peer interface name
        peer_name: String,
    },
}

use crate::commands::CommandContext;

pub async fn exec(_ctx: CommandContext<'_>, command: NetworkCommands) -> Result<()> {
    use network_rs::NetworkManager;

    let manager = NetworkManager::new().await?;

    match command {
        NetworkCommands::List => {
            println!("{}", "Network Interfaces".cyan().bold());
            println!("{}", "─".repeat(60).dimmed());

            let interfaces = manager.list_interfaces().await?;
            if interfaces.is_empty() {
                println!("{}", "No interfaces found".dimmed());
            } else {
                for (i, name) in interfaces.iter().enumerate() {
                    println!("  {}. {}", i + 1, name.cyan());
                }
                println!("\n{} {} interface(s) found", "→".green(), interfaces.len());
            }
        }
        NetworkCommands::Up { name } => {
            println!("{} Bringing up interface: {}", "→".yellow(), name.cyan());
            manager.set_interface_up(&name).await?;
            println!(
                "{} Interface '{}' is now up",
                "✓".green().bold(),
                name.cyan()
            );
        }
        NetworkCommands::AddIp { interface, ip } => {
            let (ip_addr, prefix_len) = if let Some(idx) = ip.find('/') {
                let addr_str = &ip[..idx];
                let prefix_str = &ip[idx + 1..];
                let prefix: u8 = prefix_str.parse().unwrap_or(24);
                (addr_str.parse::<std::net::IpAddr>()?, prefix)
            } else {
                (ip.parse::<std::net::IpAddr>()?, 24)
            };

            println!(
                "{} Adding IP {} to interface: {}",
                "→".yellow(),
                ip.cyan(),
                interface.cyan()
            );
            manager
                .add_ip_address(&interface, ip_addr, prefix_len)
                .await?;
            println!(
                "{} Added {}/{} to '{}'",
                "✓".green().bold(),
                ip_addr,
                prefix_len,
                interface.cyan()
            );
        }
        NetworkCommands::CreateVeth {
            host_name,
            peer_name,
        } => {
            println!(
                "{} Creating VETH pair: {} <-> {}",
                "→".yellow(),
                host_name.cyan(),
                peer_name.cyan()
            );
            manager.create_veth_pair(&host_name, &peer_name).await?;
            println!(
                "{} Created VETH pair '{}' and '{}'",
                "✓".green().bold(),
                host_name.cyan(),
                peer_name.cyan()
            );
        }
    }

    Ok(())
}
