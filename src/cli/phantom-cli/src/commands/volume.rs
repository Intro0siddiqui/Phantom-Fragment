use anyhow::Result;
use colored::*;

use crate::io_utils::chrono_lite_timestamp;
#[derive(clap::Subcommand, Debug, Clone)]
pub enum VolumeCommands {
    /// Create a new volume
    Create {
        /// Volume name
        name: String,
        /// Driver type (overlay, cas)
        #[arg(long, default_value = "overlay")]
        driver: String,
    },
    /// List all volumes
    List {
        /// Quiet output (names only)
        #[arg(short, long)]
        quiet: bool,
    },
    /// Show volume details
    Inspect {
        /// Volume name
        name: String,
    },
    /// Remove a volume
    Remove {
        /// Volume name
        name: String,
        /// Force removal
        #[arg(short, long)]
        force: bool,
    },
    /// Remove unused volumes
    Prune {
        /// Force without confirmation
        #[arg(short, long)]
        force: bool,
    },
}

use crate::commands::CommandContext;

pub async fn exec(ctx: CommandContext<'_>, command: VolumeCommands) -> Result<()> {
    let CommandContext { paths, .. } = ctx;
    let volume_dir = paths.volumes();

    match command {
        VolumeCommands::Create { name, driver } => {
            std::fs::create_dir_all(&volume_dir)?;
            let vol_path = volume_dir.join(&name);
            if vol_path.exists() {
                anyhow::bail!("Volume '{}' already exists", name);
            }
            std::fs::create_dir_all(&vol_path)?;
            let meta = serde_json::json!({
                "name": name,
                "driver": driver,
                "created_at": chrono_lite_timestamp(),
            });
            std::fs::write(vol_path.join("volume.json"), meta.to_string())?;
            println!(
                "{} Created volume '{}' ({})",
                "✓".green().bold(),
                name.cyan(),
                driver
            );
        }
        VolumeCommands::List { quiet } => {
            std::fs::create_dir_all(&volume_dir)?;
            let mut volumes: Vec<String> = Vec::new();
            for entry in std::fs::read_dir(&volume_dir)? {
                let entry = entry?;
                if entry.path().join("volume.json").exists() {
                    volumes.push(entry.file_name().to_string_lossy().to_string());
                }
            }
            if volumes.is_empty() {
                println!("No volumes found");
            } else if quiet {
                for v in volumes {
                    println!("{}", v);
                }
            } else {
                println!("{}", "Volumes".cyan().bold());
                println!("{}", "─".repeat(40).dimmed());
                for v in volumes {
                    println!("  {} {}", "•".cyan(), v);
                }
            }
        }
        VolumeCommands::Inspect { name } => {
            let vol_path = volume_dir.join(&name).join("volume.json");
            if !vol_path.exists() {
                anyhow::bail!("Volume '{}' not found", name);
            }
            let content = std::fs::read_to_string(&vol_path)?;
            println!("{}", content);
        }
        VolumeCommands::Remove { name, force } => {
            let vol_path = volume_dir.join(&name);
            if !vol_path.exists() {
                anyhow::bail!("Volume '{}' not found", name);
            }
            if !force {
                print!("Remove volume '{}'? [y/N] ", name);
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted.");
                    return Ok(());
                }
            }
            std::fs::remove_dir_all(&vol_path)?;
            println!("{} Removed volume '{}'", "✓".green(), name);
        }
        VolumeCommands::Prune { force } => {
            std::fs::create_dir_all(&volume_dir)?;
            let mut removed = 0;
            for entry in std::fs::read_dir(&volume_dir)? {
                let entry = entry?;
                let vol_name = entry.file_name().to_string_lossy().to_string();
                if !force {
                    println!("Would remove: {}", vol_name);
                } else {
                    std::fs::remove_dir_all(entry.path())?;
                    removed += 1;
                }
            }
            if force {
                println!("{} Removed {} unused volumes", "✓".green(), removed);
            } else {
                println!("Use --force to actually remove volumes");
            }
        }
    }
    Ok(())
}
