use anyhow::Result;
use colored::*;

#[derive(clap::Args, Debug, Clone)]
pub struct ImagesArgs {
    /// Show recommended base images (distros + distroless)
    #[arg(short, long)]
    pub list: bool,

    /// Show layer sharing statistics
    #[arg(long)]
    pub stats: bool,
}

use crate::commands::CommandContext;

pub fn exec(_ctx: CommandContext, args: ImagesArgs) -> Result<()> {
    use image_puller::ImagePuller;

    if args.list {
        println!("{}", "Recommended Base Images".cyan().bold());
        println!(
            "{}",
            "────────────────────────────────────────────────────────────────────────────────"
                .dimmed()
        );
        println!("{}", "Popular Linux Distributions:".yellow());
        println!(
            "  {:<30} {}",
            "alpine".cyan(),
            "Minimal Linux (5MB) - Recommended for most uses"
        );
        println!(
            "  {:<30} {}",
            "ubuntu:22.04".cyan(),
            "Ubuntu LTS (77MB) - Full-featured"
        );
        println!(
            "  {:<30} {}",
            "debian:bookworm-slim".cyan(),
            "Debian Stable (80MB)"
        );
        println!(
            "  {:<30} {}",
            "fedora:latest".cyan(),
            "Fedora (190MB) - Cutting-edge packages"
        );
        println!(
            "  {:<30} {}",
            "archlinux:base".cyan(),
            "Arch Linux (~400MB) - Rolling release"
        );
        println!(
            "  {:<30} {}",
            "kalilinux/kali-rolling".cyan(),
            "Kali Linux (~125MB) - Security distro"
        );
        println!();
        println!("{}", "Google Distroless (Minimal, No Shell):".yellow());
        println!(
            "  {:<45} {}",
            "gcr.io/distroless/static-debian12".cyan(),
            "~2MB - Static binaries"
        );
        println!(
            "  {:<45} {}",
            "gcr.io/distroless/base-debian12".cyan(),
            "~20MB - Dynamic binaries"
        );
        println!(
            "  {:<45} {}",
            "gcr.io/distroless/python3-debian12".cyan(),
            "~50MB - Python apps"
        );
        println!(
            "  {:<45} {}",
            "gcr.io/distroless/nodejs18-debian12".cyan(),
            "~100MB - Node.js apps"
        );
        println!();
        println!("{}", "Usage:".dimmed());
        println!("  phantom run {} echo Hello", "alpine".green());
        println!(
            "  phantom run {} python3 -c 'print(1)'",
            "gcr.io/distroless/python3-debian12".green()
        );
    } else if args.stats {
        // Show layer sharing statistics
        use image_store_rs::{ImageStore, StorageConfig};
        use std::path::PathBuf;

        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let cache_base = PathBuf::from(&home).join(".phantom").join("cache");

        let config = StorageConfig {
            base_path: cache_base,
            ..Default::default()
        };

        match ImageStore::new(config) {
            Ok(store) => {
                let stats = store.layer_stats();
                println!("{}", "Layer Sharing Statistics".cyan().bold());
                println!(
                    "{}",
                    "────────────────────────────────────────────────────────────────────────────────"
                        .dimmed()
                );
                println!("  Total unique layers: {}", stats.total_layers);
                println!("  Shared layers: {}", stats.shared_layers);
                println!("  Total layer references: {}", stats.total_refs);

                if stats.shared_layers > 0 {
                    println!(
                        "\n  {} Storage optimization active: {} layers are shared across images",
                        "✓".green(),
                        stats.shared_layers
                    );
                }
            }
            Err(e) => {
                println!("{} Could not load image store: {}", "Warning:".yellow(), e);
            }
        }
    } else {
        let puller = ImagePuller::new()?;
        let images = puller.list_available()?;

        println!("Fragment Image Registry");
        println!(
            "{}",
            "────────────────────────────────────────────────────────────────────────────────"
                .dimmed()
        );

        if images.is_empty() {
            println!("No images found");
            println!("\nUse 'phantom images --list' to see recommended base images.");
        } else {
            for image in images {
                println!("  - {}", image.cyan());
            }
            println!("\nUse 'phantom clean --image <NAME>' to remove.");
            println!("Use 'phantom images --list' to see recommended base images.");
            println!("Use 'phantom images --stats' to see layer sharing statistics.");
        }
    }

    Ok(())
}
