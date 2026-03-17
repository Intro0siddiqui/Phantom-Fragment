use anyhow::{Context, Result};
use colored::*;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

#[derive(clap::Args, Debug, Clone)]
pub struct CleanArgs {
    /// Image to remove (optional, if not provided removes all)
    #[arg(long, value_name = "IMAGE")]
    pub image: Option<String>,

    /// Remove all images (requires confirmation unless --force is used)
    #[arg(long)]
    pub all: bool,

    /// Clear layer cache only (does not remove images)
    #[arg(long)]
    pub cache: bool,

    /// Remove both images and cache (requires confirmation unless --force is used)
    #[arg(long)]
    pub everything: bool,

    /// Force removal without confirmation and override dependency warnings
    #[arg(short, long)]
    pub force: bool,

    /// Show what would be deleted without actually deleting
    #[arg(long)]
    pub dry_run: bool,
}

use crate::commands::CommandContext;
use crate::fragment_registry::{FragmentRegistry, FragmentStatus};

/// Format bytes as human-readable size (KB, MB, GB)
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Check if a path is currently mounted by any process
///
/// Reads /proc/*/mountinfo to check if the path appears as a mount point
fn is_path_mounted(path: &Path) -> Result<bool> {
    let proc_dir = Path::new("/proc");

    if !proc_dir.exists() {
        return Ok(false);
    }

    let target_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let target_str = target_path.to_string_lossy();

    for entry in fs::read_dir(proc_dir).context("Failed to read /proc directory")? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let dir_name = entry.file_name();
        let dir_name_str = dir_name.to_string_lossy();

        if !dir_name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let mountinfo_path = entry.path().join("mountinfo");
        if !mountinfo_path.exists() {
            continue;
        }

        if let Ok(content) = fs::read_to_string(&mountinfo_path) {
            for line in content.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 5 {
                    let mount_point = fields[4];
                    if mount_point == target_str.as_ref() {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

/// Find fragments using a specific image
fn find_fragments_using_image(
    image: &str,
    registry: &FragmentRegistry,
) -> Vec<(String, FragmentStatus)> {
    registry
        .list()
        .into_iter()
        .filter(|f| f.image.as_ref().map(|img| img == image).unwrap_or(false))
        .map(|f| (f.name.clone(), f.status.clone()))
        .collect()
}

/// Check if an image has dependencies and warn the user
///
/// Returns true if the image can be safely removed, false if there are dependencies
fn check_and_warn_dependencies(
    image: &str,
    registry: &FragmentRegistry,
    force: bool,
) -> Result<bool> {
    let fragments = find_fragments_using_image(image, registry);

    if fragments.is_empty() {
        return Ok(true);
    }

    let running_fragments: Vec<&(String, FragmentStatus)> = fragments
        .iter()
        .filter(|(_, status)| *status == FragmentStatus::Running)
        .collect();

    let stopped_fragments: Vec<&(String, FragmentStatus)> = fragments
        .iter()
        .filter(|(_, status)| *status == FragmentStatus::Stopped)
        .collect();

    // Warn about running fragments
    if !running_fragments.is_empty() {
        println!(
            "{}",
            format!(
                "WARNING: Image '{}' is used by {} running fragment(s):",
                image,
                running_fragments.len()
            )
            .yellow()
            .bold()
        );
        for (name, _) in running_fragments {
            println!("  {} {} (running)", "→".yellow(), name);
        }

        if !force {
            println!(
                "\n{} Use --force to remove image despite running fragments",
                "ℹ".blue()
            );
            return Ok(false);
        }

        println!(
            "{} --force specified, proceeding despite running fragments",
            "⚠".yellow()
        );
    }

    // Warn about stopped fragments
    if !stopped_fragments.is_empty() {
        println!(
            "{}",
            format!(
                "WARNING: Image '{}' is used by {} stopped fragment(s):",
                image,
                stopped_fragments.len()
            )
            .yellow()
        );
        for (name, _) in stopped_fragments {
            println!("  {} {} (stopped)", "→".yellow(), name);
        }

        if !force {
            println!(
                "\n{} Use --force to remove image despite fragment dependencies",
                "ℹ".blue()
            );
            return Ok(false);
        }
    }

    Ok(true)
}

/// Clean the layer cache directory
fn clean_cache(puller: &image_puller::ImagePuller, force: bool, dry_run: bool) -> Result<()> {
    // Get cache info using the new methods from ImagePuller
    let cache_size = puller
        .get_cache_size()
        .context("Failed to get cache size")?;
    let file_count = puller
        .get_cache_file_count()
        .context("Failed to get cache file count")?;

    if cache_size == 0 {
        println!("{} Cache is already empty", "ℹ".blue());
        return Ok(());
    }

    println!("Cache statistics:");
    println!("  Total size: {}", format_size(cache_size).yellow());
    println!("  Files: {}", file_count);

    // Require confirmation for large deletions (>100MB)
    let requires_confirmation = cache_size > 100 * 1024 * 1024;

    if !force && requires_confirmation {
        print!(
            "Cache is large ({}). Are you sure you want to clear it? [y/N] ",
            format_size(cache_size)
        );
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    if dry_run {
        println!(
            "\n[DRY-RUN] Would clear cache ({} in {} files)",
            format_size(cache_size),
            file_count
        );
        return Ok(());
    }

    // Clear the cache using the new method
    let cleared = puller.clear_cache().context("Failed to clear cache")?;
    println!(
        "{} Cleared cache ({} files, {} freed)",
        "✓".green(),
        cleared,
        format_size(cache_size)
    );

    Ok(())
}

/// Clean both images and cache
fn clean_everything(
    puller: &image_puller::ImagePuller,
    registry: &FragmentRegistry,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    // Get cache info
    let cache_size = puller
        .get_cache_size()
        .context("Failed to get cache size")?;
    let cache_file_count = puller
        .get_cache_file_count()
        .context("Failed to get cache file count")?;

    // Get image info
    let images = puller.list_available().context("Failed to list images")?;

    // Check for dependencies on all images
    let mut has_dependencies = false;
    let mut dependent_images = Vec::new();

    for img in &images {
        let fragments = find_fragments_using_image(img, registry);
        if !fragments.is_empty() {
            has_dependencies = true;
            let running_count = fragments
                .iter()
                .filter(|(_, s)| *s == FragmentStatus::Running)
                .count();
            dependent_images.push((img.clone(), fragments.len(), running_count));
        }
    }

    // Calculate total size
    let total_size = cache_size;
    let total_items = cache_file_count + images.len();

    println!("Cleanup summary:");
    println!("  Images to remove: {}", images.len());
    println!("  Cache files to remove: {}", cache_file_count);
    println!("  Cache size: {}", format_size(cache_size));

    if has_dependencies && !force {
        println!(
            "\n{}",
            "WARNING: Some images have fragment dependencies:"
                .yellow()
                .bold()
        );
        for (img, total, running) in &dependent_images {
            println!(
                "  {} {} ({} fragment{}, {} running)",
                "→".yellow(),
                img,
                total,
                if *total > 1 { "s" } else { "" },
                running
            );
        }
        println!(
            "\n{} Use --force to remove all images despite dependencies",
            "ℹ".blue()
        );

        if !dry_run {
            print!("\nAre you sure you want to continue? [y/N] ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }
    }

    if !dry_run {
        // Estimate image sizes (rough estimate based on typical sizes)
        println!("  Estimated total items: ~{}", total_items);
    }

    // Require confirmation for large deletions
    let requires_confirmation = total_size > 100 * 1024 * 1024 || !images.is_empty();

    if !force && requires_confirmation && !has_dependencies {
        print!("\nAre you sure you want to remove ALL images and cache? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    if dry_run {
        println!("\n[DRY-RUN] Would remove all images and cache");
        for img in &images {
            println!("  [DRY-RUN] Would remove image: {}", img);
        }
        println!("  [DRY-RUN] Would clear cache ({} files)", cache_file_count);
        return Ok(());
    }

    // Remove all images
    puller
        .remove_all_images()
        .context("Failed to remove images")?;
    println!("{} Removed {} images", "✓".green(), images.len());

    // Clear cache
    let cleared = puller.clear_cache().context("Failed to clear cache")?;
    println!(
        "{} Cleared cache ({} files, {} freed)",
        "✓".green(),
        cleared,
        format_size(cache_size)
    );

    Ok(())
}

pub fn exec(ctx: CommandContext, args: CleanArgs) -> Result<()> {
    use image_puller::ImagePuller;

    let CommandContext { registry, .. } = ctx;
    let puller = ImagePuller::new().context("Failed to create ImagePuller")?;

    // Handle --cache flag (clear cache only)
    if args.cache {
        return clean_cache(&puller, args.force, args.dry_run);
    }

    // Handle --everything flag (clear both images and cache)
    if args.everything {
        return clean_everything(&puller, registry, args.force, args.dry_run);
    }

    // Handle --all flag (remove all images, legacy behavior)
    if args.all {
        let images = puller.list_available()?;

        // Check dependencies for all images
        let mut has_dependencies = false;
        let mut dependent_images = Vec::new();

        for img in &images {
            let fragments = find_fragments_using_image(img, registry);
            if !fragments.is_empty() {
                has_dependencies = true;
                let running_count = fragments
                    .iter()
                    .filter(|(_, s)| *s == FragmentStatus::Running)
                    .count();
                dependent_images.push((img.clone(), fragments.len(), running_count));
            }
        }

        if has_dependencies && !args.force {
            println!(
                "{}",
                "WARNING: Some images have fragment dependencies:"
                    .yellow()
                    .bold()
            );
            for (img, total, running) in &dependent_images {
                println!(
                    "  {} {} ({} fragment{}, {} running)",
                    "→".yellow(),
                    img,
                    total,
                    if *total > 1 { "s" } else { "" },
                    running
                );
            }
            println!(
                "\n{} Use --force to remove all images despite dependencies",
                "ℹ".blue()
            );

            if !args.dry_run {
                print!("\nAre you sure you want to continue? [y/N] ");
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted.");
                    return Ok(());
                }
            }
        } else if !args.force {
            print!("Are you sure you want to remove ALL images? [y/N] ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        if args.dry_run {
            println!("[DRY-RUN] Would remove all images:");
            for img in images {
                println!("  [DRY-RUN] Would remove image: {}", img);
            }
            return Ok(());
        }

        puller.remove_all_images()?;
        println!("{} Removed all images", "✓".green());
        return Ok(());
    }

    // Handle --image flag (remove specific image)
    if let Some(ref img) = args.image {
        // Check dependencies for this specific image
        let can_remove = check_and_warn_dependencies(img, registry, args.force)?;

        if !can_remove {
            return Ok(());
        }

        if !args.force {
            print!("Are you sure you want to remove image '{}'? [y/N] ", img);
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        if args.dry_run {
            println!("[DRY-RUN] Would remove image: {}", img);
            return Ok(());
        }

        // Check if image rootfs is mounted
        let paths = crate::config::PhantomPaths::new();
        let rootfs_path = paths.rootfs().join(img);
        if rootfs_path.exists() && is_path_mounted(&rootfs_path)? {
            println!(
                "{}",
                format!("WARNING: Rootfs for '{}' is currently mounted", img).yellow()
            );
            if !args.force {
                println!(
                    "{} Use --force to remove image despite mounted rootfs",
                    "ℹ".blue()
                );
                return Ok(());
            }
            println!(
                "{} --force specified, proceeding despite mounted rootfs",
                "⚠".yellow()
            );
        }

        puller.remove_image(img)?;
        println!("{} Removed image '{}'", "✓".green(), img);
        return Ok(());
    }

    // No flags provided - show available images
    let images = puller.list_available()?;
    if images.is_empty() {
        println!("No images found.");
    } else {
        println!("Available images:");
        for img in images {
            println!("  - {}", img);
        }
        println!("\nUse --image <NAME> to remove specific image, or --all to remove all.");
        println!("Use --cache to clear layer cache, or --everything to remove all.");
        println!("Use --dry-run to preview what would be deleted.");
        println!("Use --force to override dependency warnings.");
    }

    Ok(())
}
