use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::commands::CommandContext;
use crate::fragment_registry::{FragmentInfo, FragmentRegistry, FragmentStatus};
use crate::ui::{error_with_prefix, success, warn, warn_with_prefix};

#[derive(clap::Args, Clone, Debug)]
pub struct DeleteArgs {
    /// Fragment name to destroy
    pub name: String,
    /// Force destroy even if running
    #[arg(short, long)]
    pub force: bool,
    /// Also remove associated rootfs image
    #[arg(long)]
    pub remove_rootfs: bool,
    /// Skip confirmation prompts
    #[arg(short = 'y', long)]
    pub yes: bool,
}

/// Find the rootfs directory for a fragment
///
/// Searches in the standard rootfs location: ~/.phantom/rootfs/<fragment_name>
///
/// # Arguments
/// * `name` - The fragment name
/// * `paths` - PhantomPaths for locating directories
///
/// # Returns
/// * `Some(PathBuf)` - Path to the rootfs directory if found
/// * `None` - If rootfs doesn't exist
pub fn find_fragment_rootfs(name: &str, paths: &crate::config::PhantomPaths) -> Option<PathBuf> {
    let rootfs_path = paths.rootfs().join(name);
    if rootfs_path.exists() {
        Some(rootfs_path)
    } else {
        None
    }
}

/// Check if an image is used by other fragments
///
/// # Arguments
/// * `image` - The image name to check
/// * `registry` - The fragment registry to search
///
/// # Returns
/// * `Ok(Vec<String>)` - List of fragment names using this image
/// * `Err` - If there's an error checking dependencies
pub fn check_image_dependencies(image: &str, registry: &FragmentRegistry) -> Result<Vec<String>> {
    let mut dependents = Vec::new();

    for fragment in registry.list() {
        if let Some(fragment_image) = &fragment.image {
            if fragment_image == image {
                dependents.push(fragment.name.clone());
            }
        }
    }

    Ok(dependents)
}

/// Check if a path is currently mounted by any process
///
/// Reads /proc/*/mountinfo to check if the path appears as a mount point
///
/// # Arguments
/// * `path` - The path to check
///
/// # Returns
/// * `Ok(true)` - Path is mounted
/// * `Ok(false)` - Path is not mounted
/// * `Err` - If there's an error reading mountinfo
pub fn is_path_mounted(path: &Path) -> Result<bool> {
    let proc_dir = Path::new("/proc");

    if !proc_dir.exists() {
        // If /proc doesn't exist, assume not mounted (e.g., in some containers)
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

        // Check if this is a PID directory (numeric name)
        if !dir_name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let mountinfo_path = entry.path().join("mountinfo");
        if !mountinfo_path.exists() {
            continue;
        }

        // Read mountinfo and check for our path
        if let Ok(content) = fs::read_to_string(&mountinfo_path) {
            for line in content.lines() {
                // mountinfo format: fields are space-separated
                // Field 5 is the mount point
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

/// Get list of running fragments that use a specific image
fn get_running_fragments_using_image<'a>(
    image: &'a str,
    registry: &'a FragmentRegistry,
) -> Vec<&'a FragmentInfo> {
    registry
        .list()
        .into_iter()
        .filter(|f| {
            f.status == FragmentStatus::Running
                && f.image.as_ref().map(|img| img == image).unwrap_or(false)
        })
        .collect()
}

/// Confirm deletion with user (unless --yes is specified)
fn confirm_deletion(message: &str, skip_confirm: bool) -> Result<bool> {
    if skip_confirm {
        return Ok(true);
    }

    print!("{} [y/N] ", message);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().eq_ignore_ascii_case("y"))
}

pub fn exec(ctx: CommandContext, args: DeleteArgs) -> anyhow::Result<()> {
    let CommandContext {
        paths, registry, ..
    } = ctx;
    let DeleteArgs {
        name,
        force,
        remove_rootfs,
        yes,
    } = args;

    println!("{} {}", "Destroying fragment:".red().bold(), name.cyan());

    let fragment = match registry.get(&name) {
        Some(f) => f.clone(),
        None => {
            error_with_prefix("Error:", &format!("Fragment '{}' not found", name));
            std::process::exit(1);
        }
    };

    // Check if fragment is running
    if fragment.status == FragmentStatus::Running && !force {
        error_with_prefix(
            "Error:",
            "Fragment is running. Use --force to destroy anyway",
        );
        std::process::exit(1);
    }

    // Check for rootfs dependencies before deletion
    let rootfs_path = find_fragment_rootfs(&name, &paths);
    let mut should_remove_rootfs = remove_rootfs;

    if let Some(ref image_name) = fragment.image {
        // Check if other fragments depend on this image
        let dependents = check_image_dependencies(image_name, registry)?;
        let other_dependents: Vec<&String> = dependents.iter().filter(|d| *d != &name).collect();

        if !other_dependents.is_empty() {
            warn_with_prefix(
                "WARNING:",
                &format!(
                    "Image '{}' is used by other fragment(s): {}",
                    image_name,
                    other_dependents
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );

            // Check if any dependent fragments are running
            let running_dependents = get_running_fragments_using_image(image_name, registry);
            if !running_dependents.is_empty() {
                warn_with_prefix(
                    "WARNING:",
                    &format!(
                        "The following running fragment(s) depend on this image: {}",
                        running_dependents
                            .iter()
                            .map(|f| f.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );

                if !force && !yes {
                    let confirmed = confirm_deletion(
                        "Removing rootfs may affect running fragments. Continue anyway?",
                        yes,
                    )?;
                    if !confirmed {
                        println!("Aborted.");
                        return Ok(());
                    }
                }
            }

            // Only remove rootfs if explicitly requested
            if !remove_rootfs {
                println!(
                    "{} Image '{}' is shared. Use --remove-rootfs to also delete the rootfs",
                    "ℹ".blue(),
                    image_name
                );
                should_remove_rootfs = false;
            }
        }
    }

    // Check if rootfs is mounted before attempting removal
    if should_remove_rootfs {
        if let Some(ref rootfs) = rootfs_path {
            if is_path_mounted(rootfs)? {
                error_with_prefix(
                    "Error:",
                    &format!(
                        "Cannot remove rootfs: '{}' is currently mounted",
                        rootfs.display()
                    ),
                );
                println!(
                    "{} Use 'umount {}' to unmount before deletion",
                    "ℹ".blue(),
                    rootfs.display()
                );
                should_remove_rootfs = false;
            }
        }
    }

    // Show PID info if running
    if let Some(pid) = fragment.pid {
        if fragment.status == FragmentStatus::Running {
            println!("  {} Terminating PID {}", "→".yellow(), pid);
        }
    }

    // Remove from registry
    registry.remove(&name)?;
    success("Removed from registry");

    // Clean up storage state file
    let storage_dir = paths.storage();
    let state_path = storage_dir.join(format!("{}.json", name));
    if state_path.exists() {
        if let Err(e) = fs::remove_file(&state_path) {
            warn(&format!("Failed to delete from storage: {}", e));
        } else {
            success("Cleaned up storage");
        }
    }

    // Remove rootfs if requested
    if should_remove_rootfs {
        if let Some(rootfs) = rootfs_path {
            // Final confirmation for rootfs deletion if not using --yes
            if !yes && !force {
                let confirmed = confirm_deletion(
                    &format!(
                        "Are you sure you want to delete rootfs at '{}'?",
                        rootfs.display()
                    ),
                    yes,
                )?;
                if !confirmed {
                    println!("{} Rootfs deletion skipped", "ℹ".blue());
                } else {
                    match fs::remove_dir_all(&rootfs) {
                        Ok(_) => {
                            success(&format!("Removed rootfs: {}", rootfs.display()));
                        }
                        Err(e) => {
                            warn(&format!("Failed to remove rootfs: {}", e));
                        }
                    }
                }
            } else {
                // --yes or --force was specified, proceed with deletion
                match fs::remove_dir_all(&rootfs) {
                    Ok(_) => {
                        success(&format!("Removed rootfs: {}", rootfs.display()));
                    }
                    Err(e) => {
                        warn(&format!("Failed to remove rootfs: {}", e));
                    }
                }
            }
        } else {
            warn("Rootfs not found, skipping removal");
        }
    }

    println!("{} Fragment destroyed", "✓".green().bold());

    Ok(())
}
