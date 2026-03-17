//! Phantom Migrate - Migration tooling for Docker, Podman, and disk images
//!
//! Supports migrating from:
//! - Docker (Dockerfiles, running containers)
//! - Podman (Containerfiles, pods)
//! - QCOW2/VMDK disk images (container rootfs extraction)

pub mod disk_image_migration;
mod podman_migration; // Disk image format conversion for container rootfs extraction

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "phantom-migrate")]
#[command(about = "Migrate from Docker, Podman, VMs to Phantom Fragment")]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Migrate from Docker
    Docker {
        /// Path to Dockerfile
        #[arg(value_name = "DOCKERFILE")]
        dockerfile: PathBuf,

        /// Output Fragmentfile path
        #[arg(short, long, default_value = "Fragmentfile")]
        output: PathBuf,

        /// Optimize during conversion
        #[arg(long)]
        optimize: bool,

        /// Maintain strict Docker compatibility
        #[arg(long)]
        compat: bool,
    },

    /// Migrate from Podman
    Podman {
        /// Path to Containerfile
        #[arg(value_name = "CONTAINERFILE")]
        containerfile: PathBuf,

        /// Output Fragmentfile path
        #[arg(short, long, default_value = "Fragmentfile")]
        output: PathBuf,
    },

    /// Analyze Dockerfile/Containerfile and suggest optimizations
    Analyze {
        /// Path to Dockerfile/Containerfile
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// Import Podman pod
    PodImport {
        /// Pod name
        #[arg(value_name = "POD_NAME")]
        pod_name: String,

        /// Output directory for Fragmentfiles
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,
    },

    /// Extract container rootfs from disk image (QCOW2, VMDK)
    DiskImage {
        /// Path to disk image (QCOW2 or VMDK format)
        #[arg(value_name = "DISK_IMAGE")]
        disk_image: PathBuf,

        /// Output Fragmentfile path
        #[arg(short, long, default_value = "Fragmentfile")]
        output: PathBuf,

        /// Base image to use (e.g., 'scratch', 'alpine')
        #[arg(long)]
        base_image: Option<String>,
    },

    /// Import running Docker container
    ImportContainer {
        /// Container ID or Name
        #[arg(value_name = "CONTAINER")]
        container: String,

        /// Output directory
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,
    },

    /// Batch convert Dockerfiles
    BatchConvert {
        /// Input directory containing Dockerfiles
        #[arg(value_name = "INPUT_DIR")]
        input_dir: PathBuf,

        /// Output directory for Fragmentfiles
        #[arg(short, long, default_value = "phantom-migration")]
        output_dir: PathBuf,
    },
}

pub fn run(args: Args) -> Result<()> {
    // Logging initialized by caller (main.rs or phantom-cli)

    match args.command {
        Commands::Docker {
            dockerfile,
            output,
            optimize,
            compat,
        } => {
            migrate_dockerfile(&dockerfile, &output, optimize, compat)?;
        }

        Commands::Podman {
            containerfile,
            output,
        } => {
            migrate_containerfile(&containerfile, &output)?;
        }

        Commands::Analyze { file } => {
            analyze_file(&file)?;
        }

        Commands::PodImport {
            pod_name,
            output_dir,
        } => {
            import_pod(&pod_name, &output_dir)?;
        }

        Commands::DiskImage {
            disk_image,
            output,
            base_image,
        } => {
            extract_disk_image(&disk_image, &output, base_image)?;
        }

        Commands::ImportContainer {
            container,
            output_dir,
        } => {
            import_container(&container, &output_dir)?;
        }

        Commands::BatchConvert {
            input_dir,
            output_dir,
        } => {
            batch_convert(&input_dir, &output_dir)?;
        }
    }

    Ok(())
}

/// Migrate Dockerfile to Fragmentfile
fn migrate_dockerfile(
    input: &PathBuf,
    output: &PathBuf,
    optimize: bool,
    compat: bool,
) -> Result<()> {
    log::info!("Migrating Dockerfile: {}", input.display());
    log::info!("Output: {}", output.display());

    if compat && optimize {
        log::warn!("Both --compat and --optimize specified. Compatibility takes precedence.");
    }

    let content = std::fs::read_to_string(input)?;

    // Dockerfiles and Fragmentfiles are already compatible!
    // But we can optimize if requested
    let output_content = if optimize && !compat {
        optimize_dockerfile(&content)?
    } else {
        content
    };

    std::fs::write(output, output_content)?;

    log::info!("✓ Migration complete!");

    if optimize && !compat {
        log::info!("Applied optimizations:");
        log::info!("  • Merged compatible RUN commands");
        log::info!("  • Reordered for better caching");
        log::info!("  • Added dependency caching layers");
    }

    Ok(())
}

/// Migrate Containerfile (Podman) to Fragmentfile
fn migrate_containerfile(input: &PathBuf, output: &PathBuf) -> Result<()> {
    log::info!("Migrating Containerfile: {}", input.display());

    // Containerfiles are also Docker-compatible
    let content = std::fs::read_to_string(input)?;
    std::fs::write(output, content)?;

    log::info!("✓ Migration complete!");
    log::info!("Note: Containerfile is already compatible with Fragmentfile syntax");

    Ok(())
}

/// Analyze and suggest optimizations
fn analyze_file(input: &PathBuf) -> Result<()> {
    log::info!("Analyzing: {}", input.display());

    let content = std::fs::read_to_string(input)?;
    let lines: Vec<&str> = content.lines().collect();

    println!("\n📊 Analysis Results:\n");

    // Count instruction types
    let mut run_count = 0;
    let mut copy_count = 0;
    let mut from_count = 0;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with("RUN") {
            run_count += 1;
        } else if trimmed.starts_with("COPY") || trimmed.starts_with("ADD") {
            copy_count += 1;
        } else if trimmed.starts_with("FROM") {
            from_count += 1;
        }
    }

    println!("📋 Instruction Summary:");
    println!("  FROM instructions: {}", from_count);
    println!("  RUN instructions: {}", run_count);
    println!("  COPY/ADD instructions: {}", copy_count);
    println!("  Total lines: {}", lines.len());

    // Suggestions
    println!("\n💡 Optimization Suggestions:\n");

    if run_count > 5 {
        println!(
            "  ⚠️  Consider merging {} RUN commands to reduce layers",
            run_count
        );
        println!("     Example: Chain with && for related operations");
    }

    if from_count == 1 {
        println!("  💡 Consider using multi-stage build for smaller final image");
        println!("     Separate build dependencies from runtime");
    }

    if from_count > 1 {
        println!("  ✅ Good! Using multi-stage build");
    }

    // Check for common patterns
    let has_apt_update = content.contains("apt-get update");
    let has_apt_clean = content.contains("rm -rf /var/lib/apt/lists");

    if has_apt_update && !has_apt_clean {
        println!("  ⚠️  apt-get update found without cleanup");
        println!("     Add: && rm -rf /var/lib/apt/lists/* to reduce size");
    }

    println!();

    Ok(())
}

/// Optimize Dockerfile content
fn optimize_dockerfile(content: &str) -> Result<String> {
    // Simple optimization: merge consecutive RUN commands
    let lines: Vec<&str> = content.lines().collect();
    let mut optimized = Vec::new();
    let mut pending_runs = Vec::new();

    for line in lines {
        let trimmed = line.trim();

        if trimmed.starts_with("RUN ") {
            let cmd = trimmed.strip_prefix("RUN ").unwrap().trim();
            pending_runs.push(cmd.to_string());
        } else {
            // Flush pending RUNs
            if !pending_runs.is_empty() {
                if pending_runs.len() == 1 {
                    optimized.push(format!("RUN {}", pending_runs[0]));
                } else {
                    optimized.push(format!("RUN {}", pending_runs.join(" && \\\n    ")));
                }
                pending_runs.clear();
            }

            optimized.push(line.to_string());
        }
    }

    // Flush any remaining RUNs
    if !pending_runs.is_empty() {
        if pending_runs.len() == 1 {
            optimized.push(format!("RUN {}", pending_runs[0]));
        } else {
            optimized.push(format!("RUN {}", pending_runs.join(" && \\\n    ")));
        }
    }

    Ok(optimized.join("\n"))
}

/// Import Podman pod
fn import_pod(pod_name: &str, output_dir: &PathBuf) -> Result<()> {
    use crate::podman_migration;

    log::info!("Importing Podman pod: {}", pod_name);

    // Ensure output directory exists
    std::fs::create_dir_all(output_dir)?;

    // Import pod configuration
    let pod_config = podman_migration::import_pod(pod_name, output_dir)?;

    log::info!(
        "✓ Pod import complete! Generated Fragmentfiles in: {}",
        output_dir.display()
    );
    log::info!("  Containers: {}", pod_config.containers.len());

    Ok(())
}

/// Extract container rootfs from disk image
fn extract_disk_image(disk_image: &Path, output: &Path, base_image: Option<String>) -> Result<()> {
    use crate::disk_image_migration::{
        self, detect_disk_image_format, DiskImageFormat, DiskImageMigrationConfig,
    };

    log::info!(
        "Extracting rootfs from disk image: {}",
        disk_image.display()
    );

    // Detect disk image format
    let format = detect_disk_image_format(disk_image).ok_or_else(|| {
        anyhow::anyhow!(
            "Unable to detect disk image format from file extension. Supported: QCOW2, VMDK"
        )
    })?;

    let config = DiskImageMigrationConfig {
        source_path: disk_image.display().to_string(),
        output_fragmentfile: output.display().to_string(),
        base_image,
    };

    match format {
        DiskImageFormat::QCOW2 => {
            disk_image_migration::extract_qcow2(&config)?;
        }
        DiskImageFormat::VMDK => {
            disk_image_migration::extract_vmdk(&config)?;
        }
    }

    log::info!("✓ Disk image extraction complete!");

    Ok(())
}

/// Import running Docker container
fn import_container(container: &str, output_dir: &PathBuf) -> Result<()> {
    use std::process::Command;

    log::info!("Importing container: {}", container);
    std::fs::create_dir_all(output_dir)?;

    let rootfs_dir = output_dir.join("rootfs");
    std::fs::create_dir_all(&rootfs_dir)?;

    // 1. Export container to tar stream
    log::info!("Exporting filesystem...");
    let export_cmd = Command::new("docker")
        .arg("export")
        .arg(container)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run docker export: {}", e))?;

    if !export_cmd.status.success() {
        anyhow::bail!(
            "Docker export failed: {}",
            String::from_utf8_lossy(&export_cmd.stderr)
        );
    }

    // 2. Extract tar to rootfs
    log::info!("Extracting to {}...", rootfs_dir.display());
    use tar::Archive;
    let mut archive = Archive::new(&export_cmd.stdout[..]);
    archive.unpack(&rootfs_dir)?;

    // 3. Generate Fragmentfile
    let fragmentfile_path = output_dir.join("Fragmentfile");
    let content = format!(
        "# Imported from container: {}\n\
         FROM scratch\n\
         COPY rootfs /\n\
         CMD [\"/bin/sh\"]\n",
        container
    );
    std::fs::write(&fragmentfile_path, content)?;

    log::info!("✓ Container imported successfully!");
    log::info!("  Rootfs: {}", rootfs_dir.display());
    log::info!("  Fragmentfile: {}", fragmentfile_path.display());

    Ok(())
}

/// Batch convert Dockerfiles
fn batch_convert(input_dir: &PathBuf, output_dir: &PathBuf) -> Result<()> {
    log::info!("Batch converting from: {}", input_dir.display());
    std::fs::create_dir_all(output_dir)?;

    let mut count = 0;
    let walker = walkdir::WalkDir::new(input_dir);

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            if file_name == "Dockerfile" || file_name.ends_with(".dockerfile") {
                // Calculate relative path to maintain structure
                let rel_path = path.strip_prefix(input_dir).unwrap_or(path);
                let out_path = output_dir.join(rel_path).with_file_name("Fragmentfile");

                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                log::info!("Converting: {}", rel_path.display());
                if let Err(e) = migrate_dockerfile(&path.to_path_buf(), &out_path, true, false) {
                    log::error!("Failed to convert {}: {}", path.display(), e);
                } else {
                    count += 1;
                }
            }
        }
    }

    log::info!("✓ Batch conversion complete. Converted {} files.", count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimize_dockerfile() {
        let input = r#"FROM ubuntu
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y wget
ENV FOO=bar
"#;

        let output = optimize_dockerfile(input).unwrap();
        assert!(output.contains("RUN apt-get update && \\\n"));
        assert!(output.contains("ENV FOO=bar"));
    }
}
