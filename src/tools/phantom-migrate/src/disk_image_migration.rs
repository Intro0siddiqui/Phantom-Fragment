//! Disk image format conversion for container rootfs extraction
//!
//! Supports extracting container rootfs from disk image formats:
//! - QCOW2 images (QEMU disk format)
//! - VMDK images (VMware disk format)
//!
//! These disk image formats may contain a Linux rootfs that can be extracted
//! and used as a container image. This is filesystem extraction, not VM migration.

use anyhow::{Context, Result};
use std::path::Path;

/// Disk image format
#[derive(Debug, Clone)]
pub enum DiskImageFormat {
    QCOW2,
    VMDK,
}

/// Disk image migration configuration
#[derive(Debug, Clone)]
pub struct DiskImageMigrationConfig {
    pub source_path: String,
    pub output_fragmentfile: String,
    pub base_image: Option<String>,
}

// ============================================================================
// QCOW2 Image Extraction
// ============================================================================

/// Extract container rootfs from QCOW2 disk image
pub fn extract_qcow2(config: &DiskImageMigrationConfig) -> Result<()> {
    log::info!("Extracting rootfs from QCOW2 image: {}", config.source_path);

    let source_path = Path::new(&config.source_path);

    // 1. Check for qemu-img tool
    check_qemu_img()?;

    // 2. Convert QCOW2 to raw format
    let raw_path = source_path.with_extension("raw");
    log::info!("Converting QCOW2 to raw format: {}", raw_path.display());
    convert_qcow2_to_raw(source_path, &raw_path)?;

    // 3. Extract root filesystem from raw image
    let rootfs_dir = source_path.with_extension("");
    let rootfs_dir = rootfs_dir.join("rootfs");
    log::info!("Extracting root filesystem to: {}", rootfs_dir.display());
    extract_rootfs_from_raw(&raw_path, &rootfs_dir)?;

    // 4. Generate Fragmentfile
    generate_fragmentfile_from_rootfs(
        &config.output_fragmentfile,
        &rootfs_dir,
        config.base_image.as_deref(),
        "QCOW2",
    )?;

    // 5. Clean up temporary raw file (optional - keep for debugging)
    log::info!("Temporary raw image: {}", raw_path.display());
    log::info!("You can delete it with: rm {}", raw_path.display());

    log::info!("Generated Fragmentfile at: {}", config.output_fragmentfile);
    log::info!("  Rootfs: {}", rootfs_dir.display());

    Ok(())
}

// ============================================================================
// VMDK Image Extraction
// ============================================================================

/// Extract container rootfs from VMDK disk image
pub fn extract_vmdk(config: &DiskImageMigrationConfig) -> Result<()> {
    log::info!("Extracting rootfs from VMDK image: {}", config.source_path);

    let source_path = Path::new(&config.source_path);

    // 1. Check for qemu-img tool
    check_qemu_img()?;

    // 2. Convert VMDK to raw format
    let raw_path = source_path.with_extension("raw");
    log::info!("Converting VMDK to raw format: {}", raw_path.display());
    convert_vmdk_to_raw(source_path, &raw_path)?;

    // 3. Extract root filesystem from raw image
    let rootfs_dir = source_path.with_extension("");
    let rootfs_dir = rootfs_dir.join("rootfs");
    log::info!("Extracting root filesystem to: {}", rootfs_dir.display());
    extract_rootfs_from_raw(&raw_path, &rootfs_dir)?;

    // 4. Generate Fragmentfile
    generate_fragmentfile_from_rootfs(
        &config.output_fragmentfile,
        &rootfs_dir,
        config.base_image.as_deref(),
        "VMDK",
    )?;

    // 5. Clean up temporary raw file (optional - keep for debugging)
    log::info!("Temporary raw image: {}", raw_path.display());
    log::info!("You can delete it with: rm {}", raw_path.display());

    log::info!("Generated Fragmentfile at: {}", config.output_fragmentfile);
    log::info!("  Rootfs: {}", rootfs_dir.display());

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if qemu-img is available
fn check_qemu_img() -> Result<()> {
    use std::process::Command;

    let result = Command::new("qemu-img").arg("--version").output();

    match result {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            log::info!(
                "qemu-img found: {}",
                version.lines().next().unwrap_or("unknown")
            );
            Ok(())
        }
        Ok(output) => Err(anyhow::anyhow!(
            "qemu-img failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )),
        Err(e) => Err(anyhow::anyhow!(
            "qemu-img not found. Please install qemu-utils package.\n\
                 On Debian/Ubuntu: sudo apt-get install qemu-utils\n\
                 On Fedora: sudo dnf install qemu-img\n\
                 On Arch: sudo pacman -S qemu-tools\n\
                 Error: {}",
            e
        )),
    }
}

/// Convert QCOW2 image to raw format
fn convert_qcow2_to_raw(source: &Path, dest: &Path) -> Result<()> {
    use std::process::Command;

    let status = Command::new("qemu-img")
        .args(["convert", "-f", "qcow2", "-O", "raw"])
        .arg(source)
        .arg(dest)
        .status()
        .context("Failed to run qemu-img convert")?;

    if !status.success() {
        anyhow::bail!("qemu-img convert failed with status: {}", status);
    }

    log::info!("QCOW2 converted to raw successfully");
    Ok(())
}

/// Convert VMDK image to raw format
fn convert_vmdk_to_raw(source: &Path, dest: &Path) -> Result<()> {
    use std::process::Command;

    let status = Command::new("qemu-img")
        .args(["convert", "-f", "vmdk", "-O", "raw"])
        .arg(source)
        .arg(dest)
        .status()
        .context("Failed to run qemu-img convert")?;

    if !status.success() {
        anyhow::bail!("qemu-img convert failed with status: {}", status);
    }

    log::info!("VMDK converted to raw successfully");
    Ok(())
}

/// Extract root filesystem from raw disk image
/// This function attempts to mount the raw image and copy the root filesystem
fn extract_rootfs_from_raw(raw_path: &Path, rootfs_dir: &Path) -> Result<()> {
    use std::fs;

    // Create rootfs directory
    fs::create_dir_all(rootfs_dir).context(format!(
        "Failed to create rootfs directory: {}",
        rootfs_dir.display()
    ))?;

    // Try to use guestfish for extraction (preferred method)
    if which::which("guestfish").is_ok() {
        log::info!("Using guestfish for rootfs extraction...");
        return extract_rootfs_with_guestfish(raw_path, rootfs_dir);
    }

    // Fallback: Try to mount the raw image
    log::info!("guestfish not found, trying mount-based extraction...");
    extract_rootfs_with_mount(raw_path, rootfs_dir)
}

/// Extract rootfs using guestfish (libguestfs)
fn extract_rootfs_with_guestfish(raw_path: &Path, rootfs_dir: &Path) -> Result<()> {
    use std::process::Command;

    // Use guestfish to list filesystems
    let output = Command::new("guestfish")
        .args(["--ro", "-a", raw_path.to_str().unwrap(), "-i"])
        .arg("list-filesystems")
        .output()
        .context("Failed to run guestfish list-filesystems")?;

    if !output.status.success() {
        anyhow::bail!(
            "guestfish failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let filesystems = String::from_utf8_lossy(&output.stdout);
    log::info!("Found filesystems:\n{}", filesystems);

    // Find the root filesystem (usually /dev/sda1 or similar)
    let root_device = filesystems
        .lines()
        .find(|line| line.contains("/"))
        .map(|line| line.split(':').next().unwrap_or(""))
        .unwrap_or("");

    if root_device.is_empty() {
        anyhow::bail!("Could not find root filesystem in image");
    }

    log::info!("Using root device: {}", root_device);

    // Extract the filesystem using guestfish tar command
    let tar_output = Command::new("guestfish")
        .args(["--ro", "-a", raw_path.to_str().unwrap(), "-i"])
        .args(["tar-out", "/", rootfs_dir.to_str().unwrap()])
        .output()
        .context("Failed to run guestfish tar-out")?;

    if !tar_output.status.success() {
        anyhow::bail!(
            "guestfish tar-out failed: {}",
            String::from_utf8_lossy(&tar_output.stderr)
        );
    }

    log::info!("Rootfs extracted successfully using guestfish");
    Ok(())
}

/// Extract rootfs by mounting the raw image (fallback method)
fn extract_rootfs_with_mount(raw_path: &Path, rootfs_dir: &Path) -> Result<()> {
    use nix::mount::{mount, umount2, MntFlags};
    use nix::unistd::geteuid;
    use std::fs;
    use std::process::Command;

    // Check if running as root
    if !geteuid().is_root() {
        return Err(anyhow::anyhow!(
            "Mount-based extraction requires root privileges. Please run with sudo.\n\
             Alternatively, install guestfish (libguestfs-tools) for rootless extraction."
        ));
    }

    // Create mount point
    let mount_point = raw_path.with_extension("mount");
    fs::create_dir_all(&mount_point).context(format!(
        "Failed to create mount point: {}",
        mount_point.display()
    ))?;

    // Find partitions in the raw image
    log::info!("Scanning for partitions in raw image...");

    // Use losetup to create a loop device
    let loop_output = Command::new("losetup")
        .args(["-f", "--show", "-P", raw_path.to_str().unwrap()])
        .output()
        .context("Failed to setup loop device")?;

    if !loop_output.status.success() {
        anyhow::bail!(
            "losetup failed: {}",
            String::from_utf8_lossy(&loop_output.stderr)
        );
    }

    let loop_device = String::from_utf8_lossy(&loop_output.stdout)
        .trim()
        .to_string();
    log::info!("Loop device: {}", loop_device);

    // Cleanup function
    let cleanup = || {
        let _ = Command::new("losetup").args(["-d", &loop_device]).status();
        let _ = umount2(&mount_point, MntFlags::MNT_DETACH);
        let _ = fs::remove_dir_all(&mount_point);
    };

    // Try to mount partitions
    let mut mounted = false;
    for partition_suffix in &["p1", "1", "p2", "2", "p3", "3"] {
        let partition = format!("{}{}", loop_device, partition_suffix);
        log::info!("Trying to mount: {}", partition);

        let mount_result = mount(
            Some(partition.as_str()),
            &mount_point,
            Some("auto"),
            nix::mount::MsFlags::MS_RDONLY,
            Some(""),
        );

        if mount_result.is_ok() {
            log::info!("Successfully mounted: {}", partition);
            mounted = true;

            // Copy rootfs
            let copy_result = Command::new("cp")
                .args([
                    "-a",
                    &mount_point.to_string_lossy(),
                    &rootfs_dir.to_string_lossy(),
                ])
                .status();

            match copy_result {
                Ok(status) if status.success() => {
                    log::info!("Rootfs copied successfully");
                }
                _ => {
                    cleanup();
                    anyhow::bail!("Failed to copy rootfs");
                }
            }

            break;
        }
    }

    if !mounted {
        cleanup();
        anyhow::bail!("Could not find a mountable partition in the raw image");
    }

    // Cleanup
    cleanup();
    log::info!("Mount point cleaned up");

    Ok(())
}

/// Generate Fragmentfile from extracted rootfs
fn generate_fragmentfile_from_rootfs(
    output_path: &str,
    rootfs_dir: &Path,
    base_image: Option<&str>,
    source_type: &str,
) -> Result<()> {
    use std::fs;

    let base = base_image.unwrap_or("scratch");

    // Try to detect the OS from the rootfs
    let os_info = detect_os_from_rootfs(rootfs_dir);

    let mut fragment_content = String::new();
    fragment_content.push_str(&format!("# Imported from {} image\n", source_type));
    fragment_content.push_str(&format!("# Source: {}\n", rootfs_dir.display()));

    if let Some((os_name, os_version)) = &os_info {
        fragment_content.push_str(&format!("# Detected OS: {} {}\n", os_name, os_version));
    }

    fragment_content.push_str(&format!("FROM {}\n", base));
    fragment_content.push_str(&format!("COPY {} /\n", rootfs_dir.display()));

    // Add detected init system
    if let Some(init) = detect_init_system(rootfs_dir) {
        fragment_content.push_str(&format!("CMD [\"{}\"]\n", init));
    } else {
        fragment_content.push_str("CMD [\"/bin/sh\"]\n");
    }

    // Add labels
    if let Some((os_name, os_version)) = &os_info {
        fragment_content.push_str(&format!("LABEL org.phantom.os=\"{}\"\n", os_name));
        if !os_version.is_empty() {
            fragment_content.push_str(&format!(
                "LABEL org.phantom.os.version=\"{}\"\n",
                os_version
            ));
        }
    }
    fragment_content.push_str(&format!("LABEL org.phantom.source=\"{}\"\n", source_type));

    fs::write(output_path, fragment_content).context("Failed to write Fragmentfile")?;

    Ok(())
}

/// Detect OS from rootfs by reading /etc/os-release or similar files
fn detect_os_from_rootfs(rootfs: &Path) -> Option<(String, String)> {
    use std::fs;

    // Try /etc/os-release first (systemd-based systems)
    let os_release_path = rootfs.join("etc/os-release");
    if let Ok(content) = fs::read_to_string(&os_release_path) {
        let mut name = String::new();
        let mut version = String::new();

        for line in content.lines() {
            if let Some(value) = line.strip_prefix("NAME=") {
                name = value.trim_matches('"').to_string();
            } else if let Some(value) = line.strip_prefix("VERSION=") {
                version = value.trim_matches('"').to_string();
            } else if let Some(value) = line.strip_prefix("VERSION_ID=") {
                if version.is_empty() {
                    version = value.trim_matches('"').to_string();
                }
            }
        }

        if !name.is_empty() {
            return Some((name, version));
        }
    }

    // Try /etc/lsb-release (Debian/Ubuntu)
    let lsb_release_path = rootfs.join("etc/lsb-release");
    if let Ok(content) = fs::read_to_string(&lsb_release_path) {
        let mut name = String::new();
        let mut version = String::new();

        for line in content.lines() {
            if let Some(value) = line.strip_prefix("DISTRIB_DESCRIPTION=") {
                name = value.trim_matches('"').to_string();
            } else if let Some(value) = line.strip_prefix("DISTRIB_RELEASE=") {
                version = value.trim_matches('"').to_string();
            }
        }

        if !name.is_empty() {
            return Some((name, version));
        }
    }

    // Try /etc/redhat-release (RHEL/CentOS)
    let redhat_release_path = rootfs.join("etc/redhat-release");
    if let Ok(content) = fs::read_to_string(&redhat_release_path) {
        return Some((content.trim().to_string(), String::new()));
    }

    // Try /etc/alpine-release (Alpine)
    let alpine_release_path = rootfs.join("etc/alpine-release");
    if let Ok(content) = fs::read_to_string(&alpine_release_path) {
        return Some(("Alpine Linux".to_string(), content.trim().to_string()));
    }

    None
}

/// Detect init system from rootfs
fn detect_init_system(rootfs: &Path) -> Option<String> {
    // Check for systemd
    if rootfs.join("usr/lib/systemd/systemd").exists()
        || rootfs.join("lib/systemd/systemd").exists()
    {
        return Some("/usr/lib/systemd/systemd".to_string());
    }

    // Check for sysvinit
    if rootfs.join("sbin/init").exists() {
        return Some("/sbin/init".to_string());
    }

    // Check for busybox
    if rootfs.join("bin/busybox").exists() {
        return Some("/bin/busybox".to_string());
    }

    // Check for sh
    if rootfs.join("bin/sh").exists() {
        return Some("/bin/sh".to_string());
    }

    None
}

// ============================================================================
// Format Detection
// ============================================================================

/// Detect disk image format from file extension
pub fn detect_disk_image_format(path: &Path) -> Option<DiskImageFormat> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .and_then(|ext| match ext.to_lowercase().as_str() {
            "qcow2" | "qcow" => Some(DiskImageFormat::QCOW2),
            "vmdk" => Some(DiskImageFormat::VMDK),
            _ => None,
        })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_detect_qcow2_format() {
        let path = PathBuf::from("disk.qcow2");
        let format = detect_disk_image_format(&path);
        assert!(matches!(format, Some(DiskImageFormat::QCOW2)));
    }

    #[test]
    fn test_detect_vmdk_format() {
        let path = PathBuf::from("disk.vmdk");
        let format = detect_disk_image_format(&path);
        assert!(matches!(format, Some(DiskImageFormat::VMDK)));
    }

    #[test]
    fn test_detect_unknown_format() {
        let path = PathBuf::from("disk.iso");
        let format = detect_disk_image_format(&path);
        assert!(format.is_none());
    }
}
