use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const FUSE_OVERLAYFS_URL: &str =
    "https://github.com/containers/fuse-overlayfs/releases/download/v1.13/fuse-overlayfs-x86_64";
const FUSE_SHA256: &str = "b7d9c5a8d4e3f2a1c9b8d7e6f5a4c3b2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6";

pub struct FuseOverlayfsManager {
    bin_path: PathBuf,
}

impl FuseOverlayfsManager {
    pub fn new() -> Result<Self> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .context("Failed to determine home directory")?;

        let bin_dir = PathBuf::from(home).join(".phantom").join("bin");
        fs::create_dir_all(&bin_dir)?;

        Ok(Self {
            bin_path: bin_dir.join("fuse-overlayfs"),
        })
    }

    pub fn get_binary_path(&self) -> PathBuf {
        self.bin_path.clone()
    }

    pub async fn ensure_binary(&self) -> Result<PathBuf> {
        if self.bin_path.exists() {
            return Ok(self.bin_path.clone());
        }

        log::info!(
            "Downloading fuse-overlayfs binary from {}...",
            FUSE_OVERLAYFS_URL
        );

        let temp_path = self.bin_path.with_extension("tmp");

        let status = Command::new("curl")
            .arg("-L")
            .arg("-o")
            .arg(&temp_path)
            .arg(FUSE_OVERLAYFS_URL)
            .status()
            .context("Failed to execute curl")?;

        if !status.success() {
            std::fs::remove_file(&temp_path).ok();
            anyhow::bail!("Failed to download fuse-overlayfs");
        }

        let output = Command::new("sha256sum")
            .arg(&temp_path)
            .output()
            .context("Failed to compute SHA256")?;
        let hash_output = String::from_utf8_lossy(&output.stdout);
        let hash = hash_output
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to parse SHA256 hash output"))?;
        if hash != FUSE_SHA256 {
            std::fs::remove_file(&temp_path).ok();
            anyhow::bail!(
                "Checksum mismatch for fuse-overlayfs: expected {}, got {}",
                FUSE_SHA256,
                hash
            );
        }

        std::fs::rename(&temp_path, &self.bin_path)?;

        // Make executable
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&self.bin_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&self.bin_path, perms)?;

        log::info!("fuse-overlayfs installed to {}", self.bin_path.display());
        Ok(self.bin_path.clone())
    }
}
