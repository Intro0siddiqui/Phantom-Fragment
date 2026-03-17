use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const PROOT_URL: &str =
    "https://github.com/proot-me/proot-static-build/raw/master/static/proot-x86_64";
const PROOT_SHA256: &str = "a8c0b6b9c5e4f7a2d8b3c1e0f9a2d4b6c8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8";

pub struct ProotManager {
    bin_path: PathBuf,
}

impl ProotManager {
    pub fn new() -> Result<Self> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .context("Failed to determine home directory")?;

        let bin_dir = PathBuf::from(home).join(".phantom").join("bin");
        fs::create_dir_all(&bin_dir)?;

        Ok(Self {
            bin_path: bin_dir.join("proot"),
        })
    }

    pub fn get_proot_path(&self) -> PathBuf {
        self.bin_path.clone()
    }

    pub async fn ensure_proot(&self) -> Result<PathBuf> {
        if self.bin_path.exists() {
            return Ok(self.bin_path.clone());
        }

        log::info!("Downloading proot binary from {}...", PROOT_URL);

        let temp_path = self.bin_path.with_extension("tmp");

        let status = Command::new("curl")
            .arg("-L")
            .arg("-o")
            .arg(&temp_path)
            .arg(PROOT_URL)
            .status()
            .context("Failed to execute curl")?;

        if !status.success() {
            std::fs::remove_file(&temp_path).ok();
            anyhow::bail!("Failed to download proot");
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
        if hash != PROOT_SHA256 {
            std::fs::remove_file(&temp_path).ok();
            anyhow::bail!(
                "Checksum mismatch for proot: expected {}, got {}",
                PROOT_SHA256,
                hash
            );
        }

        std::fs::rename(&temp_path, &self.bin_path)?;

        // Make executable
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&self.bin_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&self.bin_path, perms)?;

        log::info!("Proot installed to {}", self.bin_path.display());
        Ok(self.bin_path.clone())
    }
}
