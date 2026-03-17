//! Test helpers and utilities for integration tests

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

/// Test environment for isolated testing
/// These helpers are kept for future CLI integration tests
#[allow(dead_code)]
#[allow(dead_code)]
pub struct TestEnv {
    pub temp_dir: TempDir,
    pub phantom_cli: PathBuf,
}

#[allow(dead_code)]
impl TestEnv {
    /// Create a new test environment
    pub fn new() -> io::Result<Self> {
        let temp_dir = TempDir::new()?;
        let phantom_cli = Self::find_phantom_cli()?;

        Ok(Self {
            temp_dir,
            phantom_cli,
        })
    }

    /// Find the phantom-cli binary
    fn find_phantom_cli() -> io::Result<PathBuf> {
        // Try release build first, then debug
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Workspace root not found"))?
            .to_path_buf();

        let release_path = workspace_root.join("target/release/phantom");
        if release_path.exists() {
            return Ok(release_path);
        }

        let debug_path = workspace_root.join("target/debug/phantom");
        if debug_path.exists() {
            return Ok(debug_path);
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "phantom-cli binary not found. Run 'cargo build' first.",
        ))
    }

    /// Get path to temp directory
    pub fn temp_path(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Create a test file with specific size
    pub fn create_test_file(&self, name: &str, size_mb: usize) -> io::Result<PathBuf> {
        let path = self.temp_dir.path().join(name);
        create_file_with_size(&path, size_mb * 1024 * 1024)?;
        Ok(path)
    }

    /// Run phantom CLI command
    pub fn run_cli(&self, args: &[&str]) -> io::Result<Output> {
        Command::new(&self.phantom_cli).args(args).output()
    }

    /// Run phantom CLI command with environment variables
    pub fn run_cli_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> io::Result<Output> {
        let mut cmd = Command::new(&self.phantom_cli);
        cmd.args(args);
        for (key, val) in env {
            cmd.env(key, val);
        }
        cmd.output()
    }
}

/// Create a file with specific size filled with pattern
pub fn create_file_with_size(path: &Path, size_bytes: usize) -> io::Result<()> {
    let mut file = File::create(path)?;

    // Write in chunks for efficiency
    let chunk_size = 1024 * 1024; // 1MB chunks
    let pattern: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();

    let full_chunks = size_bytes / chunk_size;
    let remainder = size_bytes % chunk_size;

    for _ in 0..full_chunks {
        file.write_all(&pattern)?;
    }

    if remainder > 0 {
        file.write_all(&pattern[..remainder])?;
    }

    file.sync_all()?;
    Ok(())
}

/// Check if a kernel feature is available
pub fn has_kernel_feature(feature: &str) -> bool {
    match feature {
        "landlock" => {
            // Check if landlock is supported
            Path::new("/sys/kernel/security/landlock").exists()
        }
        "bpf" => {
            // Check if BPF is supported
            Path::new("/sys/fs/bpf").exists()
        }
        "io_uring" => {
            // Check if io_uring is supported (kernel 5.1+)
            let version = fs::read_to_string("/proc/version").unwrap_or_default();
            version.contains("Linux version 5.") || version.contains("Linux version 6.")
        }
        "user_namespaces" => {
            // Check if user namespaces are enabled
            fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
                .map(|s| s.trim() == "1")
                .unwrap_or(false)
                || fs::read_to_string("/proc/sys/user/max_user_namespaces")
                    .map(|s| s.trim() != "0")
                    .unwrap_or(true)
        }
        _ => false,
    }
}

/// Find a large file on the system (for testing)
pub fn find_large_system_file(min_size_mb: usize) -> Option<PathBuf> {
    // Common locations for large files
    let candidates = vec![
        "/usr/lib/x86_64-linux-gnu/libLLVM-*.so*",
        "/usr/lib/libLLVM*.so*",
        "/usr/share/icons/*/icon-theme.cache",
        "/var/cache/apt/archives/*.deb",
    ];

    for pattern in candidates {
        if let Ok(entries) = glob::glob(pattern) {
            for entry in entries.flatten() {
                if let Ok(metadata) = fs::metadata(&entry) {
                    if metadata.len() >= (min_size_mb * 1024 * 1024) as u64 {
                        return Some(entry);
                    }
                }
            }
        }
    }

    None
}

/// Download a file from URL (for future tests)
#[allow(dead_code)]
pub fn download_file(url: &str, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let response = reqwest::blocking::get(url)?;
    let bytes = response.bytes()?;
    let mut file = File::create(dest)?;
    file.write_all(&bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_file_with_size() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.bin");

        create_file_with_size(&path, 1024 * 1024).unwrap(); // 1MB

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 1024 * 1024);
    }

    #[test]
    fn test_kernel_features() {
        // Just check that the function doesn't panic
        let _ = has_kernel_feature("landlock");
        let _ = has_kernel_feature("bpf");
        let _ = has_kernel_feature("io_uring");
        let _ = has_kernel_feature("user_namespaces");
    }
}
