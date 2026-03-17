use anyhow::{Context, Result};
use health_rs::is_process_alive;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::config::PhantomPaths;

/// File lock wrapper for atomic pool operations
struct PoolLock {
    file: File,
    _path: PathBuf,
}

impl PoolLock {
    fn acquire(path: &PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("Failed to open lock file: {:?}", path))?;

        // Acquire exclusive lock
        fs2::FileExt::lock_exclusive(&file)
            .with_context(|| format!("Failed to acquire lock: {:?}", path))?;

        Ok(Self {
            file,
            _path: path.clone(),
        })
    }
}

impl Drop for PoolLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentPoolMeta {
    pub image: String,
    pub rootfs_path: String,
    pub pool_size: usize,
    pub available_pids: Vec<u32>,
    pub busy_pids: Vec<u32>,
    pub created_at: u64,
    pub last_used: u64,
    /// Whether zygote pool is enabled for ultra-fast spawning
    #[serde(default)]
    pub zygote_enabled: bool,
}

pub struct FragmentPool {
    pool_path: PathBuf,
    meta: FragmentPoolMeta,
}

impl FragmentPool {
    pub fn new_with_pids(image: String, rootfs_path: String, pids: Vec<u32>) -> Result<Self> {
        let paths = PhantomPaths::new();
        let pool_path = paths.fragment_pools().join(sanitize_image_name(&image));

        if let Some(parent) = pool_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create fragment pool directory: {:?}", parent)
            })?;
        }

        let pool_size = pids.len();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let meta = FragmentPoolMeta {
            image,
            rootfs_path,
            pool_size,
            available_pids: pids,
            busy_pids: Vec::new(),
            created_at: now,
            last_used: now,
            zygote_enabled: false,
        };
        let pool = Self { pool_path, meta };
        pool.save()?;

        Ok(pool)
    }

    pub fn load(image: &str) -> Result<Self> {
        let paths = PhantomPaths::new();
        let pool_path = paths.fragment_pools().join(sanitize_image_name(image));
        let meta_path = pool_path.join("meta.json");

        if !meta_path.exists() {
            return Err(anyhow::anyhow!(
                "Fragment pool not found for image: {}",
                image
            ));
        }

        let data = fs::read_to_string(&meta_path)?;
        let meta: FragmentPoolMeta = serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse fragment pool meta: {:?}", meta_path))?;

        Ok(Self { pool_path, meta })
    }

    pub fn get_pool(&self) -> &FragmentPoolMeta {
        &self.meta
    }

    pub fn get_pool_mut(&mut self) -> &mut FragmentPoolMeta {
        &mut self.meta
    }

    pub fn release_pid(&mut self, pid: u32) -> Result<()> {
        if let Some(pos) = self.meta.busy_pids.iter().position(|&p| p == pid) {
            self.meta.busy_pids.remove(pos);
            self.meta.available_pids.push(pid);
            self.update_last_used();
            self.save()?;
        }
        Ok(())
    }

    pub fn acquire_pid(&mut self) -> Option<u32> {
        // Try to acquire a live PID
        while let Some(pid) = self.meta.available_pids.pop() {
            // Check if process is still alive
            if is_process_alive(pid) {
                self.meta.busy_pids.push(pid);
                self.update_last_used();
                let _ = self.save();
                return Some(pid);
            } else {
                // Process is dead, log and continue to next
                log::warn!("Daemon PID {} is dead, removing from pool", pid);
            }
        }
        None
    }

    pub fn list() -> Result<Vec<FragmentPoolMeta>> {
        let paths = PhantomPaths::new();
        let pools_dir = paths.fragment_pools();

        if !pools_dir.exists() {
            return Ok(Vec::new());
        }

        let mut pools = Vec::new();

        for entry in fs::read_dir(pools_dir)? {
            let entry = entry?;
            let meta_path = entry.path().join("meta.json");

            if meta_path.exists() {
                let data = fs::read_to_string(&meta_path)?;
                let meta: FragmentPoolMeta = serde_json::from_str(&data)?;
                pools.push(meta);
            }
        }

        Ok(pools)
    }

    pub fn remove(image: &str) -> Result<()> {
        let paths = PhantomPaths::new();
        let pool_dir = paths.fragment_pools().join(sanitize_image_name(image));

        if pool_dir.exists() {
            fs::remove_dir_all(&pool_dir)
                .with_context(|| format!("Failed to remove fragment pool: {:?}", pool_dir))?;
        }

        Ok(())
    }

    pub fn remove_all() -> Result<()> {
        let paths = PhantomPaths::new();
        let pools_dir = paths.fragment_pools();

        if pools_dir.exists() {
            fs::remove_dir_all(&pools_dir)
                .with_context(|| format!("Failed to remove all fragment pools: {:?}", pools_dir))?;
        }

        Ok(())
    }

    fn save(&self) -> Result<()> {
        let meta_path = self.pool_path.join("meta.json");
        let lock_path = self.pool_path.join(".meta.lock");

        // Acquire lock before writing
        let _lock = PoolLock::acquire(&lock_path)?;

        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create fragment pool directory: {:?}", parent)
            })?;
        }

        let data = serde_json::to_string_pretty(&self.meta)
            .context("Failed to serialize fragment pool meta")?;

        // Write to temp file first, then rename for atomicity
        let temp_path = meta_path.with_extension("json.tmp");
        let mut temp_file = File::create(&temp_path)?;
        temp_file.write_all(data.as_bytes())?;
        temp_file.sync_all()?;

        // Atomic rename
        fs::rename(&temp_path, &meta_path)
            .with_context(|| format!("Failed to rename fragment pool meta: {:?}", meta_path))?;

        Ok(())
    }

    fn update_last_used(&mut self) {
        self.meta.last_used = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

fn sanitize_image_name(image: &str) -> String {
    image
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
