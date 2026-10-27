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
            .truncate(false)
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
        let pool_path = pool_dir(&image);

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
        let pool_path = pool_dir(image);
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

    /// Purge a dead or unresponsive PID slot from the pool completely
    pub fn purge_pid(&mut self, pid: u32) -> Result<()> {
        if let Some(pos) = self.meta.busy_pids.iter().position(|&p| p == pid) {
            self.meta.busy_pids.remove(pos);
        }
        if let Some(pos) = self.meta.available_pids.iter().position(|&p| p == pid) {
            self.meta.available_pids.remove(pos);
        }
        // Force kill dead process if still lingering
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        );
        self.save()?;
        Ok(())
    }

    /// Resolve the Unix socket belonging to the daemon that owns `pid`.
    ///
    /// Each daemon started by `phantom warm create` gets its own socket
    /// (`daemon_<n>.sock`) next to its PID file. Pools created by older
    /// versions have a single shared `socket.path`, so fall back to that.
    pub fn socket_path_for_pid(&self, pid: u32) -> Option<PathBuf> {
        if let Ok(entries) = fs::read_dir(&self.pool_path) {
            for entry in entries.flatten() {
                let pid_file = entry.path();
                if pid_file.extension().and_then(|s| s.to_str()) != Some("pid") {
                    continue;
                }
                let recorded = match fs::read_to_string(&pid_file) {
                    Ok(recorded) => recorded,
                    Err(_) => continue,
                };
                if recorded.trim().parse::<u32>().ok() != Some(pid) {
                    continue;
                }
                let socket = pid_file.with_extension("sock");
                if socket.exists() {
                    return Some(socket);
                }
            }
        }

        // Legacy single-socket layout.
        let legacy = fs::read_to_string(self.pool_path.join("socket.path")).ok()?;
        let socket = PathBuf::from(legacy.trim());
        if socket.exists() {
            Some(socket)
        } else {
            None
        }
    }

    pub fn acquire_pid(&mut self) -> Option<u32> {
        // Try to acquire a live PID whose own socket is healthy
        while let Some(pid) = self.meta.available_pids.pop() {
            let mut is_healthy = is_process_alive(pid);

            // Health-check *this* daemon's socket. The previous code always
            // pinged the single `socket.path`, i.e. it validated whichever
            // daemon owned that path rather than the PID being handed out.
            if is_healthy {
                match self.socket_path_for_pid(pid) {
                    Some(socket) => {
                        if let Ok(responsive) = crate::daemon::ping_daemon(&socket) {
                            if !responsive {
                                is_healthy = false;
                            }
                        }
                    }
                    None => {
                        log::warn!("No socket found for daemon PID {}, purging from pool", pid);
                        is_healthy = false;
                    }
                }
            }

            if is_healthy {
                self.meta.busy_pids.push(pid);
                self.update_last_used();
                let _ = self.save();
                return Some(pid);
            } else {
                log::warn!("Daemon PID {} is dead/unresponsive, purging from pool", pid);
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = self.save();
            }
        }
        None
    }

    pub fn list() -> Result<Vec<FragmentPoolMeta>> {
        let pools_dir = PhantomPaths::new().fragment_pools();

        if !pools_dir.exists() {
            return Ok(Vec::new());
        }

        let mut pools = Vec::new();

        for entry in fs::read_dir(pools_dir)? {
            let entry = entry?;
            let meta_path = entry.path().join("meta.json");

            if !meta_path.exists() {
                continue;
            }

            // A single corrupt pool must not hide every other pool.
            let data = match fs::read_to_string(&meta_path) {
                Ok(data) => data,
                Err(e) => {
                    log::warn!("Skipping unreadable fragment pool {:?}: {}", meta_path, e);
                    continue;
                }
            };
            match serde_json::from_str::<FragmentPoolMeta>(&data) {
                Ok(meta) => pools.push(meta),
                Err(e) => {
                    log::warn!("Skipping corrupt fragment pool {:?}: {}", meta_path, e);
                }
            }
        }

        Ok(pools)
    }

    pub fn remove(image: &str) -> Result<()> {
        let dir = pool_dir(image);

        if dir.exists() {
            fs::remove_dir_all(&dir)
                .with_context(|| format!("Failed to remove fragment pool: {:?}", dir))?;
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

    #[cfg(test)]
    fn with_meta(pool_path: PathBuf, meta: FragmentPoolMeta) -> Self {
        Self { pool_path, meta }
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

/// Directory containing a pool's metadata, PID files and sockets.
///
/// Image references such as `library/alpine:latest` must be sanitized the same
/// way everywhere; callers that build the path by hand end up looking in the
/// wrong directory and silently fall back to cold execution.
pub(crate) fn pool_dir(image: &str) -> PathBuf {
    PhantomPaths::new()
        .fragment_pools()
        .join(sanitize_image_name(image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_meta(available_pids: Vec<u32>) -> FragmentPoolMeta {
        FragmentPoolMeta {
            image: "alpine".to_string(),
            rootfs_path: "/tmp/rootfs".to_string(),
            pool_size: available_pids.len(),
            available_pids,
            busy_pids: Vec::new(),
            created_at: 0,
            last_used: 0,
            zygote_enabled: false,
        }
    }

    /// Spawn and reap a child, returning a PID that is known to be dead.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("failed to spawn helper process");
        let pid = child.id();
        child.wait().expect("failed to reap helper process");
        pid
    }

    #[test]
    fn socket_path_for_pid_uses_per_daemon_socket() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();

        fs::write(dir.join("daemon_0.pid"), "1234").unwrap();
        fs::write(dir.join("daemon_0.sock"), "").unwrap();
        fs::write(dir.join("daemon_1.pid"), "5678").unwrap();
        fs::write(dir.join("daemon_1.sock"), "").unwrap();

        let pool = FragmentPool::with_meta(dir.clone(), test_meta(vec![1234, 5678]));

        assert_eq!(
            pool.socket_path_for_pid(1234),
            Some(dir.join("daemon_0.sock"))
        );
        assert_eq!(
            pool.socket_path_for_pid(5678),
            Some(dir.join("daemon_1.sock"))
        );
        assert_eq!(pool.socket_path_for_pid(9999), None);
    }

    #[test]
    fn socket_path_for_pid_falls_back_to_legacy_socket_path() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();
        let legacy_socket = dir.join("legacy.sock");
        fs::write(&legacy_socket, "").unwrap();
        fs::write(
            dir.join("socket.path"),
            legacy_socket.to_string_lossy().as_bytes(),
        )
        .unwrap();

        let pool = FragmentPool::with_meta(dir, test_meta(vec![42]));

        assert_eq!(pool.socket_path_for_pid(42), Some(legacy_socket));
    }

    #[test]
    fn save_writes_complete_meta_atomically() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();
        let pool = FragmentPool::with_meta(dir.clone(), test_meta(vec![7, 8]));

        pool.save().unwrap();

        let data = fs::read_to_string(dir.join("meta.json")).unwrap();
        let parsed: FragmentPoolMeta = serde_json::from_str(&data).unwrap();
        assert_eq!(parsed.available_pids, vec![7, 8]);

        // The temporary file must not be left behind.
        assert!(!dir.join("meta.json.tmp").exists());
    }

    #[test]
    fn acquire_pid_purges_dead_pid_without_socket() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();
        let pid = dead_pid();

        let mut pool = FragmentPool::with_meta(dir.clone(), test_meta(vec![pid]));

        assert_eq!(pool.acquire_pid(), None);
        assert!(pool.meta.available_pids.is_empty());
        assert!(pool.meta.busy_pids.is_empty());

        // The purge must be persisted, not just applied in memory.
        let data = fs::read_to_string(dir.join("meta.json")).unwrap();
        let parsed: FragmentPoolMeta = serde_json::from_str(&data).unwrap();
        assert!(parsed.available_pids.is_empty());
    }
}
