use anyhow::{Context, Result};
use health_rs::is_process_alive;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
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
    /// Security profile the pool was built with.
    ///
    /// `None` for pools created before this was recorded. A slot is only
    /// rebuilt when the profile is known: guessing would either weaken a
    /// hardened pool or produce a fragment the caller did not ask for.
    #[serde(default)]
    pub profile: Option<String>,
    /// Lease holder for each busy slot: daemon pid -> client pid.
    ///
    /// A slot is only busy while a client is actually using it. If the client
    /// dies without releasing (SIGKILL, crash), the lease lets the next caller
    /// reclaim the slot instead of shrinking the pool permanently.
    #[serde(default)]
    pub busy_leases: HashMap<u32, u32>,
}

pub struct FragmentPool {
    pool_path: PathBuf,
    meta: FragmentPoolMeta,
}

impl FragmentPool {
    pub fn new_with_pids(
        image: String,
        rootfs_path: String,
        pids: Vec<u32>,
        profile: String,
    ) -> Result<Self> {
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
            profile: Some(profile),
            busy_leases: HashMap::new(),
        };
        let pool = Self { pool_path, meta };
        pool.save()?;

        Ok(pool)
    }

    pub fn load(image: &str) -> Result<Self> {
        Self::load_from_path(&pool_dir(image))
    }

    pub fn load_from_path(pool_path: &Path) -> Result<Self> {
        let meta_path = pool_path.join("meta.json");

        if !meta_path.exists() {
            return Err(anyhow::anyhow!(
                "Fragment pool not found at {:?}",
                meta_path
            ));
        }

        let data = fs::read_to_string(&meta_path)?;
        let meta: FragmentPoolMeta = serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse fragment pool meta: {:?}", meta_path))?;

        Ok(Self {
            pool_path: pool_path.to_path_buf(),
            meta,
        })
    }

    pub fn get_pool(&self) -> &FragmentPoolMeta {
        &self.meta
    }

    pub fn get_pool_mut(&mut self) -> &mut FragmentPoolMeta {
        &mut self.meta
    }

    pub fn release_pid(&mut self, pid: u32) -> Result<()> {
        let lock_path = self.pool_path.join(".meta.lock");
        let _lock = PoolLock::acquire(&lock_path)?;

        self.reload_locked();

        self.meta.busy_leases.remove(&pid);
        if let Some(pos) = self.meta.busy_pids.iter().position(|&p| p == pid) {
            self.meta.busy_pids.remove(pos);
            self.meta.available_pids.push(pid);
            self.update_last_used();
            self.save_locked()?;
        }
        Ok(())
    }

    /// Purge a dead or unresponsive PID slot from the pool completely
    pub fn purge_pid(&mut self, pid: u32) -> Result<()> {
        let lock_path = self.pool_path.join(".meta.lock");
        let _lock = PoolLock::acquire(&lock_path)?;

        self.reload_locked();

        self.meta.busy_leases.remove(&pid);
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
        self.save_locked()?;
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
        let lock_path = self.pool_path.join(".meta.lock");
        let _lock = PoolLock::acquire(&lock_path).ok()?;

        self.reload_locked();
        self.acquire_pid_inner()
    }

    /// Inner slot acquisition while .meta.lock is guaranteed held
    fn acquire_pid_inner(&mut self) -> Option<u32> {
        // Reclaim slots whose client died mid-request. Without this a SIGKILLed
        // `phantom run --warm` would shrink the pool by one slot forever.
        let stale: Vec<u32> = self
            .meta
            .busy_leases
            .iter()
            .filter(|(_, client)| !is_process_alive(**client))
            .map(|(daemon, _)| *daemon)
            .collect();
        for daemon_pid in stale {
            log::warn!(
                "Reclaiming warm slot {} (its client exited without releasing)",
                daemon_pid
            );
            self.meta.busy_leases.remove(&daemon_pid);
            if let Some(pos) = self.meta.busy_pids.iter().position(|&p| p == daemon_pid) {
                self.meta.busy_pids.remove(pos);
                self.meta.available_pids.push(daemon_pid);
            }
        }

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
                self.meta.busy_leases.insert(pid, std::process::id());
                self.update_last_used();
                let _ = self.save_locked();
                return Some(pid);
            } else {
                log::warn!("Daemon PID {} is dead/unresponsive, purging from pool", pid);
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = self.save_locked();
            }
        }
        None
    }

    /// Slot indices whose daemon is gone.
    ///
    /// A slot is named by its `daemon_<n>.pid` file. A missing file, an
    /// unreadable pid or a dead process all mean the pool can no longer serve
    /// from that slot, which is exactly what has to be rebuilt.
    pub fn missing_slots(&self) -> Vec<usize> {
        (0..self.meta.pool_size)
            .filter(|slot| {
                let pid_file = self.pool_path.join(format!("daemon_{}.pid", slot));
                match fs::read_to_string(&pid_file) {
                    Ok(text) => match text.trim().parse::<u32>() {
                        Ok(pid) => !is_process_alive(pid),
                        Err(_) => true,
                    },
                    Err(_) => true,
                }
            })
            .collect()
    }

    /// Record a daemon that was just started for a slot the pool had lost.
    pub fn register_pid(&mut self, pid: u32) -> Result<()> {
        let lock_path = self.pool_path.join(".meta.lock");
        let _lock = PoolLock::acquire(&lock_path)?;

        self.reload_locked();

        if !self.meta.available_pids.contains(&pid) && !self.meta.busy_pids.contains(&pid) {
            self.meta.available_pids.push(pid);
            self.save_locked()?;
        }
        Ok(())
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

    /// Reload latest metadata from disk while .meta.lock is held
    fn reload_locked(&mut self) {
        let meta_path = self.pool_path.join("meta.json");
        if let Ok(data) = fs::read_to_string(&meta_path) {
            if let Ok(fresh_meta) = serde_json::from_str::<FragmentPoolMeta>(&data) {
                self.meta = fresh_meta;
            }
        }
    }

    pub fn save(&self) -> Result<()> {
        let lock_path = self.pool_path.join(".meta.lock");
        let _lock = PoolLock::acquire(&lock_path)?;
        self.save_locked()
    }

    /// Save metadata without re-acquiring PoolLock when already held.
    fn save_locked(&self) -> Result<()> {
        let meta_path = self.pool_path.join("meta.json");

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
        // Atomic rename covers process-crash consistency; omit sync_all on hot path

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
            profile: Some("sandbox".to_string()),
            busy_leases: HashMap::new(),
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

    /// Minimal stand-in for a warm daemon: answers one health check, then exits.
    fn spawn_fake_daemon(socket: PathBuf) -> std::thread::JoinHandle<()> {
        use crate::daemon::{read_message, write_message, Message, MessageType};

        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_message(&mut stream);
                let _ = write_message(
                    &mut stream,
                    &Message::new(MessageType::HealthResponse, vec![]),
                );
            }
        })
    }

    #[test]
    fn acquire_pid_reclaims_slot_whose_client_died() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();

        // The daemon is this test process, so it is alive; its lease holder is a
        // reaped child, i.e. the client died without releasing the slot.
        let daemon_pid = std::process::id();
        let client_pid = dead_pid();

        let socket = dir.join("daemon_0.sock");
        let handle = spawn_fake_daemon(socket.clone());
        fs::write(dir.join("daemon_0.pid"), daemon_pid.to_string()).unwrap();

        let mut meta = test_meta(Vec::new());
        meta.busy_pids = vec![daemon_pid];
        meta.busy_leases = HashMap::from([(daemon_pid, client_pid)]);
        let mut pool = FragmentPool::with_meta(dir.clone(), meta);

        assert_eq!(pool.acquire_pid(), Some(daemon_pid));
        assert_eq!(pool.meta.busy_pids, vec![daemon_pid]);
        assert!(pool.meta.available_pids.is_empty());

        handle.join().unwrap();
    }

    #[test]
    fn missing_slots_reports_slots_whose_daemon_died() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();

        // Slot 0 is alive (this process), slot 1 names a reaped pid, slot 2 has
        // no pid file at all.
        fs::write(dir.join("daemon_0.pid"), std::process::id().to_string()).unwrap();
        fs::write(dir.join("daemon_1.pid"), dead_pid().to_string()).unwrap();

        let mut meta = test_meta(Vec::new());
        meta.pool_size = 3;
        let pool = FragmentPool::with_meta(dir, meta);

        assert_eq!(pool.missing_slots(), vec![1, 2]);
    }

    #[test]
    fn register_pid_persists_a_rebuilt_slot() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();
        let mut pool = FragmentPool::with_meta(dir.clone(), test_meta(Vec::new()));

        pool.register_pid(4242).unwrap();

        assert_eq!(pool.meta.available_pids, vec![4242]);
        let data = fs::read_to_string(dir.join("meta.json")).unwrap();
        let parsed: FragmentPoolMeta = serde_json::from_str(&data).unwrap();
        assert_eq!(parsed.available_pids, vec![4242]);
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

    #[test]
    fn concurrent_acquire_pid_never_hands_out_same_slot() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();

        let num_slots = 6;
        let mut pids = Vec::new();
        let mut fake_handles = Vec::new();
        let mut procs = Vec::new();

        // Spawn actual sleeping processes so `is_process_alive` returns true
        for i in 0..num_slots {
            let child = std::process::Command::new("sleep")
                .arg("10")
                .spawn()
                .expect("failed to spawn helper sleep process");
            let pid = child.id();
            procs.push(child);
            pids.push(pid);

            let socket = dir.join(format!("daemon_{}.sock", i));
            fake_handles.push(spawn_fake_daemon(socket));
            fs::write(dir.join(format!("daemon_{}.pid", i)), pid.to_string()).unwrap();
        }

        let pool = FragmentPool::with_meta(dir.clone(), test_meta(pids.clone()));
        pool.save().unwrap();

        let num_threads = 16;
        let barrier = Arc::new(Barrier::new(num_threads));
        let acquired_pids = Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut threads = Vec::new();
        for _ in 0..num_threads {
            let b = Arc::clone(&barrier);
            let results = Arc::clone(&acquired_pids);
            let pool_dir_clone = dir.clone();

            threads.push(thread::spawn(move || {
                let mut p = FragmentPool::load_from_path(&pool_dir_clone).unwrap();
                b.wait();
                if let Some(acquired) = p.acquire_pid() {
                    let mut lock = results.lock().unwrap();
                    lock.push(acquired);
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }

        let results = acquired_pids.lock().unwrap().clone();
        assert_eq!(
            results.len(),
            num_slots,
            "All available slots must be acquired, no more"
        );

        // Verify all acquired PIDs are strictly unique
        let mut unique = results.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            results.len(),
            unique.len(),
            "Concurrent acquire must never hand out the same PID twice"
        );

        for h in fake_handles {
            h.join().unwrap();
        }
        for mut p in procs {
            let _ = p.kill();
            let _ = p.wait();
        }
    }

    #[test]
    fn register_pid_reloads_under_lock_preserving_concurrent_changes() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();

        let pool = FragmentPool::with_meta(dir.clone(), test_meta(vec![100]));
        pool.save().unwrap();

        let mut pool1 = FragmentPool::load_from_path(&dir).unwrap();
        let mut pool2 = FragmentPool::load_from_path(&dir).unwrap();

        pool1.register_pid(200).unwrap();
        pool2.register_pid(300).unwrap();

        let final_pool = FragmentPool::load_from_path(&dir).unwrap();
        assert!(final_pool.meta.available_pids.contains(&100));
        assert!(final_pool.meta.available_pids.contains(&200));
        assert!(final_pool.meta.available_pids.contains(&300));
    }

    #[test]
    fn purge_pid_reloads_under_lock_preserving_concurrent_changes() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().to_path_buf();

        let pool = FragmentPool::with_meta(dir.clone(), test_meta(vec![100, 200]));
        pool.save().unwrap();

        let mut pool1 = FragmentPool::load_from_path(&dir).unwrap();
        let mut pool2 = FragmentPool::load_from_path(&dir).unwrap();

        pool1.register_pid(300).unwrap();
        pool2.purge_pid(100).unwrap();

        let final_pool = FragmentPool::load_from_path(&dir).unwrap();
        assert!(!final_pool.meta.available_pids.contains(&100));
        assert!(final_pool.meta.available_pids.contains(&200));
        assert!(final_pool.meta.available_pids.contains(&300));
    }
}
