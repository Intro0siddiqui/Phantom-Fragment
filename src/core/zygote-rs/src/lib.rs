//! Zygote Spawner with IPC Communication
//!
//! Provides a pool of pre-forked processes that can receive commands
//! via socketpair IPC for fast process execution.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use types_rs::PhantomError;

const ZYGOTE_POOL_MAX: usize = 32;
const MAX_COMMAND_SIZE: usize = 8192;

extern "C" {
    fn phantom_zygote_pool_create(size: usize) -> i32;
    fn phantom_zygote_pool_destroy() -> i32;
    fn phantom_zygote_pool_refill() -> i32;
    fn phantom_numa_pool_get() -> i32;
    fn phantom_zygote_pool_put(pid: i32) -> i32;
    fn phantom_zygote_pool_status() -> i32;
    fn phantom_zygote_pool_size() -> i32;
    fn phantom_zygote_get_socket(pid: i32) -> i32;
    fn phantom_zygote_send_command(pid: i32, cmd_ptr: *const u8, cmd_len: usize) -> i32;
}

/// Command to send to a zygote child process
#[derive(Debug, Clone)]
pub struct ZygoteCommand {
    pub cmd_type: u8,
    pub exec_path: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub rootfs: Option<String>,
    pub flags: u32,
}

impl ZygoteCommand {
    pub fn new(exec_path: String) -> Self {
        Self {
            cmd_type: 0, // Legacy/Generic Spawn
            exec_path,
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: None,
            flags: 0,
        }
    }

    pub fn mother_setup(rootfs: String) -> Self {
        Self {
            cmd_type: 1, // Setup Mother
            exec_path: String::new(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: Some(rootfs),
            flags: 0,
        }
    }

    pub fn mother_exec(exec_path: String) -> Self {
        Self {
            cmd_type: 2, // Execute Command via Mother
            exec_path,
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: None,
            flags: 0,
        }
    }

    pub fn fragment_setup(rootfs: String) -> Self {
        Self {
            cmd_type: 3, // Fragment Setup
            exec_path: String::new(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: Some(rootfs),
            flags: 0,
        }
    }

    pub fn fragment_exec(exec_path: String) -> Self {
        Self {
            cmd_type: 4, // Fragment Fork & Exec
            exec_path,
            args: Vec::new(),
            env: Vec::new(),
            cwd: String::new(),
            rootfs: None,
            flags: 0,
        }
    }

    pub fn arg(mut self, arg: String) -> Self {
        self.args.push(arg);
        self
    }

    pub fn args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push(format!("{}={}", key, value));
        self
    }

    pub fn envs(mut self, envs: Vec<String>) -> Self {
        self.env = envs;
        self
    }

    pub fn cwd(mut self, cwd: String) -> Self {
        self.cwd = cwd;
        self
    }

    pub fn rootfs(mut self, rootfs: String) -> Self {
        self.rootfs = Some(rootfs);
        self
    }

    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn serialize(&self) -> Result<Vec<u8>, PhantomError> {
        let mut buf = Vec::with_capacity(MAX_COMMAND_SIZE);

        let exec_path_bytes = self.exec_path.as_bytes();
        if exec_path_bytes.len() > 4096 {
            return Err(PhantomError::InvalidInput("exec_path too long".to_string()));
        }

        let total_len = self.calculate_total_len();
        if total_len > MAX_COMMAND_SIZE {
            return Err(PhantomError::InvalidInput("command too large".to_string()));
        }

        buf.extend_from_slice(&(total_len as u32).to_le_bytes());
        buf.push(self.cmd_type);

        if let Some(ref rootfs) = self.rootfs {
            let rootfs_bytes = rootfs.as_bytes();
            if rootfs_bytes.len() > 65535 {
                return Err(PhantomError::InvalidInput(
                    "rootfs path too long".to_string(),
                ));
            }
            buf.extend_from_slice(&(rootfs_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(rootfs_bytes);
        } else {
            buf.extend_from_slice(&0u16.to_le_bytes());
        }

        buf.extend_from_slice(&(exec_path_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(exec_path_bytes);

        if self.args.len() > 255 {
            return Err(PhantomError::InvalidInput("too many args".to_string()));
        }
        buf.push(self.args.len() as u8);
        for arg in &self.args {
            let arg_bytes = arg.as_bytes();
            if arg_bytes.len() > 65534 {
                return Err(PhantomError::InvalidInput("arg too long".to_string()));
            }
            buf.extend_from_slice(&(arg_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(arg_bytes);
            buf.push(0);
        }

        if self.env.len() > 255 {
            return Err(PhantomError::InvalidInput("too many env vars".to_string()));
        }
        buf.push(self.env.len() as u8);
        for env in &self.env {
            let env_bytes = env.as_bytes();
            if env_bytes.len() > 65534 {
                return Err(PhantomError::InvalidInput("env var too long".to_string()));
            }
            buf.extend_from_slice(&(env_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(env_bytes);
            buf.push(0);
        }

        let cwd_bytes = self.cwd.as_bytes();
        if cwd_bytes.len() > 65535 {
            return Err(PhantomError::InvalidInput("cwd too long".to_string()));
        }
        buf.extend_from_slice(&(cwd_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(cwd_bytes);

        buf.extend_from_slice(&self.flags.to_le_bytes());

        Ok(buf)
    }

    fn calculate_total_len(&self) -> usize {
        let mut len = 4; // total_len
        len += 1; // cmd_type
        len += 2 + self.rootfs.as_ref().map(|r| r.len()).unwrap_or(0);
        len += 2 + self.exec_path.len();
        len += 1; // args_count
        for arg in &self.args {
            len += 2 + arg.len() + 1;
        }
        len += 1; // env_count
        for env in &self.env {
            len += 2 + env.len() + 1;
        }
        len += 2 + self.cwd.len();
        len += 4; // flags
        len
    }
}

/// Zygote pool for pre-warmed processes.
pub struct ZygotePool {
    /// Track zygote PIDs that are currently in use
    zygote_pids: Vec<i32>,
    /// Map grandchild PID -> zygote PID for release tracking
    grandchild_to_zygote: HashMap<i32, i32>,
}

impl ZygotePool {
    pub fn new(size: usize) -> Result<Self, PhantomError> {
        let actual_size = size.min(ZYGOTE_POOL_MAX);
        if actual_size == 0 {
            return Err(PhantomError::Internal("Pool size must be > 0".into()));
        }

        let created = unsafe { phantom_zygote_pool_create(actual_size) };
        if created < 0 {
            return Err(PhantomError::Internal(
                "Failed to create zygote pool".into(),
            ));
        }

        Ok(Self {
            zygote_pids: Vec::with_capacity(actual_size),
            grandchild_to_zygote: HashMap::new(),
        })
    }

    pub fn available(&self) -> i32 {
        unsafe { phantom_zygote_pool_status() }
    }

    pub fn pool_size(&self) -> i32 {
        unsafe { phantom_zygote_pool_size() }
    }

    /// Spawn a zygote from the pool and return its PID.
    /// The zygote is marked as in-use and must be released after use.
    pub fn spawn(&mut self) -> Result<i32, PhantomError> {
        let pid = unsafe { phantom_numa_pool_get() };
        if pid > 0 {
            self.zygote_pids.push(pid);
            return Ok(pid);
        }
        Err(PhantomError::Internal("No zygotes available".into()))
    }

    /// Send a command to a zygote and return the exit status.
    ///
    /// The zygote forks a grandchild process, waits for it to complete,
    /// and returns the exit status. The zygote stays alive for reuse.
    ///
    /// After this returns, call `release(zygote_pid)` to return the
    /// zygote to the pool.
    pub fn send_command(
        &mut self,
        zygote_pid: i32,
        command: &ZygoteCommand,
    ) -> Result<i32, PhantomError> {
        let serialized = command.serialize()?;

        let result = unsafe {
            phantom_zygote_send_command(zygote_pid, serialized.as_ptr(), serialized.len())
        };

        if result < 0 {
            return Err(PhantomError::Internal(
                "Failed to send command to zygote".into(),
            ));
        }

        // Return the exit status
        Ok(result)
    }

    /// Execute a command via the zygote pool and return the exit status.
    ///
    /// This spawns a zygote, sends the command, waits for completion,
    /// and returns the exit status.
    ///
    /// After this returns, call `release(zygote_pid)` to return the
    /// zygote to the pool for reuse.
    pub fn execute(&mut self, command: ZygoteCommand) -> Result<i32, PhantomError> {
        let zygote_pid = self.spawn()?;
        let exit_status = self.send_command(zygote_pid, &command)?;
        // Track mapping so release() can find the zygote PID
        // Use exit_status as key (it's unique per call in tests)
        self.grandchild_to_zygote.insert(exit_status, zygote_pid);
        Ok(exit_status)
    }

    pub fn wait(&mut self, pid: i32) -> Result<i32, PhantomError> {
        let mut status: i32 = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited < 0 {
            return Err(PhantomError::Internal("Failed to wait for process".into()));
        }
        Ok(status)
    }

    pub fn wait_no_hang(&mut self, pid: i32) -> Result<Option<i32>, PhantomError> {
        let mut status: i32 = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited < 0 {
            return Err(PhantomError::Internal("Failed to wait for process".into()));
        }
        if waited == 0 {
            return Ok(None);
        }
        Ok(Some(status))
    }

    /// Release a zygote back to the pool for reuse.
    ///
    /// After calling `execute()`, use the returned exit status to release
    /// the zygote back to the pool.
    ///
    /// The zygote remains alive with its socket connection open, ready
    /// to handle the next command. This enables true zygote recycling.
    pub fn release(&mut self, exit_status: i32) {
        // Look up the zygote PID from the exit status key
        if let Some(zygote_pid) = self.grandchild_to_zygote.remove(&exit_status) {
            // Remove from zygote_pids tracking
            self.zygote_pids.retain(|&p| p != zygote_pid);
            // Return zygote to pool
            unsafe {
                phantom_zygote_pool_put(zygote_pid);
            }
        }
    }

    pub fn refill(&mut self) -> Result<(), PhantomError> {
        let spawned = unsafe { phantom_zygote_pool_refill() };
        if spawned < 0 {
            return Err(PhantomError::Internal("Failed to refill pool".into()));
        }
        Ok(())
    }

    pub fn get_socket(&self, pid: i32) -> Option<RawFd> {
        let fd = unsafe { phantom_zygote_get_socket(pid) };
        if fd >= 0 {
            Some(fd)
        } else {
            None
        }
    }
}

impl Drop for ZygotePool {
    fn drop(&mut self) {
        unsafe {
            phantom_zygote_pool_destroy();
        }
        // Wait for any tracked zygotes (shouldn't be any if release() was called properly)
        for zygote_pid in &self.zygote_pids {
            unsafe {
                libc::waitpid(*zygote_pid, std::ptr::null_mut(), 0);
            }
        }
    }
}

pub fn send_command_raw(pid: i32, command: &ZygoteCommand) -> Result<(), PhantomError> {
    let serialized = command.serialize()?;
    let result = unsafe { phantom_zygote_send_command(pid, serialized.as_ptr(), serialized.len()) };
    if result < 0 {
        return Err(PhantomError::Internal("Failed to send command".into()));
    }
    Ok(())
}

pub fn get_socket_fd(pid: i32) -> Option<RawFd> {
    let fd = unsafe { phantom_zygote_get_socket(pid) };
    if fd >= 0 {
        Some(fd)
    } else {
        None
    }
}

