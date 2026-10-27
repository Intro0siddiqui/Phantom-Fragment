//! Zygote Spawner with IPC Communication
//!
//! Provides a pool of pre-forked processes that can receive commands
//! via socketpair IPC for fast process execution.

use std::os::unix::io::RawFd;
use types_rs::PhantomError;

const ZYGOTE_POOL_MAX: usize = 32;
/// Must match `MAX_COMMAND_SIZE` in `zygote.zig`.
const MAX_COMMAND_SIZE: usize = 8192;
/// Longest accepted path (rootfs, exec path, cwd). Must match `MAX_PATH`.
const MAX_PATH_LEN: usize = 4096;
/// Maximum number of arguments or environment entries (u8 count on the wire).
const MAX_ITEMS: usize = 255;
/// Wire protocol version marker; also the smallest valid message.
const MIN_COMMAND_SIZE: usize = 17;

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

    /// Append one argument. Arguments are passed to the program as `argv[1..]`;
    /// `argv[0]` is always the exec path.
    pub fn arg(mut self, arg: String) -> Self {
        self.args.push(arg);
        self
    }

    /// Replace the argument list. Arguments are passed as `argv[1..]`;
    /// `argv[0]` is always the exec path.
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

    /// Validate the command against the wire protocol limits before encoding.
    fn validate(&self) -> Result<(), PhantomError> {
        if self.cmd_type > 4 {
            return Err(PhantomError::InvalidInput(format!(
                "unsupported command type {}",
                self.cmd_type
            )));
        }

        let is_setup = matches!(self.cmd_type, 1 | 3);
        if is_setup {
            match self.rootfs.as_deref() {
                Some(rootfs) if !rootfs.is_empty() => {}
                _ => {
                    return Err(PhantomError::InvalidInput(
                        "rootfs is required for setup commands".to_string(),
                    ))
                }
            }
        } else if self.exec_path.is_empty() {
            return Err(PhantomError::InvalidInput(
                "exec_path must not be empty".to_string(),
            ));
        }

        if self.exec_path.len() > MAX_PATH_LEN {
            return Err(PhantomError::InvalidInput("exec_path too long".to_string()));
        }
        if let Some(rootfs) = &self.rootfs {
            if rootfs.len() > MAX_PATH_LEN {
                return Err(PhantomError::InvalidInput(
                    "rootfs path too long".to_string(),
                ));
            }
        }
        if self.cwd.len() > MAX_PATH_LEN {
            return Err(PhantomError::InvalidInput("cwd too long".to_string()));
        }
        if self.args.len() > MAX_ITEMS {
            return Err(PhantomError::InvalidInput("too many args".to_string()));
        }
        if self.env.len() > MAX_ITEMS {
            return Err(PhantomError::InvalidInput("too many env vars".to_string()));
        }
        for arg in &self.args {
            if arg.len() > MAX_COMMAND_SIZE {
                return Err(PhantomError::InvalidInput("arg too long".to_string()));
            }
        }
        for env in &self.env {
            if env.len() > MAX_COMMAND_SIZE {
                return Err(PhantomError::InvalidInput("env var too long".to_string()));
            }
        }

        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, PhantomError> {
        self.validate()?;

        let total_len = self.calculate_total_len();
        if !(MIN_COMMAND_SIZE..=MAX_COMMAND_SIZE).contains(&total_len) {
            return Err(PhantomError::InvalidInput(format!(
                "command size {} out of range",
                total_len
            )));
        }

        let mut buf = Vec::with_capacity(total_len);

        buf.extend_from_slice(&(total_len as u32).to_le_bytes());
        buf.push(self.cmd_type);

        match self.rootfs.as_deref() {
            Some(rootfs) if !rootfs.is_empty() => {
                buf.extend_from_slice(&(rootfs.len() as u16).to_le_bytes());
                buf.extend_from_slice(rootfs.as_bytes());
            }
            _ => buf.extend_from_slice(&0u16.to_le_bytes()),
        }

        buf.extend_from_slice(&(self.exec_path.len() as u16).to_le_bytes());
        buf.extend_from_slice(self.exec_path.as_bytes());

        buf.push(self.args.len() as u8);
        for arg in &self.args {
            buf.extend_from_slice(&(arg.len() as u16).to_le_bytes());
            buf.extend_from_slice(arg.as_bytes());
            buf.push(0);
        }

        buf.push(self.env.len() as u8);
        for env in &self.env {
            buf.extend_from_slice(&(env.len() as u16).to_le_bytes());
            buf.extend_from_slice(env.as_bytes());
            buf.push(0);
        }

        buf.extend_from_slice(&(self.cwd.len() as u16).to_le_bytes());
        buf.extend_from_slice(self.cwd.as_bytes());

        buf.extend_from_slice(&self.flags.to_le_bytes());

        debug_assert_eq!(buf.len(), total_len);
        Ok(buf)
    }

    fn calculate_total_len(&self) -> usize {
        let mut len = 4; // total_len
        len += 1; // cmd_type
        len += 2 + self.rootfs.as_deref().map(str::len).unwrap_or(0);
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

/// Decode a raw `waitpid`/zygote status word into a conventional exit code.
///
/// Normal exits yield their exit status, signal deaths yield `128 + signal`
/// (shell convention), and anything else is returned unchanged.
pub fn decode_exit_status(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        status
    }
}

/// Zygote pool for pre-warmed processes.
pub struct ZygotePool {
    /// Track zygote PIDs that are currently in use
    zygote_pids: Vec<i32>,
}

impl ZygotePool {
    pub fn new(size: usize) -> Result<Self, PhantomError> {
        let actual_size = size.min(ZYGOTE_POOL_MAX);
        if actual_size == 0 {
            return Err(PhantomError::Internal("Pool size must be > 0".into()));
        }

        // SAFETY: the FFI entry point only touches the process-global pool and
        // returns a negative value on failure.
        let created = unsafe { phantom_zygote_pool_create(actual_size) };
        if created <= 0 {
            return Err(PhantomError::Internal(
                "Failed to create zygote pool".into(),
            ));
        }

        Ok(Self {
            zygote_pids: Vec::with_capacity(actual_size),
        })
    }

    pub fn available(&self) -> i32 {
        // SAFETY: pure status query over the process-global pool.
        unsafe { phantom_zygote_pool_status() }
    }

    pub fn pool_size(&self) -> i32 {
        // SAFETY: pure status query over the process-global pool.
        unsafe { phantom_zygote_pool_size() }
    }

    /// Number of zygote PIDs currently tracked as in use by this handle.
    pub fn in_use_count(&self) -> usize {
        self.zygote_pids.len()
    }

    /// Spawn a zygote from the pool and return its PID.
    /// The zygote is marked as in-use and must be released after use.
    pub fn spawn(&mut self) -> Result<i32, PhantomError> {
        // SAFETY: the FFI entry point marks a free slot in use and returns its
        // PID, or -1 when the pool is exhausted.
        let pid = unsafe { phantom_numa_pool_get() };
        if pid <= 0 {
            return Err(PhantomError::Internal("No zygotes available".into()));
        }
        if self.zygote_pids.contains(&pid) {
            return Err(PhantomError::Internal(format!(
                "Zygote PID {} handed out twice",
                pid
            )));
        }
        self.zygote_pids.push(pid);
        Ok(pid)
    }

    /// Send a command to a zygote and return the raw wait status of the
    /// process the zygote executed.
    ///
    /// The zygote forks a grandchild process, waits for it to complete, and
    /// reports the grandchild's wait status. The zygote stays alive for reuse.
    ///
    /// After this returns, call `release(zygote_pid)` to return the zygote to
    /// the pool.
    pub fn send_command(
        &mut self,
        zygote_pid: i32,
        command: &ZygoteCommand,
    ) -> Result<i32, PhantomError> {
        let serialized = command.serialize()?;

        // SAFETY: `serialized` is a valid buffer for the duration of the call
        // and the FFI validates its length prefix.
        let result = unsafe {
            phantom_zygote_send_command(zygote_pid, serialized.as_ptr(), serialized.len())
        };

        if result < 0 {
            return Err(PhantomError::Internal(
                "Failed to send command to zygote".into(),
            ));
        }

        Ok(result)
    }

    /// Execute a command via the zygote pool and return the raw wait status.
    ///
    /// This spawns a zygote, sends the command, and releases the zygote back
    /// to the pool (even on failure). Use [`decode_exit_status`] to turn the
    /// result into an exit code.
    pub fn execute(&mut self, command: ZygoteCommand) -> Result<i32, PhantomError> {
        let zygote_pid = self.spawn()?;
        let result = self.send_command(zygote_pid, &command);

        // send_command is synchronous and the zygote remains alive, so the
        // slot can be recycled immediately. Release on error too, otherwise a
        // failed command leaks the slot.
        self.release(zygote_pid);

        result
    }

    /// Block until `pid` exits and return its raw wait status.
    ///
    /// Note: only usable for processes that are direct children of this
    /// process. Processes executed by a zygote are children of the zygote;
    /// their status is returned by [`ZygotePool::send_command`] instead.
    pub fn wait(&mut self, pid: i32) -> Result<i32, PhantomError> {
        let mut status: i32 = 0;
        loop {
            // SAFETY: waitpid only writes `status` on success.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited == pid {
                return Ok(status);
            }
            if waited < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(PhantomError::Internal(format!(
                    "waitpid({}) failed: {}",
                    pid, err
                )));
            }
            // waitpid without WNOHANG cannot return 0; retry defensively.
        }
    }

    /// Non-blocking variant of [`ZygotePool::wait`].
    ///
    /// Returns `Ok(None)` if `pid` is still running, `Ok(Some(status))` once
    /// it has exited, and an error if it is not a waitable child (for example
    /// a zygote-executed grandchild).
    pub fn wait_no_hang(&mut self, pid: i32) -> Result<Option<i32>, PhantomError> {
        let mut status: i32 = 0;
        loop {
            // SAFETY: waitpid only writes `status` on success.
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == 0 {
                return Ok(None);
            }
            if waited == pid {
                return Ok(Some(status));
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(PhantomError::Internal(format!(
                "waitpid({}) failed: {}",
                pid, err
            )));
        }
    }

    /// Release a zygote back to the pool for reuse.
    ///
    /// The zygote remains alive with its socket connection open, ready to
    /// handle the next command. Returns `false` if the pool rejected the PID
    /// (unknown PID, or a double release).
    pub fn release(&mut self, zygote_pid: i32) -> bool {
        self.zygote_pids.retain(|&p| p != zygote_pid);
        // SAFETY: the FFI entry point validates the PID against the pool.
        unsafe { phantom_zygote_pool_put(zygote_pid) == 0 }
    }

    /// Restore the pool to its configured size. Returns how many zygotes were
    /// spawned. Dead slots are reaped first.
    pub fn refill(&mut self) -> Result<i32, PhantomError> {
        // SAFETY: the FFI entry point refills the process-global pool.
        let spawned = unsafe { phantom_zygote_pool_refill() };
        if spawned < 0 {
            return Err(PhantomError::Internal("Failed to refill pool".into()));
        }
        Ok(spawned)
    }

    pub fn get_socket(&self, pid: i32) -> Option<RawFd> {
        // SAFETY: the FFI entry point only reads pool bookkeeping.
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
        // The Zig side closes every socket, kills each child and reaps it.
        // SAFETY: destroying the process-global pool is idempotent.
        unsafe {
            phantom_zygote_pool_destroy();
        }
        self.zygote_pids.clear();
    }
}

pub fn send_command_raw(pid: i32, command: &ZygoteCommand) -> Result<(), PhantomError> {
    let serialized = command.serialize()?;
    // SAFETY: `serialized` is valid for the duration of the call.
    let result = unsafe { phantom_zygote_send_command(pid, serialized.as_ptr(), serialized.len()) };
    if result < 0 {
        return Err(PhantomError::Internal("Failed to send command".into()));
    }
    Ok(())
}

pub fn get_socket_fd(pid: i32) -> Option<RawFd> {
    // SAFETY: the FFI entry point only reads pool bookkeeping.
    let fd = unsafe { phantom_zygote_get_socket(pid) };
    if fd >= 0 {
        Some(fd)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parsed form of a serialized command, used to verify the wire format
    /// from the Rust side without forking.
    #[derive(Debug, PartialEq)]
    struct Parsed {
        total_len: u32,
        cmd_type: u8,
        rootfs: Option<String>,
        exec_path: String,
        args: Vec<String>,
        env: Vec<String>,
        cwd: String,
        flags: u32,
    }

    struct Cursor<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Cursor<'a> {
        fn take(&mut self, n: usize) -> &'a [u8] {
            let out = &self.buf[self.pos..self.pos + n];
            self.pos += n;
            out
        }

        fn u8(&mut self) -> u8 {
            self.take(1)[0]
        }

        fn u16(&mut self) -> u16 {
            u16::from_le_bytes(self.take(2).try_into().unwrap())
        }

        fn u32(&mut self) -> u32 {
            u32::from_le_bytes(self.take(4).try_into().unwrap())
        }

        fn string(&mut self, len: usize) -> String {
            String::from_utf8(self.take(len).to_vec()).unwrap()
        }
    }

    fn parse(buf: &[u8]) -> Parsed {
        let mut cur = Cursor { buf, pos: 0 };

        let total_len = cur.u32();
        let cmd_type = cur.u8();

        let rootfs_len = cur.u16() as usize;
        let rootfs = if rootfs_len == 0 {
            None
        } else {
            Some(cur.string(rootfs_len))
        };

        let exec_len = cur.u16() as usize;
        let exec_path = cur.string(exec_len);

        let argc = cur.u8() as usize;
        let mut args = Vec::with_capacity(argc);
        for _ in 0..argc {
            let len = cur.u16() as usize;
            args.push(cur.string(len));
            assert_eq!(cur.u8(), 0, "arg must be NUL terminated");
        }

        let envc = cur.u8() as usize;
        let mut env = Vec::with_capacity(envc);
        for _ in 0..envc {
            let len = cur.u16() as usize;
            env.push(cur.string(len));
            assert_eq!(cur.u8(), 0, "env entry must be NUL terminated");
        }

        let cwd_len = cur.u16() as usize;
        let cwd = cur.string(cwd_len);
        let flags = cur.u32();

        assert_eq!(cur.pos, buf.len(), "serializer emitted trailing bytes");
        Parsed {
            total_len,
            cmd_type,
            rootfs,
            exec_path,
            args,
            env,
            cwd,
            flags,
        }
    }

    #[test]
    fn serialize_roundtrip_preserves_every_field() {
        let cmd = ZygoteCommand::new("/bin/echo".to_string())
            .args(vec![
                "hello".to_string(),
                "world".to_string(),
                String::new(),
            ])
            .env("FOO", "bar")
            .cwd("/tmp".to_string())
            .rootfs("/srv/rootfs".to_string())
            .flags(0x42);

        let buf = cmd.serialize().unwrap();
        let parsed = parse(&buf);

        assert_eq!(parsed.total_len as usize, buf.len());
        assert_eq!(parsed.cmd_type, 0);
        assert_eq!(parsed.rootfs.as_deref(), Some("/srv/rootfs"));
        assert_eq!(parsed.exec_path, "/bin/echo");
        assert_eq!(parsed.args, vec!["hello", "world", ""]);
        assert_eq!(parsed.env, vec!["FOO=bar"]);
        assert_eq!(parsed.cwd, "/tmp");
        assert_eq!(parsed.flags, 0x42);
    }

    #[test]
    fn serialize_setup_command_roundtrip() {
        let buf = ZygoteCommand::mother_setup("/srv/rootfs".to_string())
            .serialize()
            .unwrap();
        let parsed = parse(&buf);
        assert_eq!(parsed.cmd_type, 1);
        assert_eq!(parsed.rootfs.as_deref(), Some("/srv/rootfs"));
        assert!(parsed.exec_path.is_empty());
    }

    #[test]
    fn serialize_rejects_empty_exec_path_for_exec_types() {
        for cmd in [
            ZygoteCommand::new(String::new()),
            ZygoteCommand::mother_exec(String::new()),
            ZygoteCommand::fragment_exec(String::new()),
        ] {
            assert!(cmd.serialize().is_err(), "cmd_type {}", cmd.cmd_type);
        }
    }

    #[test]
    fn serialize_requires_rootfs_for_setup_types() {
        let mut cmd = ZygoteCommand::fragment_setup(String::new());
        assert!(cmd.serialize().is_err());
        cmd.rootfs = None;
        assert!(cmd.serialize().is_err());
    }

    #[test]
    fn serialize_rejects_oversized_paths() {
        let too_long = "/".repeat(MAX_PATH_LEN + 1);

        assert!(ZygoteCommand::new(too_long.clone()).serialize().is_err());
        assert!(ZygoteCommand::new("/bin/true".to_string())
            .cwd(too_long.clone())
            .serialize()
            .is_err());
        assert!(ZygoteCommand::mother_setup(too_long).serialize().is_err());
    }

    #[test]
    fn serialize_rejects_unknown_command_type() {
        let mut cmd = ZygoteCommand::new("/bin/true".to_string());
        cmd.cmd_type = 5;
        assert!(cmd.serialize().is_err());
    }

    #[test]
    fn serialize_rejects_too_many_args_and_env() {
        let cmd =
            ZygoteCommand::new("/bin/true".to_string()).args(vec!["a".to_string(); MAX_ITEMS + 1]);
        assert!(cmd.serialize().is_err());

        let cmd = ZygoteCommand::new("/bin/true".to_string())
            .envs(vec!["A=B".to_string(); MAX_ITEMS + 1]);
        assert!(cmd.serialize().is_err());
    }

    #[test]
    fn serialize_rejects_command_over_budget() {
        // Each arg is small enough on its own, but together they exceed 8 KiB.
        let args: Vec<String> = (0..MAX_ITEMS).map(|_| "x".repeat(64)).collect();
        let cmd = ZygoteCommand::new("/bin/true".to_string()).args(args);
        let err = cmd.serialize().unwrap_err();
        assert!(matches!(err, PhantomError::InvalidInput(_)));
    }

    #[test]
    fn decode_exit_status_handles_exit_and_signal() {
        // wait status for a normal exit with code 42.
        assert_eq!(decode_exit_status(42 << 8), 42);
        // wait status for death by SIGKILL (9).
        assert_eq!(decode_exit_status(libc::SIGKILL), 128 + libc::SIGKILL);
    }

    #[test]
    fn ffi_rejects_invalid_command_buffers() {
        // SAFETY: null pointer / undersized buffer must be rejected before any
        // dereference by the FFI layer.
        let rc = unsafe { phantom_zygote_send_command(1, std::ptr::null(), 0) };
        assert_eq!(rc, -1);

        let short = [0u8; MIN_COMMAND_SIZE - 1];
        let rc = unsafe { phantom_zygote_send_command(1, short.as_ptr(), short.len()) };
        assert_eq!(rc, -1);
    }

    #[test]
    fn pool_zero_size_is_rejected_without_forking() {
        assert!(ZygotePool::new(0).is_err());
    }

    // ------------------------------------------------------------------
    // Fork-based lifecycle tests. The Zig pool is a process-global
    // singleton, so these must not run concurrently with each other.
    // ------------------------------------------------------------------

    use std::sync::{Mutex, MutexGuard};

    static POOL_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn pool_test_guard() -> MutexGuard<'static, ()> {
        POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn pool_recreate_does_not_deadlock() {
        let _guard = pool_test_guard();
        let first = ZygotePool::new(1).expect("first pool");
        // Re-creating while the global pool is live used to spin forever on
        // the non-reentrant pool mutex.
        let second = ZygotePool::new(1).expect("second pool");
        assert_eq!(second.pool_size(), 1);
        drop(second);
        drop(first);
    }

    #[test]
    fn pool_spawn_release_and_double_release() {
        let _guard = pool_test_guard();
        let mut pool = ZygotePool::new(2).expect("pool");

        let a = pool.spawn().expect("first spawn");
        let b = pool.spawn().expect("second spawn");
        assert_ne!(a, b);
        assert_eq!(pool.in_use_count(), 2);
        assert_eq!(pool.available(), 0);

        assert!(pool.release(a));
        assert_eq!(pool.in_use_count(), 1);
        assert_eq!(pool.available(), 1);

        // Double release must be rejected, not silently accepted.
        assert!(!pool.release(a));

        assert!(pool.release(b));
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn pool_execute_returns_grandchild_status() {
        let _guard = pool_test_guard();
        let mut pool = ZygotePool::new(2).expect("pool");

        let status = pool
            .execute(
                ZygoteCommand::new("/bin/sh".to_string())
                    .args(vec!["-c".to_string(), "exit 0".to_string()])
                    .cwd("/".to_string()),
            )
            .expect("execute");
        assert_eq!(decode_exit_status(status), 0);
        // The zygote itself must survive and be recycled.
        assert_eq!(pool.available(), 2);

        let status = pool
            .execute(
                ZygoteCommand::new("/bin/sh".to_string())
                    .args(vec!["-c".to_string(), "exit 42".to_string()])
                    .cwd("/".to_string()),
            )
            .expect("execute");
        assert_eq!(decode_exit_status(status), 42);
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn pool_exec_failure_does_not_leak_slot() {
        let _guard = pool_test_guard();
        let mut pool = ZygotePool::new(1).expect("pool");

        let status = pool
            .execute(ZygoteCommand::new(
                "/nonexistent/phantom-test-binary".to_string(),
            ))
            .expect("execute");
        // execve failed in the grandchild, which exits 126.
        assert_eq!(decode_exit_status(status), 126);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn pool_refill_restores_capacity_without_overshooting() {
        let _guard = pool_test_guard();
        let mut pool = ZygotePool::new(3).expect("pool");

        let pids: Vec<i32> = (0..3).map(|_| pool.spawn().expect("spawn")).collect();
        assert_eq!(pool.available(), 0);

        // All slots are in use; refill must not spawn past capacity.
        assert_eq!(pool.refill().expect("refill"), 0);

        for pid in pids {
            assert!(pool.release(pid));
        }
        assert_eq!(pool.available(), 3);
    }

    #[test]
    fn pool_refill_replaces_dead_zygote() {
        let _guard = pool_test_guard();
        let mut pool = ZygotePool::new(2).expect("pool");

        let dead = pool.spawn().expect("spawn");
        // SAFETY: killing and reaping our own child.
        unsafe {
            libc::kill(dead, libc::SIGKILL);
            libc::waitpid(dead, std::ptr::null_mut(), 0);
        }
        pool.release(dead);

        let spawned = pool.refill().expect("refill");
        assert!(spawned >= 1, "refill should replace the dead slot");
        assert_eq!(pool.pool_size(), 2);
        assert!(pool.available() >= 1);
    }
}
