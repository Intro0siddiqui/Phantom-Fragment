//! Socket-based Warm Fragment Daemon
//!
//! This module implements a secure, socket-based daemon for warm fragment execution.
//! It replaces the insecure shell-script based daemon with proper:
//! - Unix socket IPC (no polling, event-driven)
//! - Safe command execution (no eval/command injection)
//! - Proper cgroup integration (applied before exec)
//! - Resource cleanup (cgroups removed on exit)
//!
//! Architecture:
//! ```text
//! ┌─────────────────┐     Unix Socket      ┌──────────────────┐
//! │  Client        │ ◄──────────────────► │  Warm Daemon     │
//! │  (phantom run) │  [length:4][type:1]  │  (this module)   │
//! └─────────────────┘  [payload...]        └──────────────────┘
//!                                              │
//!                                              ▼
//!                                   ┌──────────────────┐
//!                                   │  Child Process   │
//!                                   │  (with cgroups)  │
//!                                   └──────────────────┘
//! ```

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cgroups_rs::CgroupManager;
use execution_rs::HardwareProfile;
use nix::sys::signal::{kill, Signal};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;

use crate::engine::sandbox::{
    apply_child_landlock, drop_child_capabilities, resolve_child_policy, write_proc_file,
    ChildPolicy,
};

// SAFETY: libc is required for signal masking before fork to prevent race conditions
// where signals are delivered to the child before it can set up signal handlers.
use libc;

/// Magic number for protocol validation
const PROTOCOL_MAGIC: u32 = 0x50484E54; // "PHNT"
/// Protocol version
const PROTOCOL_VERSION: u8 = 1;

/// Size of the fixed message header: [magic:4][version:1][type:1][length:4]
const HEADER_SIZE: usize = 10;

/// Reserved environment variable that carries the security-profile name.
///
/// `ExecRequest` has no profile field and the v1 wire format must not change,
/// so the client piggybacks the name on the existing env map. The daemon reads
/// it, strips it from the child environment and resolves it through
/// `crate::config`. This is a temporary v1-compatible carrier; `ExecV2` gets a
/// real field (see `docs/architecture/components/warm-exec-v2.md`).
pub const PROFILE_ENV: &str = "PHANTOM_PROFILE";

/// Marker prefix for a pool/profile mismatch in an error response.
///
/// The client must treat this as fatal instead of falling back to cold: a
/// mismatch means the caller explicitly asked for a profile the pool was not
/// built with, and running the command through another engine would silently
/// answer a different question. The marker keeps the v1 payload unchanged.
pub const PROFILE_MISMATCH_MARKER: &str = "warm profile mismatch:";

/// `prctl(2)` options that `libc` does not export for linux-gnu.
const PR_SET_PDEATHSIG: libc::c_int = 1;

/// Fixed descriptor the mother keeps its daemon socketpair end on.
///
/// Everything except 0/1/2 is closed in the mother before the sandbox is
/// applied, so the mother end is moved here and the fd number is deterministic
/// for the rest of the process lifetime.
const MOTHER_SOCKET_FD: RawFd = 3;

/// Fixed descriptor for the host `/dev/null` the mother opens before
/// `chroot(2)`. The image rootfs is not guaranteed to contain one, and every
/// exec child redirects 0/1/2 from it.
const MOTHER_DEVNULL_FD: RawFd = 4;

/// Upper bound for a single message payload.
///
/// The length field is attacker-controlled, so it must never be trusted when
/// allocating a buffer. 1 MiB is far above anything the warm daemon needs
/// (exec requests are a few KiB at most) while keeping a malformed or
/// malicious peer from forcing a multi-gigabyte allocation.
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Message types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Exec = 0x01,
    ExecResponse = 0x02,
    Shutdown = 0x03,
    HealthCheck = 0x04,
    HealthResponse = 0x05,
    GetMetrics = 0x06,
    MetricsResponse = 0x07,
    /// One-byte payload: the signal number to deliver to the running command.
    /// Sent by the client when the user interrupts a warm run.
    Signal = 0x08,
    Error = 0xFF,
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => MessageType::Exec,
            0x02 => MessageType::ExecResponse,
            0x03 => MessageType::Shutdown,
            0x04 => MessageType::HealthCheck,
            0x05 => MessageType::HealthResponse,
            0x06 => MessageType::GetMetrics,
            0x07 => MessageType::MetricsResponse,
            0x08 => MessageType::Signal,
            0xFF => MessageType::Error,
            _ => MessageType::Error,
        }
    }
}

/// Execution request payload
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    pub hardware_profile: Option<HardwareProfile>,
}

/// Execution response payload
#[derive(Debug, Clone)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub pid: u32,
    pub error: Option<String>,
}

/// Health status for the warm daemon
/// Tracks daemon uptime, request metrics, and cgroup status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Daemon uptime in seconds
    pub uptime_secs: u64,
    /// Total requests handled since startup
    pub total_requests: u64,
    /// Number of failed requests
    pub failed_requests: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Current number of active child processes
    pub active_children: usize,
    /// Cgroup status (true if cgroups are active and functioning)
    pub cgroup_active: bool,
    /// Daemon PID
    pub daemon_pid: u32,
}

impl HealthStatus {
    pub fn new() -> Self {
        Self {
            uptime_secs: 0,
            total_requests: 0,
            failed_requests: 0,
            avg_response_time_ms: 0.0,
            active_children: 0,
            cgroup_active: false,
            daemon_pid: 0,
        }
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics response payload for GetMetrics request
/// Contains detailed metrics in a format suitable for Prometheus export
#[derive(Debug, Clone)]
pub struct MetricsResponse {
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Total requests handled
    pub total_requests: u64,
    /// Failed requests count
    pub failed_requests: u64,
    /// Successful requests count
    pub successful_requests: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Current active children count
    pub active_children: usize,
    /// Cgroup active status
    pub cgroup_active: bool,
    /// Prometheus-formatted metrics string
    pub prometheus_metrics: String,
}

/// Binary message format:
/// [magic:4][version:1][type:1][length:4][payload:length]
#[derive(Debug, Clone)]
pub struct Message {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        if self.payload.len() > MAX_MESSAGE_SIZE {
            anyhow::bail!(
                "Message payload too large: {} bytes (max {})",
                self.payload.len(),
                MAX_MESSAGE_SIZE
            );
        }

        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
        buf.push(PROTOCOL_VERSION);
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    /// Decode a message from an in-memory buffer.
    ///
    /// Kept for protocol completeness and tests; the daemon and client read
    /// frames through [`read_message`], which validates before allocating.
    #[allow(dead_code)]
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            anyhow::bail!("Message too short");
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != PROTOCOL_MAGIC {
            anyhow::bail!("Invalid protocol magic");
        }

        let version = data[4];
        if version != PROTOCOL_VERSION {
            anyhow::bail!("Unsupported protocol version: {}", version);
        }

        let msg_type = MessageType::from(data[5]);
        let length = u32::from_le_bytes([data[6], data[7], data[8], data[9]]) as usize;

        if length > MAX_MESSAGE_SIZE {
            anyhow::bail!(
                "Message payload length {} exceeds maximum {}",
                length,
                MAX_MESSAGE_SIZE
            );
        }

        if data.len() < HEADER_SIZE + length {
            anyhow::bail!("Incomplete message payload");
        }

        let payload = data[HEADER_SIZE..HEADER_SIZE + length].to_vec();
        Ok(Self { msg_type, payload })
    }
}

/// Read and validate a complete message from a stream.
///
/// This is the single framing entry point used by both the daemon and the
/// client. The header is validated (magic, version, bounded length) *before*
/// the payload buffer is allocated, so a truncated header, a protocol
/// mismatch, or an absurd length can never trigger a huge allocation or an
/// out-of-bounds read. `read_exact` loops internally, so partial reads are
/// handled correctly.
pub fn read_message<R: Read>(reader: &mut R) -> Result<Message> {
    let mut header = [0u8; HEADER_SIZE];
    reader
        .read_exact(&mut header)
        .context("Failed to read message header")?;

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != PROTOCOL_MAGIC {
        anyhow::bail!("Invalid protocol magic: 0x{:08X}", magic);
    }

    if header[4] != PROTOCOL_VERSION {
        anyhow::bail!("Unsupported protocol version: {}", header[4]);
    }

    let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if length > MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "Message payload length {} exceeds maximum {}",
            length,
            MAX_MESSAGE_SIZE
        );
    }

    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .context("Failed to read message payload")?;

    Ok(Message {
        msg_type: MessageType::from(header[5]),
        payload,
    })
}

/// Write a framed message to a stream.
///
/// `write_all` loops internally, so short writes are handled correctly.
pub fn write_message<W: Write>(writer: &mut W, message: &Message) -> Result<()> {
    let data = message.serialize()?;
    writer.write_all(&data).context("Failed to write message")?;
    Ok(())
}

/// Maximum number of descriptors that may travel with a single frame.
///
/// A warm exec needs three (stdin, stdout, stderr); the extra slot leaves room
/// for a future control channel without changing the transport.
pub const MAX_FDS_PER_MESSAGE: usize = 4;

/// Send a framed message and, optionally, pass descriptors with it.
///
/// The frame is sent in one `sendmsg(2)` so the ancillary data is attached to
/// its first byte. The receiving side must use [`read_message_with_fds`] or the
/// descriptors are dropped (the kernel closes them with the receiving process).
pub fn write_message_with_fds(stream: &UnixStream, message: &Message, fds: &[RawFd]) -> Result<()> {
    if fds.len() > MAX_FDS_PER_MESSAGE {
        anyhow::bail!(
            "Refusing to attach {} descriptors (max {})",
            fds.len(),
            MAX_FDS_PER_MESSAGE
        );
    }

    let data = message.serialize()?;
    let mut sent = 0usize;

    while sent < data.len() {
        let iov = libc::iovec {
            // SAFETY: the pointer is only read by the kernel during sendmsg and
            // `data` outlives the call.
            iov_base: data[sent..].as_ptr() as *mut libc::c_void,
            iov_len: data.len() - sent,
        };
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
        hdr.msg_iovlen = 1;

        // The control buffer must stay alive until sendmsg returns. It is
        // built empty unless this is the first chunk and fds were requested.
        let payload_len = std::mem::size_of_val(fds);
        let mut control: Vec<u8> = if !fds.is_empty() && sent == 0 {
            // SAFETY: CMSG_SPACE is a pure arithmetic helper.
            let space = unsafe { libc::CMSG_SPACE(payload_len as u32) } as usize;
            vec![0u8; space]
        } else {
            Vec::new()
        };

        if !control.is_empty() {
            hdr.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            hdr.msg_controllen = control.len();

            // SAFETY: the buffer was sized with CMSG_SPACE for this payload.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&hdr);
                if cmsg.is_null() {
                    anyhow::bail!("Failed to build SCM_RIGHTS control message");
                }
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(payload_len as u32) as usize;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr() as *const u8,
                    libc::CMSG_DATA(cmsg),
                    payload_len,
                );
            }
        }

        // SAFETY: a valid msghdr over live buffers.
        let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &hdr, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("Failed to send message");
        }
        sent += n as usize;
    }

    Ok(())
}

/// Read a framed message and collect any descriptors sent with it.
///
/// Descriptors are received with `MSG_CMSG_CLOEXEC`, so an exec in this process
/// can never inherit them by accident. The caller owns the returned fds and must
/// close them.
pub fn read_message_with_fds(stream: &UnixStream, fds: &mut Vec<RawFd>) -> Result<Message> {
    let mut header = [0u8; HEADER_SIZE];
    let mut control = vec![0u8; 256];

    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr() as *mut libc::c_void,
        iov_len: HEADER_SIZE,
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_iov = &mut iov as *mut libc::iovec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_controllen = control.len();

    // MSG_WAITALL blocks until the full header arrives, so a short read here is
    // a real framing error rather than a partial one.
    let n = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &mut hdr,
            libc::MSG_WAITALL | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("Failed to read message header");
    }
    if (n as usize) < HEADER_SIZE {
        anyhow::bail!("Short message header: {} bytes", n);
    }

    // SAFETY: the control buffer was filled by the kernel; CMSG_* walk it within
    // msg_controllen.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let base = libc::CMSG_LEN(0) as usize;
                let count = ((*cmsg).cmsg_len.saturating_sub(base)) / std::mem::size_of::<RawFd>();
                let data = libc::CMSG_DATA(cmsg) as *const RawFd;
                for i in 0..count {
                    fds.push(*data.add(i));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&hdr, cmsg);
        }
    }

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != PROTOCOL_MAGIC {
        anyhow::bail!("Invalid protocol magic: 0x{:08X}", magic);
    }
    if header[4] != PROTOCOL_VERSION {
        anyhow::bail!("Unsupported protocol version: {}", header[4]);
    }

    let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if length > MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "Message payload length {} exceeds maximum {}",
            length,
            MAX_MESSAGE_SIZE
        );
    }

    let mut payload = vec![0u8; length];
    if length > 0 {
        (&*stream)
            .read_exact(&mut payload)
            .context("Failed to read message payload")?;
    }

    Ok(Message {
        msg_type: MessageType::from(header[5]),
        payload,
    })
}

/// Close a set of received descriptors, ignoring errors.
pub(crate) fn close_fds(fds: &[RawFd]) {
    for fd in fds {
        // SAFETY: the caller owns these descriptors; closing an already-closed
        // fd returns EBADF, which is ignored.
        unsafe {
            libc::close(*fd);
        }
    }
}

/// Bounds-checked reader for the length-prefixed exec payload.
///
/// Every field is validated against the remaining payload before it is
/// sliced, so malformed input produces an `Err` instead of a panic.
struct PayloadReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, len: usize, what: &str) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .context("Payload field length overflow")?;
        if end > self.data.len() {
            anyhow::bail!(
                "Malformed payload: {} needs {} byte(s) at offset {} but only {} remain",
                what,
                len,
                self.offset,
                self.data.len().saturating_sub(self.offset)
            );
        }
        let slice = &self.data[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn read_u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    fn read_u16(&mut self, what: &str) -> Result<u16> {
        let bytes = self.take(2, what)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self, what: &str) -> Result<u32> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self, what: &str) -> Result<u64> {
        let bytes = self.take(8, what)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_string(&mut self, what: &str) -> Result<String> {
        let len = self.read_u16(&format!("{} length", what))? as usize;
        let bytes = self.take(len, what)?;
        Ok(String::from_utf8_lossy(bytes).to_string())
    }
}

/// Parse the v1 exec payload into an [`ExecRequest`].
///
/// Shared by the daemon (client frames) and the mother (daemon frames) so both
/// sides agree on the wire format. All reads go through [`PayloadReader`]: a
/// truncated or malformed payload is rejected instead of panicking.
fn parse_exec_request(payload: &[u8]) -> Result<ExecRequest> {
    let mut reader = PayloadReader::new(payload);

    let command = reader.read_string("command")?;

    let args_count = reader.read_u8("args count")? as usize;
    let mut args = Vec::with_capacity(args_count);
    for _ in 0..args_count {
        args.push(reader.read_string("argument")?);
    }

    let env_count = reader.read_u8("env count")? as usize;
    let mut env = HashMap::new();
    for _ in 0..env_count {
        let key = reader.read_string("env key")?;
        let val = reader.read_string("env value")?;
        env.insert(key, val);
    }

    let cwd = {
        let cwd = reader.read_string("cwd")?;
        if cwd.is_empty() {
            None
        } else {
            Some(cwd)
        }
    };

    let has_profile = reader.read_u8("profile flag")? != 0;
    let hardware_profile = if has_profile {
        // Read profile: [cpu_count:4][memory_mb:4]
        let cpu_count = reader.read_u32("cpu count")? as usize;
        let memory_mb = reader.read_u32("memory mb")? as usize;
        Some(HardwareProfile {
            cpu_affinity: None,
            numa_node: None,
            cpu_count,
            memory_mb,
        })
    } else {
        None
    };

    Ok(ExecRequest {
        command,
        args,
        env,
        cwd,
        hardware_profile,
    })
}

/// Warm fragment daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub hardware_profile: Option<HardwareProfile>,
    /// Port for Prometheus metrics endpoint (default: 9090)
    pub metrics_port: u16,
    /// Security profile the mother is sandboxed with at pool-fill time.
    ///
    /// The profile is a property of the pool: a request carrying a different
    /// `PHANTOM_PROFILE` is refused rather than run with weaker confinement.
    pub security_profile: String,
    /// Name reserved for named-mother selection (next increment).
    ///
    /// Stored now so the pool metadata and future `--mother` selection have a
    /// stable identity; today it defaults to the security profile name.
    pub mother_name: String,
}

/// Running child process tracking
struct ChildProcess {
    cgroup: Option<CgroupManager>,
}

/// Everything the mother needs to apply its sandbox, resolved in the parent
/// before `fork(2)`.
///
/// The daemon is multi-threaded, so the forked child must not depend on
/// allocator state it cannot guarantee. Profile lookup, cgroup creation and
/// every path/mapping string are prepared here; the child only performs the
/// syscall sequence and the unavoidable allocations inside `libseccomp` and
/// Landlock.
struct MotherSetup {
    policy: ChildPolicy,
    /// `/sys/fs/cgroup/<mother>/cgroup.procs`, if the cgroup was created.
    cgroup_procs: Option<CString>,
    /// Image root, as a C string for `chroot(2)`.
    rootfs: CString,
    /// `"<uid> <uid> 1"` for `/proc/self/uid_map`.
    uid_map: CString,
    /// `"<gid> <gid> 1"` for `/proc/self/gid_map`.
    gid_map: CString,
    /// Highest capability number, read before the chroot hides procfs.
    last_cap: libc::c_int,
}

impl MotherSetup {
    fn prepare(config: &DaemonConfig, daemon_id: u64) -> Result<(Self, Option<CgroupManager>)> {
        let policy = resolve_child_policy(&config.security_profile)?;

        let mut cgroup_manager = None;
        let mut cgroup_procs = None;

        if let Some(profile) = config.hardware_profile.as_ref() {
            let name = format!("phantom_warm_mother_{}", daemon_id);
            let cgroup = CgroupManager::new(&name);
            match cgroup.create() {
                Ok(()) => {
                    if profile.memory_mb > 0 {
                        if let Err(e) = cgroup.set_memory_limit(profile.memory_mb as u64) {
                            log::warn!("Failed to set mother memory limit: {:?}", e);
                        }
                    }
                    if profile.cpu_count > 0 {
                        if let Err(e) = cgroup.set_cpu_limit(profile.cpu_count as u64) {
                            log::warn!("Failed to set mother CPU limit: {:?}", e);
                        }
                    }
                    cgroup_procs = Some(
                        CString::new(format!("/sys/fs/cgroup/{}/cgroup.procs", name))
                            .context("cgroup path contains a NUL byte")?,
                    );
                    cgroup_manager = Some(cgroup);
                }
                Err(e) => {
                    // Graceful degradation, matching the old per-request path:
                    // a host without delegated cgroups must still run warm.
                    log::warn!("Failed to create mother cgroup {}: {:?}", name, e);
                }
            }
        }

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|s| s.trim().parse::<libc::c_int>().ok())
            .unwrap_or(63);

        Ok((
            Self {
                policy,
                cgroup_procs,
                rootfs: CString::new(config.rootfs_path.to_string_lossy().as_bytes())
                    .context("rootfs path contains a NUL byte")?,
                uid_map: CString::new(format!("{} {} 1", uid, uid))
                    .expect("generated uid map cannot contain a NUL byte"),
                gid_map: CString::new(format!("{} {} 1", gid, gid))
                    .expect("generated gid map cannot contain a NUL byte"),
                last_cap,
            },
            cgroup_manager,
        ))
    }
}

/// Close every descriptor above `keep` in the calling process.
///
/// Used by the mother immediately after `fork(2)` so it cannot hold the
/// daemon's listener, metrics socket, or any descriptor inherited from the
/// launcher. `close_range(2)` is one syscall; the loop is a fallback for
/// kernels older than 5.9.
fn close_inherited_fds(keep: RawFd) {
    let first = (keep + 1).max(3) as libc::c_uint;

    // SAFETY: close_range takes two inclusive bounds and flags; closing every
    // fd in the range is exactly the intent here.
    let ret = unsafe { libc::syscall(libc::SYS_close_range, first, libc::c_uint::MAX, 0) };
    if ret == 0 {
        return;
    }

    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: getrlimit writes into the provided struct.
    let max = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0
        && limit.rlim_cur != libc::RLIM_INFINITY
    {
        limit.rlim_cur as libc::c_int
    } else {
        1024
    };

    for fd in (keep + 1)..max {
        // SAFETY: closing an fd that may not be open is harmless (EBADF).
        unsafe {
            libc::close(fd);
        }
    }
}

/// Apply the sandbox to the mother process, once, before it starts serving.
///
/// This is the per-request setup previously executed in `execute_command`'s
/// child branch, moved verbatim into the long-lived mother. Every failure is
/// fatal: the caller `_exit(127)`s, so a request can never be served without
/// the profile's confinement.
fn sandbox_mother(config: &DaemonConfig, setup: &MotherSetup) -> ! {
    if let Err(e) = prepare_namespaces(setup) {
        log::error!("warm mother: namespace setup failed: {:#}", e);
        // Fail closed: never serve a request without the sandbox.
        unsafe { libc::_exit(127) };
    }

    // `CLONE_NEWPID` only applies to children, so the process that mounts
    // /proc and serves requests must be a child of this one. That child is
    // PID 1 of the new namespace; this process supervises it and mirrors its
    // exit status, which is what the daemon waits on.
    // SAFETY: fork(2) from a single-threaded child of the daemon.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // If the supervisor dies (including SIGKILL from `warm remove`),
            // PID 1 must not survive as an orphan.
            // SAFETY: prctl with PR_SET_PDEATHSIG takes a signal number.
            unsafe {
                libc::prctl(PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            }
            if let Err(e) = enter_root(config, setup) {
                log::error!("warm mother: entering the rootfs failed: {:#}", e);
                unsafe { libc::_exit(127) };
            }
            mother_loop(MOTHER_SOCKET_FD)
        }
        Ok(ForkResult::Parent { child }) => {
            // The supervisor is not the server: it must not keep the protocol
            // channel open, or the daemon would never see EOF.
            // SAFETY: this process owns its copy of the descriptor.
            unsafe {
                libc::close(MOTHER_SOCKET_FD);
            }
            let code = loop {
                match nix::sys::wait::waitpid(child, None) {
                    Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => break code,
                    Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => break 128 + sig as i32,
                    Ok(_) => continue,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(_) => break 127,
                }
            };
            // SAFETY: exiting with the child's status; nothing to unwind.
            unsafe { libc::_exit(code) };
        }
        Err(e) => {
            log::error!("warm mother: fork failed: {}", e);
            unsafe { libc::_exit(127) };
        }
    }
}

/// Namespace and identity setup that must happen before the PID-namespace init
/// exists: user/mount/PID/IPC/UTS namespaces, uid/gid maps, private mounts.
fn prepare_namespaces(setup: &MotherSetup) -> Result<()> {
    // Open the host's /dev/null before the root switch: the image is not
    // guaranteed to have one, and every exec child redirects 0/1/2 from it.
    // The fixed fd number keeps the loop free of bookkeeping.
    // SAFETY: open(2) with a valid C string and flags.
    let null_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if null_fd < 0 {
        anyhow::bail!(
            "Failed to open /dev/null: {}",
            std::io::Error::last_os_error()
        );
    }
    if null_fd != MOTHER_DEVNULL_FD {
        // SAFETY: dup2 with valid descriptors; close the temporary duplicate.
        unsafe {
            if libc::dup2(null_fd, MOTHER_DEVNULL_FD) < 0 {
                anyhow::bail!(
                    "Failed to move /dev/null to fd {}: {}",
                    MOTHER_DEVNULL_FD,
                    std::io::Error::last_os_error()
                );
            }
            libc::close(null_fd);
            libc::fcntl(MOTHER_DEVNULL_FD, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }

    // Join the cgroup the parent created. The path is precomputed so the
    // child does not have to format a string before the sandbox is applied.
    if let Some(ref procs) = setup.cgroup_procs {
        // SAFETY: open(2) with a valid C string; write "0" (self) to cgroup.procs.
        unsafe {
            let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd >= 0 {
                libc::write(fd, b"0".as_ptr().cast(), 1);
                libc::close(fd);
            }
        }
    }

    // ENFORCE NAMESPACE PURITY
    // A user namespace is required first: without it the daemon (unprivileged
    // uid 1000) has no CAP_SYS_CHROOT/CAP_SYS_ADMIN and both chroot(2) and
    // mount(2) would fail with EPERM. The mount namespace is owned by the new
    // user namespace.
    //
    // The set matches the cold engine (user, mount, PID, IPC, UTS). Without
    // the PID namespace the command would see host pids and procfs could not
    // be mounted at all; without IPC/UTS it would share host semaphores and
    // the host hostname.
    let flags = libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS;
    // SAFETY: unshare(2) takes a flag mask.
    if unsafe { libc::unshare(flags) } != 0 {
        anyhow::bail!(
            "unshare(user|mount|pid|ipc|uts) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // `setgroups` does not exist on older kernels; anything else is fatal
    // because gid_map would then be unusable.
    if let Err(e) = write_proc_file("/proc/self/setgroups", b"deny") {
        if e.kind() != std::io::ErrorKind::NotFound {
            anyhow::bail!("Failed to write /proc/self/setgroups: {}", e);
        }
    }
    if let Err(e) = write_proc_file("/proc/self/uid_map", setup.uid_map.as_bytes()) {
        anyhow::bail!("Failed to write /proc/self/uid_map: {}", e);
    }
    if let Err(e) = write_proc_file("/proc/self/gid_map", setup.gid_map.as_bytes()) {
        anyhow::bail!("Failed to write /proc/self/gid_map: {}", e);
    }

    // Make all mounts private so they do not propagate to the parent.
    // SAFETY: mount(2) with static C strings and no data.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        )
    } != 0
    {
        anyhow::bail!(
            "mount(/, MS_PRIVATE|MS_REC) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}

/// Finish the sandbox as PID 1 of the new namespace and never return.
///
/// The caller must already be inside the new PID namespace: mounting procfs
/// requires the mounting process to belong to it.
fn enter_root(config: &DaemonConfig, setup: &MotherSetup) -> Result<()> {
    // Enter the image. Everything from here on runs inside the rootfs.
    // SAFETY: chroot(2) with a valid C string prepared in the parent.
    if unsafe { libc::chroot(setup.rootfs.as_ptr()) } != 0 {
        anyhow::bail!(
            "chroot({}) failed: {}",
            config.rootfs_path.display(),
            std::io::Error::last_os_error()
        );
    }

    // SAFETY: chdir(2) with a static C string.
    if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        anyhow::bail!("chdir(/) failed: {}", std::io::Error::last_os_error());
    }

    // procfs: a cold fragment mounts it, so a warm one must too. Without it
    // `ps`, `top` and even `ttyname(3)` fail, and `/proc/self` is missing.
    // Mounted once in the mother's private mount namespace; every child
    // inherits it. The mount namespace is owned by the new user namespace, so
    // CAP_SYS_ADMIN is still held here (caps are dropped below).
    if Path::new("/proc").is_dir() {
        // SAFETY: mount(2) with static C strings and no data.
        let rc = unsafe {
            libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            log::warn!(
                "warm mother: mount(/proc) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // tmpfs hygiene inside the new root. These mounts are not a security
    // boundary; failures are ignored.
    for (dir, path) in [(c"/tmp", "/tmp"), (c"/dev/shm", "/dev/shm")] {
        if !Path::new(path).is_dir() {
            continue;
        }
        // SAFETY: mount(2) with static C strings; failure is ignored.
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                dir.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            );
        }
    }

    // === Security stack ===
    // Order: landlock -> caps/no_new_privs -> seccomp -> serve.
    // Landlock and the capability drop need no privileges; the seccomp filter
    // goes last so it cannot block the remaining setup syscalls.
    apply_child_landlock(setup.policy.file_write).map_err(anyhow::Error::msg)?;
    drop_child_capabilities(setup.last_cap);

    seccomp_rs::apply_profile(setup.policy.seccomp).with_context(|| {
        format!(
            "seccomp profile '{}' could not be installed",
            setup.policy.seccomp
        )
    })?;

    Ok(())
}

/// Serve exec requests from the daemon forever.
///
/// The mother is already chrooted, namespaced, Landlocked, capability-dropped
/// and seccomp-filtered. Per request it only reads a frame, forks, waits, and
/// writes the exit status back.
fn mother_loop(mother_fd: RawFd) -> ! {
    // SAFETY: the fd was moved to MOTHER_SOCKET_FD in the child and is owned
    // by this stream for the rest of the process lifetime.
    let mut stream = unsafe { UnixStream::from_raw_fd(mother_fd) };

    loop {
        let mut fds: Vec<RawFd> = Vec::new();
        let msg = match read_message_with_fds(&stream, &mut fds) {
            Ok(msg) => msg,
            // The daemon closed the channel or the frame is invalid. Fail
            // closed: an unserved request is better than an unsandboxed one.
            Err(_) => unsafe { libc::_exit(127) },
        };

        if msg.msg_type == MessageType::Signal {
            // A relayed interrupt that arrived after its request already
            // finished. The command it was meant for is gone; dropping the
            // frame keeps the next request from being rejected as malformed.
            close_fds(&fds);
            continue;
        }

        if msg.msg_type != MessageType::Exec {
            let response = ExecResponse {
                exit_code: 127,
                pid: 0,
                error: Some(format!(
                    "mother only accepts Exec requests, got {:?}",
                    msg.msg_type
                )),
            };
            if write_exec_response(&mut stream, &response).is_err() {
                unsafe { libc::_exit(127) };
            }
            close_fds(&fds);
            continue;
        }

        let request = match parse_exec_request(&msg.payload) {
            Ok(request) => request,
            Err(e) => {
                let response = ExecResponse {
                    exit_code: 127,
                    pid: 0,
                    error: Some(e.to_string()),
                };
                if write_exec_response(&mut stream, &response).is_err() {
                    unsafe { libc::_exit(127) };
                }
                close_fds(&fds);
                continue;
            }
        };

        // SAFETY: fork(2) from the single-threaded mother. The child only
        // touches async-signal-safe libc entry points and execs.
        match unsafe { fork() } {
            Ok(ForkResult::Child) => mother_exec_child(&request, &fds),
            Ok(ForkResult::Parent { child }) => {
                // The child inherited its own copies; the mother must not keep
                // them or the client's terminal stays open for the pool's life.
                close_fds(&fds);
                let exit_code = wait_for_child_interruptible(child, &stream);
                let response = ExecResponse {
                    exit_code,
                    pid: child.as_raw() as u32,
                    error: None,
                };
                if write_exec_response(&mut stream, &response).is_err() {
                    unsafe { libc::_exit(127) };
                }
            }
            Err(e) => {
                close_fds(&fds);
                let response = ExecResponse {
                    exit_code: 127,
                    pid: 0,
                    error: Some(format!("mother fork failed: {}", e)),
                };
                if write_exec_response(&mut stream, &response).is_err() {
                    unsafe { libc::_exit(127) };
                }
            }
        }
    }
}

/// Forked child of the mother: redirect stdio, apply the request environment,
/// and exec the command. Never returns.
///
/// `stdio` holds the descriptors the client sent with the request (stdin,
/// stdout, stderr). Missing entries fall back to the mother's `/dev/null`, which
/// is the pre-handoff behaviour: a warm run without a terminal still reports an
/// exit code, it just has nowhere to print.
fn mother_exec_child(request: &ExecRequest, stdio: &[RawFd]) -> ! {
    // The mother is the parent: if it is killed (daemon cleanup, crash), the
    // command must not survive as an orphan.
    // SAFETY: prctl with PR_SET_PDEATHSIG takes a signal number as arg2.
    unsafe {
        libc::prctl(PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        for fd in 0..3i32 {
            let source = stdio.get(fd as usize).copied().unwrap_or(MOTHER_DEVNULL_FD);
            libc::dup2(source, fd);
        }
        // A pty from the client must become the command's controlling
        // terminal, otherwise the command can open it but cannot read it: it is
        // in the mother's session, so reads return EIO and job control is off.
        // setsid makes it a session leader; TIOCSCTTY then claims the slave.
        if libc::isatty(libc::STDIN_FILENO) == 1 {
            libc::setsid();
            libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0);
        }

        // The profile name is a daemon-only carrier; it must not leak into the
        // command's environment even if the daemon itself was started with it.
        libc::unsetenv(c"PHANTOM_PROFILE".as_ptr());
    }

    if let Some(ref cwd) = request.cwd {
        let Ok(c_cwd) = CString::new(cwd.as_str()) else {
            unsafe { libc::_exit(127) };
        };
        // SAFETY: chdir(2) with a valid C string.
        if unsafe { libc::chdir(c_cwd.as_ptr()) } != 0 {
            unsafe { libc::_exit(127) };
        }
    }

    for (key, val) in &request.env {
        let (Ok(c_key), Ok(c_val)) = (CString::new(key.as_str()), CString::new(val.as_str()))
        else {
            unsafe { libc::_exit(127) };
        };
        // SAFETY: setenv(3) with valid NUL-terminated strings; overwrite = 1.
        unsafe {
            libc::setenv(c_key.as_ptr(), c_val.as_ptr(), 1);
        }
    }

    let c_cmd = match CString::new(request.command.as_str()) {
        Ok(cmd) => cmd,
        Err(_) => unsafe { libc::_exit(127) },
    };

    let mut c_args: Vec<CString> = Vec::with_capacity(request.args.len() + 1);
    c_args.push(c_cmd.clone());
    for arg in &request.args {
        match CString::new(arg.as_str()) {
            Ok(c_arg) => c_args.push(c_arg),
            Err(_) => unsafe { libc::_exit(127) },
        }
    }

    // SAFETY: execvp(3) with a valid argv; it only returns on failure.
    let _ = execvp(&c_cmd, &c_args);
    unsafe { libc::_exit(127) }
}

/// Wait for the child while staying responsive to a `Signal` frame.
///
/// The mother is the only process that can signal the command: the command lives
/// in the mother's PID namespace, so a host-side pid is meaningless to it. The
/// daemon relays the caller's Ctrl+C as a frame, and this loop turns it into a
/// real signal. Without this the client's terminal interrupt would kill the CLI
/// and leave the command running.
fn wait_for_child_interruptible(child: Pid, stream: &UnixStream) -> i32 {
    // A 50 ms poll cadence made every warm run wait up to a full tick for its
    // exit status — the dominant cost of a short command. A pidfd becomes
    // readable exactly when the child exits, so poll can block until either the
    // child is gone or the client sends a signal frame. Kernels before 5.3 have
    // no pidfd_open; there the old cadence remains as a fallback.
    // SAFETY: pidfd_open(2) takes (pid, flags); flags are 0.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.as_raw(), 0) } as RawFd;
    let code = wait_for_child_with_pidfd(child, stream, pidfd);
    if pidfd >= 0 {
        // SAFETY: the descriptor was created above and is owned here.
        unsafe {
            libc::close(pidfd);
        }
    }
    code
}

fn wait_for_child_with_pidfd(child: Pid, stream: &UnixStream, pidfd: RawFd) -> i32 {
    let fd = stream.as_raw_fd();
    loop {
        match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => return code,
            Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => return 128 + sig as i32,
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return 127,
        }

        let mut pfds = [
            libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // With a pidfd the wait is exact: block until the child exits or a
        // frame arrives. Without one, fall back to the reap cadence.
        let timeout = if pidfd >= 0 { -1 } else { 50 };
        // SAFETY: two initialised pollfds.
        let ready = unsafe { libc::poll(pfds.as_mut_ptr(), 2, timeout) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return 127;
        }
        if ready == 0 {
            continue;
        }
        if (pfds[1].revents & libc::POLLIN) == 0 {
            // Either the child exited (pidfd readable; the next waitpid reaps
            // it) or the socket hung up. Nothing to relay.
            continue;
        }

        let mut fds = Vec::new();
        match read_message_with_fds(stream, &mut fds) {
            Ok(msg) if msg.msg_type == MessageType::Signal => {
                let signo = msg.payload.first().copied().unwrap_or(libc::SIGTERM as u8);
                let signal = Signal::try_from(signo as i32).unwrap_or(Signal::SIGTERM);
                let _ = kill(child, signal);
            }
            // Any other frame here would mean the daemon violated the
            // one-request-at-a-time contract; ignore it rather than kill the
            // command behind the caller's back.
            Ok(_) => {}
            Err(_) => return 127,
        }
        close_fds(&fds);
    }
}

/// Wait for the mother's response while relaying client interrupts.
///
/// The daemon is single-request-at-a-time, so while a command runs there is
/// exactly one thing the client can legitimately send: a single byte carrying
/// the signal number of a terminal interrupt. Anything else on that socket is
/// ignored. If the client disappears, the command is killed rather than left
/// running with no one waiting for it.
fn await_mother_response(mother: &UnixStream, client: &UnixStream) -> Result<Message> {
    let mother_fd = mother.as_raw_fd();
    let client_fd = client.as_raw_fd();

    // Once the client is gone there is nothing left to relay. A closed socket
    // stays readable (EOF) forever, so polling it again would emit one signal
    // frame per iteration; the leftovers queue up in the mother and are read as
    // the *next* request's first frame.
    let mut client_open = true;

    loop {
        let mut pfds = [
            libc::pollfd {
                fd: mother_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if client_open { client_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // SAFETY: two valid pollfds; a negative timeout would block forever, so
        // the 100 ms bound keeps the loop responsive to both sides.
        let ready = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 100) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error()).context("poll failed");
        }
        if ready == 0 {
            continue;
        }

        if pfds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let mut fds = Vec::new();
            let response = read_message_with_fds(mother, &mut fds)?;
            close_fds(&fds);
            return Ok(response);
        }

        if pfds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let mut byte = [0u8; 1];
            // SAFETY: one byte into a live buffer on a poll-readable socket.
            let n = unsafe {
                libc::read(
                    client_fd,
                    byte.as_mut_ptr() as *mut libc::c_void,
                    byte.len(),
                )
            };
            // n == 0 is EOF: the caller is gone, so stop the command and stop
            // watching this socket.
            let signo = if n > 0 { byte[0] } else { libc::SIGKILL as u8 };
            if n == 0 {
                client_open = false;
            }
            let msg = Message::new(MessageType::Signal, vec![signo]);
            write_message_with_fds(mother, &msg, &[])
                .context("Failed to relay signal to warm mother")?;
        }
    }
}

/// Socket-based warm fragment daemon
pub struct WarmDaemon {
    config: DaemonConfig,
    listener: UnixListener,
    running: Arc<AtomicBool>,
    children: Arc<Mutex<HashMap<u32, ChildProcess>>>,
    daemon_id: u64,
    /// Start time for uptime calculation
    start_time: Instant,
    /// Total requests handled
    total_requests: Arc<AtomicU64>,
    /// Failed requests count
    failed_requests: Arc<AtomicU64>,
    /// Sum of all response times in milliseconds (for averaging)
    total_response_time_ms: Arc<AtomicU64>,
    /// Cgroup active status
    cgroup_active: Arc<AtomicBool>,
    /// Metrics port for Prometheus scraping
    metrics_port: u16,
    /// Handle to the metrics server thread
    metrics_server_handle: Option<std::thread::JoinHandle<()>>,
    /// The long-lived, pre-sandboxed mother fragment.
    mother_pid: Pid,
    /// Daemon end of the daemon↔mother socketpair.
    mother_fd: Option<UnixStream>,
    /// Cgroup the mother joined at startup (destroyed on cleanup).
    mother_cgroup: Option<CgroupManager>,
}

impl WarmDaemon {
    /// Create a new warm daemon
    pub fn new(config: DaemonConfig) -> Result<Self> {
        // Create socket directory if needed
        if let Some(parent) = config.socket_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create socket directory: {:?}", parent))?;
        }

        // Remove a stale socket file, but never clobber a live daemon.
        //
        // Previously this unconditionally unlinked the path, so starting a
        // second daemon (or a duplicate supervisor) silently stole the socket
        // from the running one, leaving the first daemon unreachable.
        if config.socket_path.exists() {
            if UnixStream::connect(&config.socket_path).is_ok() {
                anyhow::bail!(
                    "A warm daemon is already listening on {:?}; refusing to replace its socket",
                    config.socket_path
                );
            }

            // Nothing is listening: the socket is stale, safe to remove.
            fs::remove_file(&config.socket_path).with_context(|| {
                format!("Failed to remove stale socket: {:?}", config.socket_path)
            })?;
        }

        // Bind to socket
        let listener = UnixListener::bind(&config.socket_path)
            .with_context(|| format!("Failed to bind to socket: {:?}", config.socket_path))?;

        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&config.socket_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&config.socket_path, perms)?;
        }

        // Set non-blocking
        listener
            .set_nonblocking(true)
            .context("Failed to set socket non-blocking")?;

        let daemon_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Resolve the profile and prepare every child-side string *before*
        // forking: the daemon is multi-threaded, so the child must not depend
        // on allocator state or config I/O.
        let (mother_setup, mother_cgroup) = MotherSetup::prepare(&config, daemon_id)?;

        // Fork the mother once, here, before the metrics thread and the tokio
        // runtime exist. It applies the sandbox once and then serves requests.
        let (daemon_sock, mother_sock) =
            UnixStream::pair().context("Failed to create daemon↔mother socketpair")?;
        let daemon_fd = daemon_sock.into_raw_fd();
        let mother_fd = mother_sock.into_raw_fd();
        let listener_fd = listener.as_raw_fd();

        // SAFETY: the child only runs the sandbox setup and the mother loop;
        // it never returns to the daemon's Rust state.
        let mother_pid = match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                // === MOTHER ===
                unsafe {
                    libc::close(daemon_fd);
                    // The listener is the daemon's, not the mother's.
                    if listener_fd != MOTHER_SOCKET_FD && listener_fd != mother_fd {
                        libc::close(listener_fd);
                    }
                }

                // Move the mother end to a fixed descriptor and close
                // everything else inherited from the launcher/test harness.
                if mother_fd != MOTHER_SOCKET_FD {
                    // SAFETY: dup2 atomically closes the destination (which may
                    // be the listener) and duplicates the socketpair end.
                    unsafe {
                        if libc::dup2(mother_fd, MOTHER_SOCKET_FD) < 0 {
                            libc::_exit(127);
                        }
                        libc::close(mother_fd);
                    }
                }
                close_inherited_fds(MOTHER_SOCKET_FD);
                // SAFETY: fcntl sets FD_CLOEXEC so exec'd commands do not
                // inherit the daemon channel.
                unsafe {
                    libc::fcntl(MOTHER_SOCKET_FD, libc::F_SETFD, libc::FD_CLOEXEC);
                    // If the daemon dies (including SIGKILL from `warm
                    // remove`), the mother must not survive as an orphan.
                    libc::prctl(PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                    if libc::getppid() == 1 {
                        libc::_exit(127);
                    }
                }

                // Fail closed: never serve a request without the sandbox.
                sandbox_mother(&config, &mother_setup)
            }
            Ok(ForkResult::Parent { child }) => {
                // SAFETY: the parent keeps only its own end.
                unsafe {
                    libc::close(mother_fd);
                }
                child
            }
            Err(e) => {
                // SAFETY: both socketpair ends are still owned by this process.
                unsafe {
                    libc::close(daemon_fd);
                    libc::close(mother_fd);
                }
                if let Some(cgroup) = mother_cgroup {
                    let _ = cgroup.destroy();
                }
                return Err(anyhow::anyhow!("Failed to fork warm mother: {:?}", e));
            }
        };

        // SAFETY: daemon_fd is the parent's socketpair end, now owned by the
        // stream.
        let mother_fd = unsafe { UnixStream::from_raw_fd(daemon_fd) };

        let metrics_port = config.metrics_port;

        let mut daemon = Self {
            config,
            listener,
            running: Arc::new(AtomicBool::new(true)),
            children: Arc::new(Mutex::new(HashMap::new())),
            daemon_id,
            start_time: Instant::now(),
            total_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            total_response_time_ms: Arc::new(AtomicU64::new(0)),
            cgroup_active: Arc::new(AtomicBool::new(false)),
            metrics_port,
            metrics_server_handle: None,
            mother_pid,
            mother_fd: Some(mother_fd),
            mother_cgroup,
        };

        // Start the metrics HTTP server in a background thread
        daemon.start_metrics_server()?;

        Ok(daemon)
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    /// Get the daemon PID
    pub fn pid(&self) -> u32 {
        std::process::id()
    }

    /// Get the mother fragment PID (0 after cleanup).
    ///
    /// Exposed for tests and diagnostics; the daemon itself talks to the
    /// mother through `mother_fd`.
    #[allow(dead_code)]
    pub fn mother_pid(&self) -> u32 {
        self.mother_pid.as_raw() as u32
    }

    /// Start the metrics HTTP server in a background thread
    fn start_metrics_server(&mut self) -> Result<()> {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let metrics_port = self.metrics_port;
        let running = Arc::clone(&self.running);
        let total_requests = Arc::clone(&self.total_requests);
        let failed_requests = Arc::clone(&self.failed_requests);
        let total_response_time_ms = Arc::clone(&self.total_response_time_ms);
        let cgroup_active = Arc::clone(&self.cgroup_active);
        let start_time = self.start_time;

        let handle = std::thread::spawn(move || {
            let addr = format!("0.0.0.0:{}", metrics_port);
            let listener = match TcpListener::bind(&addr) {
                Ok(l) => {
                    log::info!("Metrics server listening on http://{}", addr);
                    l
                }
                Err(e) => {
                    log::warn!("Failed to start metrics server on {}: {}", addr, e);
                    return;
                }
            };

            // Set non-blocking for graceful shutdown
            listener.set_nonblocking(true).ok();

            for stream in listener.incoming() {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let mut stream = match stream {
                    Ok(s) => s,
                    // The listener is non-blocking, so `incoming()` reports
                    // WouldBlock whenever no connection is pending. Sleep
                    // briefly instead of spinning (this previously burned a
                    // full CPU core for the daemon's whole lifetime).
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => continue,
                };

                // Set read timeout
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok();

                // Read HTTP request
                let mut buffer = [0u8; 1024];
                if stream.read(&mut buffer).is_err() {
                    continue;
                }

                // Check if it's a GET request to /metrics
                let request = String::from_utf8_lossy(&buffer);
                if request.starts_with("GET /metrics") {
                    // Build metrics response
                    let uptime_secs = start_time.elapsed().as_secs();
                    let total_reqs = total_requests.load(Ordering::Relaxed);
                    let failed_reqs = failed_requests.load(Ordering::Relaxed);
                    let total_resp_time = total_response_time_ms.load(Ordering::Relaxed);
                    let cgroup = cgroup_active.load(Ordering::Relaxed);

                    let avg_response_time_ms = if total_reqs > 0 {
                        total_resp_time as f64 / total_reqs as f64
                    } else {
                        0.0
                    };

                    let mut metrics = String::new();
                    metrics.push_str(
                        "# HELP phantom_daemon_uptime_seconds Daemon uptime in seconds\n",
                    );
                    metrics.push_str("# TYPE phantom_daemon_uptime_seconds gauge\n");
                    metrics.push_str(&format!("phantom_daemon_uptime_seconds {}\n", uptime_secs));

                    metrics.push_str("# HELP phantom_requests_total Total requests handled\n");
                    metrics.push_str("# TYPE phantom_requests_total counter\n");
                    metrics.push_str(&format!("phantom_requests_total {}\n", total_reqs));

                    metrics.push_str("# HELP phantom_requests_failed Total failed requests\n");
                    metrics.push_str("# TYPE phantom_requests_failed counter\n");
                    metrics.push_str(&format!("phantom_requests_failed {}\n", failed_reqs));

                    metrics.push_str("# HELP phantom_avg_response_time_ms Average response time in milliseconds\n");
                    metrics.push_str("# TYPE phantom_avg_response_time_ms gauge\n");
                    metrics.push_str(&format!(
                        "phantom_avg_response_time_ms {:.3}\n",
                        avg_response_time_ms
                    ));

                    metrics.push_str("# HELP phantom_cgroup_active Whether cgroups are active\n");
                    metrics.push_str("# TYPE phantom_cgroup_active gauge\n");
                    metrics.push_str(&format!(
                        "phantom_cgroup_active {}\n",
                        if cgroup { 1 } else { 0 }
                    ));

                    // Add metrics from metrics-rs
                    use metrics_rs::MetricsCollector;
                    let collector = MetricsCollector::new();
                    if let Ok(collected) = collector.export() {
                        metrics.push_str(&collected);
                    }

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                        metrics.len(),
                        metrics
                    );

                    let _ = stream.write_all(response.as_bytes());
                } else if request.starts_with("GET /health") {
                    // Health check endpoint
                    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK";
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    // 404 for other paths
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
                    let _ = stream.write_all(response.as_bytes());
                }

                let _ = stream.flush();
            }
        });

        self.metrics_server_handle = Some(handle);
        Ok(())
    }

    /// Run the daemon main loop
    pub fn run(&mut self) -> Result<()> {
        log::info!(
            "Warm daemon started (PID: {}, socket: {:?})",
            self.pid(),
            self.socket_path()
        );

        // Leave the launcher's session before accepting anything, so a Ctrl+C
        // aimed at the shell that ran `phantom warm create` cannot signal the
        // daemon or its children.
        detach_daemon_session();

        // Apply cgroup to daemon itself if profile specified
        if let Some(ref profile) = self.config.hardware_profile {
            if let Err(e) = self.apply_daemon_cgroup(profile) {
                log::warn!("Failed to apply daemon cgroup: {:?}", e);
            }
        }

        // Set up signal handling
        let running = Arc::clone(&self.running);
        ctrlc_handler(move || {
            log::info!("Received shutdown signal");
            running.store(false, Ordering::SeqCst);
        })?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            // The listener must be registered from inside the runtime: tokio's
            // `from_std` requires an active reactor.
            let listener = self
                .listener
                .try_clone()
                .context("Failed to clone daemon listener")?;
            let async_listener = tokio::net::UnixListener::from_std(listener)
                .context("Failed to register daemon listener with tokio")?;
            let mut prune_interval = tokio::time::interval(std::time::Duration::from_secs(1));

            loop {
                tokio::select! {
                    accept_result = async_listener.accept() => {
                        match accept_result {
                            Ok((stream, _addr)) => {
                                if !self.running.load(Ordering::SeqCst) {
                                    break;
                                }

                                let std_stream = match stream.into_std() {
                                    Ok(s) => s,
                                    Err(e) => {
                                        log::error!("Failed to convert client stream: {:?}", e);
                                        continue;
                                    }
                                };
                                if let Err(e) = std_stream.set_nonblocking(false) {
                                    log::error!("Failed to set client stream to blocking: {:?}", e);
                                    continue;
                                }

                                // To avoid changing the entire function signature to be static (borrow checker issues),
                                // we can't easily spawn a task for handle_client since it takes &mut self.
                                // Instead, we do it inline via block_in_place so Tokio's thread pool isn't stalled.
                                tokio::task::block_in_place(|| {
                                    let mut s = std_stream;
                                    if let Err(e) = self.handle_client(&mut s) {
                                        if is_client_gone(&e) {
                                            log::debug!("Client disconnected mid-request: {:?}", e);
                                        } else {
                                            log::error!("Client handler error: {:?}", e);
                                            let _ = self.send_error(&mut s, &e.to_string());
                                        }
                                    }

                                    // If connection dropped prematurely, the socket gets closed here.
                                    // We can prune immediately as a proactive measure in case the client disconnected while handling an exec request.
                                    let _ = self.prune_dead_children();
                                });
                            }
                            Err(e) => {
                                log::error!("Accept error: {:?}", e);
                            }
                        }
                    }
                    _ = prune_interval.tick() => {
                        let pruned = self.prune_dead_children();
                        if pruned > 0 {
                            log::debug!("Pruned {} dead children", pruned);
                        }
                    }
                }
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }
            }

            Ok::<(), anyhow::Error>(())
        })?;

        // Cleanup
        self.cleanup()?;
        Ok(())
    }

    /// Handle a client connection
    fn handle_client(&mut self, stream: &mut UnixStream) -> Result<()> {
        // Set 5-second socket read and write timeouts to prevent hanging indefinitely under IPC load
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();

        // Verify peer credentials (SO_PEERCRED) to ensure only authorized users can connect
        #[cfg(unix)]
        {
            use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
            use nix::unistd::getuid;
            let cred =
                getsockopt(&*stream, PeerCredentials).context("Failed to get peer credentials")?;
            let current_uid = getuid().as_raw();

            // Only allow connections from same user or root (UID 0)
            if cred.uid() != current_uid && cred.uid() != 0 {
                anyhow::bail!(
                    "Connection rejected: peer UID {} does not match current UID {} (expected same user or root)",
                    cred.uid(),
                    current_uid
                );
            }
        }

        // Read and validate the framed request. Header validation (magic,
        // version, bounded length) happens before any payload allocation.
        // Descriptors sent with the frame are the caller's stdio; anything that
        // is not an Exec must not keep them open.
        let mut fds: Vec<RawFd> = Vec::new();
        let msg = read_message_with_fds(stream, &mut fds)?;

        match msg.msg_type {
            MessageType::Exec => self.handle_exec(stream, &msg.payload, &fds),
            MessageType::HealthCheck => self.handle_health_check(stream),
            MessageType::GetMetrics => self.handle_get_metrics(stream),
            MessageType::Shutdown => {
                close_fds(&fds);
                self.running.store(false, Ordering::SeqCst);
                self.send_response(
                    stream,
                    MessageType::ExecResponse,
                    &ExecResponse {
                        exit_code: 0,
                        pid: 0,
                        error: None,
                    },
                )
            }
            _ => {
                close_fds(&fds);
                let error = format!("Unknown message type: {:?}", msg.msg_type);
                self.send_error(stream, &error)
            }
        }
    }

    /// Handle execution request
    fn handle_exec(
        &mut self,
        stream: &mut std::os::unix::net::UnixStream,
        payload: &[u8],
        fds: &[RawFd],
    ) -> Result<()> {
        let start = Instant::now();

        // Parse request: [cmd_len:2][cmd][args_count:1][args...][env_count:1][env...][cwd_len:2][cwd][profile:1][cpu:4][mem:4]
        let request = parse_exec_request(payload)?;

        // Execute the command and record metrics
        let (response, success) = match self.execute_command(&request, fds, stream) {
            Ok(response) => (response, true),
            Err(e) => {
                let response = ExecResponse {
                    exit_code: 127,
                    pid: 0,
                    error: Some(e.to_string()),
                };
                (response, false)
            }
        };

        // Record request metrics
        let latency_ms = start.elapsed().as_millis() as u64;
        self.record_request(latency_ms, success);

        // The mother holds its own copies; these are done.
        close_fds(fds);

        self.send_response(stream, MessageType::ExecResponse, &response)
    }

    /// Execute a command in the pre-sandboxed mother fragment.
    ///
    /// The daemon no longer forks or applies cgroup/userns/chroot/mounts/
    /// Landlock/caps/seccomp per request: the mother did that once at startup.
    /// Here we only validate the request, bind-check the profile, translate the
    /// cwd into the chroot, and exchange one Exec frame over the socketpair.
    fn execute_command(
        &mut self,
        request: &ExecRequest,
        stdio: &[RawFd],
        client: &UnixStream,
    ) -> Result<ExecResponse> {
        // Validate command - whitelist allowed characters to prevent injection
        if !is_safe_command(&request.command) {
            anyhow::bail!("Invalid command: contains unsafe characters");
        }

        // The pool is bound to one profile at creation. A request naming a
        // different profile must never run: the mother's sandbox is already
        // fixed and could only be weaker than what the caller asked for.
        let profile_name = request
            .env
            .get(PROFILE_ENV)
            .map(String::as_str)
            .unwrap_or(self.config.security_profile.as_str());
        if profile_name != self.config.security_profile {
            anyhow::bail!(
                "{} warm pool '{}' is bound to profile '{}' but request asked for '{}'",
                PROFILE_MISMATCH_MARKER,
                self.config.mother_name,
                self.config.security_profile,
                profile_name
            );
        }

        // Determine and validate working directory.
        //
        // `request.cwd` arrives as a host path under the rootfs, but the mother
        // chdir()s after chroot(2), where that host prefix no longer exists.
        // Strip it so the stored value is absolute inside the new root.
        let chroot_cwd = if let Some(ref cwd) = request.cwd {
            let cwd_path = PathBuf::from(cwd);

            // Canonicalize to resolve symlinks and ..
            let canonical_cwd = cwd_path.canonicalize().unwrap_or_else(|_| cwd_path.clone());

            // Ensure cwd is within rootfs boundary
            if !canonical_cwd.starts_with(&self.config.rootfs_path) {
                anyhow::bail!("cwd escapes rootfs boundary: {}", cwd);
            }

            let relative = canonical_cwd
                .strip_prefix(&self.config.rootfs_path)
                .expect("cwd boundary checked above");

            if relative.as_os_str().is_empty() {
                "/".to_string()
            } else {
                format!("/{}", relative.display())
            }
        } else {
            "/".to_string()
        };

        // Validate command path - ensure it exists within rootfs. This stays in
        // the daemon because only it can see the host-side rootfs path.
        {
            let cmd_path = PathBuf::from(&request.command);

            // Check for path traversal attempts
            let cmd_str = &request.command;
            if cmd_str.contains("..") {
                anyhow::bail!("command contains path traversal: {}", request.command);
            }

            // Build the full path within rootfs
            let full_path = if cmd_path.is_absolute() {
                self.config
                    .rootfs_path
                    .join(cmd_path.strip_prefix("/").unwrap_or(&cmd_path))
            } else if request.command.contains('/') {
                self.config.rootfs_path.join(&cmd_path)
            } else {
                // Bare name: the child resolves it with execvp inside the
                // chroot, so validate against a standard PATH here too.
                ["bin", "usr/bin", "sbin", "usr/sbin"]
                    .iter()
                    .map(|dir| self.config.rootfs_path.join(dir).join(&cmd_path))
                    // Rootfs binaries are absolute symlinks (`/bin/echo ->
                    // /bin/busybox`) that only resolve after the chroot, so
                    // `exists()` would reject them; lstat the link itself.
                    .find(|candidate| candidate.symlink_metadata().is_ok())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "command not found in rootfs PATH: {} (searched {:?})",
                            request.command,
                            self.config.rootfs_path
                        )
                    })?
            };

            // Verify the command exists within rootfs
            if full_path.symlink_metadata().is_err() {
                anyhow::bail!(
                    "command not found in rootfs: {} (looked at {:?})",
                    request.command,
                    full_path
                );
            }
        }

        // Build the request the mother will execute. The mother inherits the
        // daemon environment, so only the request's overrides need serializing.
        let mut mother_request = request.clone();
        mother_request.env.remove(PROFILE_ENV);
        mother_request
            .env
            .insert("PHANTOM_WARM".to_string(), "1".to_string());
        mother_request
            .env
            .insert("PHANTOM_DAEMON_ID".to_string(), self.daemon_id.to_string());
        let rootfs_str = self.config.rootfs_path.to_string_lossy();
        if !rootfs_str.is_empty() && rootfs_str != "/" {
            mother_request
                .env
                .insert("PHANTOM_ROOTFS".to_string(), rootfs_str.into_owned());
        }
        mother_request.cwd = Some(chroot_cwd);

        let payload = serialize_exec_request(&mother_request)?;
        let mother_fd = self
            .mother_fd
            .as_ref()
            .context("warm mother is not running")?;
        write_message_with_fds(mother_fd, &Message::new(MessageType::Exec, payload), stdio)
            .context("Failed to send request to warm mother")?;

        let response = await_mother_response(mother_fd, client)
            .context("Failed to read response from warm mother")?;
        if !matches!(
            response.msg_type,
            MessageType::ExecResponse | MessageType::Error
        ) {
            anyhow::bail!(
                "Unexpected response type from warm mother: {:?}",
                response.msg_type
            );
        }

        parse_exec_response(&response.payload)
    }

    /// Apply cgroup to the daemon itself
    fn apply_daemon_cgroup(&self, profile: &HardwareProfile) -> Result<()> {
        let cgroup_name = format!("phantom_daemon_{}", self.daemon_id);
        let cgroup = CgroupManager::new(&cgroup_name);
        cgroup.create()?;

        if profile.memory_mb > 0 {
            cgroup.set_memory_limit(profile.memory_mb as u64)?;
        }
        if profile.cpu_count > 0 {
            cgroup.set_cpu_limit(profile.cpu_count as u64)?;
        }

        cgroup.add_process(self.pid() as i32)?;
        self.set_cgroup_active(true);
        Ok(())
    }

    /// Handle health check
    fn handle_health_check(&self, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
        let response = format!(
            "OK pid={} children={}",
            self.pid(),
            self.children.lock().unwrap().len()
        );
        let msg = Message::new(MessageType::HealthResponse, response.into_bytes());
        let data = msg.serialize()?;
        stream.write_all(&data)?;
        Ok(())
    }

    /// Handle GetMetrics request
    fn handle_get_metrics(&self, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
        let health = self.get_health_status();
        let prometheus = self.export_prometheus_metrics();

        let response = MetricsResponse {
            uptime_secs: health.uptime_secs,
            total_requests: health.total_requests,
            failed_requests: health.failed_requests,
            successful_requests: health.total_requests.saturating_sub(health.failed_requests),
            avg_response_time_ms: health.avg_response_time_ms,
            active_children: health.active_children,
            cgroup_active: health.cgroup_active,
            prometheus_metrics: prometheus,
        };

        // Serialize: [uptime:8][total:8][failed:8][successful:8][avg_ms:8][children:4][cgroup:1][prometheus_len:2][prometheus]
        let mut payload = Vec::new();
        payload.extend_from_slice(&response.uptime_secs.to_le_bytes());
        payload.extend_from_slice(&response.total_requests.to_le_bytes());
        payload.extend_from_slice(&response.failed_requests.to_le_bytes());
        payload.extend_from_slice(&response.successful_requests.to_le_bytes());
        payload.extend_from_slice(&response.avg_response_time_ms.to_bits().to_le_bytes());
        payload.extend_from_slice(&(response.active_children as u32).to_le_bytes());
        payload.push(if response.cgroup_active { 1 } else { 0 });

        let prometheus_bytes = response.prometheus_metrics.as_bytes();
        payload.extend_from_slice(&(prometheus_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(prometheus_bytes);

        let msg = Message::new(MessageType::MetricsResponse, payload);
        let data = msg.serialize()?;
        stream.write_all(&data)?;
        Ok(())
    }

    /// Get current health status
    pub fn get_health_status(&self) -> HealthStatus {
        let uptime = self.start_time.elapsed().as_secs();
        let total = self.total_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);
        let total_time = self.total_response_time_ms.load(Ordering::Relaxed);

        let avg_response_time = if total > 0 {
            total_time as f64 / total as f64
        } else {
            0.0
        };

        HealthStatus {
            uptime_secs: uptime,
            total_requests: total,
            failed_requests: failed,
            avg_response_time_ms: avg_response_time,
            active_children: self.children.lock().unwrap().len(),
            cgroup_active: self.cgroup_active.load(Ordering::Relaxed),
            daemon_pid: self.pid(),
        }
    }

    /// Record a request with its latency and success status
    pub fn record_request(&self, latency_ms: u64, success: bool) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_ms
            .fetch_add(latency_ms, Ordering::Relaxed);

        if !success {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Prune dead/zombie child processes
    ///
    /// A zombie child is still visible to `kill(pid, 0)`, so a pure liveness
    /// probe never reaps anything. Reap with `waitpid(WNOHANG)` first and drop
    /// entries that were reaped or are no longer our children. Returns the
    /// number of pruned children.
    pub fn prune_dead_children(&self) -> usize {
        let mut locked_children = self.children.lock().unwrap();
        let pids: Vec<u32> = locked_children.keys().copied().collect();
        let mut to_remove = Vec::new();

        for pid in pids {
            match nix::sys::wait::waitpid(
                nix::unistd::Pid::from_raw(pid as i32),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG),
            ) {
                // Child is still running: keep tracking it.
                Ok(nix::sys::wait::WaitStatus::StillAlive) => {}
                // Child exited or was signalled and has now been reaped.
                Ok(_) => to_remove.push(pid),
                // Not our child anymore (already reaped elsewhere or the PID
                // was reused): drop the stale tracking entry.
                Err(nix::errno::Errno::ECHILD) => to_remove.push(pid),
                // Transient error: retry on the next tick.
                Err(_) => {}
            }
        }

        let mut pruned = 0;
        for pid in to_remove {
            if let Some(child) = locked_children.remove(&pid) {
                // Clean up cgroup if present
                if let Some(cgroup) = child.cgroup {
                    if let Err(e) = cgroup.destroy() {
                        log::warn!("Failed to destroy cgroup for PID {}: {:?}", pid, e);
                    }
                    log::debug!("Removed dead child PID {} with cgroup", pid);
                } else {
                    log::debug!("Removed dead child PID {}", pid);
                }
                pruned += 1;
            }
        }

        pruned
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus_metrics(&self) -> String {
        let health = self.get_health_status();
        let successful = health.total_requests.saturating_sub(health.failed_requests);

        format!(
            "# HELP phantom_warm_uptime_seconds Daemon uptime in seconds\n\
             # TYPE phantom_warm_uptime_seconds counter\n\
             phantom_warm_uptime_seconds {}\n\
             # HELP phantom_warm_requests_total Total requests handled\n\
             # TYPE phantom_warm_requests_total counter\n\
             phantom_warm_requests_total {}\n\
             # HELP phantom_warm_requests_failed Total failed requests\n\
             # TYPE phantom_warm_requests_failed counter\n\
             phantom_warm_requests_failed {}\n\
             # HELP phantom_warm_requests_successful Total successful requests\n\
             # TYPE phantom_warm_requests_successful counter\n\
             phantom_warm_requests_successful {}\n\
             # HELP phantom_warm_response_time_ms Average response time in milliseconds\n\
             # TYPE phantom_warm_response_time_ms gauge\n\
             phantom_warm_response_time_ms {}\n\
             # HELP phantom_warm_active_children Current active child processes\n\
             # TYPE phantom_warm_active_children gauge\n\
             phantom_warm_active_children {}\n\
             # HELP phantom_warm_cgroup_active Cgroup status (1=active, 0=inactive)\n\
             # TYPE phantom_warm_cgroup_active gauge\n\
             phantom_warm_cgroup_active {}\n\
             # HELP phantom_warm_daemon_pid Daemon process ID\n\
             # TYPE phantom_warm_daemon_pid gauge\n\
             phantom_warm_daemon_pid {}\n",
            health.uptime_secs,
            health.total_requests,
            health.failed_requests,
            successful,
            health.avg_response_time_ms,
            health.active_children,
            if health.cgroup_active { 1 } else { 0 },
            health.daemon_pid,
        )
    }

    /// Set cgroup active status
    pub fn set_cgroup_active(&self, active: bool) {
        self.cgroup_active.store(active, Ordering::Relaxed);
    }

    /// Send response
    fn send_response(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        msg_type: MessageType,
        response: &ExecResponse,
    ) -> Result<()> {
        let msg = Message::new(msg_type, encode_exec_response(response));
        write_message(stream, &msg)
    }

    /// Send error
    fn send_error(&self, stream: &mut std::os::unix::net::UnixStream, error: &str) -> Result<()> {
        let response = ExecResponse {
            exit_code: 127,
            pid: 0,
            error: Some(error.to_string()),
        };
        self.send_response(stream, MessageType::Error, &response)
    }

    /// Cleanup resources
    fn cleanup(&mut self) -> Result<()> {
        log::info!("Cleaning up warm daemon resources");

        // Kill the mother first: it is the long-lived sandboxed process, and
        // leaving it behind would orphan a chrooted process (and its cgroup).
        if self.mother_pid.as_raw() > 0 {
            let _ = nix::sys::signal::kill(self.mother_pid, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(self.mother_pid, None);
            self.mother_pid = Pid::from_raw(0);
        }

        // Close the daemon end of the channel so the mother sees EOF if it is
        // somehow still alive, and release the descriptor.
        if let Some(mother_fd) = self.mother_fd.take() {
            let _ = mother_fd.shutdown(std::net::Shutdown::Both);
        }

        // The mother was the only member of this cgroup; now that it is reaped
        // the cgroup can be removed.
        if let Some(cgroup) = self.mother_cgroup.take() {
            if let Err(e) = cgroup.destroy() {
                log::warn!("Failed to destroy mother cgroup: {:?}", e);
            }
        }

        // Remove socket file
        if self.config.socket_path.exists() {
            fs::remove_file(&self.config.socket_path).ok();
        }

        // Clean up any remaining children
        let mut locked_children = self.children.lock().unwrap();
        for (pid, child) in locked_children.drain() {
            let raw_pid = nix::unistd::Pid::from_raw(pid as i32);

            // Kill child if still running
            let _ = nix::sys::signal::kill(raw_pid, nix::sys::signal::Signal::SIGTERM);

            // Reap the child so it does not linger as a zombie. Give it a short
            // grace period, then force-kill and wait for it.
            let mut reaped = false;
            for _ in 0..20 {
                match nix::sys::wait::waitpid(raw_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Ok(_) => {
                        reaped = true;
                        break;
                    }
                    Err(nix::errno::Errno::ECHILD) => {
                        reaped = true;
                        break;
                    }
                    Err(_) => {}
                }
            }
            if !reaped {
                let _ = nix::sys::signal::kill(raw_pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(raw_pid, None);
            }

            // Destroy cgroup
            if let Some(cgroup) = child.cgroup {
                if let Err(e) = cgroup.destroy() {
                    log::warn!("Failed to destroy cgroup for PID {}: {:?}", pid, e);
                }
            }
        }

        Ok(())
    }

    /// Run the daemon main loop without signal handler (for testing)
    #[cfg(test)]
    pub fn run_test_loop(&mut self) -> Result<()> {
        log::info!(
            "Warm daemon test loop started (PID: {}, socket: {:?})",
            self.pid(),
            self.socket_path()
        );

        // Same detachment as the production loop; the test harness process is
        // the "daemon", so this is observable via /proc/<pid>/stat.
        detach_daemon_session();

        // Apply cgroup to daemon itself if profile specified
        if let Some(ref profile) = self.config.hardware_profile {
            if let Err(e) = self.apply_daemon_cgroup(profile) {
                log::warn!("Failed to apply daemon cgroup: {:?}", e);
            }
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            let listener = self
                .listener
                .try_clone()
                .context("Failed to clone daemon listener")?;
            let async_listener = tokio::net::UnixListener::from_std(listener)
                .context("Failed to register daemon listener with tokio")?;
            let mut prune_interval = tokio::time::interval(std::time::Duration::from_millis(100)); // faster prune for tests

            loop {
                tokio::select! {
                    accept_result = async_listener.accept() => {
                        match accept_result {
                            Ok((stream, _addr)) => {
                                if !self.running.load(Ordering::SeqCst) {
                                    break;
                                }
                                let std_stream = match stream.into_std() {
                                    Ok(s) => s,
                                    Err(e) => {
                                        log::error!("Failed to convert client stream: {:?}", e);
                                        continue;
                                    }
                                };
                                if let Err(e) = std_stream.set_nonblocking(false) {
                                    log::error!("Failed to set client stream to blocking: {:?}", e);
                                    continue;
                                }
                                tokio::task::block_in_place(|| {
                                    let mut s = std_stream;
                                    if let Err(e) = self.handle_client(&mut s) {
                                        log::error!("Client handler error: {:?}", e);
                                        let _ = self.send_error(&mut s, &e.to_string());
                                    }

                                    // If connection dropped prematurely, the socket gets closed here.
                                    // We can prune immediately as a proactive measure in case the client disconnected while handling an exec request.
                                    let _ = self.prune_dead_children();
                                });
                            }
                            Err(e) => {
                                log::error!("Accept error: {:?}", e);
                            }
                        }
                    }
                    _ = prune_interval.tick() => {
                        let pruned = self.prune_dead_children();
                        if pruned > 0 {
                            log::debug!("Pruned {} dead children", pruned);
                        }
                    }
                }
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }
            }

            Ok::<(), anyhow::Error>(())
        })?;

        // Cleanup
        self.cleanup()?;
        Ok(())
    }
}

impl Drop for WarmDaemon {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Validate command string for safety
/// Only allows alphanumeric, space, dash, underscore, dot, slash, colon
pub fn is_safe_command(cmd: &str) -> bool {
    if cmd.is_empty() {
        return false;
    }

    // Whitelist allowed characters
    cmd.chars().all(|c| {
        c.is_alphanumeric()
            || c == ' '
            || c == '-'
            || c == '_'
            || c == '.'
            || c == '/'
            || c == ':'
            || c == '+'
            || c == '='
    })
}

/// Set up Ctrl+C handler
fn ctrlc_handler<F>(f: F) -> Result<()>
where
    F: FnMut() + Send + 'static,
{
    ctrlc::set_handler(f).context("Failed to set Ctrl+C handler")
}

/// Detach the daemon from the session of the process that launched it.
///
/// `start_daemon_background` spawns the daemon with a plain `Command`, so it
/// inherits the launcher's session and process group: a `Ctrl+C` in the shell
/// that ran `phantom warm create` would signal the daemon and every warm child.
fn detach_daemon_session() {
    // SAFETY: setsid(2) takes no arguments.
    if unsafe { libc::setsid() } < 0 {
        let err = std::io::Error::last_os_error();
        // EPERM means the caller already leads a session: nothing to detach.
        if err.raw_os_error() != Some(libc::EPERM) {
            log::warn!("setsid() failed: {}", err);
        }
    }

    // A detached daemon has no controlling terminal, but an explicit SIGHUP
    // (supervisor restart, shell job cleanup) must not take it down.
    // SAFETY: signal(2) with SIG_IGN and a valid signal number.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    // The launcher exits as soon as the socket is ready; clear any inherited
    // parent-death signal so that does not kill the daemon.
    // SAFETY: prctl with PR_SET_PDEATHSIG takes the signal number (0 = none).
    if unsafe { libc::prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) } != 0 {
        log::warn!(
            "PR_SET_PDEATHSIG(0) failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Start daemon in background
pub fn start_daemon_background(config: DaemonConfig) -> Result<u32> {
    use std::process::Stdio;

    let socket_path = config.socket_path.clone();
    let rootfs_path = config.rootfs_path.clone();

    // Fork the daemon process
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("--internal-warm-daemon");
    cmd.arg("--socket");
    cmd.arg(&socket_path);
    cmd.arg("--rootfs");
    cmd.arg(&rootfs_path);
    cmd.arg("--profile");
    cmd.arg(&config.security_profile);

    if let Some(ref profile) = config.hardware_profile {
        cmd.arg("--cpu-count");
        cmd.arg(profile.cpu_count.to_string());
        cmd.arg("--memory-mb");
        cmd.arg(profile.memory_mb.to_string());
    }

    cmd.stdin(Stdio::null());

    // Keep the daemon's output. A daemon that dies silently is undiagnosable,
    // and both the logger (stdout) and panic messages (stderr) would otherwise
    // disappear into /dev/null. Name the log after the image so `warm list` and
    // the log agree: the rootfs path ends in the image reference.
    let log_name = rootfs_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&config.mother_name)
        .to_string();
    let log_path = crate::config::PhantomPaths::new()
        .logs()
        .join(format!("{}-daemon.log", log_name));
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path);
    let (stdout, stderr) = match log_file {
        Ok(file) => {
            let stderr = file.try_clone().map(Stdio::from).unwrap_or(Stdio::null());
            (Stdio::from(file), stderr)
        }
        Err(_) => (Stdio::null(), Stdio::null()),
    };
    cmd.stdout(stdout);
    cmd.stderr(stderr);

    let mut child = cmd.spawn().context("Failed to spawn daemon")?;
    let pid = child.id();

    // Wait for socket to be ready
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(20));

        // If the daemon exited early, reap it and report the failure instead of
        // waiting the full timeout and leaving a zombie behind.
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("Daemon exited during startup with status: {}", status);
        }

        if socket_path.exists() {
            // A bare connect would leave the daemon reading an empty frame, so
            // probe with a real health handshake: ready means "answers", not
            // "listening".
            if ping_daemon(&socket_path).unwrap_or(false) {
                return Ok(pid);
            }
        }
    }

    // Startup timed out: do not leave an orphaned daemon or zombie process.
    let _ = child.kill();
    let _ = child.wait();

    anyhow::bail!("Daemon failed to start (socket not ready)");
}

/// Whether an error just means the client hung up (killed, terminal closed).
fn is_client_gone(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            )
        })
    })
}

/// Ping a running daemon via Unix socket to verify it is responsive
pub fn ping_daemon(socket_path: &Path) -> Result<bool> {
    let mut stream = match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(1)))
        .ok();

    let msg = Message::new(MessageType::HealthCheck, vec![]);
    if write_message(&mut stream, &msg).is_err() {
        return Ok(false);
    }

    // read_message validates magic, version and the length bound, so a broken
    // or malicious peer cannot make us allocate an absurd buffer.
    match read_message(&mut stream) {
        Ok(response) => Ok(response.msg_type == MessageType::HealthResponse),
        Err(_) => Ok(false),
    }
}

/// Connect to running daemon and send exec request with auto-reconnect retries and timeouts
/// Socket the terminal-signal handler writes to. `-1` means "no warm run in
/// progress", in which case the handler does nothing.
static SIGNAL_SOCKET_FD: AtomicI32 = AtomicI32::new(-1);

/// Async-signal-safe relay: forward the signal number to the daemon as one byte.
///
/// A warm command runs in the mother's PID namespace, so the CLI cannot signal
/// it directly. The daemon polls this byte and asks the mother to deliver the
/// signal, which is the only process that can.
extern "C" fn relay_terminal_signal(signo: libc::c_int) {
    let fd = SIGNAL_SOCKET_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = [signo as u8];
        // SAFETY: write(2) is async-signal-safe.
        unsafe {
            libc::write(fd, byte.as_ptr() as *const libc::c_void, 1);
        }
    }
}

/// Installs SIGINT/SIGTERM handlers for the lifetime of one warm request and
/// restores the previous dispositions on drop.
struct SignalRelay {
    previous_int: libc::sigaction,
    previous_term: libc::sigaction,
}

impl SignalRelay {
    fn install(fd: RawFd) -> Option<Self> {
        // SAFETY: zeroed sigaction is a valid starting point; sigemptyset
        // initialises the mask and sa_sigaction holds a valid handler.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = relay_terminal_signal as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);

            let mut previous_int: libc::sigaction = std::mem::zeroed();
            let mut previous_term: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGINT, &action, &mut previous_int) != 0 {
                return None;
            }
            if libc::sigaction(libc::SIGTERM, &action, &mut previous_term) != 0 {
                libc::sigaction(libc::SIGINT, &previous_int, std::ptr::null_mut());
                return None;
            }

            SIGNAL_SOCKET_FD.store(fd, Ordering::Relaxed);
            Some(Self {
                previous_int,
                previous_term,
            })
        }
    }
}

impl Drop for SignalRelay {
    fn drop(&mut self) {
        SIGNAL_SOCKET_FD.store(-1, Ordering::Relaxed);
        // SAFETY: restoring the dispositions captured at install time.
        unsafe {
            libc::sigaction(libc::SIGINT, &self.previous_int, std::ptr::null_mut());
            libc::sigaction(libc::SIGTERM, &self.previous_term, std::ptr::null_mut());
        }
    }
}

pub fn exec_in_daemon(socket_path: &Path, request: &ExecRequest) -> Result<ExecResponse> {
    // Reject requests whose length-prefixed fields cannot be represented by the
    // wire format instead of silently truncating them with `as u16`/`as u8`.
    let payload = serialize_exec_request(request)?;

    // Interactive runs get a pty owned by this process. Passing the caller's
    // own terminal instead would hand the command a descriptor it cannot read
    // (it is in the mother's session), so shells would run without job control
    // and anything reading stdin would see EIO.
    let mut pty = super::pty::PtySession::open();

    let mut last_err = None;

    // Retry up to 3 times before failing back to cold execution
    for attempt in 1..=3 {
        let stream = match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(anyhow::anyhow!(
                    "Failed to connect to daemon at {:?}: {}",
                    socket_path,
                    e
                ));
                std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
                continue;
            }
        };

        // Only the write side has a deadline: it guards a daemon that stopped
        // reading. The response must be allowed to take as long as the command
        // does — a fixed read deadline used to abort (and re-run) any command
        // that lived longer than 5 seconds.
        stream.set_read_timeout(None).ok();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();

        let mut stream = stream;

        // From here on, Ctrl+C is relayed to the command instead of killing the
        // CLI and leaving the command orphaned.
        let _signal_relay = SignalRelay::install(stream.as_raw_fd());

        // A previous attempt handed its pty to the daemon and closed the slave
        // here, so a retry needs a fresh one; the raw-mode terminal is kept.
        if let Some(session) = pty.as_mut() {
            if session.slave_fd() < 0 && !session.reopen() {
                pty = None;
            }
        }

        // Send request, handing the daemon our stdio so the command writes to
        // the caller's terminal instead of /dev/null (warm-exec-v2 D2). With a
        // pty, all three streams are the same slave; the client keeps only the
        // master.
        let msg = Message::new(MessageType::Exec, payload.clone());
        let stdio: Vec<RawFd> = match pty.as_ref() {
            Some(session) => vec![session.slave_fd(); 3],
            None => vec![libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO],
        };
        if let Err(e) = write_message_with_fds(&stream, &msg, &stdio) {
            last_err = Some(anyhow::anyhow!("Failed to send request to daemon: {}", e));
            std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
            continue;
        }

        // The daemon holds its own copy now; the client's would keep the pty
        // from ever reporting EOF.
        if let Some(session) = pty.as_mut() {
            session.close_slave();
        }

        // Read the response, proxying the terminal while the command runs.
        let response = match pty.as_mut() {
            Some(session) => match session.proxy(&stream) {
                Ok(msg) => msg,
                Err(e) => {
                    last_err = Some(anyhow::anyhow!(
                        "Failed to read response from daemon: {}",
                        e
                    ));
                    std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
                    continue;
                }
            },
            None => match read_message(&mut stream) {
                Ok(msg) => msg,
                Err(e) => {
                    last_err = Some(anyhow::anyhow!(
                        "Failed to read response from daemon: {}",
                        e
                    ));
                    std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
                    continue;
                }
            },
        };

        if !matches!(
            response.msg_type,
            MessageType::ExecResponse | MessageType::Error
        ) {
            return Err(anyhow::anyhow!(
                "Unexpected response type from daemon: {:?}",
                response.msg_type
            ));
        }

        return parse_exec_response(&response.payload);
    }

    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("Failed to communicate with daemon after 3 attempts")))
}

/// Serialize an [`ExecRequest`] into the v1 payload used by both the client
/// and the daemon→mother channel.
///
/// Layout: [cmd_len:2][cmd][args_count:1][args...][env_count:1][env...]
/// [cwd_len:2][cwd][profile:1][cpu:4][mem:4]
fn serialize_exec_request(request: &ExecRequest) -> Result<Vec<u8>> {
    validate_exec_request(request)?;

    let mut payload = Vec::new();

    // Command
    payload.extend_from_slice(&(request.command.len() as u16).to_le_bytes());
    payload.extend_from_slice(request.command.as_bytes());

    // Args
    payload.push(request.args.len() as u8);
    for arg in &request.args {
        payload.extend_from_slice(&(arg.len() as u16).to_le_bytes());
        payload.extend_from_slice(arg.as_bytes());
    }

    // Env
    payload.push(request.env.len() as u8);
    for (key, val) in &request.env {
        payload.extend_from_slice(&(key.len() as u16).to_le_bytes());
        payload.extend_from_slice(key.as_bytes());
        payload.extend_from_slice(&(val.len() as u16).to_le_bytes());
        payload.extend_from_slice(val.as_bytes());
    }

    // Cwd
    let cwd_bytes = request.cwd.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
    payload.extend_from_slice(&(cwd_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(cwd_bytes);

    // Hardware profile
    if let Some(ref profile) = request.hardware_profile {
        payload.push(1);
        payload.extend_from_slice(&(profile.cpu_count as u32).to_le_bytes());
        payload.extend_from_slice(&(profile.memory_mb as u32).to_le_bytes());
    } else {
        payload.push(0);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
    }

    Ok(payload)
}

/// Validate that an exec request fits the wire format.
fn validate_exec_request(request: &ExecRequest) -> Result<()> {
    if request.command.len() > u16::MAX as usize {
        anyhow::bail!("Command too long: {} bytes", request.command.len());
    }
    if request.args.len() > u8::MAX as usize {
        anyhow::bail!("Too many arguments: {}", request.args.len());
    }
    for arg in &request.args {
        if arg.len() > u16::MAX as usize {
            anyhow::bail!("Argument too long: {} bytes", arg.len());
        }
    }
    if request.env.len() > u8::MAX as usize {
        anyhow::bail!("Too many environment variables: {}", request.env.len());
    }
    for (key, val) in &request.env {
        if key.len() > u16::MAX as usize || val.len() > u16::MAX as usize {
            anyhow::bail!("Environment entry too long: {}={}", key, val);
        }
    }
    if let Some(ref cwd) = request.cwd {
        if cwd.len() > u16::MAX as usize {
            anyhow::bail!("Working directory too long: {} bytes", cwd.len());
        }
    }
    Ok(())
}

/// Encode an `ExecResponse` payload: [exit_code:4][pid:4][error_len:2][error]
fn encode_exec_response(response: &ExecResponse) -> Vec<u8> {
    let mut payload =
        Vec::with_capacity(10 + response.error.as_ref().map(|e| e.len()).unwrap_or(0));
    payload.extend_from_slice(&response.exit_code.to_le_bytes());
    payload.extend_from_slice(&response.pid.to_le_bytes());

    if let Some(ref error) = response.error {
        payload.extend_from_slice(&(error.len() as u16).to_le_bytes());
        payload.extend_from_slice(error.as_bytes());
    } else {
        payload.extend_from_slice(&0u16.to_le_bytes());
    }

    payload
}

/// Write an `ExecResponse` frame to the daemon↔mother channel.
fn write_exec_response<W: Write>(writer: &mut W, response: &ExecResponse) -> Result<()> {
    let msg = Message::new(MessageType::ExecResponse, encode_exec_response(response));
    write_message(writer, &msg)
}

/// Parse an `ExecResponse` payload: [exit_code:4][pid:4][error_len:2][error]
fn parse_exec_response(payload: &[u8]) -> Result<ExecResponse> {
    let mut reader = PayloadReader::new(payload);

    let exit_code = reader.read_u32("exit code")? as i32;
    let pid = reader.read_u32("pid")?;
    let error_len = reader.read_u16("error length")? as usize;
    let error = if error_len > 0 {
        let bytes = reader.take(error_len, "error message")?;
        Some(String::from_utf8_lossy(bytes).to_string())
    } else {
        None
    };

    Ok(ExecResponse {
        exit_code,
        pid,
        error,
    })
}

/// Connect to running daemon and get metrics
pub fn get_metrics_from_daemon(socket_path: &Path) -> Result<MetricsResponse> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to daemon at {:?}", socket_path))?;

    // Without timeouts a wedged daemon makes this call hang forever.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();

    // Send GetMetrics request (empty payload)
    let msg = Message::new(MessageType::GetMetrics, vec![]);
    write_message(&mut stream, &msg)?;

    // Read response
    let response = read_message(&mut stream).context("Failed to read metrics response")?;
    if response.msg_type != MessageType::MetricsResponse {
        anyhow::bail!(
            "Unexpected response type from daemon: {:?}",
            response.msg_type
        );
    }

    // Parse MetricsResponse: [uptime:8][total:8][failed:8][successful:8][avg_ms:8][children:4][cgroup:1][prometheus_len:2][prometheus]
    let mut reader = PayloadReader::new(&response.payload);

    let uptime_secs = reader.read_u64("uptime")?;
    let total_requests = reader.read_u64("total requests")?;
    let failed_requests = reader.read_u64("failed requests")?;
    let successful_requests = reader.read_u64("successful requests")?;
    let avg_response_time_ms = f64::from_bits(reader.read_u64("avg response time")?);
    let active_children = reader.read_u32("active children")? as usize;
    let cgroup_active = reader.read_u8("cgroup active")? != 0;
    let prometheus_len = reader.read_u16("prometheus length")? as usize;
    let prometheus_metrics =
        String::from_utf8_lossy(reader.take(prometheus_len, "prometheus metrics")?).to_string();

    Ok(MetricsResponse {
        uptime_secs,
        total_requests,
        failed_requests,
        successful_requests,
        avg_response_time_ms,
        active_children,
        cgroup_active,
        prometheus_metrics,
    })
}

/// Entry point for running as a warm daemon
/// Called when --internal-warm-daemon flag is detected in main()
///
/// `WarmDaemon::run` builds its own Tokio runtime and blocks on it, which
/// panics with "Cannot start a runtime from within a runtime" when called from
/// `#[tokio::main]`. Run it on a dedicated OS thread so it owns a fresh runtime.
pub fn run_daemon_mode(args: &[String]) -> anyhow::Result<()> {
    let args = args.to_vec();
    std::thread::Builder::new()
        .name("warm-daemon".to_string())
        .spawn(move || daemon_main(&args))
        .context("Failed to spawn warm daemon thread")?
        .join()
        .map_err(|_| anyhow::anyhow!("Warm daemon thread panicked"))?
}

fn daemon_main(args: &[String]) -> anyhow::Result<()> {
    use clap::Parser;

    #[derive(Parser)]
    struct DaemonArgs {
        #[arg(long, hide = true)]
        internal_warm_daemon: bool,

        #[arg(long)]
        socket: String,

        #[arg(long)]
        rootfs: String,

        #[arg(long, default_value = "1")]
        cpu_count: usize,

        #[arg(long, default_value = "512")]
        memory_mb: usize,

        /// Security profile the mother is sandboxed with (bound at startup).
        #[arg(long, default_value = "sandbox")]
        profile: String,
    }

    let args = DaemonArgs::parse_from(args);

    let config = DaemonConfig {
        socket_path: PathBuf::from(args.socket),
        rootfs_path: PathBuf::from(args.rootfs),
        hardware_profile: Some(HardwareProfile {
            cpu_affinity: None,
            numa_node: None,
            cpu_count: args.cpu_count,
            memory_mb: args.memory_mb,
        }),
        metrics_port: 9090,
        mother_name: args.profile.clone(),
        security_profile: args.profile,
    };

    let mut daemon = WarmDaemon::new(config)?;
    daemon.run()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialize_deserialize() {
        let msg = Message::new(MessageType::Exec, vec![1, 2, 3, 4]);
        let serialized = msg.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();

        assert_eq!(msg.msg_type, deserialized.msg_type);
        assert_eq!(msg.payload, deserialized.payload);
    }

    #[test]
    fn test_is_safe_command() {
        assert!(is_safe_command("/bin/echo"));
        assert!(is_safe_command("ls -la"));
        assert!(is_safe_command("cat /etc/passwd"));
        assert!(!is_safe_command("ls; rm -rf /"));
        assert!(!is_safe_command("echo `whoami`"));
        assert!(!is_safe_command("cat $(cat /etc/shadow)"));
    }

    #[test]
    fn test_exec_request_parse() {
        let request = ExecRequest {
            command: "/bin/echo".to_string(),
            args: vec!["hello".to_string(), "world".to_string()],
            env: HashMap::new(),
            cwd: Some("/tmp".to_string()),
            hardware_profile: None,
        };

        assert_eq!(request.command, "/bin/echo");
        assert_eq!(request.args.len(), 2);
    }
}
