//! Native cold executor.
//!
//! One-shot sandbox for `phantom run <image>`: user, mount, PID, IPC, UTS and
//! (when network is disabled) network namespaces, a private root, `/proc`,
//! `/tmp`, `/dev`, then the shared security stack from [`crate::engine::sandbox`]
//! applied in the command child right before `execve`.
//!
//! Process layout:
//!
//! ```text
//! phantom (CLI)                    host pid namespace
//!   └─ sandbox child               unshare + maps, then forks
//!        └─ reaper                 first process in the new pid namespace (PID 1)
//!             └─ command child     confined by Landlock + caps + seccomp
//! ```
//!
//! Two details drive this shape:
//!
//! * `/proc` can only be mounted from inside the new PID namespace. After
//!   `unshare(CLONE_NEWPID)` the caller is still in the old namespace, so the
//!   mount has to happen after the fork, in the reaper.
//! * The command cannot be PID 1. PID 1 ignores signals it has no handler for,
//!   so a `SIGTERM` sent to the namespace would be lost. The reaper installs
//!   handlers, forwards `SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT` to the command,
//!   reaps it and exits with its status. It also dies with the CLI
//!   (`PR_SET_PDEATHSIG`), which tears down the PID namespace and therefore the
//!   command.
//!
//! Mounts are made through the *host* paths (`<rootfs>/dev`, `<rootfs>/proc`, …)
//! and the root switch happens afterwards, as bubblewrap does. Bind-mounting
//! `/dev` nodes through `/proc/self/fd` does not work here: the magic link
//! resolves back to the same path inside the new root, which makes the bind a
//! file-onto-itself mount and fails with `EINVAL`.
//!
//! The security stack is applied in the command child, not in the reaper: the
//! reaper needs `kill(2)`/`wait4(2)` to do its job and the hardened seccomp
//! profile does not allow `kill`. Applying it per command keeps the filter on
//! the process that actually runs image code.

use anyhow::Result;
use std::ffi::{CStr, CString};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use crate::engine::sandbox::{
    apply_child_landlock, drop_child_capabilities, write_proc_file, ChildPolicy,
};

/// Host device nodes bind-mounted into the image's `/dev`.
const DEV_BINDS: [&CStr; 6] = [
    c"/dev/null",
    c"/dev/zero",
    c"/dev/full",
    c"/dev/random",
    c"/dev/urandom",
    c"/dev/tty",
];

/// Exit code used by the sandbox child when it cannot set up the sandbox.
const SETUP_FAILED: i32 = 125;

/// `prctl(2)` option that is not exported for linux-gnu by `libc`.
const PR_SET_PDEATHSIG: libc::c_int = 1;

/// What to run and how to confine it.
pub(crate) struct NativeSpec {
    pub(crate) rootfs: PathBuf,
    pub(crate) command: Vec<String>,
    pub(crate) network: bool,
    /// UID the command runs as *inside* the image. The host UID is mapped onto
    /// it, so no setuid call is needed: the process is already that uid in the
    /// new user namespace.
    pub(crate) inside_uid: u32,
    pub(crate) inside_gid: u32,
    pub(crate) policy: ChildPolicy,
    /// Environment for the command. Replaces the CLI environment entirely.
    pub(crate) env: Vec<(String, String)>,
    /// Host file to bind over the image's `/etc/resolv.conf` (network enabled).
    pub(crate) resolv_conf: Option<PathBuf>,
}

/// Why the native engine could not run the command.
#[derive(Debug)]
pub(crate) enum NativeFailure {
    /// The kernel or the host cannot provide a namespace/mount primitive. The
    /// caller may fall back to bubblewrap, which needs different primitives.
    Unsupported(String),
    /// The sandbox was set up but the requested confinement could not be
    /// enforced, or the command could not be executed. Falling back would run
    /// the command with less isolation than requested, so this is fatal.
    Fatal(String),
}

impl std::fmt::Display for NativeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NativeFailure::Unsupported(m) | NativeFailure::Fatal(m) => write!(f, "{}", m),
        }
    }
}

/// Host pid of the reaper, for signal forwarding.
static REAPER_PID: AtomicI32 = AtomicI32::new(0);
/// Command pid inside the reaper's namespace, for signal forwarding.
static COMMAND_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_to_reaper(sig: libc::c_int) {
    let pid = REAPER_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

extern "C" fn forward_to_command(sig: libc::c_int) {
    let pid = COMMAND_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// Every path the reaper mounts, resolved against the image root.
struct RootSetup {
    rootfs: CString,
    proc_dir: CString,
    tmp_dir: CString,
    dev_dir: CString,
    devpts_dir: CString,
    devshm_dir: CString,
    ptmx: CString,
    /// `(host device node, target inside the image)`.
    dev_targets: Vec<(&'static CStr, CString)>,
    /// `(host resolv.conf, target inside the image)`.
    resolv: Option<(CString, CString)>,
}

impl RootSetup {
    fn new(spec: &NativeSpec) -> std::result::Result<Self, NativeFailure> {
        let root = &spec.rootfs;
        let path = |rel: &str| {
            CString::new(root.join(rel).to_string_lossy().as_bytes()).map_err(|_| {
                NativeFailure::Fatal(format!("{} contains a NUL byte", root.display()))
            })
        };

        let dev_targets = DEV_BINDS
            .iter()
            .map(|source| {
                let name = source.to_string_lossy();
                let name = name.trim_start_matches("/dev/");
                Ok((*source, path(&format!("dev/{}", name))?))
            })
            .collect::<std::result::Result<Vec<_>, NativeFailure>>()?;

        let resolv = match &spec.resolv_conf {
            Some(source) => Some((
                CString::new(source.to_string_lossy().as_bytes()).map_err(|_| {
                    NativeFailure::Fatal("resolv.conf path contains a NUL byte".into())
                })?,
                path("etc/resolv.conf")?,
            )),
            None => None,
        };

        Ok(Self {
            rootfs: CString::new(root.to_string_lossy().as_bytes())
                .map_err(|_| NativeFailure::Fatal("rootfs path contains a NUL byte".into()))?,
            proc_dir: path("proc")?,
            tmp_dir: path("tmp")?,
            dev_dir: path("dev")?,
            devpts_dir: path("dev/pts")?,
            devshm_dir: path("dev/shm")?,
            ptmx: path("dev/ptmx")?,
            dev_targets,
            resolv,
        })
    }
}

/// The command and the `execve(2)`-ready pointer arrays built from it.
///
/// The pointers are created before the fork so the children never allocate.
struct Command {
    argv: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    envp_ptrs: Vec<*const libc::c_char>,
}

impl Command {
    fn new(spec: &NativeSpec) -> std::result::Result<Self, NativeFailure> {
        let argv: Vec<CString> = spec
            .command
            .iter()
            .map(|a| CString::new(a.as_str()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| NativeFailure::Fatal("command contains a NUL byte".into()))?;
        if argv.is_empty() {
            return Err(NativeFailure::Fatal("command cannot be empty".into()));
        }
        let envp: Vec<CString> = spec
            .env
            .iter()
            .map(|(k, v)| CString::new(format!("{}={}", k, v)))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| NativeFailure::Fatal("environment contains a NUL byte".into()))?;

        // `execve(2)` wants an array of pointers, not an array of `CString`
        // (which is a fat pointer).
        Ok(Self {
            argv_ptrs: null_terminated(&argv),
            envp_ptrs: null_terminated(&envp),
            argv,
        })
    }
}

/// Run `spec` in a fresh sandbox and return the command's exit code.
pub(crate) fn execute(spec: &NativeSpec) -> std::result::Result<i32, NativeFailure> {
    let host_uid = nix::unistd::getuid().as_raw();
    let host_gid = nix::unistd::getgid().as_raw();

    let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<libc::c_int>().ok())
        .unwrap_or(63);

    // The mount points have to exist on the host path before the reaper runs.
    for dir in ["proc", "tmp", "dev", "dev/pts", "dev/shm", "etc"] {
        let _ = std::fs::create_dir_all(spec.rootfs.join(dir));
    }

    let setup = RootSetup::new(spec)?;

    let uid_map = CString::new(format!("{} {} 1", spec.inside_uid, host_uid))
        .expect("generated uid map cannot contain a NUL byte");
    let gid_map = CString::new(format!("{} {} 1", spec.inside_gid, host_gid))
        .expect("generated gid map cannot contain a NUL byte");

    let command = Command::new(spec)?;

    let mut pipe = [0 as RawFd; 2];
    // SAFETY: pipe2 fills a two-element array.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(NativeFailure::Fatal(format!(
            "pipe2 failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let (read_fd, write_fd) = (pipe[0], pipe[1]);

    let child = match unsafe { libc::fork() } {
        -1 => {
            return Err(NativeFailure::Fatal(format!(
                "fork failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        0 => run_sandbox(write_fd, setup, uid_map, gid_map, &command, spec, last_cap),
        pid => pid,
    };

    forward_signals_to(child);

    // SAFETY: closing our copy of the write end is required for EOF detection.
    unsafe { libc::close(write_fd) };

    let message = read_all(read_fd);
    // SAFETY: closing the read end after EOF.
    unsafe { libc::close(read_fd) };

    let status = wait_for(child);
    clear_signal_forwarding();

    if !message.is_empty() {
        let kind = message[0];
        let text = String::from_utf8_lossy(&message[1..]).trim().to_string();
        return Err(if kind == b'U' {
            NativeFailure::Unsupported(text)
        } else {
            NativeFailure::Fatal(text)
        });
    }

    Ok(exit_code(status))
}

/// Translate a wait status to a shell-style exit code.
fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        SETUP_FAILED
    }
}

/// Wait for `pid`, retrying on `EINTR`.
fn wait_for(pid: libc::pid_t) -> libc::c_int {
    let mut status = 0;
    loop {
        // SAFETY: waitpid writes into `status` for the given pid.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return status;
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return -1;
    }
}

fn read_all(fd: RawFd) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        // SAFETY: read(2) into a stack buffer of the given length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            out.extend_from_slice(&buf[..n as usize]);
            if out.len() > 4096 {
                break;
            }
            continue;
        }
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
    out
}

/// Report a setup failure to the parent and exit.
///
/// `kind` is `b'U'` for "this host cannot provide the primitive" and `b'F'`
/// for everything else.
fn report(fd: RawFd, kind: u8, step: &str) -> ! {
    let errno = std::io::Error::last_os_error();
    let msg = format!("{}: {}", step, errno);
    let mut buf = Vec::with_capacity(msg.len() + 2);
    buf.push(kind);
    buf.extend_from_slice(msg.as_bytes());
    // SAFETY: writing to the pipe created before the fork.
    unsafe {
        libc::write(fd, buf.as_ptr().cast(), buf.len());
        libc::_exit(SETUP_FAILED);
    }
}

/// Report a fatal (non-fallback) failure and exit.
fn fatal(fd: RawFd, msg: &str) -> ! {
    let mut buf = Vec::with_capacity(msg.len() + 1);
    buf.push(b'F');
    buf.extend_from_slice(msg.as_bytes());
    // SAFETY: writing to the report pipe.
    unsafe {
        libc::write(fd, buf.as_ptr().cast(), buf.len());
        libc::_exit(SETUP_FAILED);
    }
}

/// Body of the sandbox child: namespaces, maps, then fork the reaper.
///
/// This process stays in the host PID namespace; its child is PID 1 of the new
/// one. It waits for that child and mirrors its status.
fn run_sandbox(
    report_fd: RawFd,
    setup: RootSetup,
    uid_map: CString,
    gid_map: CString,
    command: &Command,
    spec: &NativeSpec,
    last_cap: libc::c_int,
) -> ! {
    let mut flags = libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS;
    if !spec.network {
        flags |= libc::CLONE_NEWNET;
    }

    // SAFETY: unshare(2) with a flag mask.
    if unsafe { libc::unshare(flags) } != 0 {
        report(report_fd, b'U', "unshare");
    }

    // Supplementary groups inherited from the host cannot be cleared here:
    // `setgroups(2)` is only allowed once `gid_map` exists, and an unprivileged
    // `gid_map` write requires `setgroups=deny`, which permanently blocks
    // `setgroups(2)`. They stay in the group list but none of them is mapped in
    // the new namespace, so they appear as the overflow gid (65534) and grant
    // nothing on the host. This matches the warm mother's behaviour.
    if let Err(e) = write_proc_file("/proc/self/setgroups", b"deny") {
        if e.kind() != std::io::ErrorKind::NotFound {
            report(report_fd, b'U', "write /proc/self/setgroups");
        }
    }
    if let Err(e) = write_proc_file("/proc/self/uid_map", uid_map.as_bytes()) {
        log::debug!("uid_map write failed: {}", e);
        report(report_fd, b'U', "write /proc/self/uid_map");
    }
    if let Err(e) = write_proc_file("/proc/self/gid_map", gid_map.as_bytes()) {
        log::debug!("gid_map write failed: {}", e);
        report(report_fd, b'U', "write /proc/self/gid_map");
    }

    // Make all mounts private so they do not propagate to the host.
    // SAFETY: mount(2) with a static target and no source or data.
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
        report(report_fd, b'U', "mount / private");
    }

    // This is the process that becomes PID 1 of the new namespace.
    let reaper = match unsafe { libc::fork() } {
        -1 => report(report_fd, b'F', "fork reaper"),
        0 => run_reaper(report_fd, setup, command, spec.policy, last_cap),
        pid => pid,
    };

    // The reaper owns the report pipe from here on.
    // SAFETY: closing our copy of the report pipe.
    unsafe { libc::close(report_fd) };

    let status = wait_for(reaper);
    // SAFETY: _exit(2) does not run atexit handlers or flush shared buffers.
    unsafe { libc::_exit(exit_code(status)) }
}

/// Body of the PID-1 reaper: mount the image root, switch into it, fork.
fn run_reaper(
    report_fd: RawFd,
    setup: RootSetup,
    command: &Command,
    policy: ChildPolicy,
    last_cap: libc::c_int,
) -> ! {
    // SAFETY: mount(2) calls with C strings built before the fork. A failure
    // here means the host cannot give us a usable /proc or writable /tmp, which
    // is what bubblewrap is a fallback for.
    unsafe {
        if libc::mount(
            c"tmpfs".as_ptr(),
            setup.dev_dir.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID,
            c"mode=0755".as_ptr().cast(),
        ) != 0
        {
            report(report_fd, b'U', "mount /dev");
        }
        // The tmpfs hides the image's /dev, so its subdirectories have to be
        // recreated on the new filesystem.
        libc::mkdir(setup.devpts_dir.as_ptr(), 0o755);
        libc::mkdir(setup.devshm_dir.as_ptr(), 0o755);
        if libc::mount(
            c"tmpfs".as_ptr(),
            setup.tmp_dir.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=1777".as_ptr().cast(),
        ) != 0
        {
            report(report_fd, b'U', "mount /tmp");
        }
        // procfs can only be mounted from the PID namespace that will own it,
        // which is why this happens here and not before the fork.
        if libc::mount(
            c"proc".as_ptr(),
            setup.proc_dir.as_ptr(),
            c"proc".as_ptr(),
            0,
            std::ptr::null(),
        ) != 0
        {
            report(report_fd, b'U', "mount /proc");
        }
    }

    for (source, target) in &setup.dev_targets {
        // Create the target inode on the fresh tmpfs, then bind the host node
        // over it. The host path is still reachable: the root switch is below.
        // SAFETY: open(2) with a valid C string.
        let created = unsafe { libc::open(target.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o600) };
        if created >= 0 {
            unsafe { libc::close(created) };
        }
        // SAFETY: mount(2) with a valid source and target.
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            report(report_fd, b'U', "bind /dev node");
        }
    }

    // A fresh devpts instance keeps the host's terminals out of the image. The
    // kernel refuses `newinstance` on some configurations; binding the host's
    // /dev/pts read-only is the weaker fallback the design document calls for.
    // SAFETY: mount(2) with static strings.
    let devpts = unsafe {
        libc::mount(
            c"devpts".as_ptr(),
            setup.devpts_dir.as_ptr(),
            c"devpts".as_ptr(),
            0,
            c"newinstance,ptmxmode=0666,mode=0620".as_ptr().cast(),
        )
    };
    if devpts != 0 {
        log::warn!(
            "devpts newinstance unavailable ({}); binding the host /dev/pts read-only",
            std::io::Error::last_os_error()
        );
        // SAFETY: mount(2) with a static source and a valid target.
        if unsafe {
            libc::mount(
                c"/dev/pts".as_ptr(),
                setup.devpts_dir.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_RDONLY,
                std::ptr::null(),
            )
        } != 0
        {
            report(report_fd, b'U', "bind /dev/pts");
        }
    }

    // SAFETY: unlink(2), symlink(2) and mount(2) with valid C strings.
    unsafe {
        libc::unlink(setup.ptmx.as_ptr());
        libc::symlink(c"pts/ptmx".as_ptr(), setup.ptmx.as_ptr());
        if libc::mount(
            c"tmpfs".as_ptr(),
            setup.devshm_dir.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=1777".as_ptr().cast(),
        ) != 0
        {
            log::warn!(
                "/dev/shm could not be mounted: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    if let Some((source, target)) = &setup.resolv {
        // SAFETY: open(2) and mount(2) with valid C strings.
        unsafe {
            let created = libc::open(target.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
            if created < 0 {
                report(report_fd, b'U', "create /etc/resolv.conf");
            }
            libc::close(created);
            if libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            ) != 0
            {
                report(report_fd, b'U', "bind /etc/resolv.conf");
            }
        }
    }

    // Enter the image. Everything below, including the command, runs inside it.
    // SAFETY: chroot(2) and chdir(2) with valid C strings.
    unsafe {
        if libc::chroot(setup.rootfs.as_ptr()) != 0 {
            report(report_fd, b'U', "chroot");
        }
        if libc::chdir(c"/".as_ptr()) != 0 {
            report(report_fd, b'U', "chdir /");
        }
    }

    // Die with the CLI. When the init process of a PID namespace exits, the
    // kernel kills every other process in that namespace, so this is also what
    // guarantees the command cannot outlive a crashed `phantom`.
    // SAFETY: prctl with PR_SET_PDEATHSIG takes a signal number as arg2.
    unsafe { libc::prctl(PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };

    let child = match unsafe { libc::fork() } {
        -1 => report(report_fd, b'F', "fork command"),
        0 => run_command(report_fd, command, policy, last_cap),
        pid => pid,
    };

    COMMAND_PID.store(child, Ordering::SeqCst);

    // A PID-1 process without a handler ignores these signals, so without these
    // handlers `kill <phantom>` would never reach the command.
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
        // SAFETY: installing a handler that only calls kill(2).
        unsafe { libc::signal(sig, forward_to_command as *const () as libc::sighandler_t) };
    }

    // The command child inherited the write end and keeps it until exec; ours
    // must be closed now or the CLI would block reading the pipe.
    // SAFETY: closing our copy of the report pipe.
    unsafe { libc::close(report_fd) };

    let status = wait_for(child);
    // SAFETY: _exit(2) does not run atexit handlers or flush shared buffers.
    unsafe { libc::_exit(exit_code(status)) }
}

/// Body of the command child: the security stack, then `execve`.
fn run_command(
    report_fd: RawFd,
    command: &Command,
    policy: ChildPolicy,
    last_cap: libc::c_int,
) -> ! {
    if let Err(e) = apply_child_landlock(policy.file_write) {
        fatal(report_fd, &format!("landlock: {}", e));
    }
    drop_child_capabilities(last_cap);

    if let Err(e) = seccomp_rs::apply_profile(policy.seccomp) {
        fatal(report_fd, &format!("seccomp '{}': {}", policy.seccomp, e));
    }

    // SAFETY: execve(2) with argv/envp built before the fork; it only returns on
    // failure, and the CLOEXEC report pipe is closed by a successful exec.
    unsafe {
        libc::execvpe(
            command.argv[0].as_ptr(),
            command.argv_ptrs.as_ptr(),
            command.envp_ptrs.as_ptr(),
        );
        let err = std::io::Error::last_os_error();
        fatal(
            report_fd,
            &format!("exec {}: {}", command.argv[0].to_string_lossy(), err),
        );
    }
}

/// Build a NUL-terminated array of `char *` for `execve(2)`.
fn null_terminated(args: &[CString]) -> Vec<*const libc::c_char> {
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    ptrs
}

/// Install the signal handlers that forward to the reaper.
///
/// Terminal-generated signals already reach the command through the process
/// group; this covers `kill <phantom-pid>` and service managers that signal
/// only the direct child.
fn forward_signals_to(reaper: libc::pid_t) {
    REAPER_PID.store(reaper, Ordering::SeqCst);
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
        // SAFETY: installing a handler that only calls kill(2).
        unsafe { libc::signal(sig, forward_to_reaper as *const () as libc::sighandler_t) };
    }
}

/// Forget the reaper so late signals do not hit a recycled pid.
fn clear_signal_forwarding() {
    REAPER_PID.store(0, Ordering::SeqCst);
}

/// Write the resolv.conf that an image with network access gets bound over.
pub(crate) fn write_resolv_conf(path: &Path) -> Result<()> {
    std::fs::write(path, "nameserver 8.8.8.8\nnameserver 1.1.1.1\n")?;
    Ok(())
}
