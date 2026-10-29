use libseccomp::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SeccompError {
    #[error("Seccomp error: {0}")]
    LibSeccomp(#[from] libseccomp::error::SeccompError),
    #[error("Unknown profile: {0}")]
    UnknownProfile(String),
}

pub fn is_supported() -> bool {
    // Check if seccomp is supported by the kernel
    // We can use prctl with PR_GET_SECCOMP (21) which returns 0 if seccomp is supported
    // but not enabled for the current process, or 1/2 if enabled.
    // If it returns -1 with EINVAL, it's not supported.
    unsafe {
        let ret = libc::prctl(21, 0, 0, 0, 0);
        if ret < 0 {
            let err = *libc::__errno_location();
            err != libc::EINVAL
        } else {
            true
        }
    }
}

pub fn apply_profile(name: &str) -> Result<(), SeccompError> {
    if name == "allow_all" {
        return Ok(());
    }

    // For hardened modes, use stricter default action
    let default_action = match name {
        "strict" | "hardened" => ScmpAction::Errno(libc::EPERM),
        _ => ScmpAction::Allow,
    };
    let mut ctx = ScmpFilterContext::new(default_action)?;

    match name {
        "default" | "sandbox" => {
            // Block dangerous syscalls while allowing most operations
            let blocked_syscalls = [
                "ptrace",
                "personality",
                "init_module",
                "delete_module",
                "kexec_load",
                "kexec_file_load",
            ];

            for syscall_name in blocked_syscalls.iter() {
                if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
                    ctx.add_rule(ScmpAction::Errno(libc::EPERM), syscall)?;
                }
            }
        }
        "strict" | "hardened" => {
            // Whitelist approach: allow only essential syscalls
            let allowed = [
                "read",
                "write",
                "open",
                "openat",
                "close",
                "stat",
                "fstat",
                "lstat",
                "mmap",
                "mprotect",
                "munmap",
                "brk",
                "rt_sigaction",
                "rt_sigprocmask",
                "ioctl",
                "access",
                "pipe",
                "pipe2",
                "dup",
                "dup2",
                "dup3",
                "execve",
                "exit",
                "exit_group",
                "wait4",
                "waitid",
                "clone",
                "fork",
                "vfork",
                "getpid",
                "getppid",
                "getuid",
                "geteuid",
                "getgid",
                "getegid",
                "gettid",
                "set_tid_address",
                "futex",
                "set_robust_list",
                "get_robust_list",
                "nanosleep",
                "clock_gettime",
                "clock_nanosleep",
                "getdents",
                "getdents64",
                "getcwd",
                "chdir",
                "fchdir",
                "readlink",
                "readlinkat",
                "fcntl",
                "socket",
                "connect",
                "accept",
                "accept4",
                "bind",
                "listen",
                "sendto",
                "recvfrom",
                "sendmsg",
                "recvmsg",
                "shutdown",
                "getsockname",
                "getpeername",
                "socketpair",
                "setsockopt",
                "getsockopt",
                "poll",
                "ppoll",
                "select",
                "pselect6",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_wait",
                "epoll_pwait",
                "arch_prctl",
                "prctl",
                "sigaltstack",
                "uname",
                "getrandom",
                // Startup path of a dynamically linked libc. Without these a
                // whitelist filter cannot even exec /bin/sh: ld.so reads the
                // shared objects with pread64 and looks them up with
                // newfstatat, and glibc's stat/fstat wrappers use newfstatat
                // on every modern architecture.
                "newfstatat",
                "fstatat64",
                "statx",
                "pread64",
                "readv",
                "writev",
                "lseek",
                "madvise",
                "mremap",
                "prlimit64",
                "getrlimit",
                "setrlimit",
                "getrusage",
                "rseq",
                "sched_getaffinity",
                "sched_yield",
                "faccessat",
                "faccessat2",
                "rt_sigreturn",
                "sigreturn",
                "umask",
                "sysinfo",
                "membarrier",
                "close_range",
                // NOTE: `clone3` is deliberately NOT allowed. glibc's
                // fork()/posix_spawn() try clone3 first, but only fall back to
                // `clone` on ENOSYS — the default EPERM would break process
                // creation entirely. Denying clone3 also keeps its
                // CLONE_INTO_CGROUP flag out of reach, which would otherwise
                // let a fragment escape its cgroup limits.
            ];

            for syscall_name in allowed.iter() {
                if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
                    ctx.add_rule(ScmpAction::Allow, syscall)?;
                }
            }

            // libseccomp does not synthesise this rule for us, so add it
            // explicitly: an explicit rule wins over the EPERM default action.
            if let Ok(clone3) = ScmpSyscall::from_name("clone3") {
                ctx.add_rule(ScmpAction::Errno(libc::ENOSYS), clone3)?;
            }
        }
        _ => return Err(SeccompError::UnknownProfile(name.to_string())),
    }

    ctx.load()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exit code used when the hardened profile cannot be installed at all, so
    /// the caller can skip instead of reporting a spurious failure.
    const SKIP_PROFILE_FAILED: i32 = 98;

    /// Fork a child, apply the hardened profile in it, run `f` and return the
    /// child's exit code.
    ///
    /// `f` must only use async-signal-safe calls and return its exit code;
    /// the child never returns from this function. `None` means seccomp is
    /// unavailable in this environment and the test should be skipped.
    fn with_hardened_child(f: impl FnOnce() -> i32) -> Option<i32> {
        if !is_supported() {
            return None;
        }

        // SAFETY: fork() from a test process; the child only runs `f` and
        // _exit()s, so it never touches the parent's state.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            let code = match apply_profile("hardened") {
                Ok(()) => f(),
                Err(_) => SKIP_PROFILE_FAILED,
            };
            // SAFETY: _exit is async-signal-safe and skips atexit handlers,
            // which must not run in a forked child of a threaded test binary.
            unsafe { libc::_exit(code) };
        }

        let mut status: libc::c_int = 0;
        // SAFETY: waiting on our own child.
        let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(reaped, pid, "waitpid did not reap the child");
        assert!(
            libc::WIFEXITED(status),
            "child terminated abnormally, status={status}"
        );
        Some(libc::WEXITSTATUS(status))
    }

    fn skip_if_unsupported(code: Option<i32>) -> Option<i32> {
        match code {
            Some(SKIP_PROFILE_FAILED) => {
                eprintln!("skipping: hardened profile could not be installed here");
                None
            }
            other => other,
        }
    }

    #[test]
    fn hardened_filter_makes_clone3_return_enosys() {
        // glibc's fork()/posix_spawn() probe clone3 first and only fall back to
        // clone on ENOSYS. If the hardened filter answered EPERM instead, every
        // process creation inside a hardened fragment would fail. libseccomp
        // emits the ENOSYS rule automatically while a `clone` rule exists.
        let code = skip_if_unsupported(with_hardened_child(|| {
            // SAFETY: clone3(2) with a NULL args pointer is rejected with
            // EFAULT by an unfiltered kernel, so this can never create a
            // process even if the filter is missing.
            let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) };
            if rc != -1 {
                return 1;
            }
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default();
            if errno == libc::ENOSYS {
                0
            } else {
                2
            }
        }));
        let Some(code) = code else { return };
        assert_eq!(code, 0, "expected clone3 -> ENOSYS, child exited {code}");
    }

    #[test]
    fn hardened_filter_still_allows_fork() {
        // The complement of the test above: the ENOSYS fallback must actually
        // let libc::fork() succeed, otherwise hardened fragments cannot spawn
        // any child process.
        let code = skip_if_unsupported(with_hardened_child(|| {
            // SAFETY: fork in the already-filtered child; the grandchild only
            // calls _exit and the child reaps it.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return 1;
            }
            if pid == 0 {
                // SAFETY: immediate, async-signal-safe exit.
                unsafe { libc::_exit(0) };
            }

            let mut status: libc::c_int = 0;
            // SAFETY: waiting on the grandchild we just created.
            let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
            if reaped == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                0
            } else {
                2
            }
        }));
        let Some(code) = code else { return };
        assert_eq!(code, 0, "fork() failed under hardened, child exited {code}");
    }

    #[test]
    #[ignore]
    fn test_apply_profile_dummy() {
        // This requires seccomp support in the test environment
        if let Err(e) = apply_profile("default") {
            log::warn!(
                "Failed to apply seccomp profile (expected in unprivileged environment): {}",
                e
            );
        }
    }
}
