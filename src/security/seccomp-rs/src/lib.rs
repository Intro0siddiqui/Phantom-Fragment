use libseccomp::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SeccompError {
    #[error("Seccomp error: {0}")]
    LibSeccomp(#[from] libseccomp::error::SeccompError),
    #[error("Unknown profile: {0}")]
    UnknownProfile(String),
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
            ];

            for syscall_name in allowed.iter() {
                if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
                    ctx.add_rule(ScmpAction::Allow, syscall)?;
                }
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
