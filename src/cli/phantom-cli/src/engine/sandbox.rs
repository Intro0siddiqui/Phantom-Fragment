//! Security stack shared by the warm mother and the native cold executor.
//!
//! The stack is applied inside the sandboxed process after the root/mount
//! switch and before `execve`: Landlock filesystem rules, then the capability
//! drop with `no_new_privs`, then the seccomp filter. The warm mother applies
//! it once at pool-fill time; the native cold executor applies it per run.

use anyhow::Result;
use std::path::Path;

/// `prctl(2)` options that `libc` does not export for linux-gnu.
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

/// `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words per capability set.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Landlock access flags understood by `landlock-rs`'s rule encoding
/// (`0x2` = write, `0x4` = execute; read is always implied).
const LL_ACCESS_WRITE: u64 = 0x2;
const LL_ACCESS_EXECUTE: u64 = 0x4;

/// Security policy enforced by the warm child, resolved from a config profile.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChildPolicy {
    /// Whether the profile allows writes under the rootfs.
    pub(crate) file_write: bool,
    /// `seccomp-rs` filter to install before exec.
    pub(crate) seccomp: &'static str,
}

/// Resolve a profile name through the same config the CLI uses.
///
/// An unknown name is a hard error: silently running the command unconfined
/// when the caller asked for a profile would defeat the point of the profile.
pub(crate) fn resolve_child_policy(name: &str) -> Result<ChildPolicy> {
    let config = crate::config::Config::load().unwrap_or_else(|e| {
        log::warn!(
            "Failed to load phantom config while resolving warm profile '{}': {}",
            name,
            e
        );
        crate::config::Config::default()
    });

    let profile = config
        .get_profile(name)
        .ok_or_else(|| anyhow::anyhow!("unknown security profile: {}", name))?;

    Ok(ChildPolicy {
        file_write: profile.file_write,
        seccomp: seccomp_profile_for(profile),
    })
}

/// Map a config profile to the `seccomp-rs` filter for its isolation level,
/// mirroring the mode → profile mapping in `execution-rs`.
pub(crate) fn seccomp_profile_for(profile: &crate::config::Profile) -> &'static str {
    match profile.to_execution_mode() {
        execution_rs::ExecutionMode::Sandbox => "default",
        execution_rs::ExecutionMode::Hardened => "hardened",
        execution_rs::ExecutionMode::Wasm => "strict",
    }
}

/// Confine the calling process (the forked warm child) with Landlock.
///
/// Rules use paths as seen *after* `chroot(2)`, i.e. `/` is the image root and
/// `/tmp` / `/dev/shm` are the tmpfs mounts created just before this call. A
/// rule on `/` does not cover a separate mount, so the tmpfs roots get their own
/// rule.
pub(crate) fn apply_child_landlock(file_write: bool) -> std::result::Result<(), String> {
    let ctx = match landlock_rs::LandlockContext::new() {
        Some(ctx) => ctx,
        None => {
            // Kernel without Landlock (< 5.13): nothing can be enforced, but
            // that must not stop the command from running.
            log::warn!("Landlock unavailable; warm child runs without filesystem confinement");
            return Ok(());
        }
    };

    let access = if file_write {
        LL_ACCESS_WRITE | LL_ACCESS_EXECUTE
    } else {
        LL_ACCESS_EXECUTE
    };

    for path in ["/", "/tmp", "/dev/shm"] {
        if !Path::new(path).is_dir() {
            continue;
        }
        ctx.add_rule(path, access)
            .map_err(|e| format!("Landlock rule for {} failed: {}", path, e))?;
    }

    // The standard device nodes live on their own mount, so the `/` rule does
    // not grant access to them. A read-only profile would otherwise make every
    // `2>/dev/null` and `>/dev/tty` fail, which breaks ordinary commands
    // without protecting anything: these nodes discard or pass through writes.
    for path in [
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
    ] {
        if !Path::new(path).exists() {
            continue;
        }
        // A device that cannot be opened (e.g. `/dev/tty` without a controlling
        // terminal) is simply left out: no rule means access stays denied, which
        // is the safe direction.
        if let Err(e) = ctx.add_rule(path, LL_ACCESS_WRITE) {
            log::debug!("Landlock rule for {} skipped: {}", path, e);
        }
    }

    ctx.apply()
        .map_err(|e| format!("Landlock restrict_self failed: {}", e))
}

/// Drop the capability bounding set and clear the capability sets, then set
/// `no_new_privs`.
///
/// Defence in depth: the child is already unprivileged in the parent namespace,
/// so a kernel or namespace that refuses these calls must not fail the exec.
pub(crate) fn drop_child_capabilities(last_cap: libc::c_int) {
    /// `struct __user_cap_header_struct`
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    /// `struct __user_cap_data_struct`
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // A capability dropped from the bounding set cannot be regained across
    // execve. EINVAL (unknown to this kernel) and EPERM (already absent) are
    // both expected and harmless. `last_cap` was read in the parent: after the
    // chroot the image may not expose `/proc/sys/kernel/cap_last_cap`.
    for cap in 0..=last_cap {
        // SAFETY: prctl with PR_CAPBSET_DROP takes the capability number as arg2.
        unsafe { libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) };
    }

    // Clear the calling thread's sets. The child is single-threaded here, so a
    // per-thread capset covers the whole process.
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset takes a header and an array of two data words, matching
    // _LINUX_CAPABILITY_VERSION_3.
    let ret =
        unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if ret != 0 {
        log::warn!("capset(clear) failed: {}", std::io::Error::last_os_error());
    }

    // no_new_privs is what makes the drop stick across execve.
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes the flag value as arg2.
    if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        log::warn!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Write a single value to a procfs control file.
///
/// Used for `/proc/self/{setgroups,uid_map,gid_map}` after entering a user
/// namespace. The kernel requires the mapping to be written in one call.
pub(crate) fn write_proc_file(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(data)
}
