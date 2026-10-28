//! Rootfs Executor - Execute commands inside extracted rootfs with namespace isolation

use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct RootfsExecutor {
    rootfs_path: PathBuf,
    enable_network: bool,
    use_user_ns: bool,
    use_proot: bool,
    use_overlay: bool,
    use_mounts: bool,
    runtime: Option<String>,
    run_as_root: bool,
    user: Option<String>,
}

impl RootfsExecutor {
    /// Create a new RootfsExecutor
    pub fn new(rootfs_path: PathBuf) -> Self {
        Self {
            rootfs_path,
            enable_network: false,
            use_user_ns: true, // Default to rootless
            use_proot: false,
            use_overlay: false,
            use_mounts: false,
            runtime: None,
            run_as_root: false,
            user: None,
        }
    }

    /// Enable or disable network access
    pub fn with_network(mut self, enable: bool) -> Self {
        self.enable_network = enable;
        self
    }

    /// Enable or disable user namespace mapping (rootless mode)
    /// Default is true (rootless)
    pub fn with_user_ns(mut self, enable: bool) -> Self {
        self.use_user_ns = enable;
        self
    }

    /// Enable or disable Proot emulation (advanced rootless)
    pub fn with_proot(mut self, enable: bool) -> Self {
        self.use_proot = enable;
        self
    }

    /// Enable or disable Fuse-OverlayFS (copy-on-write)
    pub fn with_overlay(mut self, enable: bool) -> Self {
        self.use_overlay = enable;
        self
    }

    /// Enable or disable native mounts (requires CAP_SYS_ADMIN)
    pub fn with_mounts(mut self, enable: bool) -> Self {
        self.use_mounts = enable;
        self
    }

    /// Set OCI runtime to use (e.g., "runc", "crun")
    pub fn with_runtime(mut self, runtime: Option<String>) -> Self {
        self.runtime = runtime;
        self
    }

    /// Run as root inside the container (requires sudo or CAP_SYS_ADMIN)
    pub fn with_root(mut self, enable: bool) -> Self {
        self.run_as_root = enable;
        if enable {
            // Disable user namespace when running as root
            self.use_user_ns = false;
        }
        self
    }

    /// Set the user to run as (e.g., "1000", "1000:1000", "nobody")
    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    /// Execute a command inside the rootfs
    /// Returns the exit code
    pub fn execute<'a>(
        &'a self,
        command: &'a [String],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32>> + Send + 'a>> {
        Box::pin(async move {
            if command.is_empty() {
                anyhow::bail!("Command cannot be empty");
            }

            log::info!("Executing in rootfs: {:?}", command);
            log::info!("Rootfs path: {}", self.rootfs_path.display());

            // Verify rootfs exists
            if !self.rootfs_path.exists() {
                anyhow::bail!("Rootfs path does not exist: {}", self.rootfs_path.display());
            }

            // Setup DNS if network is enabled
            self.setup_dns()
                .context("Failed to setup DNS configuration")?;

            if let Some(runtime) = &self.runtime {
                return self.execute_with_runtime(command, runtime).await;
            }

            if self.use_overlay {
                return self.execute_with_overlay(command).await;
            }

            if self.use_proot {
                return self.execute_with_proot(command).await;
            }

            if self.use_mounts {
                return self.execute_with_chroot(command);
            }

            // Use unshare + chroot for namespace isolation
            self.execute_with_namespaces(command)
        })
    }

    async fn execute_with_runtime(&self, command: &[String], runtime: &str) -> Result<i32> {
        use crate::oci_config::OciConfig;
        use std::fs;

        log::info!("Using OCI runtime: {}", runtime);

        // We need a bundle directory containing config.json and rootfs
        // If we are already in an overlay, rootfs_path is the merged dir.
        // But runc expects rootfs to be a subdirectory of the bundle.
        // So we might need to create a bundle dir and symlink rootfs?
        // Or just generate config.json in rootfs_path/.. and point root.path to rootfs_path basename.

        let bundle_dir = self
            .rootfs_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Rootfs path has no parent directory"))?;
        let rootfs_name = self
            .rootfs_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Rootfs path has no file name"))?
            .to_string_lossy();

        // Generate config.json
        let mut config = OciConfig::default();
        config.root.path = rootfs_name.to_string();
        config.process.args = command.to_vec();

        // Serialize config.json
        let config_path = bundle_dir.join("config.json");
        let config_json = serde_json::to_string_pretty(&config)?;
        fs::write(&config_path, config_json)?;

        // Execute runtime
        // runc run <container-id>
        let container_id = format!("phantom-{}", uuid::Uuid::new_v4());
        log::info!("Starting container {} with {}", container_id, runtime);

        let status = Command::new(runtime)
            .arg("run")
            .arg("-b")
            .arg(bundle_dir)
            .arg(&container_id)
            .status()
            .context(format!("Failed to execute runtime {}", runtime))?;

        // Cleanup config.json
        if let Err(e) = fs::remove_file(&config_path) {
            log::warn!("Failed to remove config.json: {}", e);
        }

        Ok(status.code().unwrap_or(1))
    }

    async fn execute_with_overlay(&self, command: &[String]) -> Result<i32> {
        use crate::fuse_overlayfs::FuseOverlayfsManager;
        use std::fs;

        // Ensure fuse-overlayfs is available
        let overlay_manager =
            FuseOverlayfsManager::new().context("Failed to initialize FuseOverlayfsManager")?;
        let overlay_bin = overlay_manager
            .ensure_binary()
            .await
            .context("Failed to ensure fuse-overlayfs binary")?;

        // Create temp directories for overlay
        let temp_base = self
            .rootfs_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Rootfs path has no parent directory for overlay"))?
            .join(format!("overlay-{}", uuid::Uuid::new_v4()));
        let upper_dir = temp_base.join("upper");
        let work_dir = temp_base.join("work");
        let merged_dir = temp_base.join("merged");

        fs::create_dir_all(&upper_dir)?;
        fs::create_dir_all(&work_dir)?;
        fs::create_dir_all(&merged_dir)?;

        log::info!("Setting up overlayfs at {}", merged_dir.display());

        // Mount overlay
        // fuse-overlayfs -o lowerdir=ROOTFS,upperdir=UPPER,workdir=WORK MERGED
        let status = Command::new(&overlay_bin)
            .arg("-o")
            .arg(format!(
                "lowerdir={},upperdir={},workdir={}",
                self.rootfs_path.display(),
                upper_dir.display(),
                work_dir.display()
            ))
            .arg(&merged_dir)
            .status()
            .context("Failed to mount fuse-overlayfs")?;

        if !status.success() {
            anyhow::bail!("Failed to mount overlayfs");
        }

        // Create a temporary executor for the merged directory
        // We need to preserve settings but point to merged_dir
        // And disable overlay for the inner execution to avoid recursion loop
        let inner_executor = RootfsExecutor::new(merged_dir.clone())
            .with_network(self.enable_network)
            .with_user_ns(self.use_user_ns)
            .with_proot(self.use_proot)
            .with_overlay(false); // Important!

        // Execute command
        let result = inner_executor.execute(command).await;

        // Cleanup
        log::info!("Cleaning up overlayfs...");
        if let Err(e) = Command::new("fusermount")
            .arg("-u")
            .arg(&merged_dir)
            .status()
        {
            log::warn!("Failed to unmount fusermount: {}", e);
        }
        if let Err(e) = fs::remove_dir_all(&temp_base) {
            log::warn!("Failed to remove overlay temp directory: {}", e);
        }

        result
    }

    async fn execute_with_proot(&self, command: &[String]) -> Result<i32> {
        use crate::proot::ProotManager;

        // Ensure proot is available
        let proot_manager = ProotManager::new().context("Failed to initialize ProotManager")?;
        let proot_path = proot_manager
            .ensure_proot()
            .await
            .context("Failed to ensure proot binary")?;

        let mut cmd = Command::new(proot_path);

        // Root emulation (fake root privileges)
        cmd.arg("-0");

        // Rootfs path
        cmd.arg("-r");
        cmd.arg(&self.rootfs_path);

        // Bind mounts
        cmd.arg("-b").arg("/proc");
        cmd.arg("-b").arg("/sys");
        cmd.arg("-b").arg("/dev");

        // Bind resolv.conf if network enabled
        if self.enable_network {
            cmd.arg("-b").arg("/etc/resolv.conf:/etc/resolv.conf");
        }

        // Working directory
        cmd.arg("-w").arg("/");

        // Command
        cmd.args(command);

        log::info!("Running with Proot: {:?}", cmd);

        let status = cmd.status().context("Failed to execute proot command")?;
        Ok(status.code().unwrap_or(1))
    }

    /// Execute with namespace isolation using bubblewrap (bwrap)
    fn execute_with_namespaces(&self, command: &[String]) -> Result<i32> {
        let mut bwrap_args = vec![
            // Bind the rootfs to /
            "--bind".to_string(),
            self.rootfs_path.to_string_lossy().to_string(),
            "/".to_string(),
            // Basic mounts
            "--dev".to_string(),
            "/dev".to_string(),
            "--proc".to_string(),
            "/proc".to_string(),
            "--tmpfs".to_string(),
            "/tmp".to_string(),
        ];

        // User handling
        if let Some(ref user) = self.user {
            // bwrap only accepts numeric ids, so names must be resolved against
            // the image's own user database before building the argv.
            match resolve_uid_gid(&self.rootfs_path, user) {
                Some((uid, gid)) => {
                    log::info!("Running as UID={}, GID={}", uid, gid);
                    bwrap_args.extend_from_slice(&[
                        "--uid".to_string(),
                        uid.to_string(),
                        "--gid".to_string(),
                        gid.to_string(),
                    ]);
                }
                None => {
                    // Keeping the invoking user is the safe rootless default.
                    log::warn!(
                        "Cannot resolve user '{}' in the image's /etc/passwd or /etc/group; \
                         running as the invoking user",
                        user
                    );
                }
            }
        } else if self.run_as_root {
            // When running as root, use uid/gid 0 inside container
            bwrap_args.extend_from_slice(&[
                "--uid".to_string(),
                "0".to_string(),
                "--gid".to_string(),
                "0".to_string(),
            ]);
        } else if self.use_user_ns {
            bwrap_args.push("--unshare-user".to_string());
        }

        // Other namespace isolation
        bwrap_args.extend_from_slice(&[
            "--unshare-ipc".to_string(),
            "--unshare-pid".to_string(),
            "--unshare-uts".to_string(),
            "--die-with-parent".to_string(),
        ]);

        // Ensure /etc exists in rootfs for DNS bind mount
        let etc_dir = self.rootfs_path.join("etc");
        if !etc_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&etc_dir) {
                log::warn!("Failed to create /etc in rootfs: {}", e);
            }
        }

        // Network isolation
        if self.enable_network {
            bwrap_args.push("--share-net".to_string());
            // NOTE: DNS is configured in setup_dns() before this point
            // We don't bind mount /etc/resolv.conf here because that would overwrite
            // the public DNS configuration we set up earlier
        } else {
            bwrap_args.push("--unshare-net".to_string());
        }

        // Working directory
        bwrap_args.extend_from_slice(&[
            "--chdir".to_string(),
            "/".to_string(),
            // Set proper PATH for container execution
            "--setenv".to_string(),
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ]);

        // Add the command
        bwrap_args.extend_from_slice(command);

        log::info!("Running bwrap: {:?}", bwrap_args);

        let status = Command::new("bwrap")
            .args(&bwrap_args)
            .status()
            .context("Failed to execute command with bwrap")?;

        Ok(status.code().unwrap_or(1))
    }

    /// Execute using simple chroot  (fallback if unshare not available)
    fn execute_with_chroot(&self, command: &[String]) -> Result<i32> {
        if self.use_mounts {
            self.setup_mounts(&self.rootfs_path)?;
        }

        let mut cmd = Command::new("chroot");
        cmd.arg(&self.rootfs_path);
        cmd.args(command);

        log::info!(
            "Running: chroot {} {:?}",
            self.rootfs_path.display(),
            command
        );

        let status = cmd.status().context("Failed to execute command")?;

        if self.use_mounts {
            if let Err(e) = self.cleanup_mounts(&self.rootfs_path) {
                log::warn!("Failed to cleanup mounts: {}", e);
            }
        }

        Ok(status.code().unwrap_or(1))
    }

    /// Setup essential mounts for the rootfs
    fn setup_mounts(&self, rootfs: &Path) -> Result<()> {
        log::info!("Setting up native mounts for {}", rootfs.display());

        // Mount /proc
        let proc_path = rootfs.join("proc");
        std::fs::create_dir_all(&proc_path).ok();
        mount(
            Some("proc"),
            &proc_path,
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            None::<&str>,
        )
        .context("Failed to mount /proc")?;

        // Mount /sys
        let sys_path = rootfs.join("sys");
        std::fs::create_dir_all(&sys_path).ok();
        mount(
            Some("sysfs"),
            &sys_path,
            Some("sysfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .context("Failed to mount /sys")?;

        // Mount /dev (bind mount from host for simplicity in this MVP)
        let dev_path = rootfs.join("dev");
        std::fs::create_dir_all(&dev_path).ok();
        mount(
            Some("/dev"),
            &dev_path,
            None::<&str>,
            MsFlags::MS_BIND
                | MsFlags::MS_REC
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NOEXEC
                | MsFlags::MS_NODEV,
            None::<&str>,
        )
        .context("Failed to bind mount /dev")?;

        Ok(())
    }

    /// Cleanup mounts
    fn cleanup_mounts(&self, rootfs: &Path) -> Result<()> {
        use nix::mount::{umount2, MntFlags};

        log::info!("Cleaning up native mounts for {}", rootfs.display());

        let mounts = ["dev", "sys", "proc"];
        for m in mounts {
            let path = rootfs.join(m);
            if path.exists() {
                if let Err(e) = umount2(&path, MntFlags::MNT_DETACH) {
                    log::warn!("Failed to unmount {}: {}", path.display(), e);
                }
            }
        }

        Ok(())
    }

    /// Configure DNS by using public DNS servers (when network is enabled)
    fn setup_dns(&self) -> Result<()> {
        if self.enable_network {
            log::info!("DNS setup enabled for rootfs: {:?}", self.rootfs_path);
            let target_resolv = self.rootfs_path.join("etc/resolv.conf");

            // Ensure /etc exists
            if let Some(parent) = target_resolv.parent() {
                std::fs::create_dir_all(parent)
                    .context("Failed to create /etc directory in rootfs")?;
            }

            // Remove existing file if it exists (handles read-only files from previous runs)
            if target_resolv.exists() {
                log::info!("Removing existing resolv.conf: {:?}", target_resolv);
                // Make file writable first if needed, then remove it
                if let Err(e) = std::fs::set_permissions(
                    &target_resolv,
                    std::os::unix::fs::PermissionsExt::from_mode(0o644),
                ) {
                    log::warn!("Failed to set permissions on resolv.conf: {}", e);
                }
                if let Err(e) = std::fs::remove_file(&target_resolv) {
                    log::warn!("Failed to remove existing resolv.conf: {}", e);
                }
            }

            // Use public DNS servers (host DNS like 127.0.0.53 or internal IPs may be unreachable)
            let fallback_content = "nameserver 8.8.8.8\nnameserver 1.1.1.1\n";
            std::fs::write(&target_resolv, fallback_content)
                .context("Failed to create resolv.conf with public DNS")?;
            log::info!(
                "Configured DNS with public DNS servers (8.8.8.8, 1.1.1.1) at {:?}",
                target_resolv
            );
        }
        Ok(())
    }
}

/// Resolve a `user[:group]` spec to numeric `(uid, gid)` ids.
///
/// Numeric components are used as-is. Names are looked up in the rootfs' own
/// `/etc/passwd` and `/etc/group`, since the image's user database (not the
/// host's) is what applies inside the container. When only a user is given, the
/// gid defaults to that user's primary group from `/etc/passwd`, falling back to
/// the uid. Returns `None` when a name cannot be resolved.
fn resolve_uid_gid(rootfs: &Path, spec: &str) -> Option<(u32, u32)> {
    let (user_part, group_part) = match spec.split_once(':') {
        Some((user, group)) => (user, Some(group)),
        None => (spec, None),
    };
    let user_part = user_part.trim();
    if user_part.is_empty() {
        return None;
    }

    let (uid, primary_gid) = match user_part.parse::<u32>() {
        Ok(uid) => (uid, None),
        Err(_) => lookup_passwd(rootfs, user_part)?,
    };

    let gid = match group_part.map(str::trim) {
        None | Some("") => primary_gid.unwrap_or(uid),
        Some(group) => match group.parse::<u32>() {
            Ok(gid) => gid,
            Err(_) => lookup_group(rootfs, group)?,
        },
    };

    Some((uid, gid))
}

/// Look up `name` in the rootfs' `/etc/passwd`, returning `(uid, primary_gid)`.
fn lookup_passwd(rootfs: &Path, name: &str) -> Option<(u32, Option<u32>)> {
    let content = std::fs::read_to_string(rootfs.join("etc/passwd")).ok()?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut fields = line.split(':');
        if fields.next() != Some(name) {
            continue;
        }

        // name:passwd:uid:gid:...
        let _passwd = fields.next();
        let Some(uid) = fields.next().and_then(|f| f.trim().parse::<u32>().ok()) else {
            continue;
        };
        let gid = fields.next().and_then(|f| f.trim().parse::<u32>().ok());
        return Some((uid, gid));
    }

    None
}

/// Look up `name` in the rootfs' `/etc/group`, returning its gid.
fn lookup_group(rootfs: &Path, name: &str) -> Option<u32> {
    let content = std::fs::read_to_string(rootfs.join("etc/group")).ok()?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut fields = line.split(':');
        if fields.next() != Some(name) {
            continue;
        }

        // name:passwd:gid:members
        let _passwd = fields.next();
        return fields.next().and_then(|f| f.trim().parse::<u32>().ok());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = RootfsExecutor::new(PathBuf::from("/tmp/test-rootfs"));
        assert_eq!(executor.rootfs_path, PathBuf::from("/tmp/test-rootfs"));
        assert!(!executor.enable_network);
    }

    #[test]
    fn test_with_network() {
        let executor = RootfsExecutor::new(PathBuf::from("/tmp/test-rootfs")).with_network(true);
        assert!(executor.enable_network);
    }

    /// Minimal throwaway rootfs with an `etc/` directory.
    struct TempRootfs {
        path: PathBuf,
    }

    impl TempRootfs {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);

            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "phantom-rootfs-executor-test-{}-{}",
                std::process::id(),
                n
            ));
            std::fs::create_dir_all(path.join("etc")).expect("create temp rootfs");
            Self { path }
        }

        fn write_etc(&self, file: &str, content: &str) {
            std::fs::write(self.path.join("etc").join(file), content).expect("write etc file");
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempRootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    const PASSWD_ROOT: &str = "root:x:0:0:root:/root:/bin/sh\n";
    const PASSWD_APP: &str = "root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n";

    #[test]
    fn resolves_root_name() {
        let rootfs = TempRootfs::new();
        rootfs.write_etc("passwd", PASSWD_ROOT);
        assert_eq!(resolve_uid_gid(rootfs.path(), "root"), Some((0, 0)));
    }

    #[test]
    fn resolves_user_name_to_primary_gid() {
        let rootfs = TempRootfs::new();
        rootfs.write_etc("passwd", PASSWD_APP);
        assert_eq!(resolve_uid_gid(rootfs.path(), "app"), Some((1000, 1000)));
    }

    #[test]
    fn resolves_user_and_group_names() {
        let rootfs = TempRootfs::new();
        rootfs.write_etc("passwd", PASSWD_APP);
        rootfs.write_etc("group", "root:x:0:\napp:x:1000:\n");
        assert_eq!(
            resolve_uid_gid(rootfs.path(), "app:app"),
            Some((1000, 1000))
        );
    }

    #[test]
    fn passes_numeric_ids_through() {
        let rootfs = TempRootfs::new();
        assert_eq!(
            resolve_uid_gid(rootfs.path(), "1000:1001"),
            Some((1000, 1001))
        );
    }

    #[test]
    fn falls_back_to_uid_without_group_entry() {
        let rootfs = TempRootfs::new();
        rootfs.write_etc("passwd", PASSWD_APP);
        rootfs.write_etc("group", "root:x:0:\n");
        assert_eq!(resolve_uid_gid(rootfs.path(), "app"), Some((1000, 1000)));
    }

    #[test]
    fn unknown_user_is_none() {
        let rootfs = TempRootfs::new();
        rootfs.write_etc("passwd", PASSWD_APP);
        assert_eq!(resolve_uid_gid(rootfs.path(), "ghost"), None);
    }

    #[test]
    fn unknown_group_is_none() {
        let rootfs = TempRootfs::new();
        rootfs.write_etc("passwd", PASSWD_APP);
        rootfs.write_etc("group", "root:x:0:\n");
        assert_eq!(resolve_uid_gid(rootfs.path(), "app:ghosts"), None);
    }

    #[test]
    fn malformed_passwd_does_not_panic() {
        let rootfs = TempRootfs::new();
        rootfs.write_etc(
            "passwd",
            "\nnot-enough-fields\napp:x:not-a-number:1000::/home/app:/bin/sh\n",
        );
        assert_eq!(resolve_uid_gid(rootfs.path(), "app"), None);
    }

    #[test]
    fn missing_passwd_is_none() {
        let rootfs = TempRootfs::new();
        assert_eq!(resolve_uid_gid(rootfs.path(), "app"), None);
    }
}
