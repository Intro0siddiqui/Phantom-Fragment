use anyhow::{Context, Result};
use colored::*;
use health_rs::is_process_alive;
use std::path::PathBuf;
use std::time::Instant;

use crate::config::PhantomPaths;
use crate::daemon::{start_daemon_background, DaemonConfig};
use crate::daemon::{DaemonSupervisor, SupervisorConfig};
use crate::fragment_pool::FragmentPool;
use crate::ui::{info, print_divider_full, print_header, success};
use execution_rs::HardwareProfile;

#[derive(clap::Subcommand, Clone, Debug)]
pub enum WarmCommands {
    /// Create a warm fragment pool for an image (beta/experimental)
    Create {
        /// Image name to create fragment for (e.g., alpine, ubuntu)
        image: String,
        /// Pool size (number of pre-forked processes)
        #[arg(default_value = "3")]
        size: usize,
        /// Enable automatic daemon restart supervision
        #[arg(long, default_value = "true")]
        supervise: bool,
        /// Initialize zygote pool for ultra-fast spawning
        #[arg(long)]
        zygote: bool,
    },
    /// List fragment pools (beta/experimental)
    List,
    /// Remove a fragment pool (beta/experimental)
    Remove {
        /// Image name of the pool to remove
        image: String,
    },
    /// Remove all fragment pools (beta/experimental)
    RemoveAll,
    /// Run benchmark to compare warm vs cold start (beta/experimental)
    Benchmark {
        /// Number of iterations for benchmark
        #[arg(long, default_value = "50")]
        iterations: usize,
        /// Pool size for warm benchmark
        #[arg(long, default_value = "5")]
        size: usize,
    },
    /// Start daemon supervision for a pool (auto-restart on crash) (beta/experimental)
    Supervise {
        /// Image name of the pool to supervise
        image: String,
    },
    /// Check daemon health and supervisor status (beta/experimental)
    Status {
        /// Image name to check
        image: String,
    },
}

use crate::commands::CommandContext;

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

fn kill_existing_daemons(pid_file_dir: &std::path::Path) -> Result<usize> {
    if !pid_file_dir.exists() {
        return Ok(0);
    }

    let mut killed_count = 0;

    if let Ok(entries) = std::fs::read_dir(pid_file_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("pid") {
                if let Ok(pid_str) = std::fs::read_to_string(&path) {
                    if let Ok(pid) = pid_str.trim().parse::<u32>() {
                        if is_process_alive(pid) {
                            let _ = std::process::Command::new("kill")
                                .arg("-9")
                                .arg(pid.to_string())
                                .output();
                            killed_count += 1;
                        }
                    }
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    Ok(killed_count)
}

pub async fn exec(_ctx: CommandContext<'_>, args: WarmCommands) -> Result<()> {
    // Warn that warm fragments are beta/experimental
    println!("{} Warm fragments are a beta/experimental feature with limitations (daemon stability, IPC issues)", "⚠".yellow().bold());
    println!();

    match args {
        WarmCommands::Create {
            image,
            size,
            supervise: _,
            zygote,
        } => {
            print_header("Create Fragment Pool (experimental)");
            print_divider_full();
            println!("\n{} Creating fragment pool for: {}", "→".yellow(), image);
            println!("{} Pool size: {}", "→".yellow(), size);
            if zygote {
                println!("{} Zygote pool: enabled", "→".yellow());
            }

            use image_puller::ImagePuller;

            let puller = ImagePuller::new().context("Failed to create ImagePuller")?;

            print!("\n{} Pulling image... ", "→".yellow());
            let rootfs_path = puller.get_rootfs(&image, true).await?;
            println!("{}", "Done".green());
            info("Rootfs:", &rootfs_path.display().to_string());

            let paths = PhantomPaths::new();
            let pid_file_dir = paths.fragment_pools().join(sanitize_image_name(&image));
            std::fs::create_dir_all(&pid_file_dir).ok();

            let killed = kill_existing_daemons(&pid_file_dir)?;
            if killed > 0 {
                println!("{} Killed {} existing daemon(s)", "✓".green(), killed);
            }

            print!("\n{} Starting daemon processes... ", "→".yellow());

            let mut registered_pids: Vec<u32> = Vec::new();

            for i in 0..size {
                let pid_file = pid_file_dir.join(format!("daemon_{}.pid", i));

                match start_daemon_in_rootfs(&rootfs_path, &pid_file, &image) {
                    Ok(pid) => {
                        println!("  {} Daemon {} started (PID: {})", "✓".green(), i, pid);
                        registered_pids.push(pid);
                    }
                    Err(e) => {
                        println!("  {} Failed to start daemon {}: {:?}", "⚠".yellow(), i, e);
                    }
                }
            }

            if registered_pids.is_empty() {
                println!("{}", "Failed".red());
                anyhow::bail!("Failed to start any daemon processes");
            }
            println!("{} {} fragments ready", "✓".green(), registered_pids.len());

            let rootfs_str = rootfs_path.display().to_string();
            let mut pool =
                FragmentPool::new_with_pids(image.clone(), rootfs_str, registered_pids.clone())?;

            // Initialize zygote pool if requested
            let zygote_enabled = if zygote {
                use zygote_rs::ZygotePool;
                match ZygotePool::new(4) {
                    Ok(_pool) => {
                        println!(
                            "{} Zygote pool initialized (4 pre-forked processes)",
                            "✓".green()
                        );
                        // Mark pool as having zygote support
                        pool.get_pool_mut().zygote_enabled = true;
                        true
                    }
                    Err(e) => {
                        println!(
                            "{} Zygote pool initialization failed: {:?}",
                            "⚠".yellow(),
                            e
                        );
                        println!("   Requires CAP_SYS_ADMIN or unprivileged userns");
                        false
                    }
                }
            } else {
                false
            };

            success(&format!(
                "Fragment pool created for '{}' with {} fragments",
                image,
                registered_pids.len()
            ));
            if zygote && zygote_enabled {
                println!(
                    "{} Use 'phantom run --zygote {} <command>' for ultra-fast execution",
                    "→".cyan(),
                    image
                );
            } else {
                println!(
                    "{} Use 'phantom run {} <command>' to run commands",
                    "→".cyan(),
                    image
                );
            }
            return Ok(());
        }
        WarmCommands::List => {
            print_header("Fragment Pools (beta/experimental)");
            print_divider_full();
            let pools = FragmentPool::list()?;
            if pools.is_empty() {
                println!("\n{} No fragment pools found.", "ℹ".cyan());
            } else {
                println!();
                for pool in pools {
                    println!("  Image: {}", pool.image.yellow());
                    println!("  Rootfs: {}", pool.rootfs_path);
                    println!("  Pool Size: {}", pool.pool_size);
                    println!(
                        "  Available: {} | Busy: {}",
                        pool.available_pids.len().to_string().green(),
                        pool.busy_pids.len().to_string().yellow()
                    );
                    println!(
                        "  Created: {} | Last Used: {}",
                        pool.created_at, pool.last_used
                    );
                    println!();
                }
            }
            return Ok(());
        }
        WarmCommands::Remove { image } => {
            print_header("Remove Fragment Pool (beta/experimental)");
            print_divider_full();
            println!("\n{} Removing fragment pool for: {}", "→".yellow(), image);
            FragmentPool::remove(&image)?;
            println!("{} Fragment pool removed.", "✓".green().bold());
            return Ok(());
        }
        WarmCommands::RemoveAll => {
            print_header("Remove All Fragment Pools (beta/experimental)");
            print_divider_full();
            println!("\n{} Removing all fragment pools...", "→".yellow());
            FragmentPool::remove_all()?;
            println!("{} All fragment pools removed.", "✓".green().bold());
            return Ok(());
        }
        WarmCommands::Benchmark { iterations, size } => {
            run_benchmark(iterations, size).await?;
            return Ok(());
        }
        WarmCommands::Supervise { image } => {
            print_header("Start Daemon Supervision (beta/experimental)");
            print_divider_full();
            println!("\n{} Starting supervision for: {}", "→".yellow(), image);

            // Load the pool
            let pool = FragmentPool::load(&image)?;
            let pool_meta = pool.get_pool();

            // Read socket path from socket.path file
            let paths = PhantomPaths::new();
            let pool_dir = paths.fragment_pools().join(sanitize_image_name(&image));
            let socket_path_file = pool_dir.join("socket.path");

            let socket_path = if socket_path_file.exists() {
                let socket_path_str = std::fs::read_to_string(&socket_path_file)?;
                std::path::PathBuf::from(socket_path_str.trim())
            } else {
                // Fallback to default naming
                pool_dir.join(format!("{}.sock", sanitize_image_name(&image)))
            };

            // Create supervisor config
            let daemon_config = DaemonConfig {
                socket_path: socket_path.clone(),
                rootfs_path: PathBuf::from(&pool_meta.rootfs_path),
                hardware_profile: Some(HardwareProfile {
                    cpu_affinity: None,
                    numa_node: None,
                    cpu_count: 2,
                    memory_mb: 512,
                }),
                metrics_port: 9090,
            };

            let supervisor_config = SupervisorConfig {
                daemon_config,
                auto_restart: true,
                max_restart_attempts: 10,
                max_backoff_ms: 30000,
                health_check_interval_ms: 5000,
                verbose: true,
            };

            let mut supervisor = DaemonSupervisor::new(supervisor_config);

            println!("{} Starting supervisor...", "→".yellow());
            let _handle = supervisor.start_background()?;

            println!("{} Supervisor started successfully", "✓".green());
            println!("{} Monitoring daemon at: {:?}", "→".cyan(), socket_path);
            println!(
                "\n{} The supervisor will automatically restart the daemon if it crashes.",
                "ℹ".cyan()
            );
            println!("{} Press Ctrl+C to stop supervision.", "ℹ".cyan());

            // Keep running until interrupted
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

                let stats = supervisor.get_stats();
                let state = supervisor.state();

                print!(
                    "\r{} State: {:?} | Restarts: {} | Health checks: {} succeeded, {} failed",
                    "→".cyan(),
                    state,
                    stats.total_restarts,
                    stats.health_check_successes,
                    stats.health_check_failures
                );
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
        }
        WarmCommands::Status { image } => {
            print_header("Daemon Status (beta/experimental)");
            print_divider_full();
            println!("\n{} Checking status for: {}", "→".yellow(), image);

            let paths = PhantomPaths::new();
            let pool_dir = paths.fragment_pools().join(sanitize_image_name(&image));

            // Read socket path from the socket.path file
            let socket_path_file = pool_dir.join("socket.path");
            if !socket_path_file.exists() {
                println!(
                    "{} No socket path file found. Pool may not exist or daemon not started.",
                    "⚠".yellow()
                );
                return Ok(());
            }

            let socket_path_str = std::fs::read_to_string(&socket_path_file)
                .context("Failed to read socket path file")?;
            let socket_path = std::path::PathBuf::from(socket_path_str.trim());

            // Check if socket exists
            if !socket_path.exists() {
                println!(
                    "{} No daemon socket found at: {:?}",
                    "⚠".yellow(),
                    socket_path
                );
                println!("{} Daemon may not be running or crashed.", "ℹ".cyan());
                return Ok(());
            }

            // Try to connect and get health status
            match std::os::unix::net::UnixStream::connect(&socket_path) {
                Ok(_) => {
                    println!("{} Daemon is running and responsive", "✓".green());
                    println!("{} Socket: {:?}", "→".cyan(), socket_path);

                    // Try to get metrics
                    match crate::daemon::get_metrics_from_daemon(&socket_path) {
                        Ok(metrics) => {
                            println!("\n{} Metrics:", "→".yellow());
                            println!("  Uptime: {} seconds", metrics.uptime_secs);
                            println!("  Total requests: {}", metrics.total_requests);
                            println!("  Failed requests: {}", metrics.failed_requests);
                            println!("  Active children: {}", metrics.active_children);
                            println!("  Avg response time: {:.2}ms", metrics.avg_response_time_ms);
                            println!("  Cgroup active: {}", metrics.cgroup_active);
                        }
                        Err(e) => {
                            println!("{} Could not get metrics: {:?}", "⚠".yellow(), e);
                        }
                    }
                }
                Err(e) => {
                    println!(
                        "{} Daemon socket exists but not responding: {}",
                        "⚠".yellow(),
                        e
                    );
                    println!("{} Daemon may be hung or in a bad state.", "ℹ".cyan());
                }
            }

            // Check for PID files
            let pid_files: Vec<_> = std::fs::read_dir(&pool_dir)
                .ok()
                .into_iter()
                .flat_map(|entries| entries.filter_map(|e| e.ok()))
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("pid"))
                .collect();

            if !pid_files.is_empty() {
                println!("\n{} Registered daemon PIDs:", "→".yellow());
                for pid_file in pid_files {
                    if let Ok(pid_str) = std::fs::read_to_string(pid_file.path()) {
                        if let Ok(pid) = pid_str.trim().parse::<u32>() {
                            let is_alive = is_process_alive(pid);
                            let status = if is_alive {
                                "alive".green()
                            } else {
                                "dead".red()
                            };
                            println!("  PID {}: {}", pid, status);
                        }
                    }
                }
            }

            return Ok(());
        }
    }
}

/// Run warm vs cold start benchmark
async fn run_benchmark(iterations: usize, size: usize) -> Result<()> {
    use zygote_rs::ZygotePool;

    print_header("Zygote Pool Warm Up");
    print_divider_full();

    println!(
        "\n{} Running benchmark ({} iterations)...\n",
        "→".yellow(),
        iterations
    );

    println!("--- Cold Start ---");
    let mut cold_total = 0.0;
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = std::process::Command::new("/bin/true").output();
        cold_total += start.elapsed().as_secs_f64() * 1000.0;
    }
    let cold_avg = cold_total / iterations as f64;
    println!("Average: {:.2}ms", cold_avg);

    println!("\n--- Warm Start (pool size: {}) ---", size);
    let pool_init_start = Instant::now();
    match ZygotePool::new(size) {
        Ok(mut pool) => {
            let pool_init = pool_init_start.elapsed().as_secs_f64() * 1000.0;
            println!("Pool init: {:.2}ms", pool_init);

            let mut warm_total = 0.0;
            for _ in 0..iterations {
                let start = Instant::now();
                let _ = pool.spawn();
                warm_total += start.elapsed().as_secs_f64() * 1000.0;
            }
            let warm_avg = warm_total / iterations as f64;
            println!("Average: {:.2}ms", warm_avg);

            println!("\n{}", "═".repeat(40).dimmed());
            println!("{} Cold: {:.2}ms", "Cold:".red(), cold_avg);
            println!("{} Warm: {:.2}ms", "Warm:".green(), warm_avg);
            println!(
                "{} Speedup: {:.1}x",
                "Speedup:".yellow(),
                cold_avg / warm_avg
            );
            println!(
                "{} Pool init overhead: {:.2}ms",
                "Init:".dimmed(),
                pool_init
            );
            println!("{}", "═".repeat(40).dimmed());
        }
        Err(e) => {
            println!("{} Zygote pool unavailable: {:?}", "⚠".yellow(), e);
            println!("   This requires CAP_SYS_ADMIN or unprivileged userns.");
            println!("\n{} Cold: {:.2}ms", "Cold:".red(), cold_avg);
            println!("   Warm: (unavailable - needs kernel permissions)");
            println!(
                "\n{} The zygote pool provides faster spawn but requires",
                "ℹ".cyan()
            );
            println!("   privileges. On systems without permissions, cold spawn");
            println!("   at ~1ms is already very fast.");
        }
    }

    Ok(())
}

/// Start a socket-based warm fragment daemon in the rootfs
///
/// This replaces the insecure shell-script daemon with a proper:
/// - Unix socket IPC (event-driven, no polling)
/// - Safe command execution (no eval, uses Command::new directly)
/// - Cgroup integration (applied before exec)
/// - Proper cleanup on exit
fn start_daemon_in_rootfs(
    rootfs_path: &std::path::Path,
    pid_file: &std::path::Path,
    image_name: &str,
) -> Result<u32> {
    let pool_dir = pid_file.parent().unwrap();
    std::fs::create_dir_all(pool_dir).ok();

    // Create socket path in the pool directory
    let socket_path = pool_dir.join(format!("{}.sock", sanitize_image_name(image_name)));

    // Create hardware profile with default limits
    let hardware_profile = Some(HardwareProfile {
        cpu_affinity: None,
        numa_node: None,
        cpu_count: 2,
        memory_mb: 512,
    });

    let config = DaemonConfig {
        socket_path: socket_path.clone(),
        rootfs_path: rootfs_path.to_path_buf(),
        hardware_profile,
        metrics_port: 9090,
    };

    // Start the daemon in background
    let daemon_pid =
        start_daemon_background(config).context("Failed to start warm fragment daemon")?;

    // Write PID file
    std::fs::write(pid_file, daemon_pid.to_string()).context("Failed to write daemon PID file")?;

    // Write socket path to a file for the client to find
    let socket_path_file = pool_dir.join("socket.path");
    std::fs::write(&socket_path_file, socket_path.to_string_lossy().as_bytes())
        .context("Failed to write socket path")?;

    Ok(daemon_pid)
}
