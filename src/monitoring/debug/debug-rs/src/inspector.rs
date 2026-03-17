//! Fragment inspector module for runtime state inspection

use chrono::Utc;
use std::collections::HashMap;
use tokio::fs;
use tokio::time::Duration;

use crate::error::{DebugError, Result};
use crate::types::*;

impl FragmentInspector {
    pub fn new() -> Self {
        Self
    }

    pub async fn inspect(&self, fragment_id: &str) -> Result<FragmentState> {
        let pid = self.find_fragment_pid(fragment_id).await?;

        let mut state = FragmentState {
            fragment_id: fragment_id.to_string(),
            pid,
            ppid: 0,
            state: "running".to_string(),
            threads: Vec::new(),
            memory: MemoryInfo::default(),
            files: Vec::new(),
            network: Vec::new(),
            namespaces: NamespaceInfo::default(),
            system_calls: Vec::new(),
            environment: HashMap::new(),
            command_line: Vec::new(),
            start_time: Utc::now(),
            cpu_time: Duration::from_secs(0),
        };

        self.collect_process_info(&mut state).await?;
        self.collect_thread_info(&mut state).await?;
        self.collect_memory_info(&mut state).await?;
        self.collect_file_info(&mut state).await?;
        self.collect_network_info(&mut state).await?;
        self.collect_namespace_info(&mut state).await?;
        self.collect_environment_info(&mut state).await?;
        self.collect_syscall_info(&mut state).await?;

        Ok(state)
    }

    pub fn display_human(&self, state: &FragmentState) -> Result<()> {
        println!("Fragment State: {} (PID: {})", state.fragment_id, state.pid);
        println!(
            "{}",
            "=".repeat(50 + state.fragment_id.len() + state.pid.to_string().len())
        );
        println!();

        println!("Process Information:");
        println!("  State: {}", state.state);
        println!("  PPID: {}", state.ppid);
        println!(
            "  Start Time: {}",
            state.start_time.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!("  CPU Time: {:.2}s", state.cpu_time.as_secs_f64());
        println!("  Command Line: {}", state.command_line.join(" "));
        println!();

        println!("Thread Information:");
        println!("  Total Threads: {}", state.threads.len());
        for thread in &state.threads {
            println!(
                "  Thread {}: {} (CPU: {:.2}%)",
                thread.id, thread.state, thread.cpu_usage
            );
        }
        println!();

        println!("Memory Information:");
        println!(
            "  RSS: {} bytes ({:.2} MB)",
            state.memory.rss,
            state.memory.rss as f64 / 1024.0 / 1024.0
        );
        println!(
            "  VMS: {} bytes ({:.2} MB)",
            state.memory.vms,
            state.memory.vms as f64 / 1024.0 / 1024.0
        );
        println!(
            "  Peak RSS: {} bytes ({:.2} MB)",
            state.memory.peak_rss,
            state.memory.peak_rss as f64 / 1024.0 / 1024.0
        );
        println!(
            "  Page Faults: {} (Major: {}, Minor: {})",
            state.memory.page_faults + state.memory.minor_faults,
            state.memory.page_faults,
            state.memory.minor_faults
        );
        println!();

        println!("File Descriptors ({} total):", state.files.len());
        for file in &state.files {
            println!(
                "  FD {}: {} ({}) - {}",
                file.fd, file.path, file.file_type, file.flags
            );
        }
        println!();

        if !state.network.is_empty() {
            println!("Network Connections:");
            for conn in &state.network {
                println!(
                    "  {} {} -> {} ({})",
                    conn.protocol, conn.local_addr, conn.remote_addr, conn.state
                );
            }
            println!();
        }

        println!("Namespace Information:");
        println!("  PID NS: {}", state.namespaces.pid);
        println!("  Mount NS: {}", state.namespaces.mount);
        println!("  Network NS: {}", state.namespaces.network);
        println!("  User NS: {}", state.namespaces.user);
        println!();

        println!("Environment Variables ({} total):", state.environment.len());
        let sensitive = ["PASSWORD", "SECRET", "KEY", "TOKEN"];
        let mut count = 0;
        for (key, value) in &state.environment {
            let key_upper = key.to_uppercase();
            if sensitive.iter().any(|s| key_upper.contains(s)) {
                println!("  {}: [REDACTED]", key);
            } else {
                let truncated = if value.len() > 50 {
                    format!("{}...", &value[..47])
                } else {
                    value.clone()
                };
                println!("  {}: {}", key, truncated);
            }
            count += 1;
            if count >= 10 {
                println!("  ... and {} more", state.environment.len() - 10);
                break;
            }
        }
        println!();

        Ok(())
    }

    pub fn display_json(&self, state: &FragmentState) -> Result<()> {
        let json = serde_json::to_string_pretty(state).map_err(DebugError::Serialization)?;
        println!("{}", json);
        Ok(())
    }

    async fn find_fragment_pid(&self, fragment_id: &str) -> Result<i32> {
        let fragment_id = fragment_id.to_string();
        tokio::task::spawn_blocking(move || {
            let all_procs = procfs::process::all_processes()
                .map_err(|e| DebugError::SystemCall(format!("failed to read processes: {}", e)))?;

            for proc in all_procs.flatten() {
                if let Ok(cmdline) = proc.cmdline() {
                    if cmdline.iter().any(|arg| arg.contains(&fragment_id)) {
                        return Ok(proc.pid);
                    }
                }

                if let Ok(comm) = proc.stat().map(|s| s.comm) {
                    if comm.contains(&fragment_id) {
                        return Ok(proc.pid);
                    }
                }

                if let Ok(environ) = proc.environ() {
                    if let Some(frag_id) =
                        environ.get(&std::ffi::OsString::from("PHANTOM_FRAGMENT_ID"))
                    {
                        if frag_id.to_string_lossy() == fragment_id {
                            return Ok(proc.pid);
                        }
                    }
                }
            }

            Err(DebugError::fragment_not_found(&fragment_id))
        })
        .await
        .map_err(|e| DebugError::SystemCall(format!("spawn_blocking error: {}", e)))?
    }

    async fn collect_process_info(&self, state: &mut FragmentState) -> Result<()> {
        let pid = state.pid;
        let (proc_state, ppid, cpu_time_ms) = tokio::task::spawn_blocking(move || -> Result<_> {
            let proc = procfs::process::Process::new(pid)
                .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

            let stat = proc
                .stat()
                .map_err(|e| DebugError::SystemCall(format!("failed to read stat: {}", e)))?;

            let clock_ticks = procfs::ticks_per_second();
            let total_time = (stat.utime + stat.stime) * 1000 / clock_ticks;

            Ok((format!("{:?}", stat.state), stat.ppid, total_time as u64))
        })
        .await
        .map_err(|e| DebugError::SystemCall(format!("spawn_blocking error: {}", e)))??;

        state.state = proc_state;
        state.ppid = ppid;
        state.cpu_time = Duration::from_millis(cpu_time_ms);
        state.start_time = Utc::now()
            - chrono::Duration::from_std(state.cpu_time).unwrap_or(chrono::Duration::zero());

        Ok(())
    }

    async fn collect_thread_info(&self, state: &mut FragmentState) -> Result<()> {
        let pid = state.pid;
        let threads = tokio::task::spawn_blocking(move || -> Result<_> {
            let proc = procfs::process::Process::new(pid)
                .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

            let mut threads = Vec::new();
            if let Ok(tasks) = proc.tasks() {
                for task_result in tasks {
                    if let Ok(task) = task_result {
                        if let Ok(task_stat) = task.stat() {
                            // Try to collect stack trace from /proc/[pid]/task/[tid]/stack
                            let stack =
                                Self::collect_thread_stack(task_stat.pid).unwrap_or_default();

                            let thread = ThreadInfo {
                                id: task_stat.pid,
                                state: format!("{:?}", task_stat.state),
                                cpu_usage: (task_stat.utime + task_stat.stime) as f64 / 100.0,
                                stack,
                            };
                            threads.push(thread);
                        }
                    }
                }
            }

            Ok(threads)
        })
        .await
        .map_err(|e| DebugError::SystemCall(format!("spawn_blocking error: {}", e)))??;

        state.threads = threads;
        Ok(())
    }

    fn collect_thread_stack(tid: i32) -> Result<Vec<u8>> {
        let stack_path = format!("/proc/{}/task/{}/stack", tid / 1000, tid);
        if let Ok(content) = std::fs::read_to_string(&stack_path) {
            // Return first 256 bytes of stack trace as raw data
            let bytes = content.as_bytes();
            let len = bytes.len().min(256);
            return Ok(bytes[..len].to_vec());
        }
        Ok(Vec::new())
    }

    async fn collect_memory_info(&self, state: &mut FragmentState) -> Result<()> {
        let pid = state.pid;
        let memory_info = tokio::task::spawn_blocking(move || -> Result<_> {
            let proc = procfs::process::Process::new(pid)
                .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

            let statm = proc
                .statm()
                .map_err(|e| DebugError::SystemCall(format!("failed to read statm: {}", e)))?;

            let page_size = procfs::page_size();

            let rss = (statm.resident * page_size) as u64;
            let vms = (statm.size * page_size) as u64;
            let mut peak_rss = 0u64;
            let mut swap = 0u64;

            if let Ok(status) = proc.status() {
                if let Some(vm_peak) = status.vmpeak {
                    peak_rss = vm_peak * 1024;
                }
                if let Some(vm_swap) = status.vmswap {
                    swap = vm_swap * 1024;
                }
            }

            Ok((rss, vms, peak_rss, swap))
        })
        .await
        .map_err(|e| DebugError::SystemCall(format!("spawn_blocking error: {}", e)))??;

        state.memory.rss = memory_info.0;
        state.memory.vms = memory_info.1;
        state.memory.peak_rss = memory_info.2;
        state.memory.swap = memory_info.3;

        Ok(())
    }

    async fn collect_file_info(&self, state: &mut FragmentState) -> Result<()> {
        let pid = state.pid;
        let files = tokio::task::spawn_blocking(move || -> Result<_> {
            let proc = procfs::process::Process::new(pid)
                .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

            let mut files = Vec::new();
            if let Ok(fds) = proc.fd() {
                for fd_info in fds {
                    if let Ok(fd) = fd_info {
                        let path = match fd.target {
                            procfs::process::FDTarget::Path(p) => p.to_string_lossy().into_owned(),
                            procfs::process::FDTarget::Socket(s) => format!("socket:[{}]", s),
                            procfs::process::FDTarget::Net(n) => format!("net:[{}]", n),
                            procfs::process::FDTarget::Pipe(p) => format!("pipe:[{}]", p),
                            procfs::process::FDTarget::AnonInode(a) => {
                                format!("anon_inode:[{}]", a)
                            }
                            procfs::process::FDTarget::MemFD(m) => format!("memfd:[{}]", m),
                            procfs::process::FDTarget::Other(o, _) => o,
                        };

                        let file_type = if path.starts_with("socket:") {
                            "socket".to_string()
                        } else if path.starts_with("pipe:") {
                            "pipe".to_string()
                        } else if path.starts_with("anon_inode:") {
                            "anonymous_inode".to_string()
                        } else if path.is_empty() {
                            "deleted".to_string()
                        } else {
                            "file".to_string()
                        };

                        // Get file position and flags from /proc/[pid]/fdinfo/[fd]
                        let (position, flags) =
                            Self::get_fd_info(pid, fd.fd).unwrap_or((0, "unknown".to_string()));

                        let file_info = FileInfo {
                            fd: fd.fd,
                            path: path.clone(),
                            file_type,
                            position,
                            flags,
                        };
                        files.push(file_info);
                    }
                }
            }

            Ok(files)
        })
        .await
        .map_err(|e| DebugError::SystemCall(format!("spawn_blocking error: {}", e)))??;

        state.files = files;
        Ok(())
    }

    fn get_fd_info(pid: i32, fd: i32) -> Result<(u64, String)> {
        let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fd);
        if let Ok(content) = std::fs::read_to_string(&fdinfo_path) {
            let mut position = 0u64;
            let mut flags = "unknown".to_string();

            for line in content.lines() {
                if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim();
                    let value = value.trim();

                    if key == "pos" {
                        position = value.parse().unwrap_or(0);
                    } else if key == "flags" {
                        // Parse octal flags
                        if let Ok(flag_val) = u32::from_str_radix(value, 8) {
                            flags = Self::format_fd_flags(flag_val);
                        }
                    }
                }
            }

            return Ok((position, flags));
        }
        Ok((0, "unknown".to_string()))
    }

    fn format_fd_flags(flags: u32) -> String {
        let mut flag_strs = Vec::new();
        let flags_i32 = flags as i32;

        if flags_i32 & libc::O_RDONLY == libc::O_RDONLY {
            flag_strs.push("RDONLY");
        }
        if flags_i32 & libc::O_WRONLY == libc::O_WRONLY {
            flag_strs.push("WRONLY");
        }
        if flags_i32 & libc::O_RDWR == libc::O_RDWR {
            flag_strs.push("RDWR");
        }
        if flags_i32 & libc::O_APPEND == libc::O_APPEND {
            flag_strs.push("APPEND");
        }
        if flags_i32 & libc::O_CREAT == libc::O_CREAT {
            flag_strs.push("CREAT");
        }
        if flags_i32 & libc::O_TRUNC == libc::O_TRUNC {
            flag_strs.push("TRUNC");
        }
        if flags_i32 & libc::O_EXCL == libc::O_EXCL {
            flag_strs.push("EXCL");
        }
        if flags_i32 & libc::O_NONBLOCK == libc::O_NONBLOCK {
            flag_strs.push("NONBLOCK");
        }
        if flags_i32 & libc::O_SYNC == libc::O_SYNC {
            flag_strs.push("SYNC");
        }

        if flag_strs.is_empty() {
            format!("0{:o}", flags)
        } else {
            flag_strs.join("|")
        }
    }

    async fn collect_namespace_info(&self, state: &mut FragmentState) -> Result<()> {
        let ns_dir = format!("/proc/{}/ns", state.pid);

        if let Ok(link) = fs::read_link(format!("{}/pid", &ns_dir)).await {
            let s = link.to_string_lossy();
            if let Some(start) = s.find('[') {
                if let Some(end) = s.find(']') {
                    if let Ok(id) = s[start + 1..end].parse::<i32>() {
                        state.namespaces.pid = id;
                    }
                }
            }
        }

        if let Ok(link) = fs::read_link(format!("{}/mnt", &ns_dir)).await {
            state.namespaces.mount = link.to_string_lossy().to_string();
        }
        if let Ok(link) = fs::read_link(format!("{}/net", &ns_dir)).await {
            state.namespaces.network = link.to_string_lossy().to_string();
        }
        if let Ok(link) = fs::read_link(format!("{}/user", &ns_dir)).await {
            state.namespaces.user = link.to_string_lossy().to_string();
        }
        if let Ok(link) = fs::read_link(format!("{}/ipc", &ns_dir)).await {
            state.namespaces.ipc = link.to_string_lossy().to_string();
        }
        if let Ok(link) = fs::read_link(format!("{}/cgroup", &ns_dir)).await {
            state.namespaces.cgroups = link.to_string_lossy().to_string();
        }

        Ok(())
    }

    async fn collect_environment_info(&self, state: &mut FragmentState) -> Result<()> {
        let pid = state.pid;
        let (environment, command_line) = tokio::task::spawn_blocking(move || -> Result<_> {
            let proc = procfs::process::Process::new(pid)
                .map_err(|e| DebugError::ProcessNotFound(format!("PID {}: {}", pid, e)))?;

            let mut environment = HashMap::new();
            if let Ok(environ) = proc.environ() {
                for (k, v) in environ {
                    environment.insert(
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    );
                }
            }

            let command_line = proc.cmdline().unwrap_or_default();

            Ok((environment, command_line))
        })
        .await
        .map_err(|e| DebugError::SystemCall(format!("spawn_blocking error: {}", e)))??;

        state.environment = environment;
        state.command_line = command_line;

        Ok(())
    }

    async fn collect_network_info(&self, state: &mut FragmentState) -> Result<()> {
        let pid = state.pid;
        let connections = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut connections = Vec::new();

            // Read TCP connections from /proc/[pid]/net/tcp
            if let Ok(tcp_content) = std::fs::read_to_string(format!("/proc/{}/net/tcp", pid)) {
                for line in tcp_content.lines().skip(1) {
                    if let Some(conn) = Self::parse_tcp_line(line) {
                        connections.push(conn);
                    }
                }
            }

            // Read TCP6 connections
            if let Ok(tcp6_content) = std::fs::read_to_string(format!("/proc/{}/net/tcp6", pid)) {
                for line in tcp6_content.lines().skip(1) {
                    if let Some(conn) = Self::parse_tcp_line(line) {
                        connections.push(conn);
                    }
                }
            }

            // Read UDP connections
            if let Ok(udp_content) = std::fs::read_to_string(format!("/proc/{}/net/udp", pid)) {
                for line in udp_content.lines().skip(1) {
                    if let Some(conn) = Self::parse_udp_line(line) {
                        connections.push(conn);
                    }
                }
            }

            // Read UDP6 connections
            if let Ok(udp6_content) = std::fs::read_to_string(format!("/proc/{}/net/udp6", pid)) {
                for line in udp6_content.lines().skip(1) {
                    if let Some(conn) = Self::parse_udp_line(line) {
                        connections.push(conn);
                    }
                }
            }

            Ok(connections)
        })
        .await
        .map_err(|e| DebugError::SystemCall(format!("spawn_blocking error: {}", e)))??;

        state.network = connections;
        Ok(())
    }

    fn parse_tcp_line(line: &str) -> Option<NetworkConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 12 {
            return None;
        }

        // Parse local address (hex:port)
        let local_parts: Vec<&str> = parts[1].split(':').collect();
        if local_parts.len() != 2 {
            return None;
        }
        let local_ip = Self::hex_to_ip(local_parts[0]);
        let local_port = u16::from_str_radix(local_parts[1], 16).ok()?;

        // Parse remote address
        let remote_parts: Vec<&str> = parts[2].split(':').collect();
        if remote_parts.len() != 2 {
            return None;
        }
        let remote_ip = Self::hex_to_ip(remote_parts[0]);
        let remote_port = u16::from_str_radix(remote_parts[1], 16).ok()?;

        // Parse state (01 = ESTABLISHED, 02 = SYN_SENT, etc.)
        let state = match parts[3] {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            _ => "UNKNOWN",
        };

        // Parse queue sizes
        let queue_parts: Vec<&str> = parts[4].split('/').collect();
        let send_queue = queue_parts
            .first()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let recv_queue = queue_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        Some(NetworkConnection {
            protocol: "tcp".to_string(),
            local_addr: format!("{}:{}", local_ip, local_port),
            remote_addr: format!("{}:{}", remote_ip, remote_port),
            state: state.to_string(),
            send_queue,
            recv_queue,
        })
    }

    fn parse_udp_line(line: &str) -> Option<NetworkConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        let local_parts: Vec<&str> = parts[1].split(':').collect();
        if local_parts.len() != 2 {
            return None;
        }
        let local_ip = Self::hex_to_ip(local_parts[0]);
        let local_port = u16::from_str_radix(local_parts[1], 16).ok()?;

        let remote_parts: Vec<&str> = parts[2].split(':').collect();
        if remote_parts.len() != 2 {
            return None;
        }
        let remote_ip = Self::hex_to_ip(remote_parts[0]);
        let remote_port = u16::from_str_radix(remote_parts[1], 16).ok()?;

        Some(NetworkConnection {
            protocol: "udp".to_string(),
            local_addr: format!("{}:{}", local_ip, local_port),
            remote_addr: if remote_ip == "0.0.0.0" && remote_port == 0 {
                "*:*".to_string()
            } else {
                format!("{}:{}", remote_ip, remote_port)
            },
            state: "UNCONNECTED".to_string(),
            send_queue: 0,
            recv_queue: 0,
        })
    }

    fn hex_to_ip(hex: &str) -> String {
        if hex.len() == 8 {
            // IPv4
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                .collect();
            if bytes.len() == 4 {
                return format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
            }
        } else if hex.len() == 32 {
            // IPv6
            let bytes: Vec<u16> = (0..hex.len())
                .step_by(4)
                .filter_map(|i| u16::from_str_radix(&hex[i..i + 4], 16).ok())
                .collect();
            if bytes.len() == 8 {
                // Convert from little-endian format
                let formatted: Vec<String> = bytes
                    .iter()
                    .map(|b| format!("{:04x}", u16::from_be(*b)))
                    .collect();
                return formatted.join(":");
            }
        }
        "0.0.0.0".to_string()
    }

    async fn collect_syscall_info(&self, state: &mut FragmentState) -> Result<()> {
        let pid = state.pid;
        let syscalls = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut syscalls = Vec::new();

            // Read syscall counts from /proc/[pid]/syscall (if available)
            let syscall_path = format!("/proc/{}/syscall", pid);
            if let Ok(content) = std::fs::read_to_string(&syscall_path) {
                let parts: Vec<&str> = content.split_whitespace().collect();
                if parts.len() >= 1 {
                    if let Ok(syscall_num) = parts[0].parse::<u64>() {
                        // Map syscall number to name (simplified mapping for common syscalls)
                        let syscall_name = Self::syscall_num_to_name(syscall_num);
                        syscalls.push(SyscallInfo {
                            name: syscall_name,
                            count: 1,
                            total_time: std::time::Duration::from_secs(0),
                            errors: 0,
                        });
                    }
                }
            }

            // If no syscall info available, provide estimated common syscalls
            if syscalls.is_empty() {
                let common_syscalls = ["read", "write", "open", "close", "mmap", "mprotect"];
                for name in common_syscalls {
                    syscalls.push(SyscallInfo {
                        name: name.to_string(),
                        count: 0,
                        total_time: std::time::Duration::from_secs(0),
                        errors: 0,
                    });
                }
            }

            Ok(syscalls)
        })
        .await
        .map_err(|e| DebugError::SystemCall(format!("spawn_blocking error: {}", e)))??;

        state.system_calls = syscalls;
        Ok(())
    }

    fn syscall_num_to_name(num: u64) -> String {
        // x86_64 syscall numbers (common ones)
        match num {
            0 => "read".to_string(),
            1 => "write".to_string(),
            2 => "open".to_string(),
            3 => "close".to_string(),
            9 => "mmap".to_string(),
            10 => "mprotect".to_string(),
            12 => "brk".to_string(),
            21 => "access".to_string(),
            42 => "connect".to_string(),
            43 => "accept".to_string(),
            49 => "bind".to_string(),
            50 => "listen".to_string(),
            59 => "execve".to_string(),
            62 => "kill".to_string(),
            231 => "exit_group".to_string(),
            _ => format!("syscall_{}", num),
        }
    }
}
