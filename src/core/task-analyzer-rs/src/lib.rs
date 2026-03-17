//! Task Analyzer - Intelligent Component Selection
//!
//! Analyzes commands to determine minimal required components for execution.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Component types that can be loaded
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Component {
    // Network components
    TcpStack,
    UdpStack,
    DnsResolver,
    SocketApi,
    HttpClient,

    // Filesystem components
    FileIo,
    DirectoryOps,
    MountOps,

    // Process components
    ProcessSpawn,
    IpcMechanisms,
    SignalHandling,

    // System components
    TimeApi,
    RandomApi,
    CryptoApi,
}

/// Required components for a task
#[derive(Debug, Clone)]
pub struct RequiredComponents {
    pub components: HashSet<Component>,
    pub reason: String,
}

/// Command to analyze
#[derive(Debug, Clone)]
pub struct Command {
    pub executable: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub working_dir: Option<String>,
}

/// Task analyzer
pub struct TaskAnalyzer {
    // Network detection patterns
    network_patterns: Vec<&'static str>,
    // File operation patterns
    fileio_patterns: Vec<&'static str>,
    // Known network executables
    network_executables: HashSet<&'static str>,
}

impl TaskAnalyzer {
    pub fn new() -> Self {
        let mut network_executables = HashSet::new();
        network_executables.insert("curl");
        network_executables.insert("wget");
        network_executables.insert("nc");
        network_executables.insert("telnet");
        network_executables.insert("ssh");
        network_executables.insert("scp");
        network_executables.insert("rsync");
        network_executables.insert("git");
        network_executables.insert("npm");
        network_executables.insert("pip");
        network_executables.insert("cargo");

        Self {
            network_patterns: vec![
                "http://",
                "https://",
                "ftp://",
                "://", // Generic URL
                "--url",
                "-u",
                "--download",
                "clone",
                "fetch",
                "pull",
                "push",
            ],
            fileio_patterns: vec![
                "-o", "--output", "-i", "--input", "-f", "--file", ">", "<", ">>",
            ],
            network_executables,
        }
    }

    /// Analyze a command to determine required components
    pub fn analyze(&self, command: &Command) -> RequiredComponents {
        let mut components = HashSet::new();
        let mut reasons = Vec::new();

        // Check executable name
        let exe_name = Path::new(&command.executable)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&command.executable);

        // Network detection
        if self.needs_network(exe_name, &command.args) {
            components.insert(Component::TcpStack);
            components.insert(Component::DnsResolver);
            components.insert(Component::SocketApi);
            reasons.push("network access detected");
        }

        // HTTP specific
        if self.needs_http(&command.args) {
            components.insert(Component::HttpClient);
            reasons.push("HTTP operations");
        }

        // File I/O detection
        if self.needs_fileio(&command.args) {
            components.insert(Component::FileIo);
            reasons.push("file operations");
        }

        // Directory operations
        if self.needs_directory_ops(exe_name, &command.args) {
            components.insert(Component::DirectoryOps);
            reasons.push("directory operations");
        }

        // Process spawning
        if self.needs_process_spawn(exe_name) {
            components.insert(Component::ProcessSpawn);
            reasons.push("subprocess execution");
        }

        // Time API (almost always needed)
        components.insert(Component::TimeApi);

        RequiredComponents {
            components,
            reason: reasons.join(", "),
        }
    }

    /// Check if network components are needed
    fn needs_network(&self, exe_name: &str, args: &[String]) -> bool {
        // Check known network executables
        if self.network_executables.contains(exe_name) {
            return true;
        }

        // Check arguments for network patterns
        for arg in args {
            for pattern in &self.network_patterns {
                if arg.contains(pattern) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if HTTP client is needed
    fn needs_http(&self, args: &[String]) -> bool {
        args.iter()
            .any(|arg| arg.starts_with("http://") || arg.starts_with("https://"))
    }

    /// Check if file I/O is needed
    fn needs_fileio(&self, args: &[String]) -> bool {
        for arg in args {
            for pattern in &self.fileio_patterns {
                if arg.contains(pattern) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if directory operations are needed
    fn needs_directory_ops(&self, exe_name: &str, args: &[String]) -> bool {
        // Known directory commands
        if matches!(exe_name, "ls" | "mkdir" | "rmdir" | "find" | "tree") {
            return true;
        }

        // Check for directory-related flags
        args.iter()
            .any(|arg| arg.contains("-r") || arg.contains("--recursive") || arg.ends_with('/'))
    }

    /// Check if process spawning is needed
    fn needs_process_spawn(&self, exe_name: &str) -> bool {
        matches!(exe_name, "sh" | "bash" | "zsh" | "fish" | "make" | "cmake")
    }

    /// Estimate total memory footprint
    pub fn estimate_memory(&self, components: &RequiredComponents) -> usize {
        let base = 3 * 1024 * 1024; // 3MB base
        let mut total = base;

        for component in &components.components {
            total += match component {
                Component::TcpStack => 2 * 1024 * 1024,
                Component::UdpStack => 1024 * 1024,
                Component::DnsResolver => 512 * 1024,
                Component::SocketApi => 256 * 1024,
                Component::HttpClient => 1024 * 1024,
                Component::FileIo => 512 * 1024,
                Component::DirectoryOps => 256 * 1024,
                Component::MountOps => 512 * 1024,
                Component::ProcessSpawn => 1024 * 1024,
                Component::IpcMechanisms => 512 * 1024,
                Component::SignalHandling => 128 * 1024,
                Component::TimeApi => 64 * 1024,
                Component::RandomApi => 64 * 1024,
                Component::CryptoApi => 2 * 1024 * 1024,
            };
        }

        total
    }
}

impl Default for TaskAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let analyzer = TaskAnalyzer::new();
        let cmd = Command {
            executable: "/bin/echo".to_string(),
            args: vec!["hello".to_string()],
            env: vec![],
            working_dir: None,
        };

        let result = analyzer.analyze(&cmd);
        assert!(result.components.contains(&Component::TimeApi));
        // Echo doesn't need network
        assert!(!result.components.contains(&Component::TcpStack));
    }

    #[test]
    fn test_network_command() {
        let analyzer = TaskAnalyzer::new();
        let cmd = Command {
            executable: "/usr/bin/curl".to_string(),
            args: vec!["https://example.com".to_string()],
            env: vec![],
            working_dir: None,
        };

        let result = analyzer.analyze(&cmd);
        assert!(result.components.contains(&Component::TcpStack));
        assert!(result.components.contains(&Component::DnsResolver));
        assert!(result.components.contains(&Component::HttpClient));
    }

    #[test]
    fn test_file_command() {
        let analyzer = TaskAnalyzer::new();
        let cmd = Command {
            executable: "/bin/cat".to_string(),
            args: vec!["-o".to_string(), "output.txt".to_string()],
            env: vec![],
            working_dir: None,
        };

        let result = analyzer.analyze(&cmd);
        assert!(result.components.contains(&Component::FileIo));
    }

    #[test]
    fn test_memory_estimation() {
        let analyzer = TaskAnalyzer::new();
        let cmd = Command {
            executable: "/usr/bin/curl".to_string(),
            args: vec!["https://example.com".to_string()],
            env: vec![],
            working_dir: None,
        };

        let result = analyzer.analyze(&cmd);
        let mem = analyzer.estimate_memory(&result);

        // Should be > base (3MB) + network components
        assert!(mem > 3 * 1024 * 1024);
        assert!(mem < 10 * 1024 * 1024); // But less than 10MB
    }

    #[test]
    fn test_directory_operations() {
        let analyzer = TaskAnalyzer::new();
        let cmd = Command {
            executable: "/bin/ls".to_string(),
            args: vec!["-la".to_string()],
            env: vec![],
            working_dir: None,
        };

        let result = analyzer.analyze(&cmd);
        assert!(result.components.contains(&Component::DirectoryOps));
    }
}
