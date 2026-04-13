//! Image Analyzer Module
//!
//! Analyzes container images to detect:
//! - Installed packages and their versions
//! - Configuration issues
//! - Security misconfigurations
//! - Best practice violations

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Package information extracted from an image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    /// Package name
    pub name: String,

    /// Package version
    pub version: String,

    /// Package manager (apk, apt, yum, npm, pip, etc.)
    pub manager: String,

    /// Package description
    pub description: Option<String>,

    /// Dependencies
    pub dependencies: Vec<String>,
}

/// Configuration issue found in an image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigIssue {
    /// Issue identifier
    pub id: String,

    /// Severity level
    pub severity: String,

    /// Issue title
    pub title: String,

    /// Issue description
    pub description: String,

    /// Recommended fix
    pub recommendation: String,

    /// Affected file/path
    pub path: Option<String>,
}

/// Image analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageAnalysis {
    /// Image reference
    pub image_ref: String,

    /// Detected packages
    pub packages: Vec<PackageInfo>,

    /// Configuration issues
    pub config_issues: Vec<ConfigIssue>,

    /// Detected OS/distribution
    pub os_info: Option<OsInfo>,

    /// Running user (if detectable)
    pub user: Option<String>,

    /// Exposed ports (from config)
    pub exposed_ports: Vec<u16>,

    /// Environment variables
    pub env_vars: HashMap<String, String>,
}

/// Operating system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    /// Distribution name
    pub name: String,

    /// Version
    pub version: String,

    /// ID (e.g., "alpine", "ubuntu", "debian")
    pub id: String,

    /// Package manager
    pub package_manager: String,
}

/// Image analyzer
pub struct ImageAnalyzer {
    /// Root filesystem path being analyzed
    pub rootfs_path: PathBuf,
}

impl ImageAnalyzer {
    /// Create a new analyzer for a rootfs path
    pub fn new(rootfs_path: &Path) -> Self {
        Self {
            rootfs_path: rootfs_path.to_path_buf(),
        }
    }

    /// Analyze the image and return analysis results
    pub fn analyze(&self, image_ref: &str) -> Result<ImageAnalysis, crate::ScannerError> {
        // Detect OS
        let os_info = self.detect_os();

        // Detect packages based on OS
        let packages = if let Some(ref os) = os_info {
            self.detect_packages(&os.package_manager)
        } else {
            let mut all_pkgs = Vec::new();
            // Try all package managers
            for manager in &["apk", "dpkg", "rpm", "pacman"] {
                let mut pkgs = self.detect_packages(manager);
                all_pkgs.append(&mut pkgs);
            }
            all_pkgs
        };

        // Check for configuration issues
        let config_issues = self.check_config_issues();

        // Try to detect user
        let user = self.detect_user();

        // Try to detect exposed ports
        let exposed_ports = self.detect_exposed_ports();

        // Try to detect environment variables
        let env_vars = self.detect_env_vars();

        Ok(ImageAnalysis {
            image_ref: image_ref.to_string(),
            packages,
            config_issues,
            os_info,
            user,
            exposed_ports,
            env_vars,
        })
    }

    /// Detect operating system from release files
    fn detect_os(&self) -> Option<OsInfo> {
        // Check for Alpine
        if self.rootfs_path.join("etc/alpine-release").exists() {
            if let Ok(version) = fs::read_to_string(self.rootfs_path.join("etc/alpine-release")) {
                return Some(OsInfo {
                    name: "Alpine Linux".to_string(),
                    version: version.trim().to_string(),
                    id: "alpine".to_string(),
                    package_manager: "apk".to_string(),
                });
            }
        }

        // Check for Debian/Ubuntu
        if self.rootfs_path.join("etc/debian_version").exists() {
            if let Ok(version) = fs::read_to_string(self.rootfs_path.join("etc/debian_version")) {
                let os_name = if self.rootfs_path.join("etc/lsb-release").exists() {
                    if let Ok(content) =
                        fs::read_to_string(self.rootfs_path.join("etc/lsb-release"))
                    {
                        if content.contains("Ubuntu") {
                            "Ubuntu"
                        } else {
                            "Debian"
                        }
                    } else {
                        "Debian"
                    }
                } else {
                    "Debian"
                };

                return Some(OsInfo {
                    name: os_name.to_string(),
                    version: version.trim().to_string(),
                    id: if os_name == "Ubuntu" {
                        "ubuntu"
                    } else {
                        "debian"
                    }
                    .to_string(),
                    package_manager: "apt".to_string(),
                });
            }
        }

        // Check for Red Hat/CentOS
        if self.rootfs_path.join("etc/redhat-release").exists() {
            if let Ok(content) = fs::read_to_string(self.rootfs_path.join("etc/redhat-release")) {
                return Some(OsInfo {
                    name: content.trim().to_string(),
                    version: String::new(),
                    id: "rhel".to_string(),
                    package_manager: "yum".to_string(),
                });
            }
        }

        None
    }

    /// Detect installed packages
    fn detect_packages(&self, manager: &str) -> Vec<PackageInfo> {
        match manager {
            "apk" => self.detect_apk_packages(),
            "dpkg" | "apt" => self.detect_dpkg_packages(),
            "rpm" | "yum" => self.detect_rpm_packages(),
            _ => Vec::new(),
        }
    }

    /// Detect Alpine packages (apk)
    fn detect_apk_packages(&self) -> Vec<PackageInfo> {
        let mut packages = Vec::new();
        let apk_db = self.rootfs_path.join("lib/apk/db/installed");

        if apk_db.exists() {
            if let Ok(content) = fs::read_to_string(&apk_db) {
                let mut current_pkg: Option<String> = None;
                let mut current_ver: Option<String> = None;

                for line in content.lines() {
                    if line.starts_with("P:") {
                        current_pkg = Some(line[2..].trim().to_string());
                    } else if line.starts_with("V:") {
                        current_ver = Some(line[2..].trim().to_string());
                    } else if line.starts_with("o:") && current_pkg.is_some() {
                        // End of package entry
                        if let (Some(pkg), Some(ver)) = (current_pkg.take(), current_ver.take()) {
                            packages.push(PackageInfo {
                                name: pkg,
                                version: ver,
                                manager: "apk".to_string(),
                                description: None,
                                dependencies: Vec::new(),
                            });
                        }
                    }
                }

                // Handle last package
                if let (Some(pkg), Some(ver)) = (current_pkg, current_ver) {
                    packages.push(PackageInfo {
                        name: pkg,
                        version: ver,
                        manager: "apk".to_string(),
                        description: None,
                        dependencies: Vec::new(),
                    });
                }
            }
        }

        packages
    }

    /// Detect Debian packages (dpkg)
    fn detect_dpkg_packages(&self) -> Vec<PackageInfo> {
        let mut packages = Vec::new();
        let dpkg_status = self.rootfs_path.join("var/lib/dpkg/status");

        if dpkg_status.exists() {
            if let Ok(content) = fs::read_to_string(&dpkg_status) {
                let mut current_pkg: Option<String> = None;
                let mut current_ver: Option<String> = None;

                for line in content.lines() {
                    if line.starts_with("Package:") {
                        current_pkg = Some(line[8..].trim().to_string());
                    } else if line.starts_with("Version:") {
                        current_ver = Some(line[8..].trim().to_string());
                    } else if line.is_empty() && current_pkg.is_some() {
                        if let (Some(pkg), Some(ver)) = (current_pkg.take(), current_ver.take()) {
                            packages.push(PackageInfo {
                                name: pkg,
                                version: ver,
                                manager: "dpkg".to_string(),
                                description: None,
                                dependencies: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        packages
    }

    /// Detect RPM packages
    fn detect_rpm_packages(&self) -> Vec<PackageInfo> {
        // RPM database is binary, would need rpm crate to parse
        // For now, return empty
        Vec::new()
    }

    /// Check for configuration issues
    fn check_config_issues(&self) -> Vec<ConfigIssue> {
        let mut issues = Vec::new();

        // Check for root user
        if let Ok(passwd) = self.read_file("etc/passwd") {
            if passwd
                .lines()
                .any(|l: &str| l.starts_with("root:") && !l.contains("/sbin/nologin"))
            {
                issues.push(ConfigIssue {
                    id: "SEC001".to_string(),
                    severity: "HIGH".to_string(),
                    title: "Root user enabled".to_string(),
                    description: "The root user is enabled and can login. Consider using a non-root user.".to_string(),
                    recommendation: "Create a non-root user and switch to it using USER directive in Dockerfile.".to_string(),
                    path: Some("etc/passwd".to_string()),
                });
            }
        }

        // Check for sensitive files
        let sensitive_paths = [
            "etc/shadow",
            "etc/gshadow",
            "root/.ssh/id_rsa",
            "root/.ssh/id_dsa",
        ];

        for path in &sensitive_paths {
            if self.rootfs_path.join(path).exists() {
                issues.push(ConfigIssue {
                    id: "SEC002".to_string(),
                    severity: "CRITICAL".to_string(),
                    title: format!("Sensitive file present: {}", path),
                    description: format!("The file {} contains sensitive information and should not be in the image.", path),
                    recommendation: "Remove sensitive files from the image or use .dockerignore.".to_string(),
                    path: Some(path.to_string()),
                });
            }
        }

        // Check for package manager cache
        let cache_paths = ["var/cache/apk", "var/cache/apt", "var/cache/yum"];

        for path in &cache_paths {
            if self.rootfs_path.join(path).exists() {
                issues.push(ConfigIssue {
                    id: "OPT001".to_string(),
                    severity: "LOW".to_string(),
                    title: format!("Package cache present: {}", path),
                    description: format!("Package manager cache at {} increases image size unnecessarily.", path),
                    recommendation: "Clean package cache after installation (e.g., apk --no-cache, apt-get clean).".to_string(),
                    path: Some(path.to_string()),
                });
            }
        }

        // Check for shell in distroless images
        let shell_paths = ["bin/sh", "bin/bash", "usr/bin/sh", "usr/bin/bash"];
        let has_shell = shell_paths
            .iter()
            .any(|p| self.rootfs_path.join(p).exists());

        // If it looks like a distroless image but has shell
        if !self.rootfs_path.join("etc/os-release").exists() && has_shell {
            issues.push(ConfigIssue {
                id: "SEC003".to_string(),
                severity: "MEDIUM".to_string(),
                title: "Shell present in minimal image".to_string(),
                description: "A shell is present in what appears to be a minimal image. Consider using distroless for better security.".to_string(),
                recommendation: "Use distroless images for production to reduce attack surface.".to_string(),
                path: None,
            });
        }

        // Check for world-writable files
        if let Ok(entries) = self.find_world_writable_files() {
            for path in entries {
                issues.push(ConfigIssue {
                    id: "SEC004".to_string(),
                    severity: "MEDIUM".to_string(),
                    title: "World-writable file".to_string(),
                    description: format!(
                        "The file {} is world-writable, which is a security risk.",
                        path
                    ),
                    recommendation: "Remove world-writable permissions: chmod o-w".to_string(),
                    path: Some(path),
                });
            }
        }

        issues
    }

    /// Detect default user
    fn detect_user(&self) -> Option<String> {
        // Check for USER in any config file
        // This is a simplified check
        if let Ok(config) = self.read_file("etc/passwd") {
            // Find non-root users
            for line in config.lines() {
                if !line.starts_with("root:")
                    && !line.contains("/sbin/nologin")
                    && !line.contains("/bin/false")
                {
                    if let Some(name) = line.split(':').next() {
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }

    /// Detect exposed ports (from common config files)
    fn detect_exposed_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();

        // Check common config files for port configurations
        let config_files = [
            "etc/nginx/nginx.conf",
            "etc/apache2/ports.conf",
            "etc/httpd/conf/httpd.conf",
        ];

        let port_regex = Regex::new(r"(?:listen|port)\s+(\d+)").unwrap();

        for file in &config_files {
            if let Ok(content) = self.read_file(file) {
                for cap in port_regex.captures_iter(&content) {
                    if let Ok(port) = cap[1].parse::<u16>() {
                        ports.push(port);
                    }
                }
            }
        }

        ports
    }

    /// Detect environment variables
    fn detect_env_vars(&self) -> HashMap<String, String> {
        let mut env_vars = HashMap::new();

        // Check /etc/environment
        if let Ok(content) = self.read_file("etc/environment") {
            for line in content.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    env_vars.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }

        env_vars
    }

    /// Helper to read a file from rootfs
    fn read_file(&self, path: &str) -> Result<String, std::io::Error> {
        fs::read_to_string(self.rootfs_path.join(path))
    }

    /// Find world-writable files
    fn find_world_writable_files(&self) -> Result<Vec<String>, std::io::Error> {
        let mut world_writable = Vec::new();

        // Check common sensitive directories
        let check_dirs = ["etc", "bin", "sbin", "usr/bin", "usr/sbin"];

        for dir in &check_dirs {
            let dir_path = self.rootfs_path.join(dir);
            if dir_path.exists() {
                if let Ok(entries) = fs::read_dir(&dir_path) {
                    for entry in entries.flatten() {
                        if let Ok(metadata) = entry.metadata() {
                            let mode = metadata.permissions().mode();
                            // Check if world-writable (mode & 0o002)
                            if mode & 0o002 != 0 {
                                if let Some(path) = entry.path().to_str() {
                                    world_writable.push(path.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(world_writable)
    }
}

// Extension trait for permissions
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
