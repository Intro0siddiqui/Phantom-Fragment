use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

const PHANTOM_DIR: &str = ".phantom";

#[derive(Debug, Clone)]
pub struct PhantomPaths {
    base: PathBuf,
}

impl PhantomPaths {
    pub fn new() -> Self {
        let base = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/root"))
            .join(PHANTOM_DIR);
        Self { base }
    }

    pub fn logs(&self) -> PathBuf {
        self.base.join("logs")
    }

    pub fn volumes(&self) -> PathBuf {
        self.base.join("volumes")
    }

    pub fn registry(&self) -> PathBuf {
        self.base.join("registry.json")
    }

    pub fn storage(&self) -> PathBuf {
        self.base.join("storage")
    }

    pub fn rootfs(&self) -> PathBuf {
        self.base.join("rootfs")
    }

    pub fn fragment_pools(&self) -> PathBuf {
        self.base.join("fragment-pools")
    }

    pub fn bin(&self) -> PathBuf {
        self.base.join("bin")
    }
}

impl Default for PhantomPaths {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct SecurityConfig {
    pub pids_limit: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SeccompRuleConfig {
    pub syscall: String,
    pub action: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Profile {
    pub isolation: String, // "sandbox", "hardened", "wasm"
    #[serde(default = "default_true")]
    pub network: bool,
    #[serde(default = "default_true")]
    pub file_write: bool,
    pub memory_mb: Option<usize>,
    pub cpu_count: Option<usize>,
    pub cpu_affinity: Option<Vec<u32>>,
    pub numa_node: Option<u32>,
    pub seccomp_rules: Option<Vec<SeccompRuleConfig>>,
}

fn default_true() -> bool {
    true
}

static BUILTIN_PROFILES: OnceLock<HashMap<String, Profile>> = OnceLock::new();

impl Config {
    fn built_in_defaults() -> &'static HashMap<String, Profile> {
        BUILTIN_PROFILES.get_or_init(|| {
            let mut profiles = HashMap::new();

            profiles.insert(
                "sandbox".to_string(),
                Profile {
                    isolation: "sandbox".to_string(),
                    network: true,
                    file_write: true,
                    memory_mb: Some(512),
                    cpu_count: None,
                    cpu_affinity: None,
                    numa_node: None,
                    seccomp_rules: None,
                },
            );

            profiles.insert(
                "hardened".to_string(),
                Profile {
                    isolation: "hardened".to_string(),
                    network: false,
                    file_write: false,
                    memory_mb: Some(256),
                    cpu_count: Some(1),
                    cpu_affinity: None,
                    numa_node: None,
                    seccomp_rules: None,
                },
            );

            profiles.insert(
                "wasm".to_string(),
                Profile {
                    isolation: "wasm".to_string(),
                    network: false,
                    file_write: false,
                    memory_mb: Some(256),
                    cpu_count: Some(1),
                    cpu_affinity: None,
                    numa_node: None,
                    seccomp_rules: None,
                },
            );

            profiles
        })
    }

    /// Load configuration with built-in defaults merged with user config
    pub fn load() -> Result<Self> {
        let mut config = Config {
            profiles: Self::built_in_defaults().clone(),
            security: SecurityConfig::default(),
        };

        if let Ok(path) = std::env::var("PHANTOM_CONFIG") {
            let user_config = Self::from_file(&PathBuf::from(path))?;
            config.merge_user_config(user_config);
            return Ok(config);
        }

        if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            let path = PathBuf::from(home).join(".phantom").join("config.toml");
            if let Ok(user_config) = Self::from_file(&path) {
                config.merge_user_config(user_config);
                return Ok(config);
            }
        }

        let path = PathBuf::from("/etc/phantom/config.toml");
        if let Ok(user_config) = Self::from_file(&path) {
            config.merge_user_config(user_config);
            return Ok(config);
        }

        Ok(config)
    }

    /// Merge user config into built-in defaults (user config takes precedence)
    fn merge_user_config(&mut self, user_config: Config) {
        // Merge profiles (user overrides built-in)
        for (name, profile) in user_config.profiles {
            self.profiles.insert(name, profile);
        }
        // Merge security config
        if user_config.security.pids_limit.is_some() {
            self.security.pids_limit = user_config.security.pids_limit;
        }
    }

    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    pub fn get_profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }
}

impl Profile {
    pub fn to_execution_mode(&self) -> execution_rs::ExecutionMode {
        match self.isolation.as_str() {
            "hardened" => execution_rs::ExecutionMode::Hardened,
            "wasm" => execution_rs::ExecutionMode::Wasm,
            _ => execution_rs::ExecutionMode::Sandbox,
        }
    }

    pub fn to_risk_profile(&self) -> execution_rs::RiskProfile {
        execution_rs::RiskProfile {
            network_access: self.network,
            file_write: self.file_write,
            privileged_ops: false, // Config profiles shouldn't grant root implicitly?
            untrusted_source: self.isolation == "hardened" || self.isolation == "wasm",
        }
    }

    pub fn to_performance_profile(&self) -> execution_rs::PerformanceProfile {
        execution_rs::PerformanceProfile {
            latency_sensitive: false,
            high_throughput: false,
        }
    }

    pub fn to_hardware_profile(&self) -> Option<execution_rs::HardwareProfile> {
        Some(execution_rs::HardwareProfile {
            cpu_affinity: self.cpu_affinity.clone(),
            numa_node: self.numa_node,
            cpu_count: self.cpu_count.unwrap_or(1),
            memory_mb: self.memory_mb.unwrap_or(512),
        })
    }
}
