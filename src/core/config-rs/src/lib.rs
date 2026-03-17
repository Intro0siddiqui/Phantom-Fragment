use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PhantomConfig {
    pub execution: ExecutionConfig,
    pub security: SecurityConfig,
    pub resources: ResourceConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExecutionConfig {
    pub mode: String, // "direct", "sandbox", "hardened"
    pub max_concurrent_fragments: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityConfig {
    pub seccomp_profile: String,
    pub capabilities: CapabilitiesConfig,
    pub cgroups: CgroupsConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CapabilitiesConfig {
    pub drop_bounding: Vec<String>,
    pub ambient: Vec<String>,
    pub no_new_privs: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CgroupsConfig {
    pub memory_limit_mb: u64,
    pub cpu_quota: f32,
    pub pids_limit: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResourceConfig {
    pub root_dir: String,
    pub storage_driver: String,
}

impl PhantomConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: PhantomConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.execution.max_concurrent_fragments == 0 {
            return Err(ConfigError::Validation(
                "max_concurrent_fragments must be > 0".into(),
            ));
        }
        // Add more validation logic here
        Ok(())
    }
}

impl Default for PhantomConfig {
    fn default() -> Self {
        Self {
            execution: ExecutionConfig {
                mode: "sandbox".to_string(),
                max_concurrent_fragments: 10,
            },
            security: SecurityConfig {
                seccomp_profile: "default".to_string(),
                capabilities: CapabilitiesConfig {
                    drop_bounding: vec!["CAP_SYS_ADMIN".to_string()],
                    ambient: vec![],
                    no_new_privs: true,
                },
                cgroups: CgroupsConfig {
                    memory_limit_mb: 512,
                    cpu_quota: 1.0,
                    pids_limit: 100,
                },
            },
            resources: ResourceConfig {
                root_dir: "/var/lib/phantom".to_string(),
                storage_driver: "overlay2".to_string(),
            },
        }
    }
}
