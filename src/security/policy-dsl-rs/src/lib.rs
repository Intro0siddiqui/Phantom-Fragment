//! Policy DSL Compiler - YAML to Kernel Bytecode
//!
//! Compiles security policies from YAML to optimized kernel enforcement:
//! - Seccomp BPF filters
//! - Landlock filesystem rules
//! - Future: eBPF programs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use types_rs::PhantomError;

/// Security policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub seccomp: SeccompPolicy,
    #[serde(default)]
    pub landlock: LandlockPolicy,
    #[serde(default)]
    pub cgroups: CgroupPolicy,
}

/// Cgroup resource limits
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupPolicy {
    pub pids_limit: Option<u32>,
    pub memory_limit_mb: Option<u64>,
    pub cpu_quota: Option<f32>,
    pub io_limits: Option<IoLimits>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoLimits {
    pub read_bps: Option<u64>,
    pub write_bps: Option<u64>,
    pub read_iops: Option<u64>,
    pub write_iops: Option<u64>,
}

/// Seccomp policy configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeccompPolicy {
    pub default_action: String, // "allow" or "kill"
    #[serde(default)]
    pub rules: Vec<SeccompRule>,
}

/// Individual seccomp rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompRule {
    pub syscall: String,
    pub action: String, // "allow", "kill", "trap", "errno", "log"
    #[serde(default)]
    pub args: Vec<SyscallArg>,
}

/// Syscall argument constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallArg {
    pub index: u32,
    pub value: u64,
    pub op: String, // "eq", "ne", "gt", "ge", "lt", "le", "masked_eq"
}

/// Landlock filesystem policy
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LandlockPolicy {
    #[serde(default)]
    pub rules: Vec<LandlockRule>,
}

/// Landlock filesystem rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LandlockRule {
    pub path: String,
    pub access: Vec<String>, // "read", "write", "execute", "read_dir", "remove", "make_*"
}

/// Compiled policy output
#[derive(Debug)]
pub struct CompiledPolicy {
    pub name: String,
    pub seccomp_filter: Option<Vec<u8>>, // BPF bytecode
    pub landlock_rules: Vec<CompiledLandlockRule>,
}

#[derive(Debug, Clone)]
pub struct CompiledLandlockRule {
    pub path: String,
    pub access_mask: u64,
}

/// Policy compiler
pub struct PolicyCompiler {
    policies: HashMap<String, SecurityPolicy>,
}

impl PolicyCompiler {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    /// Load policy from YAML string
    pub fn load_yaml(&mut self, yaml: &str) -> Result<String, PhantomError> {
        let policy: SecurityPolicy = serde_yaml::from_str(yaml)
            .map_err(|e| PhantomError::Internal(format!("YAML parse error: {}", e)))?;

        let name = policy.name.clone();
        self.policies.insert(name.clone(), policy);
        Ok(name)
    }

    /// Compile a loaded policy
    pub fn compile(&self, policy_name: &str) -> Result<CompiledPolicy, PhantomError> {
        let policy = self
            .policies
            .get(policy_name)
            .ok_or_else(|| PhantomError::Internal(format!("Policy not found: {}", policy_name)))?;

        let seccomp_filter = if !policy.seccomp.rules.is_empty() {
            Some(self.compile_seccomp(&policy.seccomp)?)
        } else {
            None
        };

        let landlock_rules = self.compile_landlock(&policy.landlock)?;

        Ok(CompiledPolicy {
            name: policy.name.clone(),
            seccomp_filter,
            landlock_rules,
        })
    }

    /// Compile seccomp rules to BPF bytecode
    fn compile_seccomp(&self, seccomp: &SeccompPolicy) -> Result<Vec<u8>, PhantomError> {
        use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

        // Determine default action
        let default_action = match seccomp.default_action.as_str() {
            "allow" => ScmpAction::Allow,
            "kill" => ScmpAction::KillThread,
            _ => ScmpAction::KillThread,
        };

        let mut ctx = ScmpFilterContext::new(default_action).map_err(|e| {
            PhantomError::Internal(format!("Failed to create seccomp context: {}", e))
        })?;

        // Add rules
        for rule in &seccomp.rules {
            let syscall = ScmpSyscall::from_name(&rule.syscall).map_err(|_| {
                PhantomError::Internal(format!("Invalid syscall: {}", rule.syscall))
            })?;

            let action = match rule.action.as_str() {
                "allow" => ScmpAction::Allow,
                "kill" => ScmpAction::KillThread,
                "trap" => ScmpAction::Trap,
                "errno" => ScmpAction::Errno(1), // EPERM
                "log" => ScmpAction::Log,
                _ => ScmpAction::KillThread,
            };

            ctx.add_rule(action, syscall).map_err(|e| {
                PhantomError::Internal(format!("Failed to add seccomp rule: {}", e))
            })?;
        }

        // Workaround for missing export_bpf_mem in some libseccomp versions
        use std::io::Read;
        let temp_path = std::env::temp_dir().join(format!("phantom_seccomp_{}.bpf", std::process::id()));

        let file = std::fs::File::create(&temp_path).map_err(|e| {
            PhantomError::Internal(format!("Failed to create temp BPF file: {}", e))
        })?;

        ctx.export_bpf(&file).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            PhantomError::Internal(format!("Failed to export BPF: {}", e))
        })?;

        let mut bpf = Vec::new();
        let mut file = std::fs::File::open(&temp_path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            PhantomError::Internal(format!("Failed to reopen BPF file: {}", e))
        })?;

        file.read_to_end(&mut bpf).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            PhantomError::Internal(format!("Failed to read BPF file: {}", e))
        })?;

        let _ = std::fs::remove_file(&temp_path);
        Ok(bpf)
    }

    /// Compile landlock rules
    fn compile_landlock(
        &self,
        landlock: &LandlockPolicy,
    ) -> Result<Vec<CompiledLandlockRule>, PhantomError> {
        let mut compiled_rules = Vec::new();

        for rule in &landlock.rules {
            let mut access_mask: u64 = 0;

            for access_str in &rule.access {
                let mask = match access_str.as_str() {
                    "read" => 0x0001, // Simplified constants
                    "write" => 0x0002,
                    "execute" => 0x0004,
                    "read_dir" => 0x0008,
                    "remove" => 0x0010,
                    "make_char" => 0x0020,
                    "make_block" => 0x0040,
                    "make_reg" => 0x0080,
                    "make_sock" => 0x0100,
                    "make_fifo" => 0x0200,
                    "make_dir" => 0x0400,
                    "make_sym" => 0x0800,
                    _ => {
                        return Err(PhantomError::Internal(format!(
                            "Invalid landlock access: {}",
                            access_str
                        )))
                    }
                };
                access_mask |= mask;
            }

            compiled_rules.push(CompiledLandlockRule {
                path: rule.path.clone(),
                access_mask,
            });
        }

        Ok(compiled_rules)
    }

    /// Get policy by name
    pub fn get_policy(&self, name: &str) -> Option<&SecurityPolicy> {
        self.policies.get(name)
    }

    /// List all loaded policies
    pub fn list_policies(&self) -> Vec<String> {
        self.policies.keys().cloned().collect()
    }
}

impl Default for PolicyCompiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_simple_policy() {
        let yaml = r#"
name: test-policy
version: "1.0"
seccomp:
  default_action: allow
  rules:
    - syscall: write
      action: allow
    - syscall: open
      action: allow
"#;

        let mut compiler = PolicyCompiler::new();
        let name = compiler.load_yaml(yaml).unwrap();
        assert_eq!(name, "test-policy");

        let policy = compiler.get_policy("test-policy").unwrap();
        assert_eq!(policy.seccomp.rules.len(), 2);
    }

    #[test]
    fn test_compile_seccomp_policy() {
        let yaml = r#"
name: strict-policy
version: "1.0"
seccomp:
  default_action: kill
  rules:
    - syscall: read
      action: allow
    - syscall: write
      action: allow
    - syscall: exit
      action: allow
"#;

        let mut compiler = PolicyCompiler::new();
        compiler.load_yaml(yaml).unwrap();
        let compiled = compiler.compile("strict-policy").unwrap();

        assert!(compiled.seccomp_filter.is_some());
        assert_eq!(compiled.name, "strict-policy");
    }

    #[test]
    fn test_landlock_compilation() {
        let yaml = r#"
name: fs-policy
version: "1.0"
landlock:
  rules:
    - path: /tmp
      access: [read, write, make_dir]
    - path: /home/user
      access: [read]
"#;

        let mut compiler = PolicyCompiler::new();
        compiler.load_yaml(yaml).unwrap();
        let compiled = compiler.compile("fs-policy").unwrap();

        assert_eq!(compiled.landlock_rules.len(), 2);
        assert!(compiled.landlock_rules[0].access_mask > 0);
    }
}
