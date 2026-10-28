# Security at Line Rate

## Overview

The **Security at Line Rate Fragment** delivers zero-overhead security through BPF-LSM policies, Landlock integration, and AOT-compiled security rules targeting <5ms policy application.

**Implementation Status**: ✅ IMPLEMENTED
- BPF-LSM integration: ✅ IMPLEMENTED
- Landlock integration: ✅ IMPLEMENTED
- AOT policy compilation: ✅ IMPLEMENTED

## Core Architecture

```rust
use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use std::collections::HashMap;

/// Security at Line Rate - zero-overhead security enforcement
pub struct SecurityLineRate {
    // BPF-LSM integration
    bpf_lsm_manager: BpfLsmManager,
    landlock_integration: LandlockIntegration,
    seccomp_bpf_cache: SeccompBpfCache,
    
    // AOT compilation
    policy_compiler: SecurityPolicyCompiler,
    rule_engine: RuleEngine,
    
    // Runtime enforcement
    capability_manager: CapabilityManager,
    namespace_enforcer: NamespaceEnforcer,
    audit_logger: FastAuditLogger,
    
    // Performance optimization
    policy_cache: PolicyCache,
    hot_path_optimizer: HotPathOptimizer,
}

impl SecurityLineRate {
    /// AOT policy compilation for zero runtime overhead
    pub fn compile_security_policy(
        &mut self,
        profile: &str,
        policy: &SecurityPolicy,
    ) -> Result<()> {
        // Phase 1: Compile seccomp rules to BPF bytecode
        let seccomp_bpf = self.policy_compiler
            .compile_seccomp(&policy.seccomp_rules)
            .context("seccomp compilation failed")?;
        
        // Phase 2: Compile Landlock rules
        let landlock_rules = self.policy_compiler
            .compile_landlock(&policy.filesystem_rules)
            .context("landlock compilation failed")?;
        
        // Phase 3: Compile BPF-LSM policies
        let bpf_lsm_programs = self.policy_compiler
            .compile_bpf_lsm(&policy.lsm_rules)
            .context("BPF-LSM compilation failed")?;
        
        // Phase 4: Cache compiled policies
        let compiled_policy = CompiledSecurityPolicy {
            seccomp_bpf,
            landlock_rules,
            bpf_lsm_programs,
            compiled_at: Instant::now(),
        };
        
        self.policy_cache.store(profile, compiled_policy)
    }

    /// Zero-overhead policy application
    pub fn apply_compiled_policy(&mut self, pid: i32, profile: &str) -> Result<()> {
        let start = Instant::now();
        
        let policy = self.policy_cache
            .get(profile)
            .context("policy not found")?;
        
        // Apply all policies atomically
        self.apply_atomic_policies(pid, &policy)
            .context("policy application failed")?;
        
        // Target: <5ms total application time
        let duration = start.elapsed();
        if duration > Duration::from_millis(5) {
            self.audit_logger.log_slow_policy_application(profile, duration);
        }
        
        Ok(())
    }
}

impl BpfLsmManager {
    /// BPF-LSM enforcement
    pub fn enforce_policy(&mut self, policy: &BpfLsmPolicy) -> Result<()> {
        // Load BPF program into LSM hooks
        for (hook_point, program) in &policy.programs {
            self.load_lsm_program(hook_point, program)
                .with_context(|| format!("LSM program load failed for {}", hook_point))?;
        }
        Ok(())
    }
}
```

## Landlock Enforcement Scope

`LandlockContext::restrict_self()` requests `LANDLOCK_RESTRICT_SELF_TSYNC` (Landlock ABI 8, kernel 6.7+), so the ruleset covers every thread in the process rather than only the thread that applied it.

| Kernel | Behaviour |
|--------|-----------|
| ABI >= 8 | Ruleset applies to all threads. `RestrictionStatus::all_threads` is `true`. |
| ABI < 8 | `CompatLevel::BestEffort` drops the flag instead of failing. Only the applying thread and its children are restricted, and a warning is logged. |
| Ruleset not enforced | `RestrictionStatus::ruleset == NotEnforced` logs a warning; the caller still sees `Ok` because the rest of the sandbox (seccomp, capabilities, namespaces) remains in effect. |

**Why this matters:** a thread-scoped ruleset is a silent under-enforcement if Landlock is ever applied inside a threaded runtime. Phantom currently applies it in a freshly forked single-threaded child, where the two scopes are equivalent — TSYNC is defence in depth for future call sites. Test the behaviour by checking `RestrictionStatus::all_threads`, not by inspecting the requested flags (`RulesetCreated` keeps those private).

## Security Levels

### Minimal (Direct Mode)
- Basic process isolation
- No capability restrictions
- Minimal syscall filtering

### Medium (Sandbox Mode)  
- Full capability dropping
- Comprehensive seccomp filtering
- Landlock filesystem restrictions
- Network namespace isolation

### Maximum (Hardened Mode)
- BPF-LSM enforcement
- AppArmor/SELinux integration
- Comprehensive audit logging
- Real-time threat detection
