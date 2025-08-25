# Adaptive Execution Modes V3 - Design Specification

## Overview

The **Adaptive Execution Modes** system provides intelligent runtime selection between different isolation and execution strategies based on workload requirements, security needs, and platform capabilities. This enables optimal performance while maintaining security guarantees.

## Execution Mode Architecture

### Core Execution Modes

```go
type ExecutionMode int

const (
    // Direct Mode - Minimal isolation for maximum performance
    ExecutionModeDirect ExecutionMode = iota
    
    // Sandbox Mode - Balanced security and performance (default)
    ExecutionModeSandbox
    
    // Hardened Mode - Maximum security for production/CI
    ExecutionModeHardened
    
    // MicroVM Mode - Hardware-level isolation (legacy/special cases)
    ExecutionModeMicroVM
    
    // Wasm Mode - Cross-platform portable execution
    ExecutionModeWasm
)

type RuntimeType int

const (
    RuntimeTypeNamespace RuntimeType = iota  // Linux namespaces + cgroups
    RuntimeTypeWasm                          // WebAssembly with WASI
    RuntimeTypeMicroVM                       // Firecracker/QEMU (legacy)
)

// ExecutionModeConfig defines the complete execution environment
type ExecutionModeConfig struct {
    Mode           ExecutionMode
    Runtime        RuntimeType
    SecurityLevel  SecurityLevel
    PerformanceProfile PerformanceProfile
    ResourceLimits ResourceLimits
    NetworkPolicy  NetworkPolicy
    
    // V3 enhancements
    LandlockRules  *LandlockRuleSet
    WasmCapabilities *WasmCapabilitySet
    AdaptivePolicy   *AdaptivePolicy
}
```

### Mode Selection Matrix

| Mode | Runtime | Security Level | Startup Time | Memory Usage | Use Case |
|------|---------|---------------|--------------|--------------|----------|
| **Direct** | Namespace/Wasm | Minimal | <15ms | <5MB | Development, debugging |
| **Sandbox** | Namespace/Wasm | Medium | <25ms | <8MB | LLM execution, testing |
| **Hardened** | Namespace | Maximum | <60ms | <12MB | Production, CI/CD |
| **MicroVM** | Firecracker | Maximum | <200ms | <30MB | Legacy isolation |
| **Wasm** | WebAssembly | Medium-High | <30ms | <6MB | Cross-platform |

## Detailed Mode Specifications

### 1. **Direct Mode** - Ultra-Fast Development

**Target**: <15ms startup, minimal security overhead
**Use Cases**: Inner development loops, debugging, trusted code

```yaml
# Direct mode profile example
profile: direct-dev
mode: direct
runtime: auto  # namespace on Linux, wasm on others

security:
  level: minimal
  capabilities: []
  seccomp: allow-all
  landlock: disabled
  network: host

performance:
  zygote: true
  io_mode: direct
  memory_allocator: system
  cpu_affinity: inherit

resources:
  memory: unlimited
  cpu: unlimited
  pids: 1024
  disk: unlimited

adaptive:
  auto_upgrade: false  # Stay in direct mode
  fallback: sandbox
```

**Implementation**:
```go
func (em *ExecutionModeManager) ConfigureDirectMode(profile string) *ExecutionModeConfig {
    return &ExecutionModeConfig{
        Mode:    ExecutionModeDirect,
        Runtime: em.selectOptimalRuntime(),
        
        SecurityLevel: SecurityLevel{
            Capabilities:    []string{},  // Inherit from parent
            SeccompProfile:  "allow-all",
            LandlockEnabled: false,
            Namespaces:      []string{"user", "pid"}, // Minimal
        },
        
        PerformanceProfile: PerformanceProfile{
            ZygoteEnabled:     true,
            IOMode:           "direct",
            MemoryAllocator:  "system",
            CPUAffinity:      "inherit",
            PageCachePrefetch: false,
        },
        
        ResourceLimits: ResourceLimits{
            Memory: ResourceLimit{Value: -1}, // Unlimited
            CPU:    ResourceLimit{Value: -1},
            PIDs:   ResourceLimit{Value: 1024},
        },
        
        NetworkPolicy: NetworkPolicy{
            Mode:     "host",
            Isolated: false,
        },
    }
}
```

### 2. **Sandbox Mode** - Balanced Default

**Target**: <25ms startup, optimal security/performance balance
**Use Cases**: LLM code execution, general development, testing

```yaml
# Sandbox mode profile example
profile: python-ai-sandbox
mode: sandbox
runtime: auto  # Smart selection based on platform

security:
  level: medium
  capabilities: []
  seccomp: python-ai.bpf
  landlock: enabled
  paths:
    - path: /tmp
      access: read-write
    - path: /usr/lib/python3.*
      access: read-only
  network: loopback-only

performance:
  zygote: true
  io_mode: uring
  memory_allocator: jemalloc
  cpu_affinity: numa-aware
  prefetch: python

resources:
  memory: 512MB
  cpu: 1.0
  pids: 256
  disk: 1GB

adaptive:
  auto_upgrade: hardened  # Upgrade on security events
  auto_downgrade: direct  # Downgrade for performance if safe
  triggers:
    - network_access: upgrade
    - file_write_outside_tmp: upgrade
    - high_cpu_usage: maintain
```

**Implementation**:
```go
func (em *ExecutionModeManager) ConfigureSandboxMode(profile string) *ExecutionModeConfig {
    config := &ExecutionModeConfig{
        Mode:    ExecutionModeSandbox,
        Runtime: em.selectOptimalRuntime(),
        
        SecurityLevel: SecurityLevel{
            Capabilities:    []string{}, // Drop all
            SeccompProfile:  profile + "-sandbox.bpf",
            LandlockEnabled: true,
            Namespaces:      []string{"user", "pid", "mount", "net", "uts", "ipc"},
        },
        
        PerformanceProfile: PerformanceProfile{
            ZygoteEnabled:     true,
            IOMode:           "uring",
            MemoryAllocator:  "jemalloc",
            CPUAffinity:      "numa-aware",
            PageCachePrefetch: true,
        },
    }
    
    // Add Landlock rules
    config.LandlockRules = em.compileLandlockRules(profile, []LandlockRule{
        {Path: "/tmp", Access: LandlockAccessReadWrite},
        {Path: "/usr/lib/python*", Access: LandlockAccessReadOnly},
        {Path: "/proc/self", Access: LandlockAccessReadOnly},
    })
    
    return config
}
```

### 3. **Hardened Mode** - Maximum Security

**Target**: <60ms startup, enterprise-grade security
**Use Cases**: Production environments, CI/CD, untrusted code

```yaml
# Hardened mode profile example
profile: production-hardened
mode: hardened
runtime: namespace  # Force namespace for full security

security:
  level: maximum
  capabilities: []
  seccomp: hardened.bpf
  landlock: enabled
  apparmor: enabled
  paths:
    - path: /tmp/sandbox
      access: read-write
  network: disabled
  
  # Additional hardening
  no_new_privs: true
  readonly_rootfs: true
  masked_paths:
    - /proc/kcore
    - /proc/latency_stats
    - /sys/firmware

performance:
  zygote: true
  io_mode: uring
  memory_allocator: secure
  cpu_affinity: isolated
  audit_all: true

resources:
  memory: 256MB
  cpu: 0.5
  pids: 64
  disk: 100MB
  timeout: 300s

adaptive:
  auto_upgrade: false    # Never auto-upgrade from hardened
  auto_downgrade: false  # Never auto-downgrade
  monitoring: enhanced
```

### 4. **WebAssembly Mode** - Cross-Platform

**Target**: <30ms startup, portable execution
**Use Cases**: Cross-platform compatibility, edge devices, web integration

```yaml
# WebAssembly mode profile example
profile: wasm-portable
mode: wasm
runtime: wasm

security:
  level: high
  wasm_capabilities:
    - wasi:filesystem/read@/tmp
    - wasi:sockets/loopback
  memory_isolation: true
  stack_protection: true

performance:
  wasm_engine: wasmtime
  compilation: aot  # Ahead-of-time compilation
  memory_mode: linear
  simd: enabled

resources:
  memory: 128MB
  stack: 8MB
  heap: 64MB
  
adaptive:
  fallback: sandbox
  upgrade_triggers:
    - filesystem_access: sandbox
    - network_access: sandbox
```

## Adaptive Policy Engine

### Smart Mode Selection

```go
type AdaptivePolicyEngine struct {
    // Mode selection logic
    modeSelector     *ModeSelector
    securityAnalyzer *SecurityAnalyzer
    performanceProfiler *PerformanceProfiler
    
    // Learning system
    behaviorModel    *BehaviorModel
    riskAssessment   *RiskAssessment
    
    // Runtime adaptation
    modeTransitions  map[string]ExecutionMode
    adaptiveRules    []*AdaptiveRule
}

type AdaptiveRule struct {
    Trigger      TriggerCondition
    Action       AdaptiveAction
    Confidence   float64
    TimeWindow   time.Duration
}

type TriggerCondition struct {
    Type      TriggerType
    Threshold float64
    Pattern   string
}

type TriggerType int

const (
    TriggerNetworkAccess TriggerType = iota
    TriggerFileSystemWrite
    TriggerSyscallPattern
    TriggerMemoryUsage
    TriggerCPUUsage
    TriggerSecurityViolation
    TriggerPerformanceRegression
)

// Intelligent mode selection based on workload analysis
func (ape *AdaptivePolicyEngine) SelectOptimalMode(
    request *ExecutionRequest,
    context *ExecutionContext,
) ExecutionMode {
    
    // Phase 1: Risk assessment
    riskLevel := ape.riskAssessment.AnalyzeRequest(request)
    
    // Phase 2: Performance requirements analysis
    perfRequirements := ape.performanceProfiler.AnalyzeRequirements(request)
    
    // Phase 3: Platform capability check
    platformCaps := ape.getPlatformCapabilities()
    
    // Phase 4: Historical behavior analysis
    historicalBehavior := ape.behaviorModel.GetBehaviorProfile(request.Profile)
    
    // Decision matrix
    if riskLevel >= RiskLevelHigh {
        return ExecutionModeHardened
    }
    
    if perfRequirements.LatencyTarget < 20*time.Millisecond {
        if riskLevel <= RiskLevelLow {
            return ExecutionModeDirect
        }
    }
    
    if !platformCaps.HasLinuxNamespaces {
        return ExecutionModeWasm
    }
    
    // Default to balanced sandbox mode
    return ExecutionModeSandbox
}

// Runtime mode adaptation based on behavior
func (ape *AdaptivePolicyEngine) AdaptMode(
    containerID string,
    currentMode ExecutionMode,
    behavior *RuntimeBehavior,
) ExecutionMode {
    
    for _, rule := range ape.adaptiveRules {
        if rule.Matches(behavior) && rule.Confidence > 0.8 {
            switch rule.Action.Type {
            case AdaptiveActionUpgrade:
                if currentMode < ExecutionModeHardened {
                    return currentMode + 1
                }
            case AdaptiveActionDowngrade:
                if currentMode > ExecutionModeDirect {
                    return currentMode - 1
                }
            }
        }
    }
    
    return currentMode // No change
}
```

### Runtime Transition System

```go
type ModeTransitionManager struct {
    activeContainers map[string]*ActiveContainer
    transitionQueue  chan *TransitionRequest
    
    // Hot migration support
    migrationEngine  *HotMigrationEngine
    stateSerializer  *StateSerializer
}

type TransitionRequest struct {
    ContainerID  string
    FromMode     ExecutionMode
    ToMode       ExecutionMode
    Reason       TransitionReason
    Urgency      TransitionUrgency
}

// Hot migration between execution modes
func (mtm *ModeTransitionManager) TransitionMode(
    containerID string,
    targetMode ExecutionMode,
    reason TransitionReason,
) error {
    
    container := mtm.activeContainers[containerID]
    if container == nil {
        return fmt.Errorf("container not found: %s", containerID)
    }
    
    currentMode := container.Config.Mode
    
    // Check if transition is valid and safe
    if !mtm.isTransitionValid(currentMode, targetMode) {
        return fmt.Errorf("invalid transition: %v -> %v", currentMode, targetMode)
    }
    
    // Determine migration strategy
    strategy := mtm.selectMigrationStrategy(currentMode, targetMode, reason)
    
    switch strategy {
    case MigrationStrategyHot:
        return mtm.performHotMigration(container, targetMode)
    case MigrationStrategyCold:
        return mtm.performColdMigration(container, targetMode)
    case MigrationStrategyRestart:
        return mtm.performRestartMigration(container, targetMode)
    }
    
    return nil
}

// Hot migration implementation (for compatible mode transitions)
func (mtm *ModeTransitionManager) performHotMigration(
    container *ActiveContainer,
    targetMode ExecutionMode,
) error {
    
    // Phase 1: Serialize current state
    state, err := mtm.stateSerializer.SerializeContainer(container)
    if err != nil {
        return fmt.Errorf("state serialization failed: %w", err)
    }
    
    // Phase 2: Create new execution environment
    newConfig := mtm.generateModeConfig(targetMode, container.Profile)
    newContainer, err := mtm.createContainer(newConfig)
    if err != nil {
        return fmt.Errorf("new container creation failed: %w", err)
    }
    
    // Phase 3: Restore state in new environment
    if err := mtm.stateSerializer.RestoreContainer(newContainer, state); err != nil {
        mtm.destroyContainer(newContainer)
        return fmt.Errorf("state restoration failed: %w", err)
    }
    
    // Phase 4: Atomic swap
    oldContainer := container
    mtm.activeContainers[container.ID] = newContainer
    
    // Phase 5: Cleanup old container
    go func() {
        time.Sleep(100 * time.Millisecond) // Grace period
        mtm.destroyContainer(oldContainer)
    }()
    
    return nil
}
```

## Performance Optimization

### Mode-Specific Optimizations

```go
// Performance profiles for each execution mode
var ModePerformanceProfiles = map[ExecutionMode]PerformanceProfile{
    ExecutionModeDirect: {
        ZygotePoolSize:    1,  // Minimal pool
        IOBufferSize:      4096,
        MemoryAllocator:   "system",
        CPUScheduling:     "inherit",
        SecurityOverhead:  0,  // No security checks
    },
    
    ExecutionModeSandbox: {
        ZygotePoolSize:    3,  // Balanced pool
        IOBufferSize:      64 * 1024,
        MemoryAllocator:   "jemalloc",
        CPUScheduling:     "numa-aware",
        SecurityOverhead:  5,  // ~5ms security setup
    },
    
    ExecutionModeHardened: {
        ZygotePoolSize:    2,  // Smaller pool, more memory per instance
        IOBufferSize:      32 * 1024,
        MemoryAllocator:   "secure",
        CPUScheduling:     "isolated",
        SecurityOverhead:  15, // ~15ms comprehensive security
    },
    
    ExecutionModeWasm: {
        ZygotePoolSize:    4,  // Wasm instances are lighter
        IOBufferSize:      16 * 1024,
        MemoryAllocator:   "linear",
        CPUScheduling:     "wasm-optimized",
        SecurityOverhead:  2,  // Wasm has built-in isolation
    },
}
```

## Implementation Plan

### Phase 1: Core Mode Infrastructure (Week 1-2)
- [ ] Implement ExecutionModeManager
- [ ] Basic mode configuration system
- [ ] Mode selection matrix
- [ ] Direct and Sandbox mode implementation

### Phase 2: Advanced Modes (Week 2-3)
- [ ] Hardened mode with full security stack
- [ ] WebAssembly mode integration
- [ ] Cross-platform compatibility layer
- [ ] Performance optimization per mode

### Phase 3: Adaptive Engine (Week 3-4)
- [ ] AdaptivePolicyEngine implementation
- [ ] Runtime behavior analysis
- [ ] Mode transition system
- [ ] Hot migration for compatible modes

### Phase 4: Testing & Validation (Week 4)
- [ ] Mode performance benchmarking
- [ ] Security validation for each mode
- [ ] Transition testing
- [ ] Cross-platform compatibility testing

## Success Criteria

### Performance Targets
- [ ] **Direct Mode**: <15ms startup, minimal overhead
- [ ] **Sandbox Mode**: <25ms startup, <5ms security overhead  
- [ ] **Hardened Mode**: <60ms startup, comprehensive security
- [ ] **Wasm Mode**: <30ms startup, cross-platform native performance
- [ ] **Mode Transitions**: <100ms hot migration, <500ms cold migration

### Security Validation
- [ ] Each mode meets specified security level
- [ ] No privilege escalation during transitions
- [ ] Proper isolation boundaries maintained
- [ ] Audit trail for all mode changes

### Adaptive Intelligence
- [ ] >85% optimal mode selection accuracy
- [ ] <5% false positive security upgrades
- [ ] Smooth degradation under resource pressure
- [ ] Learning from historical behavior patterns

This adaptive execution system provides the foundation for Phantom Fragment V3's intelligent runtime optimization while maintaining security guarantees across different threat models and performance requirements.