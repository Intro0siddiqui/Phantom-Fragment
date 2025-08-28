# Zygote Spawner Fragment

## Overview

The **Zygote Spawner Fragment V3** is the cornerstone of Phantom Fragment's performance advantage, targeting <80ms startup times across all platforms through hybrid namespace/WebAssembly pre-warming with Landlock security integration.

## Architecture Design

### Core Components

```go
// Enhanced Zygote Spawner
type ZygoteSpawner struct {
    // Core pools for different execution modes
    namespacePools    map[string]*NamespaceZygotePool
    wasmPools         map[string]*WasmZygotePool
    
    // Security integration
    landlockCompiler  *LandlockPolicyCompiler
    seccompCache      *SeccompBPFCache
    
    // Performance optimization
    mlPredictor       *DemandPredictor
    psiMonitor        *PSIMonitor
    numaScheduler     *NUMAScheduler
    
    // I/O optimization
    atomicWriter      *AtomicOverlayWriter
    prefetcher        *PageCachePrefetcher
    
    // Metrics and monitoring
    metrics           *ZygoteMetrics
    healthChecker     *ZygoteHealthChecker
}

// Namespace-based zygote pool (Linux optimal)
type NamespaceZygotePool struct {
    profile           string
    warmProcesses     []*NamespaceZygote
    poolSize          int
    targetSize        int
    spawnedCount      int64
    
    landlockRules     *CompiledLandlockRules
    atomicOverlays    []string
    cpuAffinity       []int
    numaNode          int
}

// WebAssembly-based zygote pool (cross-platform)
type WasmZygotePool struct {
    profile           string
    wasmInstances     []*WasmZygote
    wasmEngine        *wasmtime.Engine
    moduleCache       map[string]*wasmtime.Module
    
    // WASI configuration
    wasiConfig        *WasiSandboxConfig
    virtualFS         *WasmVirtualFS
}

// Individual namespace zygote process
type NamespaceZygote struct {
    pid               int
    pidFD             int
    rootfsFD          int
    overlayPath       string
    
    // Security context
    seccompFD         int
    landlockFD        int
    cgroupPath        string
    
    // State management
    createdAt         time.Time
    lastUsed          time.Time
    ready             bool
    spawned           int32
}

// Individual WebAssembly instance
type WasmZygote struct {
    instance          *wasmtime.Instance
    module            *wasmtime.Module
    store             *wasmtime.Store
    
    // WASI context
    wasiCtx           *wasi.WasiCtx
    virtualFS         *WasmVirtualFS
    
    // State management
    createdAt         time.Time
    lastUsed          time.Time
    ready             bool
}
```

## Implementation Details

### 1. **Startup Performance Optimization**

#### **Implementation Strategy**

```go
// High-performance zygote creation with Landlock pre-application
func (z *ZygoteSpawner) CreateNamespaceZygote(profile string) (*NamespaceZygote, error) {
    start := time.Now()
    
    // Phase 1: clone3() with all namespaces (1-2ms)
    var pidfd int
    pid, err := syscall.Clone3(&syscall.Clone3Args{
        Flags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | 
               syscall.CLONE_NEWMOUNT | syscall.CLONE_NEWNET |
               syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC,
        PidFD: &pidfd,
        ChildTID: nil,
    })
    if err != nil {
        return nil, fmt.Errorf("clone3 failed: %w", err)
    }
    
    // Phase 2: Apply pre-compiled Landlock policy (<1ms)
    landlockRules := z.landlockCompiler.GetCompiledRules(profile)
    if err := landlockRules.ApplyToPID(pid); err != nil {
        syscall.Kill(pid, syscall.SIGKILL)
        return nil, fmt.Errorf("landlock application failed: %w", err)
    }
    
    // Phase 3: Setup atomic overlay filesystem (2-3ms)
    overlayPath, err := z.atomicWriter.CreateAtomicOverlay(profile, pid)
    if err != nil {
        syscall.Kill(pid, syscall.SIGKILL)
        return nil, fmt.Errorf("overlay creation failed: %w", err)
    }
    
    // Phase 4: Pre-load seccomp BPF (1ms)
    seccompFD, err := z.seccompCache.GetCompiledSeccomp(profile)
    if err != nil {
        syscall.Kill(pid, syscall.SIGKILL)
        return nil, fmt.Errorf("seccomp loading failed: %w", err)
    }
    
    // Phase 5: Setup in child process via pidfd_send_signal coordination
    if err := z.setupZygoteChild(pid, pidfd, overlayPath, seccompFD); err != nil {
        syscall.Kill(pid, syscall.SIGKILL)
        return nil, fmt.Errorf("child setup failed: %w", err)
    }
    
    zygote := &NamespaceZygote{
        pid:         pid,
        pidFD:       pidfd,
        overlayPath: overlayPath,
        seccompFD:   seccompFD,
        createdAt:   start,
        ready:       true,
    }
    
    // Record creation time (target: <8ms total)
    z.metrics.RecordZygoteCreation(profile, time.Since(start))
    return zygote, nil
}

// WebAssembly zygote creation for cross-platform
func (z *ZygoteSpawner) CreateWasmZygote(profile string) (*WasmZygote, error) {
    start := time.Now()
    
    // Phase 1: Get cached Wasm module (0.5ms)
    module, exists := z.wasmPools[profile].moduleCache[profile]
    if !exists {
        return nil, fmt.Errorf("wasm module not found for profile: %s", profile)
    }
    
    // Phase 2: Create new store and instance (2-3ms)
    store := wasmtime.NewStore(z.wasmPools[profile].wasmEngine)
    instance, err := wasmtime.NewInstance(store, module, []wasmtime.AsExtern{})
    if err != nil {
        return nil, fmt.Errorf("wasm instantiation failed: %w", err)
    }
    
    // Phase 3: Setup WASI sandbox context (1-2ms)
    wasiConfig := z.wasmPools[profile].wasiConfig.Clone()
    wasiCtx, err := wasi.NewWasiCtx(wasiConfig)
    if err != nil {
        return nil, fmt.Errorf("wasi context creation failed: %w", err)
    }
    
    zygote := &WasmZygote{
        instance:  instance,
        module:    module,
        store:     store,
        wasiCtx:   wasiCtx,
        createdAt: start,
        ready:     true,
    }
    
    // Record creation time (target: <5ms total)
    z.metrics.RecordWasmZygoteCreation(profile, time.Since(start))
    return zygote, nil
}
```

### 2. **Fast Spawning from Warm Zygotes**

```go
// Ultra-fast spawning from namespace zygote
func (nz *NamespaceZygote) SpawnContainer(cmd []string, env map[string]string) (*Container, error) {
    start := time.Now()
    
    // Phase 1: Clone from zygote with copy-on-write (1-2ms)
    childPID, err := syscall.CloneFromPidFD(nz.pidFD, syscall.CLONE_VM)
    if err != nil {
        return nil, fmt.Errorf("zygote clone failed: %w", err)
    }
    
    // Phase 2: Setup environment and working directory (<1ms)
    if err := z.setupContainerEnvironment(childPID, env); err != nil {
        return nil, err
    }
    
    // Phase 3: Execute command via execveat (1ms)
    if err := z.execInContainer(childPID, cmd); err != nil {
        return nil, err
    }
    
    container := &Container{
        ID:          generateContainerID(),
        PID:         childPID,
        ParentZygote: nz,
        CreatedAt:   start,
    }
    
    // Record spawn time (target: <15ms)
    atomic.AddInt32(&nz.spawned, 1)
    nz.lastUsed = time.Now()
    
    return container, nil
}

// Fast spawning from Wasm zygote
func (wz *WasmZygote) SpawnWasmContainer(wasmBinary []byte, args []string) (*WasmContainer, error) {
    start := time.Now()
    
    // Phase 1: Clone Wasm instance (1ms)
    newStore := wasmtime.NewStore(wz.instance.Engine())
    newInstance, err := wasmtime.NewInstance(newStore, wz.module, []wasmtime.AsExtern{})
    if err != nil {
        return nil, err
    }
    
    // Phase 2: Setup isolated WASI context (<1ms)
    isolatedWasi := wz.wasiCtx.Clone()
    isolatedWasi.SetArgs(args)
    
    // Phase 3: Execute Wasm function (1-2ms)
    startFunc := newInstance.GetFunc(newStore, "_start")
    if startFunc == nil {
        return nil, fmt.Errorf("_start function not found")
    }
    
    container := &WasmContainer{
        ID:        generateContainerID(),
        Instance:  newInstance,
        Store:     newStore,
        WasiCtx:   isolatedWasi,
        CreatedAt: start,
    }
    
    // Record spawn time (target: <25ms)
    wz.lastUsed = time.Now()
    return container, nil
}
```

### 3. **Intelligent Pool Management**

```go
// ML-enhanced pool management
type DemandPredictor struct {
    model         *torchscript.Module
    historyBuffer *CircularBuffer
    profiles      map[string]*ProfileStats
}

// Predictive pool sizing
func (z *ZygoteSpawner) ManagePools() {
    for profile, pool := range z.namespacePools {
        // Get ML prediction for next 5 minutes
        predicted := z.mlPredictor.PredictDemand(profile, 300*time.Second)
        current := len(pool.warmProcesses)
        
        // PSI-aware scaling decisions
        pressure := z.psiMonitor.GetCurrentPressure()
        
        if pressure.CPU < 0.7 && predicted > float64(current)*1.2 {
            // Scale up proactively
            targetSize := int(predicted * 1.3) // 30% buffer
            z.scalePoolToSize(profile, targetSize)
            
        } else if predicted < float64(current)*0.6 && current > 2 {
            // Scale down to save resources
            targetSize := max(2, int(predicted*1.1)) // Keep minimum 2
            z.scalePoolToSize(profile, targetSize)
        }
    }
}

// NUMA-aware zygote placement
func (z *ZygoteSpawner) selectOptimalNUMANode(profile string) int {
    // Check current CPU pressure per NUMA node
    topology := z.numaScheduler.GetTopology()
    
    bestNode := 0
    lowestPressure := 1.0
    
    for nodeID, node := range topology.Nodes {
        pressure := z.psiMonitor.GetNUMAPressure(nodeID)
        if pressure.CPU < lowestPressure {
            lowestPressure = pressure.CPU
            bestNode = nodeID
        }
    }
    
    return bestNode
}
```

### 4. **Security Integration with Landlock**

```go
// Landlock policy compiler for AOT security
type LandlockPolicyCompiler struct {
    rulesets    map[string]*CompiledLandlockRules
    compiler    *landlockcompiler.Compiler
}

type CompiledLandlockRules struct {
    ruleset     []byte
    paths       []LandlockPath
    compiled    bool
}

// Pre-compile Landlock rules for zero runtime overhead
func (lpc *LandlockPolicyCompiler) CompilePolicy(profile string, policy *SecurityPolicy) error {
    // Convert YAML policy to Landlock rules
    rules := &landlock.Ruleset{}
    
    // File system access rules
    for _, path := range policy.FileSystem.AllowedPaths {
        rules.AddRule(&landlock.PathRule{
            Path:    path.Path,
            Access:  convertToLandlockAccess(path.Permissions),
        })
    }
    
    // Network access rules (if supported)
    if policy.Network.Enabled {
        for _, rule := range policy.Network.Rules {
            rules.AddRule(&landlock.NetworkRule{
                Port:   rule.Port,
                Access: landlock.AccessNetworkConnect,
            })
        }
    }
    
    // Compile to bytecode
    compiled, err := rules.Compile()
    if err != nil {
        return fmt.Errorf("landlock compilation failed: %w", err)
    }
    
    lpc.rulesets[profile] = &CompiledLandlockRules{
        ruleset:  compiled,
        compiled: true,
    }
    
    return nil
}
```

### 5. **Performance Monitoring & Metrics**

```go
type ZygoteMetrics struct {
    // Creation metrics
    CreationLatency    *prometheus.HistogramVec
    WarmProcessCount   *prometheus.GaugeVec
    SpawnLatency       *prometheus.HistogramVec
    
    // Pool management metrics
    PoolSizeOptimal    *prometheus.GaugeVec
    PoolSizeActual     *prometheus.GaugeVec
    ScalingEvents      *prometheus.CounterVec
    
    // Performance metrics
    MemoryUsage        *prometheus.GaugeVec
    CPUUsage           *prometheus.GaugeVec
    SecurityOverhead   *prometheus.HistogramVec
}

// Comprehensive performance tracking
func (zm *ZygoteMetrics) RecordZygoteCreation(profile string, duration time.Duration) {
    zm.CreationLatency.WithLabelValues(profile, "namespace").Observe(duration.Seconds())
    
    // Alert if creation time exceeds target
    if duration > 8*time.Millisecond {
        log.Warnf("Zygote creation for %s took %v (target: <8ms)", profile, duration)
    }
}

func (zm *ZygoteMetrics) RecordSpawn(profile string, duration time.Duration, mode string) {
    zm.SpawnLatency.WithLabelValues(profile, mode).Observe(duration.Seconds())
    
    // Performance regression detection
    if mode == "namespace" && duration > 15*time.Millisecond {
        log.Warnf("Spawn latency regression for %s: %v (target: <15ms)", profile, duration)
    } else if mode == "wasm" && duration > 25*time.Millisecond {
        log.Warnf("Wasm spawn latency regression for %s: %v (target: <25ms)", profile, duration)
    }
}
```

This design provides the foundation for achieving Phantom Fragment's ambitious performance targets while maintaining security and cross-platform compatibility.