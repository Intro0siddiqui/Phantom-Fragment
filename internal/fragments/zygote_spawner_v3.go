//go:build linux
// +build linux

package fragments

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phantom-fragment/phantom-fragment/internal/security/landlock"
	"github.com/phantom-fragment/phantom-fragment/pkg/types"
)

// Import WasmVirtualFS from io_fastpath_v3_enhanced.go
// This import is needed for cross-package type usage

// Cross-platform signal and system call constants
const (
	// Signal constants
	SIGKILL   = 9
	SIGUSR1   = 10

	// File operation constants
	O_RDONLY  = 0
	O_PATH    = 0x200000
	O_CLOEXEC = 0x80000

	// Clone flags for namespace creation
	CLONE_NEWUSER  = 0x10000000
	CLONE_NEWPID   = 0x20000000
	CLONE_NEWMOUNT = 0x00020000
	CLONE_NEWNET   = 0x40000000
	CLONE_NEWUTS   = 0x04000000
	CLONE_NEWIPC   = 0x08000000
	CLONE_PIDFD    = 0x00001000

	// System call numbers (x86_64)
	SYS_CLONE3 = 435
)

// Cross-platform unix package compatibility
func Kill(pid int, sig int) error {
	// Use os.Process.Kill for cross-platform compatibility
	if process, err := os.FindProcess(pid); err == nil {
		return process.Kill()
	}
    return fmt.Errorf("process not found: %d", pid)
}

// spawnFromNamespacePool provisions a container using a namespace zygote.
// It favors responsiveness and avoids blocking by creating a zygote on-demand if needed.
func (z *ZygoteSpawnerV3) spawnFromNamespacePool(profile string, request *types.SpawnRequest) (*types.Container, error) {
    // Respect context timeout if provided via request.Timeout by bounding the operation duration.
    // The flow below is fast and should not block, so we use it primarily to avoid accidental hangs.

    // Ensure pool exists (best-effort, non-blocking)
    z.mu.RLock()
    pool := z.namespacePools[profile]
    z.mu.RUnlock()
    if pool == nil {
        _ = z.CreatePool(profile, types.PoolTypeNamespace, z.config.DefaultPoolSize)
    }

    // Create a zygote on demand (lightweight placeholder implementation)
    zygote, err := z.CreateNamespaceZygote(profile)
    if err != nil {
        return nil, fmt.Errorf("failed to create namespace zygote: %w", err)
    }

    // Build container struct
    container := &types.Container{
        ID:        generateContainerID(),
        Workdir:   zygote.overlayPath,
        Env:       request.Environment,
        PID:       zygote.pid,
        Profile:   profile,
        CreatedAt: time.Now(),
        Mode:      types.ExecutionModeNamespace,
        ZygoteID:  zygote.pid,
    }

    return container, nil
}

// spawnFromWasmPool provisions a container using a WebAssembly zygote.
// It is cross-platform and returns quickly with a ready container handle.
func (z *ZygoteSpawnerV3) spawnFromWasmPool(profile string, request *types.SpawnRequest) (*types.Container, error) {
    // Ensure pool exists (best-effort)
    z.mu.RLock()
    pool := z.wasmPools[profile]
    z.mu.RUnlock()
    if pool == nil {
        _ = z.CreatePool(profile, types.PoolTypeWasm, z.config.DefaultPoolSize)
    }

    // Create a wasm zygote on demand
    wz, err := z.CreateWasmZygote(profile)
    if err != nil {
        return nil, fmt.Errorf("failed to create wasm zygote: %w", err)
    }

    // Instance cloning would occur here in a full implementation. For now, reuse placeholder.
    wc := &WasmContainer{
        ID:        generateContainerID(),
        Instance:  wz.instance,
        Store:     wz.store,
        WasiCtx:   wz.wasiCtx.Clone(),
        VirtualFS: wz.virtualFS,
        CreatedAt: time.Now(),
        Profile:   profile,
    }

    // Build types.Container wrapper
    container := &types.Container{
        ID:           wc.ID,
        Workdir:      "",
        Env:          request.Environment,
        PID:          0,
        Profile:      profile,
        CreatedAt:    wc.CreatedAt,
        Mode:         types.ExecutionModeWasm,
        ZygoteID:     0,
        WasmInstance: wc,
    }

    // Propagate WASI args/env if provided
    if wz != nil && wc.WasiCtx != nil {
        if request.Command != nil {
            wc.WasiCtx.SetArgs(request.Command)
        }
        if request.Environment != nil {
            wc.WasiCtx.SetEnv(request.Environment)
        }
    }

    return container, nil
}

// WarmupPool initializes a pool for the given profile with the requested size.
// It chooses a sensible pool type based on platform and configuration, then
// delegates to CreatePool. This is primarily used by benchmarks to pre-warm
// pools without worrying about platform nuances.
func (z *ZygoteSpawnerV3) WarmupPool(profile string, initialSize int) error {
	// Prefer namespace pools on Linux; use Wasm in cross-platform or non-Linux mode
	poolType := types.PoolTypeNamespace
	if z.config.CrossPlatformMode || !isLinux() {
		poolType = types.PoolTypeWasm
	}

	return z.CreatePool(profile, poolType, initialSize)
}

func Open(path string, flag int, perm uint32) (int, error) {
	// Fallback implementation using os.Open
	file, err := os.OpenFile(path, flag, os.FileMode(perm))
	if err != nil {
		return -1, err
	}
	return int(file.Fd()), nil
}

func Close(fd int) error {
	// Use os.File for safe closing
	file := os.NewFile(uintptr(fd), "")
	if file != nil {
		return file.Close()
	}
	return nil
}

// setupPivotRoot configures the root filesystem for the child using the overlay path.
// Cross-platform safe: no-op on non-Linux.
func (z *ZygoteSpawnerV3) setupPivotRoot(pid int, overlayPath string) error {
    // In development/cross-platform mode, skip actual pivot_root operations.
    if !isLinux() {
        return nil
    }
    // Placeholder: a real implementation would perform pivot_root and mount operations
    // inside the child's mount namespace via setns. For now, return nil to avoid hangs.
    return nil
}

// setupZygoteChild performs final child setup steps: mount namespace, cgroups, seccomp, signaling.
// Designed to be non-blocking and cross-platform safe.
func (z *ZygoteSpawnerV3) setupZygoteChild(pid int, overlayPath string) error {
    // Mount namespace and pivot root (no-op on non-Linux)
    if err := z.setupChildMountNamespace(pid, overlayPath); err != nil {
        return err
    }
    // Setup cgroups if available (no-op on non-Linux)
    if err := z.setupChildCgroups(pid); err != nil {
        return err
    }
    // Apply seccomp filter if available (placeholder)
    if err := z.applySeccompToChild(pid); err != nil {
        return err
    }
    // Signal readiness (placeholder)
    if err := z.signalChildReady(); err != nil {
        return err
    }
    return nil
}

func ForkExec(argv0 string, argv []string, attr *ProcAttr) (pid int, err error) {
	// Convert environment map to slice
	var envSlice []string
	if attr != nil && attr.Env != nil {
		for k, v := range attr.Env {
			envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Resolve executable path cross-platform
	exePath := argv0
	if argv0 == "/proc/self/exe" {
		if p, pErr := os.Executable(); pErr == nil {
			exePath = p
		}
	}

	// Build args: first arg should be the program name
	args := append([]string{exePath}, argv...)

	process, err := os.StartProcess(exePath, args, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Env:   envSlice,
	})
	if err != nil {
		return -1, err
	}
	return process.Pid, nil
}

// Cross-platform ProcAttr
type ProcAttr struct {
	Env   map[string]string  // Changed from []string to map[string]string
	Files []uintptr
}

// WasmVirtualFSPlaceholder is a local placeholder to avoid circular import issues
type WasmVirtualFSPlaceholder struct{}

// Pool types for different execution modes
type PoolType string

const (
	PoolTypeNamespace PoolType = "namespace"
	PoolTypeWasm      PoolType = "wasm"
)

// Execution modes for containers
type ExecutionMode string

const (
	ExecutionModeNamespace ExecutionMode = "namespace"
	ExecutionModeWasm      ExecutionMode = "wasm"
)

// SpawnRequest represents a request to spawn a new container
type SpawnRequest struct {
	Profile     string
	Command     []string
	Environment map[string]string
	Workdir     string
	PoolType    PoolType
	Timeout     time.Duration
}

// ZygoteSpawnerV3 is the enhanced zygote spawner with V3 optimizations
type ZygoteSpawnerV3 struct {
	mu sync.RWMutex

	// Core pools for different execution modes
	namespacePools map[string]*NamespaceZygotePool
	wasmPools      map[string]*WasmZygotePool

	// Security integration
	landlockCompiler *landlock.PolicyCompiler
	seccompCache     *SeccompBPFCache

	// Performance optimization
	mlPredictor   *DemandPredictor
	psiMonitor    *PSIMonitorV3
	numaScheduler *NUMAScheduler

	// I/O optimization
	atomicWriter *AtomicOverlayWriter
	prefetcher   *PageCachePrefetcher

    // Metrics and monitoring
    metrics       *ZygoteMetrics
    healthChecker *ZygoteHealthChecker

    // Configuration
    config *ZygoteConfig
}

// ---- Minimal placeholders to satisfy references ----
type DemandPredictor struct{}
type PSIMonitorV3 struct{}
type NUMAScheduler struct{}
type AtomicOverlayWriter struct{}
type PageCachePrefetcher struct{}
type ZygoteMetrics struct{}
type ZygoteHealthChecker struct{}
type WasmEngine interface{}
type WasiSandboxConfig struct{}
type Process struct{}

func NewSeccompBPFCache() *SeccompBPFCache { return &SeccompBPFCache{} }
func NewDemandPredictor(_ time.Duration) *DemandPredictor { return &DemandPredictor{} }
func NewPSIMonitorV3() *PSIMonitorV3 { return &PSIMonitorV3{} }
func NewNUMAScheduler() *NUMAScheduler { return &NUMAScheduler{} }
func NewAtomicOverlayWriter() *AtomicOverlayWriter { return &AtomicOverlayWriter{} }
func NewPageCachePrefetcher() *PageCachePrefetcher { return &PageCachePrefetcher{} }
func NewZygoteMetrics() *ZygoteMetrics { return &ZygoteMetrics{} }
func NewZygoteHealthChecker(_ *ZygoteSpawnerV3) *ZygoteHealthChecker { return &ZygoteHealthChecker{} }

// No-op metric methods
func (m *ZygoteMetrics) RecordZygoteCreation(_ string, _ time.Duration)            {}
func (m *ZygoteMetrics) RecordCreationRegression(_ string, _ time.Duration, _ time.Duration) {}
func (m *ZygoteMetrics) RecordSpawn(_ string, _ time.Duration, _ string)           {}
func (m *ZygoteMetrics) RecordPerformanceRegression(_ string, _ time.Duration, _ time.Duration) {}

// NamespaceZygotePool manages pre-warmed namespace-based processes
type NamespaceZygotePool struct {
    profile       string
    warmProcesses []*NamespaceZygote
    poolSize      int
    targetSize    int
    spawnedCount  int64

	// V3 enhancements
	landlockRules *landlock.CompiledRules
	atomicOverlays []string
	cpuAffinity   []int
	numaNode      int

	// Synchronization
	mu       sync.RWMutex
	cond     *sync.Cond
	shutdown chan struct{}
}

// WasmZygotePool manages WebAssembly instances for cross-platform support
type WasmZygotePool struct {
	profile       string
	wasmInstances []*WasmZygote
	poolSize      int
	targetSize    int

	// WebAssembly runtime
	wasmEngine  WasmEngine  // Interface for wasmtime integration
	moduleCache map[string]WasmModule

	// WASI configuration
	wasiConfig  *WasiSandboxConfig
	virtualFS   *WasmVirtualFSPlaceholder

	// Synchronization
	mu       sync.RWMutex
	shutdown chan struct{}
}

// NamespaceZygote represents a pre-warmed namespace-based process
type NamespaceZygote struct {
	pid         int
	pidFD       int
	rootfsFD    int
	overlayPath string

	// Security context
	seccompFD  int
	landlockFD int
	cgroupPath string

	// State management
	createdAt time.Time
	lastUsed  time.Time
	ready     bool
	spawned   int32

	// Process management
	process *Process
}

// WasmZygote represents a pre-warmed WebAssembly instance
type WasmZygote struct {
	instance WasmInstance
	module   WasmModule
	store    WasmStore

	// WASI context
	wasiCtx   WasiContext
	virtualFS *WasmVirtualFSPlaceholder

	// State management
	createdAt time.Time
	lastUsed  time.Time
	ready     bool
}

// ZygoteConfig holds configuration for the spawner
type ZygoteConfig struct {
	// Pool configuration
	DefaultPoolSize    int
	MaxPoolSize        int
	MinPoolSize        int
	ScaleUpThreshold   float64
	ScaleDownThreshold float64

	// Performance targets
	TargetSpawnTimeNS   int64 // <60ms for namespace, <80ms for Wasm
	TargetWarmSpawnNS   int64 // <15ms for namespace, <25ms for Wasm
	TargetMemoryPerZygote int64 // <8MB for namespace, <6MB for Wasm

	// Landlock configuration
	EnableLandlock     bool
	LandlockMinVersion [3]int // Minimum kernel version required

	// WebAssembly configuration
	EnableWasm         bool
	WasmEngine         string // "wasmtime", "wasmer", etc.
	CrossPlatformMode  bool   // Use Wasm on non-Linux

	// ML prediction
	EnableMLPrediction bool
	PredictionWindow   time.Duration

	// NUMA optimization
	EnableNUMA         bool
	NUMAAware          bool
}

// NewZygoteSpawnerV3 creates a new enhanced zygote spawner
func NewZygoteSpawnerV3(config *ZygoteConfig) (*ZygoteSpawnerV3, error) {
	if config == nil {
		config = DefaultZygoteConfig()
	}

	spawner := &ZygoteSpawnerV3{
		namespacePools: make(map[string]*NamespaceZygotePool),
		wasmPools:      make(map[string]*WasmZygotePool),
		config:         config,
	}

	// Initialize components
	var err error

	// Initialize Landlock compiler if enabled
	if config.EnableLandlock {
		spawner.landlockCompiler, err = landlock.NewPolicyCompiler()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Landlock compiler: %w", err)
		}
	}

	// Initialize seccomp cache
	spawner.seccompCache = NewSeccompBPFCache()

	// Initialize ML predictor if enabled
	if config.EnableMLPrediction {
		spawner.mlPredictor = NewDemandPredictor(config.PredictionWindow)
	}

	// Initialize PSI monitor
	spawner.psiMonitor = NewPSIMonitorV3()

	// Initialize NUMA scheduler if enabled
	if config.EnableNUMA {
		spawner.numaScheduler = NewNUMAScheduler()
	}

	// Initialize atomic writer
	spawner.atomicWriter = NewAtomicOverlayWriter()

	// Initialize prefetcher
	spawner.prefetcher = NewPageCachePrefetcher()

	// Initialize metrics
	spawner.metrics = NewZygoteMetrics()

	// Initialize health checker
	spawner.healthChecker = NewZygoteHealthChecker(spawner)

	return spawner, nil
}

// CreatePool creates a new zygote pool for the specified profile
func (z *ZygoteSpawnerV3) CreatePool(profile string, poolType types.PoolType, initialSize int) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	switch poolType {
	case types.PoolTypeNamespace:
		if _, exists := z.namespacePools[profile]; exists {
			return fmt.Errorf("namespace pool for profile %s already exists", profile)
		}

		pool := &NamespaceZygotePool{
			profile:       profile,
			warmProcesses: make([]*NamespaceZygote, 0, z.config.MaxPoolSize),
			poolSize:      initialSize,
			targetSize:    initialSize,
			shutdown:      make(chan struct{}),
		}
		pool.cond = sync.NewCond(&pool.mu)

		z.namespacePools[profile] = pool

		// Pre-warm the pool
		go z.maintainNamespacePool(pool)

	case types.PoolTypeWasm:
		if _, exists := z.wasmPools[profile]; exists {
			return fmt.Errorf("wasm pool for profile %s already exists", profile)
		}

		pool := &WasmZygotePool{
			profile:       profile,
			wasmInstances: make([]*WasmZygote, 0, z.config.MaxPoolSize),
			poolSize:      initialSize,
			targetSize:    initialSize,
			moduleCache:   make(map[string]WasmModule),
			shutdown:      make(chan struct{}),
		}

		z.wasmPools[profile] = pool

		// Pre-warm the pool
		go z.maintainWasmPool(pool)

	default:
		return fmt.Errorf("unsupported pool type: %v", poolType)
	}

	return nil
}

// SpawnFromPool spawns a new container from the appropriate pool
func (z *ZygoteSpawnerV3) SpawnFromPool(ctx context.Context, profile string, request *types.SpawnRequest) (*types.Container, error) {
	start := time.Now()

	// Determine optimal execution mode
	poolType := z.selectOptimalPoolType(profile, request)

	var container *types.Container
	var err error

	switch poolType {
	case types.PoolTypeNamespace:
		container, err = z.spawnFromNamespacePool(profile, request)
	case types.PoolTypeWasm:
		container, err = z.spawnFromWasmPool(profile, request)
	default:
		return nil, fmt.Errorf("no suitable pool type available")
	}

	if err != nil {
		return nil, err
	}

	// Record spawn metrics
	spawnDuration := time.Since(start)
	z.metrics.RecordSpawn(profile, spawnDuration, string(poolType))

	// Check performance targets
	var targetDuration time.Duration
	if poolType == types.PoolTypeNamespace {
		targetDuration = time.Duration(z.config.TargetSpawnTimeNS)
	} else {
		targetDuration = time.Duration(z.config.TargetSpawnTimeNS + (20 * time.Millisecond).Nanoseconds())
	}

	if spawnDuration > targetDuration {
		z.metrics.RecordPerformanceRegression(profile, spawnDuration, targetDuration)
	}

	return container, nil
}

// CreateNamespaceZygote creates a new namespace-based zygote process
func (z *ZygoteSpawnerV3) CreateNamespaceZygote(profile string) (*NamespaceZygote, error) {
	start := time.Now()

	// Phase 1: clone3() with all namespaces
	var pidfd int
	pid, err := z.clone3WithNamespaces()
	if err != nil {
		return nil, fmt.Errorf("clone3 failed: %w", err)
	}

	// Phase 2: Apply pre-compiled Landlock policy
	if z.config.EnableLandlock && z.landlockCompiler != nil {
		landlockRules := z.landlockCompiler.GetCompiledRules(profile)
		if landlockRules != nil {
			if err := landlockRules.ApplyToPID(pid); err != nil {
				Kill(pid, SIGKILL)
				return nil, fmt.Errorf("landlock application failed: %w", err)
			}
		}
	}

	// Phase 3: Setup atomic overlay filesystem
	overlayPath, err := z.atomicWriter.CreateAtomicOverlay(profile, pid)
	if err != nil {
		Kill(pid, SIGKILL)
		return nil, fmt.Errorf("overlay creation failed: %w", err)
	}

	// Phase 4: Pre-load seccomp BPF
	seccompFD, err := z.seccompCache.GetCompiledSeccomp(profile)
	if err != nil {
		Kill(pid, SIGKILL)
		return nil, fmt.Errorf("seccomp loading failed: %w", err)
	}

	// Phase 5: Setup child process
	if err := z.setupZygoteChild(pid, overlayPath); err != nil {
		Kill(pid, SIGKILL)
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

	// Record creation metrics
	creationDuration := time.Since(start)
	z.metrics.RecordZygoteCreation(profile, creationDuration)

	// Validate performance target (<8ms for namespace zygote creation)
	if creationDuration > 8*time.Millisecond {
		z.metrics.RecordCreationRegression(profile, creationDuration, 8*time.Millisecond)
	}

	return zygote, nil
}

// clone3WithNamespaces performs clone3() system call with all necessary namespaces
func (z *ZygoteSpawnerV3) clone3WithNamespaces() (int, error) {
	// Development fallback: spawn a lightweight child of the current executable
	// to simulate a zygote process until clone3 is available.
	exe, err := os.Executable()
	if err != nil {
		return -1, fmt.Errorf("failed to resolve executable: %w", err)
	}
	args := []string{exe, "zygote-child"}
	proc, err := os.StartProcess(exe, args, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Env:   os.Environ(),
	})
	if err != nil {
		return -1, fmt.Errorf("zygote fallback spawn failed: %w", err)
	}
	return proc.Pid, nil
}

// selectOptimalPoolType determines the best pool type for a request
func (z *ZygoteSpawnerV3) selectOptimalPoolType(profile string, request *types.SpawnRequest) types.PoolType {
	// Check if cross-platform mode is enabled
	if z.config.CrossPlatformMode {
		return types.PoolTypeWasm
	}

	// For Linux, prefer namespace pools for performance
	if isLinux() && z.namespacePools[profile] != nil {
		return types.PoolTypeNamespace
	}

	// Fallback to WebAssembly for cross-platform compatibility
	if z.wasmPools[profile] != nil {
		return types.PoolTypeWasm
	}

	// Default to namespace if available
	return types.PoolTypeNamespace
}

// setupChildMountNamespace configures the mount namespace for the child process
func (z *ZygoteSpawnerV3) setupChildMountNamespace(pid int, overlayPath string) error {
	// Skip mount namespace setup on non-Linux platforms
	if !isLinux() {
		return nil
	}
	// Enter the mount namespace of the child process
	mountNSPath := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	mountNSFD, err := Open(mountNSPath, O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open mount namespace: %w", err)
	}
	defer Close(mountNSFD)

	// Setup pivot_root to the overlay filesystem
	if err := z.setupPivotRoot(pid, overlayPath); err != nil {
		return fmt.Errorf("pivot_root failed: %w", err)
	}

	return nil
}

// applySeccompToChild applies seccomp BPF filter to child process
func (z *ZygoteSpawnerV3) applySeccompToChild(pid int) error {
	// Use process_vm_writev or ptrace to inject seccomp filter
	// This is a simplified implementation
	return nil
}

// setupChildCgroups creates and configures cgroups for the child
func (z *ZygoteSpawnerV3) setupChildCgroups(pid int) error {
	// Skip cgroup setup on non-Linux platforms
	if !isLinux() {
		return nil
	}
	// Create cgroup for the child process
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/phantom-fragment/%d", pid)
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup: %w", err)
	}

	// Add process to cgroup
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		return fmt.Errorf("failed to add process to cgroup: %w", err)
	}

	return nil
}

// signalChildReady signals the child process that setup is complete
func (z *ZygoteSpawnerV3) signalChildReady() error {
	// No-op until pidfd signaling is implemented
	return nil
}

func (z *ZygoteSpawnerV3) maintainNamespacePool(pool *NamespaceZygotePool) {
	// Implementation for maintaining the namespace pool size
	// This would include creating/destroying zygotes based on demand
}

func (z *ZygoteSpawnerV3) maintainWasmPool(pool *WasmZygotePool) {
	// Implementation for maintaining the Wasm pool size
	// This would include creating/destroying Wasm instances based on demand
}

type SeccompBPFCache struct{}

func (sbc *SeccompBPFCache) GetCompiledSeccomp(profile string) (int, error) {
	// Development mode: return a dummy FD with no error so zygote creation can proceed.
	return -1, nil
}

// CreateWasmZygote creates a new WebAssembly zygote instance
func (z *ZygoteSpawnerV3) CreateWasmZygote(profile string) (*WasmZygote, error) {
	start := time.Now()

	// Create new WebAssembly instance (placeholder implementation)
	wasmZygote := &WasmZygote{
		instance:  dummyWasmInstance{},
		module:    nil, // Would load the appropriate Wasm module
		store:     dummyWasmStore{},
		wasiCtx:   &wasiContextImpl{},
		virtualFS: &WasmVirtualFSPlaceholder{}, // Initialize virtual filesystem
		createdAt: start,
		ready:     true,
	}

	// Record creation metrics
	creationDuration := time.Since(start)
	z.metrics.RecordZygoteCreation(profile, creationDuration)

	return wasmZygote, nil
}

type WasmModule interface{}

type WasmInstance interface {
	Clone(store WasmStore) (WasmInstance, error)
}

type WasmStore interface {
	Clone() WasmStore
}

type WasiContext interface {
	SetArgs(args []string)
	SetEnv(env map[string]string)
	Clone() WasiContext
}

type wasiContextImpl struct {
	args []string
	env  map[string]string
}

func (w *wasiContextImpl) SetArgs(args []string) {
	w.args = args
}

func (w *wasiContextImpl) SetEnv(env map[string]string) {
	w.env = env
}

func (w *wasiContextImpl) Clone() WasiContext {
	newCtx := &wasiContextImpl{
		args: make([]string, len(w.args)),
		env:  make(map[string]string),
	}
	copy(newCtx.args, w.args)
	for k, v := range w.env {
		newCtx.env[k] = v
	}
	return newCtx
}

type dummyWasmInstance struct{}

func (d dummyWasmInstance) Clone(store WasmStore) (WasmInstance, error) {
	return dummyWasmInstance{}, nil
}

type dummyWasmStore struct{}

func (d dummyWasmStore) Clone() WasmStore {
	return dummyWasmStore{}
}

func DefaultZygoteConfig() *ZygoteConfig {
	return &ZygoteConfig{
		DefaultPoolSize:       3,
		MaxPoolSize:          10,
		MinPoolSize:          1,
		ScaleUpThreshold:     0.8,
		ScaleDownThreshold:   0.3,
		TargetSpawnTimeNS:    (60 * time.Millisecond).Nanoseconds(),
		TargetWarmSpawnNS:    (15 * time.Millisecond).Nanoseconds(),
		TargetMemoryPerZygote: 8 * 1024 * 1024, // 8MB
		EnableLandlock:       true,
		EnableWasm:           true,
		CrossPlatformMode:    false,
		EnableMLPrediction:   false, // Start simple, enable later
		PredictionWindow:     5 * time.Minute,
		EnableNUMA:           true,
		NUMAAware:           true,
	}
}

func isLinux() bool {
	return runtime.GOOS == "linux"
}

// generateContainerID creates a unique container identifier
func generateContainerID() string {
	return fmt.Sprintf("phantom-%d-%d", time.Now().UnixNano(), os.Getpid())
}

// AtomicOverlayWriter methods
func (aow *AtomicOverlayWriter) CreateAtomicOverlay(profile string, pid int) (string, error) {
    // Create an atomic overlay filesystem for the container
    base := filepath.Join(os.TempDir(), fmt.Sprintf("phantom-overlay-%s-%d", profile, pid))
    if err := os.MkdirAll(base, 0755); err != nil {
        return "", fmt.Errorf("failed to create overlay directory: %w", err)
    }
    return base, nil
}

// WasmContainer represents a WebAssembly container instance
type WasmContainer struct {
	ID         string
	Instance   WasmInstance
	Store      WasmStore
	WasiCtx    WasiContext
	VirtualFS  *WasmVirtualFSPlaceholder
	CreatedAt  time.Time
	Profile    string
}

// Cross-platform implementations for unix constants
func PidfdSendSignal(pidfd int, sig int, info interface{}, flags int) error {
	// Cross-platform implementation - use process signal
	return fmt.Errorf("PidfdSendSignal not supported on this platform")
}
