package orchestrator

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phantom-fragment/phantom-fragment/pkg/fragments"
	"github.com/phantom-fragment/phantom-fragment/pkg/types"
)

// PSI-aware Fragment Graph Orchestrator for optimal container placement
type PSIAwareOrchestrator struct {
	// PSI monitoring
	psiMonitor      *PSIMonitor
	numaTopology    *NUMATopology
	systemResources *SystemResourceManager

	// Fragment management
	zygoteSpawner *fragments.ZygoteSpawnerV3
	// fragmentPools are managed internally by the ZygoteSpawnerV3.
	loadBalancer *LoadBalancer

	// Scheduling and placement
	scheduler       *IntelligentScheduler
	placementEngine *PlacementEngine
	affinityManager *AffinityManager

	// Performance optimization
	performanceModel *PerformanceModel
	predictionEngine *PredictionEngine
	adaptiveScaler   *AdaptiveScaler

	// Monitoring and metrics
	metrics       *OrchestratorMetrics
	healthChecker *HealthChecker

	// Configuration
	config *OrchestratorConfig

	// Synchronization
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// PSI (Pressure Stall Information) monitoring for system pressure awareness
type PSIMonitor struct {
	// PSI file paths
	cpuPSIPath    string
	memoryPSIPath string
	ioPSIPath     string

	// Current pressure readings
	cpuPressure    *PressureMetrics
	memoryPressure *PressureMetrics
	ioPressure     *PressureMetrics

	// Update frequency
	updateInterval time.Duration
	lastUpdate     time.Time

	mu sync.RWMutex
}

// Pressure metrics from PSI
type PressureMetrics struct {
	Some10    float64 // 10-second average for "some" pressure
	Some60    float64 // 60-second average for "some" pressure
	Some300   float64 // 300-second average for "some" pressure
	Full10    float64 // 10-second average for "full" pressure (CPU doesn't have this)
	Full60    float64 // 60-second average for "full" pressure
	Full300   float64 // 300-second average for "full" pressure
	Total     uint64  // Total stall time in microseconds
	Timestamp time.Time
}

// NUMA topology awareness for optimal placement
type NUMATopology struct {
	nodes           []*NUMANode
	nodeCount       int
	cpuToNode       map[int]int
	memoryDistances [][]int

	// Current utilization
	nodeUtilization map[int]*NodeUtilization

	// Affinity tracking
	processAffinity map[string]int // containerID -> preferred node

	mu sync.RWMutex
}

type NUMANode struct {
	ID          int
	CPUs        []int
	Memory      int64 // Available memory in bytes
	Distance    []int // Distance to other nodes
	Available   bool
	Utilization *NodeUtilization
}

type NodeUtilization struct {
	CPUUsage       float64
	MemoryUsage    int64
	IOLoad         float64
	ContainerCount int
	LastUpdate     time.Time
}

type PoolHealthStatus int

const (
	PoolHealthy PoolHealthStatus = iota
	PoolDegraded
	PoolUnhealthy
	PoolRecovering
)

// Orchestrator configuration
type OrchestratorConfig struct {
	// PSI thresholds
	CPUPressureThreshold    float64
	MemoryPressureThreshold float64
	IOPressureThreshold     float64

	// NUMA settings
	EnableNUMAAffinity   bool
	NUMABalancingEnabled bool
	PreferLocalMemory    bool

	// Pool management
	DefaultPoolSize        int
	MaxPoolSize            int
	PoolScaleUpThreshold   float64
	PoolScaleDownThreshold float64

	// Performance optimization
	EnablePredictiveScaling bool
	PredictionWindow        time.Duration
	AdaptiveThresholds      bool

	// Monitoring
	PSIUpdateInterval     time.Duration
	MetricsUpdateInterval time.Duration
	HealthCheckInterval   time.Duration
}

// NewPSIAwareOrchestrator creates a new PSI-aware orchestrator
func NewPSIAwareOrchestrator(config *OrchestratorConfig, zygoteSpawner *fragments.ZygoteSpawnerV3) (*PSIAwareOrchestrator, error) {
	if config == nil {
		config = &OrchestratorConfig{
			CPUPressureThreshold:    0.8,
			MemoryPressureThreshold: 0.7,
			IOPressureThreshold:     0.6,
			EnableNUMAAffinity:      true,
			DefaultPoolSize:         3,
			MaxPoolSize:             10,
			PSIUpdateInterval:       1 * time.Second,
			MetricsUpdateInterval:   5 * time.Second,
			HealthCheckInterval:     30 * time.Second,
		}
	}

	orchestrator := &PSIAwareOrchestrator{
		config:        config,
		zygoteSpawner: zygoteSpawner,
		// fragmentPools are managed internally by the ZygoteSpawnerV3.
		shutdown: make(chan struct{}),
	}

	// Initialize PSI monitor
	var err error
	orchestrator.psiMonitor, err = NewPSIMonitor(config.PSIUpdateInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PSI monitor: %w", err)
	}

	// Initialize NUMA topology
	orchestrator.numaTopology, err = NewNUMATopology()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize NUMA topology: %w", err)
	}

	// Initialize other components
	orchestrator.systemResources = NewSystemResourceManager()
	orchestrator.loadBalancer = NewLoadBalancer(orchestrator.numaTopology)
	orchestrator.scheduler = NewIntelligentScheduler(orchestrator.psiMonitor, orchestrator.numaTopology)
	orchestrator.placementEngine = NewPlacementEngine(orchestrator.numaTopology)
	orchestrator.affinityManager = NewAffinityManager()
	orchestrator.performanceModel = NewPerformanceModel()
	orchestrator.predictionEngine = NewPredictionEngine()
	orchestrator.adaptiveScaler = NewAdaptiveScaler(config)
	orchestrator.metrics = NewOrchestratorMetrics()
	orchestrator.healthChecker = NewHealthChecker()

	return orchestrator, nil
}

// SpawnContainer spawns a container with PSI-aware placement
func (o *PSIAwareOrchestrator) SpawnContainer(ctx context.Context, profile string, request *types.SpawnRequest) (*types.Container, error) {
	start := time.Now()

	// Phase 1: Check system pressure and capacity
	if err := o.checkSystemCapacity(); err != nil {
		return nil, fmt.Errorf("system capacity check failed: %w", err)
	}

	// Phase 2: Select optimal NUMA node
	targetNode, err := o.selectOptimalNode(profile, request)
	if err != nil {
		return nil, fmt.Errorf("NUMA node selection failed: %w", err)
	}

	// Phase 3: Spawning is handled by the ZygoteSpawner, which manages pools internally.

	// Phase 4: Spawn container from pool
	container, err := o.zygoteSpawner.SpawnFromPool(ctx, profile, request)
	if err != nil {
		return nil, fmt.Errorf("container spawn failed: %w", err)
	}

	// Phase 5: Apply NUMA affinity
	if o.config.EnableNUMAAffinity {
		if err := o.applyNUMAAffinity(container, targetNode); err != nil {
			// Log warning but don't fail the spawn
			fmt.Printf("Warning: NUMA affinity application failed: %v\n", err)
		}
	}

	// Phase 6: Update metrics and tracking
	spawnDuration := time.Since(start)
	o.metrics.RecordContainerSpawn(profile, targetNode, spawnDuration)
	// Pool metrics are now handled internally by the ZygoteSpawner.

	return container, nil
}

// checkSystemCapacity checks if system has capacity for new containers
func (o *PSIAwareOrchestrator) checkSystemCapacity() error {
	o.psiMonitor.mu.RLock()
	defer o.psiMonitor.mu.RUnlock()

	// Check CPU pressure
	if o.psiMonitor.cpuPressure.Some10 > o.config.CPUPressureThreshold {
		return fmt.Errorf("high CPU pressure: %.2f > %.2f",
			o.psiMonitor.cpuPressure.Some10, o.config.CPUPressureThreshold)
	}

	// Check memory pressure
	if o.psiMonitor.memoryPressure.Some10 > o.config.MemoryPressureThreshold {
		return fmt.Errorf("high memory pressure: %.2f > %.2f",
			o.psiMonitor.memoryPressure.Some10, o.config.MemoryPressureThreshold)
	}

	// Check I/O pressure
	if o.psiMonitor.ioPressure.Some10 > o.config.IOPressureThreshold {
		return fmt.Errorf("high I/O pressure: %.2f > %.2f",
			o.psiMonitor.ioPressure.Some10, o.config.IOPressureThreshold)
	}

	return nil
}

// selectOptimalNode selects the best NUMA node for container placement
func (o *PSIAwareOrchestrator) selectOptimalNode(profile string, request *types.SpawnRequest) (int, error) {
	o.numaTopology.mu.RLock()
	defer o.numaTopology.mu.RUnlock()

	bestNode := -1
	bestScore := float64(-1)

	for _, node := range o.numaTopology.nodes {
		if !node.Available {
			continue
		}

		score := o.calculateNodeScore(node, profile, request)
		if score > bestScore {
			bestScore = score
			bestNode = node.ID
		}
	}

	if bestNode == -1 {
		return 0, fmt.Errorf("no available NUMA node found")
	}

	return bestNode, nil
}

// calculateNodeScore calculates placement score for a NUMA node
func (o *PSIAwareOrchestrator) calculateNodeScore(node *NUMANode, profile string, _ *types.SpawnRequest) float64 {
	utilization := node.Utilization

	// Base score from resource utilization (lower is better)
	cpuScore := 1.0 - utilization.CPUUsage
	memoryScore := 1.0 - float64(utilization.MemoryUsage)/float64(node.Memory)
	ioScore := 1.0 - utilization.IOLoad

	// Container density penalty (avoid overloading nodes)
	densityScore := 1.0 - float64(utilization.ContainerCount)/20.0 // Assume max 20 containers per node

	// Profile affinity bonus (prefer nodes that have run this profile before)
	affinityScore := 0.0
	if o.hasProfileAffinity(node.ID, profile) {
		affinityScore = 0.2
	}

	// Weighted final score
	finalScore := (cpuScore*0.3 + memoryScore*0.3 + ioScore*0.2 + densityScore*0.1 + affinityScore*0.1)

	return finalScore
}

// Start starts the orchestrator background processes
func (o *PSIAwareOrchestrator) Start(ctx context.Context) error {
	// Start PSI monitoring
	o.wg.Add(1)
	go o.psiMonitorLoop(ctx)

	// Start NUMA utilization tracking
	o.wg.Add(1)
	go o.numaUtilizationLoop(ctx)

	// The poolManagementLoop is now handled internally by the ZygoteSpawnerV3.

	// Start health checking
	o.wg.Add(1)
	go o.healthCheckLoop(ctx)

	// Start metrics collection
	o.wg.Add(1)
	go o.metricsLoop(ctx)

	return nil
}

// psiMonitorLoop continuously monitors PSI metrics
func (o *PSIAwareOrchestrator) psiMonitorLoop(ctx context.Context) {
	defer o.wg.Done()

	ticker := time.NewTicker(o.config.PSIUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-o.shutdown:
			return
		case <-ticker.C:
			if err := o.psiMonitor.UpdateMetrics(); err != nil {
				fmt.Printf("PSI update error: %v\n", err)
			}
		}
	}
}

// NewPSIMonitor creates a new PSI monitor
func NewPSIMonitor(updateInterval time.Duration) (*PSIMonitor, error) {
	monitor := &PSIMonitor{
		cpuPSIPath:     "/proc/pressure/cpu",
		memoryPSIPath:  "/proc/pressure/memory",
		ioPSIPath:      "/proc/pressure/io",
		updateInterval: updateInterval,
		cpuPressure:    &PressureMetrics{},
		memoryPressure: &PressureMetrics{},
		ioPressure:     &PressureMetrics{},
	}

	// Check if PSI is available
	if _, err := os.Stat(monitor.cpuPSIPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("PSI not available on this system")
	}

	// Initial metrics update
	if err := monitor.UpdateMetrics(); err != nil {
		return nil, fmt.Errorf("initial PSI metrics update failed: %w", err)
	}

	return monitor, nil
}

// UpdateMetrics updates PSI pressure metrics
func (m *PSIMonitor) UpdateMetrics() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Update CPU pressure
	if err := m.updatePressureFile(m.cpuPSIPath, m.cpuPressure, false); err != nil {
		return fmt.Errorf("CPU pressure update failed: %w", err)
	}

	// Update memory pressure
	if err := m.updatePressureFile(m.memoryPSIPath, m.memoryPressure, true); err != nil {
		return fmt.Errorf("memory pressure update failed: %w", err)
	}

	// Update I/O pressure
	if err := m.updatePressureFile(m.ioPSIPath, m.ioPressure, true); err != nil {
		return fmt.Errorf("I/O pressure update failed: %w", err)
	}

	m.lastUpdate = time.Now()
	return nil
}

// updatePressureFile reads and parses a PSI pressure file
func (m *PSIMonitor) updatePressureFile(path string, metrics *PressureMetrics, hasFull bool) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")

	// Parse "some" line
	if len(lines) > 0 {
		if err := m.parsePressureLine(lines[0], "some", metrics, false); err != nil {
			return fmt.Errorf("failed to parse 'some' line: %w", err)
		}
	}

	// Parse "full" line if available (CPU doesn't have full pressure)
	if hasFull && len(lines) > 1 {
		if err := m.parsePressureLine(lines[1], "full", metrics, true); err != nil {
			return fmt.Errorf("failed to parse 'full' line: %w", err)
		}
	}

	metrics.Timestamp = time.Now()
	return nil
}

// parsePressureLine parses a single PSI pressure line
func (m *PSIMonitor) parsePressureLine(line, prefix string, metrics *PressureMetrics, isFull bool) error {
	// Example line: "some avg10=0.14 avg60=0.17 avg300=0.20 total=12345678"
	if !strings.HasPrefix(line, prefix) {
		return fmt.Errorf("unexpected line prefix: %s", line)
	}

	parts := strings.Fields(line)
	if len(parts) < 4 {
		return fmt.Errorf("insufficient parts in line: %s", line)
	}

	for _, part := range parts[1:] {
		if strings.HasPrefix(part, "avg10=") {
			val, err := strconv.ParseFloat(strings.TrimPrefix(part, "avg10="), 64)
			if err != nil {
				return fmt.Errorf("failed to parse avg10: %w", err)
			}
			if isFull {
				metrics.Full10 = val
			} else {
				metrics.Some10 = val
			}
		} else if strings.HasPrefix(part, "avg60=") {
			val, err := strconv.ParseFloat(strings.TrimPrefix(part, "avg60="), 64)
			if err != nil {
				return fmt.Errorf("failed to parse avg60: %w", err)
			}
			if isFull {
				metrics.Full60 = val
			} else {
				metrics.Some60 = val
			}
		} else if strings.HasPrefix(part, "avg300=") {
			val, err := strconv.ParseFloat(strings.TrimPrefix(part, "avg300="), 64)
			if err != nil {
				return fmt.Errorf("failed to parse avg300: %w", err)
			}
			if isFull {
				metrics.Full300 = val
			} else {
				metrics.Some300 = val
			}
		} else if strings.HasPrefix(part, "total=") {
			val, err := strconv.ParseUint(strings.TrimPrefix(part, "total="), 10, 64)
			if err != nil {
				return fmt.Errorf("failed to parse total: %w", err)
			}
			metrics.Total = val
		}
	}

	return nil
}

// Placeholder implementations for other components
func NewNUMATopology() (*NUMATopology, error)          { return &NUMATopology{}, nil }
func NewSystemResourceManager() *SystemResourceManager { return &SystemResourceManager{} }
func NewLoadBalancer(numa *NUMATopology) *LoadBalancer { return &LoadBalancer{} }
func NewIntelligentScheduler(psi *PSIMonitor, numa *NUMATopology) *IntelligentScheduler {
	return &IntelligentScheduler{}
}
func NewPlacementEngine(numa *NUMATopology) *PlacementEngine       { return &PlacementEngine{} }
func NewAffinityManager() *AffinityManager                         { return &AffinityManager{} }
func NewPerformanceModel() *PerformanceModel                       { return &PerformanceModel{} }
func NewPredictionEngine() *PredictionEngine                       { return &PredictionEngine{} }
func NewAdaptiveScaler(config *OrchestratorConfig) *AdaptiveScaler { return &AdaptiveScaler{} }
func NewOrchestratorMetrics() *OrchestratorMetrics                 { return &OrchestratorMetrics{} }
func NewHealthChecker() *HealthChecker                             { return &HealthChecker{} }

// Placeholder types and methods
type SystemResourceManager struct{}
type LoadBalancer struct{}
type IntelligentScheduler struct{}
type PlacementEngine struct{}
type AffinityManager struct{}
type PerformanceModel struct{}
type PredictionEngine struct{}
type AdaptiveScaler struct{}
type OrchestratorMetrics struct{}
type HealthChecker struct{}
type PressureHistory struct{}
type TrendAnalyzer struct{}
type PressureThresholds struct{}
type AlertManager struct{}

func (o *PSIAwareOrchestrator) applyNUMAAffinity(_ *types.Container, _ int) error {
	return nil
}
func (o *PSIAwareOrchestrator) hasProfileAffinity(_ int, _ string) bool { return false }
func (o *PSIAwareOrchestrator) numaUtilizationLoop(ctx context.Context) {}
func (o *PSIAwareOrchestrator) healthCheckLoop(ctx context.Context)     {}
func (o *PSIAwareOrchestrator) metricsLoop(ctx context.Context)         {}
func (m *OrchestratorMetrics) RecordContainerSpawn(profile string, node int, duration time.Duration) {
}
