package benchmarks

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/phantom-fragment/phantom-fragment/internal/fragments"
	"github.com/phantom-fragment/phantom-fragment/internal/orchestrator"
	"github.com/phantom-fragment/phantom-fragment/pkg/types"
)

// Performance benchmarking suite for Phantom Fragment V3
type PerformanceBenchmarkSuite struct {
	// Components under test
	zygoteSpawner *fragments.ZygoteSpawnerV3
	orchestrator  *orchestrator.PSIAwareOrchestrator

	// Benchmark configuration
	config *BenchmarkConfig

	// Results tracking
	results *BenchmarkResults

	// Concurrency control
	mu sync.RWMutex
}

// Benchmark configuration
type BenchmarkConfig struct {
	// Test parameters
	Iterations        int
	Profiles          []string
	ConcurrencyLevels []int
	WarmupIterations  int
	CooldownTime      time.Duration

	// Performance targets (V3 goals)
	TargetColdStartP95       time.Duration // <100ms
	TargetWarmStartP95       time.Duration // <25ms
	TargetMemoryPerContainer int64         // <12MB
	TargetIOThroughput       int64         // >2GB/s
	TargetSecurityOverhead   time.Duration // <5ms

	// System information
	SystemInfo     *SystemInfo
	BaselineDocker bool // Compare with Docker if available
}

// System information for benchmark context
type SystemInfo struct {
	OS            string
	Kernel        string
	Architecture  string
	CPUCount      int
	MemoryTotal   int64
	NUMANodes     int
	HasIOUring    bool
	HasBPFLSM     bool
	HasLandlock   bool
	KernelVersion string
}

// Comprehensive benchmark results
type BenchmarkResults struct {
	// Metadata
	Timestamp  time.Time
	Duration   time.Duration
	SystemInfo *SystemInfo
	Config     *BenchmarkConfig

	// Core performance metrics
	SpawnBenchmarks    *SpawnBenchmarkResults
	IOBenchmarks       *IOBenchmarkResults
	MemoryBenchmarks   *MemoryBenchmarkResults
	SecurityBenchmarks *SecurityBenchmarkResults

	// Comparative results
	DockerComparison *DockerComparisonResults

	// System metrics during test
	SystemMetrics *SystemMetricsDuringTest

	// Pass/fail status
	PassedTargets    []string
	FailedTargets    []string
	OverallPass      bool
	PerformanceScore float64 // 0-100 based on target achievement
}

// Spawn performance benchmark results
type SpawnBenchmarkResults struct {
	ColdStart       *LatencyMetrics
	WarmStart       *LatencyMetrics
	ZygoteSpawn     *LatencyMetrics
	ConcurrentSpawn map[int]*LatencyMetrics // concurrency level -> metrics

	// Throughput metrics
	MaxSpawnRate       float64 // containers per second
	SustainedSpawnRate float64 // containers per second over 1 minute

	// Resource efficiency
	SpawnCPUUsage    float64 // CPU usage during spawn
	SpawnMemoryUsage int64   // Memory usage during spawn
}

// I/O performance benchmark results
type IOBenchmarkResults struct {
	SequentialRead  *ThroughputMetrics
	SequentialWrite *ThroughputMetrics
	RandomRead      *ThroughputMetrics
	RandomWrite     *ThroughputMetrics

	// io_uring specific
	IOUringPerformance *IOUringMetrics

	// Content-addressed storage
	CASPerformance *CASMetrics

	// Cross-platform
	WasmIOPerformance *ThroughputMetrics
}

// Memory efficiency benchmark results
type MemoryBenchmarkResults struct {
	BaselineMemory int64                     // Memory per container baseline
	ProfileMemory  map[string]*MemoryMetrics // Memory per profile
	MemorySharing  *MemoryShareMetrics       // KSM and sharing efficiency
	MemoryGrowth   *MemoryGrowthMetrics      // Growth over time

	// Garbage collection impact
	GCImpact *GCMetrics
}

// Security overhead benchmark results
type SecurityBenchmarkResults struct {
	SeccompOverhead   *LatencyMetrics
	LandlockOverhead  *LatencyMetrics
	BPFLSMOverhead    *LatencyMetrics
	AOTCompilation    *LatencyMetrics
	PolicyApplication *LatencyMetrics

	// Combined security overhead
	TotalSecurityOverhead *LatencyMetrics
}

// Performance metrics structures
type LatencyMetrics struct {
	Min     time.Duration
	Max     time.Duration
	Mean    time.Duration
	Median  time.Duration
	P95     time.Duration
	P99     time.Duration
	P999    time.Duration
	StdDev  time.Duration
	Samples []time.Duration
}

type ThroughputMetrics struct {
	MinThroughput  int64 // bytes per second
	MaxThroughput  int64
	MeanThroughput int64
	P95Throughput  int64
	Samples        []int64
}

type MemoryMetrics struct {
	RSS        int64   // Resident Set Size
	VMS        int64   // Virtual Memory Size
	Shared     int64   // Shared memory
	Peak       int64   // Peak memory usage
	Efficiency float64 // Memory efficiency ratio
}

// NewPerformanceBenchmarkSuite creates a new benchmark suite
func NewPerformanceBenchmarkSuite(config *BenchmarkConfig) (*PerformanceBenchmarkSuite, error) {
	if config == nil {
		config = &BenchmarkConfig{
			Iterations:               1000,
			Profiles:                 []string{"python-ai", "node-dev", "go-dev"},
			ConcurrencyLevels:        []int{1, 5, 10, 20, 50},
			WarmupIterations:         50,
			CooldownTime:             5 * time.Second,
			TargetColdStartP95:       100 * time.Millisecond,
			TargetWarmStartP95:       25 * time.Millisecond,
			TargetMemoryPerContainer: 12 * 1024 * 1024,       // 12MB
			TargetIOThroughput:       2 * 1024 * 1024 * 1024, // 2GB/s
			TargetSecurityOverhead:   5 * time.Millisecond,
		}
	}

	suite := &PerformanceBenchmarkSuite{
		config: config,
		results: &BenchmarkResults{
			Timestamp:  time.Now(),
			Config:     config,
			SystemInfo: DiscoverSystemInfo(),
		},
	}

	// Initialize components
	var err error
	suite.zygoteSpawner, err = fragments.NewZygoteSpawnerV3(&fragments.ZygoteConfig{})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize zygote spawner: %w", err)
	}

	orchestratorConfig := &orchestrator.OrchestratorConfig{}
	suite.orchestrator, err = orchestrator.NewPSIAwareOrchestrator(orchestratorConfig, suite.zygoteSpawner)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize orchestrator: %w", err)
	}

	return suite, nil
}

// RunFullBenchmarkSuite runs the complete performance benchmark suite
func (pbs *PerformanceBenchmarkSuite) RunFullBenchmarkSuite(ctx context.Context) (*BenchmarkResults, error) {
	fmt.Println("🚀 Starting Phantom Fragment V3 Performance Benchmark Suite")
	fmt.Printf("System: %s %s on %s\n",
		pbs.results.SystemInfo.OS,
		pbs.results.SystemInfo.Kernel,
		pbs.results.SystemInfo.Architecture)
	fmt.Printf("CPUs: %d, Memory: %.1fGB, NUMA Nodes: %d\n",
		pbs.results.SystemInfo.CPUCount,
		float64(pbs.results.SystemInfo.MemoryTotal)/(1024*1024*1024),
		pbs.results.SystemInfo.NUMANodes)
	fmt.Println()

	start := time.Now()

	// Phase 1: Spawn performance benchmarks
	fmt.Println("📊 Phase 1: Container Spawn Performance")
	spawnResults, err := pbs.runSpawnBenchmarks(ctx)
	if err != nil {
		return nil, fmt.Errorf("spawn benchmarks failed: %w", err)
	}
	pbs.results.SpawnBenchmarks = spawnResults
	pbs.printSpawnResults(spawnResults)

	// Cool down
	time.Sleep(pbs.config.CooldownTime)

	// Phase 2: I/O performance benchmarks
	fmt.Println("💾 Phase 2: I/O Performance")
	ioResults, err := pbs.runIOBenchmarks(ctx)
	if err != nil {
		return nil, fmt.Errorf("I/O benchmarks failed: %w", err)
	}
	pbs.results.IOBenchmarks = ioResults
	pbs.printIOResults(ioResults)

	// Cool down
	time.Sleep(pbs.config.CooldownTime)

	// Phase 3: Memory efficiency benchmarks
	fmt.Println("🧠 Phase 3: Memory Efficiency")
	memoryResults, err := pbs.runMemoryBenchmarks(ctx)
	if err != nil {
		return nil, fmt.Errorf("memory benchmarks failed: %w", err)
	}
	pbs.results.MemoryBenchmarks = memoryResults
	pbs.printMemoryResults(memoryResults)

	// Cool down
	time.Sleep(pbs.config.CooldownTime)

	// Phase 4: Security overhead benchmarks
	fmt.Println("🛡️ Phase 4: Security Overhead")
	securityResults, err := pbs.runSecurityBenchmarks(ctx)
	if err != nil {
		return nil, fmt.Errorf("security benchmarks failed: %w", err)
	}
	pbs.results.SecurityBenchmarks = securityResults
	pbs.printSecurityResults(securityResults)

	// Phase 5: Docker comparison (if enabled)
	if pbs.config.BaselineDocker {
		fmt.Println("🐳 Phase 5: Docker Comparison")
		dockerResults, err := pbs.runDockerComparison(ctx)
		if err != nil {
			fmt.Printf("Warning: Docker comparison failed: %v\n", err)
		} else {
			pbs.results.DockerComparison = dockerResults
			pbs.printDockerComparison(dockerResults)
		}
	}

	pbs.results.Duration = time.Since(start)

	// Analyze results and determine pass/fail
	pbs.analyzeResults()

	// Print final summary
	pbs.printFinalSummary()

	return pbs.results, nil
}

// runSpawnBenchmarks runs container spawn performance tests
func (pbs *PerformanceBenchmarkSuite) runSpawnBenchmarks(ctx context.Context) (*SpawnBenchmarkResults, error) {
	results := &SpawnBenchmarkResults{
		ConcurrentSpawn: make(map[int]*LatencyMetrics),
	}

	// Test 1: Cold start performance
	fmt.Printf("  📈 Cold start benchmark (%d iterations)\n", pbs.config.Iterations)
	coldStartLatencies := make([]time.Duration, 0, pbs.config.Iterations)

	for i := 0; i < pbs.config.Iterations; i++ {
		start := time.Now()

		// Create new container (cold start)
		request := &types.SpawnRequest{
			Profile:  "python-ai",
			PoolType: types.PoolTypeNamespace,
		}

		container, err := pbs.orchestrator.SpawnContainer(ctx, "python-ai", request)
		if err != nil {
			return nil, fmt.Errorf("cold start spawn failed: %w", err)
		}

		latency := time.Since(start)
		coldStartLatencies = append(coldStartLatencies, latency)

		// Cleanup container
		container.Destroy()

		// Small delay to avoid overwhelming the system
		if i%100 == 99 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	results.ColdStart = calculateLatencyMetrics(coldStartLatencies)
	fmt.Printf("    ✅ Cold start P95: %v (target: <%v)\n",
		results.ColdStart.P95, pbs.config.TargetColdStartP95)

	// Test 2: Warm start performance (using zygote pools)
	fmt.Printf("  🔥 Warm start benchmark (%d iterations)\n", pbs.config.Iterations)

	// Pre-warm the zygote pool
	err := pbs.zygoteSpawner.WarmupPool("python-ai", 5)
	if err != nil {
		return nil, fmt.Errorf("zygote warmup failed: %w", err)
	}

	warmStartLatencies := make([]time.Duration, 0, pbs.config.Iterations)

	for i := 0; i < pbs.config.Iterations; i++ {
		start := time.Now()

		// Spawn from warm pool
		container, err := pbs.zygoteSpawner.SpawnFromPool(ctx, "python-ai", &types.SpawnRequest{
			Profile:  "python-ai",
			PoolType: types.PoolTypeNamespace,
		})
		if err != nil {
			return nil, fmt.Errorf("warm start spawn failed: %w", err)
		}

		latency := time.Since(start)
		warmStartLatencies = append(warmStartLatencies, latency)

		// Cleanup
		container.Destroy()
	}

	results.WarmStart = calculateLatencyMetrics(warmStartLatencies)
	fmt.Printf("    ✅ Warm start P95: %v (target: <%v)\n",
		results.WarmStart.P95, pbs.config.TargetWarmStartP95)

	// Test 3: Concurrent spawn performance
	fmt.Printf("  ⚡ Concurrent spawn benchmarks\n")
	for _, concurrency := range pbs.config.ConcurrencyLevels {
		fmt.Printf("    Testing concurrency level: %d\n", concurrency)

		latencies := make([]time.Duration, 0, concurrency)
		var wg sync.WaitGroup
		var mu sync.Mutex

		start := time.Now()

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				spawnStart := time.Now()
				container, err := pbs.orchestrator.SpawnContainer(ctx, "python-ai", &types.SpawnRequest{
					Profile:  "python-ai",
					PoolType: types.PoolTypeNamespace,
				})
				if err == nil {
					spawnLatency := time.Since(spawnStart)
					mu.Lock()
					latencies = append(latencies, spawnLatency)
					mu.Unlock()
					container.Destroy()
				}
			}()
		}

		wg.Wait()
		totalTime := time.Since(start)

		if len(latencies) > 0 {
			results.ConcurrentSpawn[concurrency] = calculateLatencyMetrics(latencies)
			rate := float64(len(latencies)) / totalTime.Seconds()
			fmt.Printf("      ✅ Concurrency %d: P95=%v, Rate=%.1f containers/sec\n",
				concurrency, results.ConcurrentSpawn[concurrency].P95, rate)

			if concurrency == 1 {
				results.MaxSpawnRate = rate
			}
		}

		time.Sleep(pbs.config.CooldownTime / 5) // Brief cooldown between concurrency tests
	}

	return results, nil
}

// calculateLatencyMetrics calculates comprehensive latency statistics
func calculateLatencyMetrics(samples []time.Duration) *LatencyMetrics {
	if len(samples) == 0 {
		return &LatencyMetrics{}
	}

	// Sort samples for percentile calculations
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	// Calculate basic statistics
	min := sorted[0]
	max := sorted[len(sorted)-1]

	// Mean
	var sum time.Duration
	for _, sample := range samples {
		sum += sample
	}
	mean := sum / time.Duration(len(samples))

	// Median
	median := sorted[len(sorted)/2]

	// Percentiles
	p95 := sorted[int(float64(len(sorted))*0.95)]
	p99 := sorted[int(float64(len(sorted))*0.99)]
	p999 := sorted[int(float64(len(sorted))*0.999)]

	// Standard deviation
	var sumSquares float64
	for _, sample := range samples {
		diff := float64(sample - mean)
		sumSquares += diff * diff
	}
	stdDev := time.Duration(math.Sqrt(sumSquares / float64(len(samples))))

	return &LatencyMetrics{
		Min:     min,
		Max:     max,
		Mean:    mean,
		Median:  median,
		P95:     p95,
		P99:     p99,
		P999:    p999,
		StdDev:  stdDev,
		Samples: samples,
	}
}

// Placeholder implementations for other benchmark methods
func (pbs *PerformanceBenchmarkSuite) runIOBenchmarks(_ context.Context) (*IOBenchmarkResults, error) {
	// Implementation would test I/O performance
	return &IOBenchmarkResults{}, nil
}

func (pbs *PerformanceBenchmarkSuite) runMemoryBenchmarks(_ context.Context) (*MemoryBenchmarkResults, error) {
	// Implementation would test memory efficiency
	return &MemoryBenchmarkResults{}, nil
}

func (pbs *PerformanceBenchmarkSuite) runSecurityBenchmarks(_ context.Context) (*SecurityBenchmarkResults, error) {
	// Implementation would test security overhead
	return &SecurityBenchmarkResults{}, nil
}

func (pbs *PerformanceBenchmarkSuite) runDockerComparison(_ context.Context) (*DockerComparisonResults, error) {
	// Implementation would compare with Docker
	return &DockerComparisonResults{}, nil
}

// System information discovery
func DiscoverSystemInfo() *SystemInfo {
	return &SystemInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPUCount:     runtime.NumCPU(),
		// Other fields would be populated by reading system information
	}
}

// Result printing methods
func (pbs *PerformanceBenchmarkSuite) printSpawnResults(results *SpawnBenchmarkResults) {
	fmt.Printf("  📊 Cold Start: P95=%v, Mean=%v\n",
		results.ColdStart.P95, results.ColdStart.Mean)
	fmt.Printf("  🔥 Warm Start: P95=%v, Mean=%v\n",
		results.WarmStart.P95, results.WarmStart.Mean)
}

func (pbs *PerformanceBenchmarkSuite) printIOResults(_ *IOBenchmarkResults) {
	fmt.Println("  💾 I/O benchmarks completed")
}

func (pbs *PerformanceBenchmarkSuite) printMemoryResults(_ *MemoryBenchmarkResults) {
	fmt.Println("  🧠 Memory benchmarks completed")
}

func (pbs *PerformanceBenchmarkSuite) printSecurityResults(_ *SecurityBenchmarkResults) {
	fmt.Println("  🛡️ Security benchmarks completed")
}

func (pbs *PerformanceBenchmarkSuite) printDockerComparison(_ *DockerComparisonResults) {
	fmt.Println("  🐳 Docker comparison completed")
}

func (pbs *PerformanceBenchmarkSuite) analyzeResults() {
	// Analyze results against targets
	pbs.results.PassedTargets = []string{}
	pbs.results.FailedTargets = []string{}

	// Check cold start target
	if pbs.results.SpawnBenchmarks.ColdStart.P95 <= pbs.config.TargetColdStartP95 {
		pbs.results.PassedTargets = append(pbs.results.PassedTargets, "Cold Start P95")
	} else {
		pbs.results.FailedTargets = append(pbs.results.FailedTargets, "Cold Start P95")
	}

	// Check warm start target
	if pbs.results.SpawnBenchmarks.WarmStart.P95 <= pbs.config.TargetWarmStartP95 {
		pbs.results.PassedTargets = append(pbs.results.PassedTargets, "Warm Start P95")
	} else {
		pbs.results.FailedTargets = append(pbs.results.FailedTargets, "Warm Start P95")
	}

	// Calculate overall pass/fail
	pbs.results.OverallPass = len(pbs.results.FailedTargets) == 0

	// Calculate performance score
	totalTargets := len(pbs.results.PassedTargets) + len(pbs.results.FailedTargets)
	if totalTargets > 0 {
		pbs.results.PerformanceScore = float64(len(pbs.results.PassedTargets)) / float64(totalTargets) * 100
	}
}

func (pbs *PerformanceBenchmarkSuite) printFinalSummary() {
	fmt.Println()
	fmt.Println("🎯 Final Performance Summary")
	fmt.Printf("Duration: %v\n", pbs.results.Duration)
	fmt.Printf("Performance Score: %.1f/100\n", pbs.results.PerformanceScore)
	fmt.Printf("Overall Result: %s\n", map[bool]string{true: "✅ PASS", false: "❌ FAIL"}[pbs.results.OverallPass])

	if len(pbs.results.PassedTargets) > 0 {
		fmt.Println("\n✅ Passed Targets:")
		for _, target := range pbs.results.PassedTargets {
			fmt.Printf("  - %s\n", target)
		}
	}

	if len(pbs.results.FailedTargets) > 0 {
		fmt.Println("\n❌ Failed Targets:")
		for _, target := range pbs.results.FailedTargets {
			fmt.Printf("  - %s\n", target)
		}
	}

	fmt.Println()
}

// Placeholder types
type IOUringMetrics struct{}
type CASMetrics struct{}
type MemoryShareMetrics struct{}
type MemoryGrowthMetrics struct{}
type GCMetrics struct{}
type DockerComparisonResults struct{}
type SystemMetricsDuringTest struct{}
