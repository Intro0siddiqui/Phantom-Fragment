package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/phantom-fragment/phantom-fragment/internal/benchmarks"
)

// Phantom Fragment Performance Benchmark CLI
func main() {
	var (
		iterations    = flag.Int("iterations", 1000, "Number of iterations for each benchmark")
		profiles      = flag.String("profiles", "python-ai,node-dev,go-dev", "Comma-separated list of profiles to test")
		concurrency   = flag.String("concurrency", "1,5,10,20", "Comma-separated list of concurrency levels")
		output        = flag.String("output", "", "Output file for benchmark results (JSON)")
		compareDocker = flag.Bool("compare-docker", false, "Compare performance with Docker")
		warmup        = flag.Int("warmup", 50, "Number of warmup iterations")
		verbose       = flag.Bool("verbose", false, "Enable verbose output")
		targets       = flag.Bool("show-targets", false, "Show performance targets and exit")
		system        = flag.Bool("system-check", false, "Check system capabilities and exit")
	)
	flag.Parse()

	// Show performance targets
	if *targets {
		showPerformanceTargets()
		return
	}

	// System capability check
	if *system {
		checkSystemCapabilities()
		return
	}

	// Print banner
	printBanner()

	// Parse configuration
	config := &benchmarks.BenchmarkConfig{
		Iterations:               *iterations,
		Profiles:                parseProfiles(*profiles),
		ConcurrencyLevels:       parseConcurrencyLevels(*concurrency),
		WarmupIterations:        *warmup,
		CooldownTime:           5 * time.Second,
		BaselineDocker:         *compareDocker,
		TargetColdStartP95:     100 * time.Millisecond,
		TargetWarmStartP95:     25 * time.Millisecond,
		TargetMemoryPerContainer: 12 * 1024 * 1024, // 12MB
		TargetIOThroughput:     2 * 1024 * 1024 * 1024, // 2GB/s
		TargetSecurityOverhead: 5 * time.Millisecond,
	}

	if *verbose {
		fmt.Printf("Configuration:\n")
		fmt.Printf("  Iterations: %d\n", config.Iterations)
		fmt.Printf("  Profiles: %v\n", config.Profiles)
		fmt.Printf("  Concurrency Levels: %v\n", config.ConcurrencyLevels)
		fmt.Printf("  Warmup Iterations: %d\n", config.WarmupIterations)
		fmt.Printf("  Compare Docker: %v\n", config.BaselineDocker)
		fmt.Println()
	}

	// Create benchmark suite
	suite, err := benchmarks.NewPerformanceBenchmarkSuite(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create benchmark suite: %v\n", err)
		os.Exit(1)
	}

	// Run benchmarks
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	fmt.Println("🚀 Starting Phantom Fragment V3 Performance Benchmarks...")
	fmt.Printf("Estimated duration: %v\n", estimateDuration(config))
	fmt.Println()

	results, err := suite.RunFullBenchmarkSuite(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Benchmark suite failed: %v\n", err)
		os.Exit(1)
	}

	// Save results to file if specified
	if *output != "" {
		if err := saveResults(results, *output); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save results: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("📊 Results saved to: %s\n", *output)
	}

	// Exit with appropriate code
	if results.OverallPass {
		fmt.Println("🎉 All performance targets met!")
		os.Exit(0)
	} else {
		fmt.Println("⚠️ Some performance targets not met")
		os.Exit(1)
	}
}

func printBanner() {
	fmt.Println(`
┌─────────────────────────────────────────────────────────────┐
│                 Phantom Fragment V3                        │
│            Performance Benchmark Suite                     │
│                                                            │
│  🎯 Targets: <100ms spawn, <12MB memory, >2GB/s I/O       │
│  🚀 Features: Zygote spawning, PSI awareness, io_uring    │
│  🛡️ Security: BPF-LSM, Landlock, AOT compilation         │
└─────────────────────────────────────────────────────────────┘
`)
}

func showPerformanceTargets() {
	fmt.Println("🎯 Phantom Fragment V3 Performance Targets")
	fmt.Println()
	fmt.Println("Container Spawn Performance:")
	fmt.Println("  • Cold Start P95: <100ms (vs Docker ~400-800ms)")
	fmt.Println("  • Warm Start P95: <25ms (vs Docker ~200-400ms)")
	fmt.Println("  • Zygote Spawn P95: <15ms")
	fmt.Println()
	fmt.Println("Memory Efficiency:")
	fmt.Println("  • Memory per Container: <12MB (vs Docker ~80-150MB)")
	fmt.Println("  • Memory Sharing: >60% deduplication")
	fmt.Println("  • Memory Growth: <5% over 1 hour")
	fmt.Println()
	fmt.Println("I/O Performance:")
	fmt.Println("  • Sequential Read: >2.5GB/s")
	fmt.Println("  • Sequential Write: >2.0GB/s")
	fmt.Println("  • Random I/O: >1.5GB/s")
	fmt.Println("  • io_uring Efficiency: >90% CPU utilization")
	fmt.Println()
	fmt.Println("Security Overhead:")
	fmt.Println("  • Total Security Overhead: <5ms")
	fmt.Println("  • AOT Policy Compilation: <50ms")
	fmt.Println("  • BPF-LSM Application: <1ms")
	fmt.Println("  • Landlock Enforcement: <2ms")
	fmt.Println()
	fmt.Println("System Scalability:")
	fmt.Println("  • Max Concurrent Spawns: >50 containers/second")
	fmt.Println("  • Sustained Throughput: >100 containers/minute")
	fmt.Println("  • NUMA Efficiency: <20% variance across nodes")
	fmt.Println("  • PSI Awareness: Graceful degradation under pressure")
}

func checkSystemCapabilities() {
	fmt.Println("🔍 System Capability Check")
	fmt.Println()

	// Basic system info
	fmt.Printf("OS: %s\n", runtime.GOOS)
	fmt.Printf("Architecture: %s\n", runtime.GOARCH)
	fmt.Printf("CPUs: %d\n", runtime.NumCPU())
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Println()

	// Check kernel features
	fmt.Println("Kernel Feature Support:")
	
	// Check PSI support
	if checkFile("/proc/pressure/cpu") {
		fmt.Println("  ✅ PSI (Pressure Stall Information)")
	} else {
		fmt.Println("  ❌ PSI not available (requires Linux 4.20+)")
	}

	// Check io_uring support
	if checkFile("/usr/include/linux/io_uring.h") {
		fmt.Println("  ✅ io_uring headers available")
	} else {
		fmt.Println("  ❌ io_uring headers not found")
	}

	// Check BPF support
	if checkFile("/sys/fs/bpf") {
		fmt.Println("  ✅ BPF filesystem mounted")
	} else {
		fmt.Println("  ❌ BPF filesystem not available")
	}

	// Check NUMA support
	if checkFile("/sys/devices/system/node") {
		fmt.Println("  ✅ NUMA topology available")
	} else {
		fmt.Println("  ❌ NUMA not available")
	}

	// Check cgroups v2
	if checkFile("/sys/fs/cgroup/cgroup.controllers") {
		fmt.Println("  ✅ cgroups v2")
	} else if checkFile("/sys/fs/cgroup") {
		fmt.Println("  ⚠️ cgroups v1 (v2 recommended)")
	} else {
		fmt.Println("  ❌ cgroups not available")
	}

	// Check security features
	if checkFile("/proc/sys/kernel/unprivileged_userns_clone") {
		fmt.Println("  ✅ User namespaces")
	} else {
		fmt.Println("  ❌ User namespaces not available")
	}

	fmt.Println()
	fmt.Println("Recommendations:")
	
	if runtime.GOOS != "linux" {
		fmt.Println("  ⚠️ Best performance on Linux (current OS: " + runtime.GOOS + ")")
	}
	
	if runtime.NumCPU() < 4 {
		fmt.Println("  ⚠️ Recommended: 4+ CPU cores for optimal performance")
	}

	fmt.Println("  💡 For maximum performance:")
	fmt.Println("    - Use Linux kernel 6.1+ for latest io_uring features")
	fmt.Println("    - Enable cgroups v2")
	fmt.Println("    - Ensure BPF and eBPF support")
	fmt.Println("    - Consider NUMA topology for multi-socket systems")
}

func parseProfiles(profileStr string) []string {
	profiles := strings.Split(profileStr, ",")
	for i, profile := range profiles {
		profiles[i] = strings.TrimSpace(profile)
	}
	return profiles
}

func parseConcurrencyLevels(concurrencyStr string) []int {
	parts := strings.Split(concurrencyStr, ",")
	levels := make([]int, 0, len(parts))
	
	for _, part := range parts {
		var level int
		if _, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &level); err == nil {
			levels = append(levels, level)
		}
	}
	
	return levels
}

func estimateDuration(config *benchmarks.BenchmarkConfig) time.Duration {
	// Rough estimation based on test complexity
	baseTime := time.Duration(config.Iterations) * 2 * time.Millisecond // 2ms per iteration average
	profileMultiplier := time.Duration(len(config.Profiles))
	concurrencyTests := time.Duration(len(config.ConcurrencyLevels)) * 30 * time.Second
	
	// Add warmup and cooldown time
	warmupTime := time.Duration(config.WarmupIterations) * 1 * time.Millisecond
	cooldownTime := 4 * config.CooldownTime // 4 major phases
	
	// Additional time for I/O, memory, and security tests
	additionalTests := 5 * time.Minute
	
	total := baseTime*profileMultiplier + concurrencyTests + warmupTime + cooldownTime + additionalTests
	
	if config.BaselineDocker {
		total += 3 * time.Minute // Docker comparison overhead
	}
	
	return total
}

func saveResults(results *benchmarks.BenchmarkResults, filename string) error {
	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Convert results to JSON
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write results file: %w", err)
	}

	return nil
}

func checkFile(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}