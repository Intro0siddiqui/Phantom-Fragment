package main

import (
	"fmt"
	"time"

	"github.com/phantom-fragment/phantom-utils/memory"
	"github.com/phantom-fragment/phantom-utils/metrics"
	"github.com/phantom-fragment/phantom-utils/numa"
)

func main() {
	// Example 1: NUMA Topology
	fmt.Println("=== NUMA Topology ===")
	topology := numa.NewTopology()
	fmt.Printf("NUMA Available: %v\n", numa.IsNUMAAvailable())
	fmt.Printf("Total Nodes: %d\n", len(topology.Nodes))
	fmt.Printf("Total Memory: %d bytes\n", topology.GetTotalMemory())

	for _, node := range topology.Nodes {
		fmt.Printf("Node %d: CPUs=%v Memory=%d bytes\n",
			node.ID, node.CPUs, node.Memory)
	}

	// Example 2: Buffer Pool
	fmt.Println("\n=== Buffer Pool ===")
	pool := memory.NewBufferPool(64 * 1024 * 1024) // 64MB pool

	// Allocate and free buffers
	buf1 := pool.Allocate(4096)
	buf2 := pool.Allocate(8192)

	fmt.Printf("Allocated buffers: %d and %d bytes\n", len(buf1), len(buf2))

	stats := pool.Stats()
	fmt.Printf("Pool stats: %d pools, %d total buffers\n",
		stats.Pools, stats.TotalBuffers)

	pool.Free(buf1)
	pool.Free(buf2)

	// Example 3: System Metrics
	fmt.Println("\n=== System Metrics ===")
	collector := metrics.NewSystemCollector()

	// Get PSI metrics if available
	if metrics.IsPSIAvailable() {
		psi := collector.GetPSIMetrics()
		fmt.Printf("PSI - CPU: %.2f, Memory: %.2f, IO: %.2f\n",
			psi.CPUStall, psi.MemoryStall, psi.IOStall)
	}

	// Get system info
	info := metrics.GetSystemInfo()
	fmt.Printf("System: %s/%s, CPUs: %d, Memory: %d bytes\n",
		info.OS, info.Arch, info.CPUs, info.Memory)

	// Example 4: Performance Tracking
	fmt.Println("\n=== Performance Tracking ===")
	tracker := metrics.NewPerformanceTracker(100)

	// Simulate some performance samples
	for i := 0; i < 5; i++ {
		sample := metrics.PerformanceSample{
			Timestamp:     time.Now(),
			CPUPercent:    25.0 + float64(i*5),
			MemoryPercent: 60.0 + float64(i*2),
			IOPercent:     10.0 + float64(i*3),
		}
		tracker.AddSample(sample)
		time.Sleep(100 * time.Millisecond)
	}

	avg := tracker.GetAverage(3)
	fmt.Printf("Average performance: CPU=%.1f%%, Memory=%.1f%%, IO=%.1f%%\n",
		avg.CPUPercent, avg.MemoryPercent, avg.IOPercent)

	// Example 5: Simple Allocator
	fmt.Println("\n=== Simple Allocator ===")
	allocator := memory.NewSimpleAllocator(32 * 1024 * 1024)

	data := allocator.Malloc(1024)
	fmt.Printf("Allocated %d bytes via simple allocator\n", len(data))

	allocator.Free(data)
	fmt.Println("Freed memory")
}
