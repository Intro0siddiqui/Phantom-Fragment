package memory

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MemoryMetrics manages memory-related metrics and monitoring
type MemoryMetrics struct {
	registry *prometheus.Registry
	
	// Prometheus metrics
	allocationsTotal prometheus.Counter
	deallocationsTotal prometheus.Counter
	allocatedBytes prometheus.Gauge
	peakAllocatedBytes prometheus.Gauge
	
	bufferPoolHits prometheus.Counter
	bufferPoolMisses prometheus.Counter
	bufferPoolUsage prometheus.Gauge
	bufferPoolEfficiency prometheus.Gauge
	
	ksmPagesShared prometheus.Gauge
	ksmPagesSharing prometheus.Gauge
	ksmPagesUnshared prometheus.Gauge
	ksmSavedMemory prometheus.Gauge
	ksmEfficiency prometheus.Gauge
	
	memoryPressure prometheus.Gauge
	memoryFragmentation prometheus.Gauge
	memoryUsagePercent prometheus.Gauge
	
	// Internal tracking
	stats *MemoryStats
	config *MetricsConfig
	
	mu sync.RWMutex
	shutdown chan struct{}
	collectorRunning bool
}

// MemoryStats contains comprehensive memory statistics
type MemoryStats struct {
	Timestamp time.Time
	
	// Allocation statistics
	TotalAllocations int64
	TotalDeallocations int64
	CurrentAllocations int64
	PeakAllocations int64
	
	AllocatedBytes int64
	PeakAllocatedBytes int64
	FreedBytes int64
	
	// Buffer pool statistics
	BufferPoolHits int64
	BufferPoolMisses int64
	BufferPoolAllocations int64
	BufferPoolDeallocations int64
	BufferPoolUsage int64
	BufferPoolEfficiency float64
	
	// KSM statistics
	KSMPagesShared int64
	KSMPagesSharing int64
	KSMPagesUnshared int64
	KSMSavedMemory int64
	KSMEfficiency float64
	
	// System memory
	SystemTotalMemory int64
	SystemUsedMemory int64
	SystemFreeMemory int64
	SystemAvailableMemory int64
	
	// Process memory
	ProcessResidentMemory int64
	ProcessVirtualMemory int64
	ProcessHeapMemory int64
	ProcessStackMemory int64
	
	// Performance metrics
	AllocationRate float64 // allocations/second
	DeallocationRate float64 // deallocations/second
	MemoryFragmentation float64 // 0.0-1.0
	MemoryPressure float64 // 0.0-1.0
	
	// Garbage collection
	GCCount int64
	GCTotalPause time.Duration
	GCLastPause time.Duration
	
	// Detailed breakdown
	BySize map[int]*SizeClassStats
	ByType map[string]*TypeStats
}

// SizeClassStats contains statistics for a specific size class
type SizeClassStats struct {
	Size int
	Allocations int64
	Deallocations int64
	CurrentAllocations int64
	AllocatedBytes int64
	WastedBytes int64
	Efficiency float64
	
	// Time series data
	AllocationRate float64
	DeallocationRate float64
	
	LastUpdated time.Time
}

// TypeStats contains statistics for a specific allocation type
type TypeStats struct {
	TypeName string
	Allocations int64
	Deallocations int64
	CurrentAllocations int64
	AllocatedBytes int64
	AverageLifetime time.Duration
	
	// Distribution
	SizeDistribution map[int]int64
	AgeDistribution map[time.Duration]int64
	
	LastUpdated time.Time
}

// MetricsConfig contains metrics collection configuration
type MetricsConfig struct {
	Enabled bool
	CollectionInterval time.Duration
	RetentionPeriod time.Duration
	ExportInterval time.Duration
	
	// Detailed tracking
	TrackSizeClasses bool
	TrackAllocationTypes bool
	TrackGarbageCollection bool
	
	// Thresholds for alerts
	HighMemoryUsageThreshold float64
	HighFragmentationThreshold float64
	HighPressureThreshold float64
	
	// Export settings
	ExportToPrometheus bool
	ExportToFile bool
	ExportPath string
	
	// Sampling rate for detailed tracking
	SamplingRate float64 // 0.0-1.0
}

// DefaultMetricsConfig returns default metrics configuration
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		Enabled: true,
		CollectionInterval: 5 * time.Second,
		RetentionPeriod: 24 * time.Hour,
		ExportInterval: 30 * time.Second,
		
		TrackSizeClasses: true,
		TrackAllocationTypes: true,
		TrackGarbageCollection: true,
		
		HighMemoryUsageThreshold: 0.8,  // 80%
		HighFragmentationThreshold: 0.3, // 30%
		HighPressureThreshold: 0.7,     // 70%
		
		ExportToPrometheus: true,
		ExportToFile: false,
		ExportPath: "/var/log/memory-metrics",
		
		SamplingRate: 0.1, // 10% sampling
	}
}

// NewMemoryMetrics creates a new memory metrics collector
func NewMemoryMetrics(config *MetricsConfig) (*MemoryMetrics, error) {
	if config == nil {
		config = DefaultMetricsConfig()
	}

	metrics := &MemoryMetrics{
		registry: prometheus.NewRegistry(),
		stats:    &MemoryStats{
			Timestamp: time.Now(),
			BySize:    make(map[int]*SizeClassStats),
			ByType:    make(map[string]*TypeStats),
		},
		config:   config,
		shutdown: make(chan struct{}),
	}

	// Initialize Prometheus metrics if enabled
	if config.ExportToPrometheus {
		if err := metrics.initializePrometheusMetrics(); err != nil {
			return nil, fmt.Errorf("failed to initialize Prometheus metrics: %w", err)
		}
	}

	// Start background collector if enabled
	if config.Enabled {
		go metrics.backgroundCollector()
	}

	return metrics, nil
}

// RecordAllocation records a memory allocation event
func (mm *MemoryMetrics) RecordAllocation(size int, allocType string) {
	if !mm.config.Enabled {
		return
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Update basic statistics
	mm.stats.TotalAllocations++
	mm.stats.CurrentAllocations++
	mm.stats.AllocatedBytes += int64(size)
	
	if mm.stats.CurrentAllocations > mm.stats.PeakAllocations {
		mm.stats.PeakAllocations = mm.stats.CurrentAllocations
	}
	if mm.stats.AllocatedBytes > mm.stats.PeakAllocatedBytes {
		mm.stats.PeakAllocatedBytes = mm.stats.AllocatedBytes
	}

	// Update size class statistics
	if mm.config.TrackSizeClasses {
		sizeClass := mm.getSizeClass(size)
		if _, exists := mm.stats.BySize[sizeClass]; !exists {
			mm.stats.BySize[sizeClass] = &SizeClassStats{
				Size: sizeClass,
				LastUpdated: time.Now(),
			}
		}
		
		stats := mm.stats.BySize[sizeClass]
		stats.Allocations++
		stats.CurrentAllocations++
		stats.AllocatedBytes += int64(size)
		stats.LastUpdated = time.Now()
	}

	// Update type statistics
	if mm.config.TrackAllocationTypes && mm.shouldSample() {
		if _, exists := mm.stats.ByType[allocType]; !exists {
			mm.stats.ByType[allocType] = &TypeStats{
				TypeName: allocType,
				SizeDistribution: make(map[int]int64),
				AgeDistribution: make(map[time.Duration]int64),
				LastUpdated: time.Now(),
			}
		}
		
		stats := mm.stats.ByType[allocType]
		stats.Allocations++
		stats.CurrentAllocations++
		stats.AllocatedBytes += int64(size)
		stats.SizeDistribution[size]++
		stats.LastUpdated = time.Now()
	}

	// Update Prometheus metrics
	if mm.config.ExportToPrometheus {
		mm.allocationsTotal.Inc()
		mm.allocatedBytes.Set(float64(mm.stats.AllocatedBytes))
		mm.peakAllocatedBytes.Set(float64(mm.stats.PeakAllocatedBytes))
	}
}

// RecordDeallocation records a memory deallocation event
func (mm *MemoryMetrics) RecordDeallocation(size int, allocType string, lifetime time.Duration) {
	if !mm.config.Enabled {
		return
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Update basic statistics
	mm.stats.TotalDeallocations++
	mm.stats.CurrentAllocations--
	mm.stats.AllocatedBytes -= int64(size)
	mm.stats.FreedBytes += int64(size)

	// Update size class statistics
	if mm.config.TrackSizeClasses {
		sizeClass := mm.getSizeClass(size)
		if stats, exists := mm.stats.BySize[sizeClass]; exists {
			stats.Deallocations++
			stats.CurrentAllocations--
			stats.AllocatedBytes -= int64(size)
			stats.LastUpdated = time.Now()
		}
	}

	// Update type statistics
	if mm.config.TrackAllocationTypes && mm.shouldSample() {
		if stats, exists := mm.stats.ByType[allocType]; exists {
			stats.Deallocations++
			stats.CurrentAllocations--
			stats.AllocatedBytes -= int64(size)
			stats.AverageLifetime = mm.calculateAverageLifetime(stats, lifetime)
			stats.AgeDistribution[mm.roundDuration(lifetime)]++
			stats.LastUpdated = time.Now()
		}
	}

	// Update Prometheus metrics
	if mm.config.ExportToPrometheus {
		mm.deallocationsTotal.Inc()
		mm.allocatedBytes.Set(float64(mm.stats.AllocatedBytes))
	}
}

// RecordBufferPoolHit records a buffer pool hit
func (mm *MemoryMetrics) RecordBufferPoolHit(size int) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.stats.BufferPoolHits++
	
	if mm.config.ExportToPrometheus {
		mm.bufferPoolHits.Inc()
	}
}

// RecordBufferPoolMiss records a buffer pool miss
func (mm *MemoryMetrics) RecordBufferPoolMiss(size int) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.stats.BufferPoolMisses++
	
	if mm.config.ExportToPrometheus {
		mm.bufferPoolMisses.Inc()
	}
}

// UpdateBufferPoolUsage updates buffer pool usage statistics
func (mm *MemoryMetrics) UpdateBufferPoolUsage(usage int64, efficiency float64) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.stats.BufferPoolUsage = usage
	mm.stats.BufferPoolEfficiency = efficiency
	
	if mm.config.ExportToPrometheus {
		mm.bufferPoolUsage.Set(float64(usage))
		mm.bufferPoolEfficiency.Set(efficiency)
	}
}

// UpdateKSMStats updates KSM statistics
func (mm *MemoryMetrics) UpdateKSMStats(pagesShared, pagesSharing, pagesUnshared, savedMemory int64, efficiency float64) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.stats.KSMPagesShared = pagesShared
	mm.stats.KSMPagesSharing = pagesSharing
	mm.stats.KSMPagesUnshared = pagesUnshared
	mm.stats.KSMSavedMemory = savedMemory
	mm.stats.KSMEfficiency = efficiency
	
	if mm.config.ExportToPrometheus {
		mm.ksmPagesShared.Set(float64(pagesShared))
		mm.ksmPagesSharing.Set(float64(pagesSharing))
		mm.ksmPagesUnshared.Set(float64(pagesUnshared))
		mm.ksmSavedMemory.Set(float64(savedMemory))
		mm.ksmEfficiency.Set(efficiency)
	}
}

// UpdateSystemMemory updates system memory statistics
func (mm *MemoryMetrics) UpdateSystemMemory(total, used, free, available int64) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.stats.SystemTotalMemory = total
	mm.stats.SystemUsedMemory = used
	mm.stats.SystemFreeMemory = free
	mm.stats.SystemAvailableMemory = available
	
	// Calculate memory pressure
	if total > 0 {
		mm.stats.MemoryPressure = float64(used) / float64(total)
		
		if mm.config.ExportToPrometheus {
			mm.memoryPressure.Set(mm.stats.MemoryPressure)
			mm.memoryUsagePercent.Set(mm.stats.MemoryPressure * 100)
		}
	}
}

// UpdateProcessMemory updates process memory statistics
func (mm *MemoryMetrics) UpdateProcessMemory(resident, virtual, heap, stack int64) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.stats.ProcessResidentMemory = resident
	mm.stats.ProcessVirtualMemory = virtual
	mm.stats.ProcessHeapMemory = heap
	mm.stats.ProcessStackMemory = stack
}

// UpdateGCStats updates garbage collection statistics
func (mm *MemoryMetrics) UpdateGCStats(count int64, totalPause, lastPause time.Duration) {
	if !mm.config.TrackGarbageCollection {
		return
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.stats.GCCount = count
	mm.stats.GCTotalPause = totalPause
	mm.stats.GCLastPause = lastPause
}

// GetStats returns current memory statistics
func (mm *MemoryMetrics) GetStats() *MemoryStats {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	stats := *mm.stats // Copy
	stats.Timestamp = time.Now()
	
	// Calculate rates
	duration := time.Since(mm.stats.Timestamp).Seconds()
	if duration > 0 {
		stats.AllocationRate = float64(stats.TotalAllocations) / duration
		stats.DeallocationRate = float64(stats.TotalDeallocations) / duration
	}
	
	// Calculate fragmentation
	if stats.AllocatedBytes > 0 {
		stats.MemoryFragmentation = mm.calculateFragmentation()
	}
	
	return &stats
}

// GetSizeClassStats returns statistics for a specific size class
func (mm *MemoryMetrics) GetSizeClassStats(sizeClass int) (*SizeClassStats, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	stats, exists := mm.stats.BySize[sizeClass]
	if !exists {
		return nil, fmt.Errorf("size class %d not found", sizeClass)
	}
	
	returnStats := *stats // Copy
	return &returnStats, nil
}

// GetTypeStats returns statistics for a specific allocation type
func (mm *MemoryMetrics) GetTypeStats(typeName string) (*TypeStats, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	stats, exists := mm.stats.ByType[typeName]
	if !exists {
		return nil, fmt.Errorf("allocation type %s not found", typeName)
	}
	
	returnStats := *stats // Copy
	return &returnStats, nil
}

// ResetStats resets all statistics
func (mm *MemoryMetrics) ResetStats() {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.stats = &MemoryStats{
		Timestamp: time.Now(),
		BySize:    make(map[int]*SizeClassStats),
		ByType:    make(map[string]*TypeStats),
	}
}

// Shutdown stops the metrics collector
func (mm *MemoryMetrics) Shutdown() error {
	if !mm.config.Enabled {
		return nil
	}

	close(mm.shutdown)
	mm.collectorRunning = false
	
	// Export final statistics
	if mm.config.ExportToFile {
		mm.exportToFile()
	}

	return nil
}

// backgroundCollector runs the background metrics collection
func (mm *MemoryMetrics) backgroundCollector() {
	mm.collectorRunning = true
	defer func() { mm.collectorRunning = false }()

	ticker := time.NewTicker(mm.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mm.shutdown:
			return
		case <-ticker.C:
			mm.collectSystemMetrics()
			mm.collectProcessMetrics()
			mm.collectGCMetrics()
			
			// Export metrics if enabled
			if mm.config.ExportToFile && time.Since(mm.stats.Timestamp) > mm.config.ExportInterval {
				mm.exportToFile()
			}
		}
	}
}

// collectSystemMetrics collects system-level memory metrics
func (mm *MemoryMetrics) collectSystemMetrics() {
	// Read /proc/meminfo on Linux systems
	memInfo, err := readMemInfo()
	if err != nil {
		return
	}

	total := int64(memInfo.Total)
	used := int64(memInfo.Used)
	free := int64(memInfo.Free)
	available := int64(memInfo.Available)

	mm.UpdateSystemMemory(total, used, free, available)
}

// collectProcessMetrics collects process-level memory metrics
func (mm *MemoryMetrics) collectProcessMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Convert to bytes
	resident := int64(m.HeapInuse + m.StackInuse + m.MSpanInuse + m.MCacheInuse)
	virtual := int64(m.Sys)
	heap := int64(m.HeapInuse)
	stack := int64(m.StackInuse)

	mm.UpdateProcessMemory(resident, virtual, heap, stack)
}

// collectGCMetrics collects garbage collection metrics
func (mm *MemoryMetrics) collectGCMetrics() {
	if !mm.config.TrackGarbageCollection {
		return
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Calculate pause times
	totalPause := time.Duration(m.PauseTotalNs) * time.Nanosecond
	lastPause := time.Duration(m.PauseNs[(m.NumGC+255)%256]) * time.Nanosecond

	mm.UpdateGCStats(int64(m.NumGC), totalPause, lastPause)
}

// initializePrometheusMetrics initializes Prometheus metrics
func (mm *MemoryMetrics) initializePrometheusMetrics() error {
	// Allocation metrics
	mm.allocationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "memory_allocations_total",
		Help: "Total number of memory allocations",
	})
	
	mm.deallocationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "memory_deallocations_total",
		Help: "Total number of memory deallocations",
	})
	
	mm.allocatedBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "memory_allocated_bytes",
		Help: "Current allocated memory in bytes",
	})
	
	mm.peakAllocatedBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "memory_peak_allocated_bytes",
		Help: "Peak allocated memory in bytes",
	})

	// Buffer pool metrics
	mm.bufferPoolHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "buffer_pool_hits_total",
		Help: "Total number of buffer pool hits",
	})
	
	mm.bufferPoolMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "buffer_pool_misses_total",
		Help: "Total number of buffer pool misses",
	})
	
	mm.bufferPoolUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "buffer_pool_usage_bytes",
		Help: "Current buffer pool usage in bytes",
	})
	
	mm.bufferPoolEfficiency = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "buffer_pool_efficiency_ratio",
		Help: "Buffer pool efficiency ratio (0.0-1.0)",
	})

	// KSM metrics
	mm.ksmPagesShared = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ksm_pages_shared",
		Help: "Number of shared pages by KSM",
	})
	
	mm.ksmPagesSharing = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ksm_pages_sharing",
		Help: "Number of pages sharing memory",
	})
	
	mm.ksmPagesUnshared = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ksm_pages_unshared",
		Help: "Number of unshared pages",
	})
	
	mm.ksmSavedMemory = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ksm_saved_memory_bytes",
		Help: "Memory saved by KSM in bytes",
	})
	
	mm.ksmEfficiency = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ksm_efficiency_ratio",
		Help: "KSM efficiency ratio (0.0-1.0)",
	})

	// System metrics
	mm.memoryPressure = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "memory_pressure_ratio",
		Help: "System memory pressure ratio (0.0-1.0)",
	})
	
	mm.memoryFragmentation = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "memory_fragmentation_ratio",
		Help: "Memory fragmentation ratio (0.0-1.0)",
	})
	
	mm.memoryUsagePercent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "memory_usage_percent",
		Help: "System memory usage percentage",
	})

	return nil
}

// exportToFile exports metrics to a file
func (mm *MemoryMetrics) exportToFile() {
	// Implementation would write metrics to file in JSON or CSV format
	// This is a placeholder for actual file export logic
}

// Helper methods
func (mm *MemoryMetrics) getSizeClass(size int) int {
	// Simple size class calculation
	// In production, use more sophisticated classification
	switch {
	case size <= 64:
		return 64
	case size <= 256:
		return 256
	case size <= 1024:
		return 1024
	case size <= 4096:
		return 4096
	case size <= 16384:
		return 16384
	case size <= 65536:
		return 65536
	default:
		return (size + 4095) &^ 4095 // Round to 4KB
	}
}

func (mm *MemoryMetrics) shouldSample() bool {
	// Simple sampling based on configured rate
	return mm.config.SamplingRate >= 1.0 || 
		   (mm.config.SamplingRate > 0 && 
			float64(mm.stats.TotalAllocations)%(1.0/mm.config.SamplingRate) < 1.0)
}

func (mm *MemoryMetrics) calculateAverageLifetime(stats *TypeStats, newLifetime time.Duration) time.Duration {
	if stats.Allocations == 0 {
		return newLifetime
	}
	
	currentTotal := stats.AverageLifetime * time.Duration(stats.Allocations)
	newTotal := currentTotal + newLifetime
	return newTotal / time.Duration(stats.Allocations+1)
}

func (mm *MemoryMetrics) roundDuration(d time.Duration) time.Duration {
	// Round to nearest second for distribution buckets
	return (d + time.Second/2) / time.Second * time.Second
}

func (mm *MemoryMetrics) calculateFragmentation() float64 {
	// Simple fragmentation calculation
	// In production, use more sophisticated algorithm
	
	totalAllocated := mm.stats.AllocatedBytes
	if totalAllocated == 0 {
		return 0.0
	}
	
	// Calculate wasted space (simplified)
	wasted := int64(0)
	for _, stats := range mm.stats.BySize {
		if stats.AllocatedBytes > 0 {
			// Assume some overhead per allocation
			wasted += int64(stats.CurrentAllocations) * 16 // 16 bytes overhead per allocation
		}
	}
	
	return float64(wasted) / float64(totalAllocated)
}

// readMemInfo reads memory information from /proc/meminfo
func readMemInfo() (*MemInfo, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var memInfo MemInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "MemTotal:":
			memInfo.Total, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemFree:":
			memInfo.Free, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemAvailable:":
			memInfo.Available, _ = strconv.ParseUint(fields[1], 10, 64)
		case "Buffers:":
			memInfo.Buffers, _ = strconv.ParseUint(fields[1], 10, 64)
		case "Cached:":
			memInfo.Cached, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}

	memInfo.Used = memInfo.Total - memInfo.Free - memInfo.Buffers - memInfo.Cached
	return &memInfo, nil
}

// MemInfo contains memory information from /proc/meminfo
type MemInfo struct {
	Total     uint64
	Free      uint64
	Available uint64
	Used      uint64
	Buffers   uint64
	Cached    uint64
}