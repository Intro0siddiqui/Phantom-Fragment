package memory

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
)

// MemoryDisciplineV3 provides advanced memory management with jemalloc integration, buffer pools, and KSM
type MemoryDisciplineV3 struct {
	jemalloc      *JemallocAllocator
	bufferPool    *BufferPoolManager
	ksmManager    *KSMManager
	metrics       *MemoryMetrics
	
	config        *DisciplineConfig
	stats         *DisciplineStats
	
	mu            sync.RWMutex
	shutdown      chan struct{}
	initialized   bool
	
	// Memory regions tracking
	regions       map[uuid.UUID]*MemoryRegion
	allocations   map[uintptr]*AllocationInfo
	
	// Background workers
	compactionWorkerRunning bool
	metricsWorkerRunning    bool
	ksmWorkerRunning       bool
}

// DisciplineConfig contains memory discipline configuration
type DisciplineConfig struct {
	// Core components
	EnableJemalloc     bool
	EnableBufferPools  bool
	EnableKSM          bool
	EnableMetrics      bool
	
	// Memory limits
	MaxHeapSize        int64
	MaxBufferPoolSize  int64
	MaxKSMPages        int64
	
	// Performance tuning
	ArenaCount         int
	ThreadCacheEnabled bool
	PurgeInterval      time.Duration
	CompactionInterval time.Duration
	
	// Advanced features
	UseHugePages       bool
	UseTransparentHugePages bool
	UseMemoryLocking   bool
	
	// Security features
	EnableGuardPages   bool
	EnableRandomization bool
	EnablePoisoning    bool
	
	// Monitoring and metrics
	MetricsInterval    time.Duration
	StatsLogInterval   time.Duration
	
	// Fallback settings
	FallbackToSystemAlloc bool
	WarnOnFallback      bool
}

// DisciplineStats contains memory discipline statistics
type DisciplineStats struct {
	Timestamp time.Time
	
	// Allocation statistics
	TotalAllocations int64
	TotalDeallocations int64
	CurrentAllocations int64
	PeakAllocations int64
	
	AllocatedBytes int64
	PeakAllocatedBytes int64
	FreedBytes int64
	
	// Component statistics
	JemallocStats *JemallocStats
	BufferPoolStats *BufferPoolStats
	KSMStats *KSMStats
	MetricsStats *MemoryStats
	
	// Performance metrics
	AllocationLatency time.Duration
	DeallocationLatency time.Duration
	AverageAllocationSize int64
	
	// Efficiency metrics
	MemoryEfficiency float64
	CacheHitRate float64
	FragmentationLevel float64
	
	// Error statistics
	AllocationErrors int64
	DeallocationErrors int64
	OOMEvents int64
	
	// System metrics
	SystemMemoryUsage float64
	ProcessMemoryUsage float64
	GarbageCollectionCount int64
}

// MemoryRegion represents a managed memory region
type MemoryRegion struct {
	ID uuid.UUID
	StartAddr uintptr
	Size int
	Type string
	Flags int
	
	AllocationCount int
	FreeSpace int
	Fragmentation float64
	
	CreatedAt time.Time
	LastUsed time.Time
	
	// Security features
	GuardPagesEnabled bool
	RandomizedOffset int
	PoisonPattern []byte
	
	// Performance features
	UseHugePages bool
	LockedInMemory bool
	
	// KSM integration
	KSMEnabled bool
	KSMMergedPages int
	KSMSavedBytes int64
}

// AllocationInfo contains information about a memory allocation
type AllocationInfo struct {
	ID uuid.UUID
	Addr uintptr
	Size int
	Type string
	
	AllocatedAt time.Time
	LastUsed time.Time
	Lifetime time.Duration
	AccessCount int64
	
	// Memory discipline features
	FromBufferPool bool
	BufferPoolHit bool
	KSMEnabled bool
	
	// Security features
	GuardPages bool
	Randomized bool
	Poisoned bool
	
	// Performance features
	Alignment int
	NUMANode int
	
	// Stack trace for debugging
	StackTrace []string
}

// DefaultDisciplineConfig returns default memory discipline configuration
func DefaultDisciplineConfig() *DisciplineConfig {
	return &DisciplineConfig{
		EnableJemalloc:    true,
		EnableBufferPools: true,
		EnableKSM:         true,
		EnableMetrics:     true,
		
		MaxHeapSize:       1 << 30, // 1GB
		MaxBufferPoolSize: 256 << 20, // 256MB
		MaxKSMPages:       10000,
		
		ArenaCount:        runtime.GOMAXPROCS(0),
		ThreadCacheEnabled: true,
		PurgeInterval:     30 * time.Second,
		CompactionInterval: 5 * time.Minute,
		
		UseHugePages:       false,
		UseTransparentHugePages: true,
		UseMemoryLocking:  false,
		
		EnableGuardPages:  true,
		EnableRandomization: true,
		EnablePoisoning:   true,
		
		MetricsInterval:   5 * time.Second,
		StatsLogInterval:  60 * time.Second,
		
		FallbackToSystemAlloc: true,
		WarnOnFallback:      true,
	}
}

// NewMemoryDisciplineV3 creates a new memory discipline instance
func NewMemoryDisciplineV3(config *DisciplineConfig) (*MemoryDisciplineV3, error) {
	if config == nil {
		config = DefaultDisciplineConfig()
	}

	md := &MemoryDisciplineV3{
		config:      config,
		stats:       &DisciplineStats{Timestamp: time.Now()},
		shutdown:    make(chan struct{}),
		regions:     make(map[uuid.UUID]*MemoryRegion),
		allocations: make(map[uintptr]*AllocationInfo),
	}

	// Initialize components based on configuration
	if err := md.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize memory discipline components: %w", err)
	}

	// Start background workers
	md.startBackgroundWorkers()

	md.initialized = true
	return md, nil
}

// Malloc allocates memory with advanced features
func (md *MemoryDisciplineV3) Malloc(size int, alignment int) (unsafe.Pointer, error) {
	start := time.Now()
	
	// Try buffer pool first if enabled
	if md.config.EnableBufferPools && size <= md.bufferPool.MaxBufferSize() {
		buf, err := md.bufferPool.Allocate(size, alignment)
		if err == nil {
			md.recordAllocation(uintptr(unsafe.Pointer(&buf[0])), size, "buffer_pool", true)
			md.recordBufferPoolHit(size)
			
			latency := time.Since(start)
			md.recordAllocationLatency(latency)
			
			return unsafe.Pointer(&buf[0]), nil
		}
		// Fall through to jemalloc if buffer pool fails
	}

	// Use jemalloc if enabled
	if md.config.EnableJemalloc {
		ptr, err := md.jemalloc.Malloc(size, alignment)
		if err == nil {
			md.recordAllocation(uintptr(ptr), size, "jemalloc", false)
			
			// Enable KSM for this allocation if appropriate
			if md.config.EnableKSM && size >= 4096 { // Page-sized or larger
				md.enableKSMForAllocation(uintptr(ptr), size)
			}
			
			latency := time.Since(start)
			md.recordAllocationLatency(latency)
			
			return ptr, nil
		}
		
		// Fall through to system allocator if configured
		if md.config.WarnOnFallback {
			// Log warning about fallback
		}
	}

	// Fallback to system allocator
	if md.config.FallbackToSystemAlloc {
		var ptr unsafe.Pointer
		var err error
		
		if alignment > 0 {
			ptr, err = md.systemAlignedAlloc(size, alignment)
		} else {
			ptr = md.systemMalloc(size)
		}
		
		if err == nil && ptr != nil {
			md.recordAllocation(uintptr(ptr), size, "system", false)
			
			latency := time.Since(start)
			md.recordAllocationLatency(latency)
			
			return ptr, nil
		}
	}

	// All allocation methods failed
	md.recordAllocationError()
	return nil, fmt.Errorf("failed to allocate %d bytes", size)
}

// Free deallocates memory with proper cleanup
func (md *MemoryDisciplineV3) Free(ptr unsafe.Pointer) error {
	start := time.Now()
	
	if ptr == nil {
		return nil
	}

	addr := uintptr(ptr)
	
	// Check if this allocation is tracked
	md.mu.RLock()
	allocInfo, exists := md.allocations[addr]
	md.mu.RUnlock()
	
	if !exists {
		// Not tracked by our system, use system free
		md.systemFree(ptr)
		return nil
	}

	// Handle based on allocation type
	var err error
	
	if allocInfo.FromBufferPool {
		// Return to buffer pool
		buf := (*[1 << 30]byte)(ptr)[:allocInfo.Size]
		err = md.bufferPool.Free(buf)
	} else if allocInfo.Type == "jemalloc" {
		// Use jemalloc free
		err = md.jemalloc.Free(ptr)
		
		// Disable KSM if it was enabled
		if allocInfo.KSMEnabled {
			md.disableKSMForAllocation(addr)
		}
	} else {
		// System allocation
		md.systemFree(ptr)
	}

	if err == nil {
		// Remove from tracking
		md.mu.Lock()
		delete(md.allocations, addr)
		md.mu.Unlock()
		
		// Record statistics
		md.recordDeallocation(allocInfo.Size)
		latency := time.Since(start)
		md.recordDeallocationLatency(latency)
	}

	return err
}

// Calloc allocates and zeroes memory
func (md *MemoryDisciplineV3) Calloc(count int, size int, alignment int) (unsafe.Pointer, error) {
	ptr, err := md.Malloc(count*size, alignment)
	if err != nil {
		return nil, err
	}
	
	// Zero the memory
	mem := (*[1 << 30]byte)(ptr)[:count*size]
	for i := range mem {
		mem[i] = 0
	}
	
	return ptr, nil
}

// Realloc resizes an existing allocation
func (md *MemoryDisciplineV3) Realloc(ptr unsafe.Pointer, newSize int, alignment int) (unsafe.Pointer, error) {
	if ptr == nil {
		return md.Malloc(newSize, alignment)
	}
	
	if newSize == 0 {
		md.Free(ptr)
		return nil, nil
	}

	// Get current allocation info
	addr := uintptr(ptr)
	md.mu.RLock()
	allocInfo, exists := md.allocations[addr]
	md.mu.RUnlock()
	
	if !exists {
		// Not our allocation, create new one and copy
		newPtr, err := md.Malloc(newSize, alignment)
		if err != nil {
			return nil, err
		}
		
		// We don't know the original size, so we can't copy safely
		// This is a limitation for external allocations
		return newPtr, nil
	}

	// If same size, return original pointer
	if allocInfo.Size == newSize {
		return ptr, nil
	}

	// Handle based on allocation type
	if allocInfo.FromBufferPool {
		// Buffer pool allocations can't be resized
		newPtr, err := md.Malloc(newSize, alignment)
		if err != nil {
			return nil, err
		}
		
		// Copy data and free old allocation
		copy((*[1 << 30]byte)(newPtr)[:min(allocInfo.Size, newSize)], 
			 (*[1 << 30]byte)(ptr)[:allocInfo.Size])
		md.Free(ptr)
		
		return newPtr, nil
	} else if allocInfo.Type == "jemalloc" {
		// Try jemalloc realloc first
		newPtr, err := md.jemalloc.Realloc(ptr, newSize, alignment)
		if err == nil {
			// Update tracking
			md.mu.Lock()
			delete(md.allocations, addr)
			md.recordAllocation(uintptr(newPtr), newSize, "jemalloc", false)
			md.mu.Unlock()
			
			return newPtr, nil
		}
		
		// Fallback to malloc+copy+free
		newPtr, err = md.Malloc(newSize, alignment)
		if err != nil {
			return nil, err
		}
		
		copy((*[1 << 30]byte)(newPtr)[:min(allocInfo.Size, newSize)], 
			 (*[1 << 30]byte)(ptr)[:allocInfo.Size])
		md.Free(ptr)
		
		return newPtr, nil
	} else {
		// System allocation - use system realloc or fallback
		newPtr, err := md.systemRealloc(ptr, newSize, alignment)
		if err == nil {
			// Update tracking
			md.mu.Lock()
			delete(md.allocations, addr)
			md.recordAllocation(uintptr(newPtr), newSize, "system", false)
			md.mu.Unlock()
			
			return newPtr, nil
		}
		
		// Fallback to malloc+copy+free
		newPtr, err = md.Malloc(newSize, alignment)
		if err != nil {
			return nil, err
		}
		
		copy((*[1 << 30]byte)(newPtr)[:min(allocInfo.Size, newSize)], 
			 (*[1 << 30]byte)(ptr)[:allocInfo.Size])
		md.Free(ptr)
		
		return newPtr, nil
	}
}

// initializeComponents sets up all configured memory components
func (md *MemoryDisciplineV3) initializeComponents() error {
	var err error

	// Initialize jemalloc if enabled
	if md.config.EnableJemalloc {
		md.jemalloc, err = NewJemallocAllocator(&JemallocConfig{
			ArenaCount:         md.config.ArenaCount,
			ThreadCacheEnabled: md.config.ThreadCacheEnabled,
			UseHugePages:       md.config.UseHugePages,
			GuardPagesEnabled:  md.config.EnableGuardPages,
			MaxHeapSize:        md.config.MaxHeapSize,
			PurgeInterval:      md.config.PurgeInterval,
		})
		if err != nil {
			return fmt.Errorf("jemalloc initialization failed: %w", err)
		}
	}

	// Initialize buffer pools if enabled
	if md.config.EnableBufferPools {
		md.bufferPool, err = NewBufferPoolManager(int(md.config.MaxBufferPoolSize))
		if err != nil {
			return fmt.Errorf("buffer pool initialization failed: %w", err)
		}
	}

	\t// Initialize KSM manager if enabled\n\tif md.config.EnableKSM {\n\t\tmd.ksmManager, err = NewKSMManagerWithConfig(&KSMConfig{\n\t\t\tEnabled:          true,\n\t\t\tPagesToScan:      int(md.config.MaxKSMPages),\n\t\t\tMergeAcrossNodes: false,\n\t\t\tAutoTune:         true,\n\t\t})\n\t\tif err != nil {\n\t\t\treturn fmt.Errorf(\"KSM manager initialization failed: %w\", err)\n\t\t}\n\t}

	// Initialize metrics if enabled
	if md.config.EnableMetrics {
		md.metrics, err = NewMemoryMetrics(nil)
		if err != nil {
			return fmt.Errorf("metrics initialization failed: %w", err)
		}
	}

	return nil
}

// startBackgroundWorkers starts all background maintenance workers
func (md *MemoryDisciplineV3) startBackgroundWorkers() {
	// Start metrics collection worker
	if md.config.EnableMetrics {
		md.metricsWorkerRunning = true
		go md.metricsWorker()
	}

	// Start compaction worker for jemalloc
	if md.config.EnableJemalloc {
		md.compactionWorkerRunning = true
		go md.compactionWorker()
	}

	// Start KSM worker if enabled
	if md.config.EnableKSM {
		md.ksmWorkerRunning = true
		go md.ksmWorker()
	}
}

// metricsWorker collects and reports memory metrics
func (md *MemoryDisciplineV3) metricsWorker() {
	ticker := time.NewTicker(md.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			md.collectMetrics()
		case <-md.shutdown:
			md.metricsWorkerRunning = false
			return
		}
	}
}

// compactionWorker performs periodic memory compaction
func (md *MemoryDisciplineV3) compactionWorker() {
	ticker := time.NewTicker(md.config.CompactionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if md.jemalloc != nil {
				md.jemalloc.Compact()
			}
		case <-md.shutdown:
			md.compactionWorkerRunning = false
			return
		}
	}
}

// ksmWorker manages Kernel Samepage Merging
func (md *MemoryDisciplineV3) ksmWorker() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if md.ksmManager != nil {
				md.ksmManager.ScanAllRegions()
			}
		case <-md.shutdown:
			md.ksmWorkerRunning = false
			return
		}
	}
}

// collectMetrics gathers all memory metrics
func (md *MemoryDisciplineV3) collectMetrics() {
	md.mu.Lock()
	defer md.mu.Unlock()

	// Update basic statistics
	md.stats.Timestamp = time.Now()
	md.stats.CurrentAllocations = int64(len(md.allocations))
	
	// Collect component-specific metrics
	if md.jemalloc != nil {
		md.stats.JemallocStats = md.jemalloc.GetStats()
	}
	
	if md.bufferPool != nil {
		md.stats.BufferPoolStats = md.bufferPool.GetStats()
	}
	
	if md.ksmManager != nil {
		md.stats.KSMStats = md.ksmManager.GetStats()
	}
	
	if md.metrics != nil {
		md.stats.MetricsStats = md.metrics.GetStats()
	}
	
	// Calculate efficiency metrics
	md.calculateEfficiencyMetrics()
}

// calculateEfficiencyMetrics computes memory efficiency statistics
func (md *MemoryDisciplineV3) calculateEfficiencyMetrics() {
	// Implementation would calculate:
	// - Memory efficiency ratio
	// - Cache hit rates
	// - Fragmentation levels
	// - Other performance metrics
}

// recordAllocation tracks a new memory allocation
func (md *MemoryDisciplineV3) recordAllocation(addr uintptr, size int, allocType string, fromBufferPool bool) {
	md.mu.Lock()
	defer md.mu.Unlock()

	info := &AllocationInfo{
		ID:            uuid.New(),
		Addr:          addr,
		Size:          size,
		Type:          allocType,
		FromBufferPool: fromBufferPool,
		AllocatedAt:   time.Now(),
		LastUsed:      time.Now(),
	}

	md.allocations[addr] = info
	md.stats.TotalAllocations++
	md.stats.AllocatedBytes += int64(size)
	
	if int64(len(md.allocations)) > md.stats.PeakAllocations {
		md.stats.PeakAllocations = int64(len(md.allocations))
	}
	
	if md.stats.AllocatedBytes > md.stats.PeakAllocatedBytes {
		md.stats.PeakAllocatedBytes = md.stats.AllocatedBytes
	}
}

// recordDeallocation tracks memory deallocation
func (md *MemoryDisciplineV3) recordDeallocation(size int) {
	md.mu.Lock()
	defer md.mu.Unlock()

	md.stats.TotalDeallocations++
	md.stats.FreedBytes += int64(size)
	md.stats.AllocatedBytes -= int64(size)
}

// recordAllocationLatency records allocation performance
func (md *MemoryDisciplineV3) recordAllocationLatency(latency time.Duration) {
	md.mu.Lock()
	defer md.mu.Unlock()

	// Update average latency
	if md.stats.AllocationLatency == 0 {
		md.stats.AllocationLatency = latency
	} else {
		// Simple moving average
		md.stats.AllocationLatency = (md.stats.AllocationLatency*9 + latency) / 10
	}
}

// recordDeallocationLatency records deallocation performance
func (md *MemoryDisciplineV3) recordDeallocationLatency(latency time.Duration) {
	md.mu.Lock()
	defer md.mu.Unlock()

	// Update average latency
	if md.stats.DeallocationLatency == 0 {
		md.stats.DeallocationLatency = latency
	} else {
		// Simple moving average
		md.stats.DeallocationLatency = (md.stats.DeallocationLatency*9 + latency) / 10
	}
}

// recordBufferPoolHit records successful buffer pool usage
func (md *MemoryDisciplineV3) recordBufferPoolHit(size int) {
	md.mu.Lock()
	defer md.mu.Unlock()

	// Update buffer pool statistics
	if md.stats.BufferPoolStats == nil {
		md.stats.BufferPoolStats = &BufferPoolStats{}
	}
	
	md.stats.BufferPoolStats.Hits++
	md.stats.BufferPoolStats.BytesAllocated += int64(size)
}

// recordAllocationError records allocation failures
func (md *MemoryDisciplineV3) recordAllocationError() {
	md.mu.Lock()
	defer md.mu.Unlock()

	md.stats.AllocationErrors++
}

// enableKSMForAllocation enables KSM for a specific allocation
func (md *MemoryDisciplineV3) enableKSMForAllocation(addr uintptr, size int) {
	if md.ksmManager != nil {
		md.ksmManager.EnableForRegion(addr, size, 0)
		
		md.mu.Lock()
		if info, exists := md.allocations[addr]; exists {
			info.KSMEnabled = true
		}
		md.mu.Unlock()
	}
}

// disableKSMForAllocation disables KSM for a specific allocation
func (md *MemoryDisciplineV3) disableKSMForAllocation(addr uintptr) {
	if md.ksmManager != nil {
		md.ksmManager.DisableForRegion(addr)
	}
}

// systemMalloc fallback to system allocator
func (md *MemoryDisciplineV3) systemMalloc(size int) unsafe.Pointer {
	return unsafe.Pointer(&make([]byte, size)[0])
}

// systemAlignedAlloc fallback to aligned system allocation
func (md *MemoryDisciplineV3) systemAlignedAlloc(size int, alignment int) (unsafe.Pointer, error) {
	// Simple implementation - in production would use proper aligned allocation
	buf := make([]byte, size+alignment-1)
	addr := uintptr(unsafe.Pointer(&buf[0]))
	alignedAddr := (addr + uintptr(alignment-1)) & ^uintptr(alignment-1)
	return unsafe.Pointer(alignedAddr), nil
}

// systemFree fallback to system deallocator
func (md *MemoryDisciplineV3) systemFree(ptr unsafe.Pointer) {
	// Go's garbage collector will handle this
}

// systemRealloc fallback to system reallocator
func (md *MemoryDisciplineV3) systemRealloc(ptr unsafe.Pointer, newSize int, alignment int) (unsafe.Pointer, error) {
	// Simple implementation - allocate new and copy
	newPtr, err := md.systemAlignedAlloc(newSize, alignment)
	if err != nil {
		return nil, err
	}
	
	// We don't know the original size, so this is unsafe
	// In production, we'd need to track sizes
	return newPtr, nil
}

// Shutdown cleanly stops all memory discipline components
func (md *MemoryDisciplineV3) Shutdown() error {
	close(md.shutdown)
	
	// Wait for workers to stop
	for md.metricsWorkerRunning || md.compactionWorkerRunning || md.ksmWorkerRunning {
		time.Sleep(100 * time.Millisecond)
	}

	// Clean up components
	var errs []error
	
	if md.jemalloc != nil {
		if err := md.jemalloc.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	
	if md.bufferPool != nil {
		if err := md.bufferPool.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	
	if md.ksmManager != nil {
		if err := md.ksmManager.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	
	return nil
}

// GetStats returns current memory discipline statistics
func (md *MemoryDisciplineV3) GetStats() *DisciplineStats {
	md.mu.RLock()
	defer md.mu.RUnlock()
	
	stats := *md.stats // Return a copy
	return &stats
}

// GetConfig returns the current configuration
func (md *MemoryDisciplineV3) GetConfig() *DisciplineConfig {
	return md.config
}

// IsInitialized returns true if the memory discipline is ready
func (md *MemoryDisciplineV3) IsInitialized() bool {
	return md.initialized
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}