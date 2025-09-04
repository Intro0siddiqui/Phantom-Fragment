package memory

import (
	"fmt"
	"sort"
	"sync"
	"time"
	"unsafe"
)

// BufferPoolManager manages pre-allocated memory buffers for efficient reuse
type BufferPoolManager struct {
	pools      map[BufferSize]*BufferPool
	globalPool *GlobalBufferPool

	allocationMap map[uintptr]*BufferAllocation
	stats         *BufferPoolStats
	config        *BufferPoolConfig

	mu       sync.RWMutex
	shutdown chan struct{}
}

// BufferPoolConfig configuration for buffer pool manager
type BufferPoolConfig struct {
	MaxPoolSize       int
	MinBufferSize     int
	MaxBufferSize     int
	GrowthFactor      float64
	CleanupInterval   time.Duration
	IdleTimeout       time.Duration
	MaxBuffersPerPool int
}

// BufferSize represents a specific buffer size class
type BufferSize int

// BufferPool manages buffers of a specific size
type BufferPool struct {
	size          BufferSize
	buffers       chan []byte
	allocations   int64
	deallocations int64
	hits          int64
	misses        int64

	lastUsed time.Time
	stats    *PoolStats

	mu sync.RWMutex
}

// GlobalBufferPool manages oversized buffers and special allocations
type GlobalBufferPool struct {
	oversizedBuffers map[BufferSize][]byte
	specialPools     map[BufferSize]*BufferPool
	stats            *GlobalPoolStats

	mu sync.RWMutex
}

// BufferAllocation tracks buffer allocation metadata
type BufferAllocation struct {
	Buffer      []byte
	Pool        *BufferPool
	AllocatedAt time.Time
	LastUsedAt  time.Time
	AccessCount int64
	Size        int
}

// BufferPoolStats contains buffer pool statistics
type BufferPoolStats struct {
	TotalAllocations   int64
	TotalDeallocations int64
	TotalHits          int64
	TotalMisses        int64

	CurrentUsage int64
	PeakUsage    int64
	WastedMemory int64

	PoolCount   int
	BufferCount int

	Timestamp time.Time
}

// PoolStats contains per-pool statistics
type PoolStats struct {
	Size          BufferSize
	Capacity      int
	Available     int
	Allocations   int64
	Deallocations int64
	Hits          int64
	Misses        int64

	MemoryEfficiency float64
	HitRate          float64

	LastAccess time.Time
}

// GlobalPoolStats contains global pool statistics
type GlobalPoolStats struct {
	OversizedAllocations int64
	SpecialAllocations   int64
	CacheHits            int64
	CacheMisses          int64

	OversizedMemory int64
	SpecialMemory   int64
}

// NewBufferPoolManager creates a new buffer pool manager
func NewBufferPoolManager(maxPoolSize int) (*BufferPoolManager, error) {
	config := &BufferPoolConfig{
		MaxPoolSize:       maxPoolSize,
		MinBufferSize:     64,        // 64 bytes
		MaxBufferSize:     64 * 1024, // 64KB
		GrowthFactor:      1.5,
		CleanupInterval:   30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxBuffersPerPool: 1000,
	}

	bpm := &BufferPoolManager{
		pools: make(map[BufferSize]*BufferPool),
		globalPool: &GlobalBufferPool{
			oversizedBuffers: make(map[BufferSize][]byte),
			specialPools:     make(map[BufferSize]*BufferPool),
			stats:            &GlobalPoolStats{},
		},
		allocationMap: make(map[uintptr]*BufferAllocation),
		stats:         &BufferPoolStats{},
		config:        config,
		shutdown:      make(chan struct{}),
	}

	// Initialize size classes
	bpm.initializeSizeClasses()

	// Start cleanup worker
	go bpm.cleanupWorker()

	return bpm, nil
}

// Allocate allocates a buffer of the requested size
func (bpm *BufferPoolManager) Allocate(size int, alignment int) ([]byte, error) {
	bpm.mu.Lock()
	defer bpm.mu.Unlock()

	// Handle oversized buffers
	if size > int(bpm.config.MaxBufferSize) {
		return bpm.allocateOversized(size)
	}

	// Get appropriate size class
	sizeClass := bpm.getSizeClass(size)

	// Get or create pool for this size class
	pool, exists := bpm.pools[sizeClass]
	if !exists {
		pool = bpm.createPool(sizeClass)
	}

	// Try to get buffer from pool
	var buf []byte
	select {
	case buf = <-pool.buffers:
		pool.hits++
		bpm.stats.TotalHits++
	default:
		// Pool is empty, allocate new buffer
		buf = make([]byte, int(sizeClass))
		pool.misses++
		bpm.stats.TotalMisses++
	}

	// Update statistics
	pool.allocations++
	bpm.stats.TotalAllocations++
	bpm.stats.CurrentUsage += int64(len(buf))
	if bpm.stats.CurrentUsage > bpm.stats.PeakUsage {
		bpm.stats.PeakUsage = bpm.stats.CurrentUsage
	}

	// Track allocation
	allocation := &BufferAllocation{
		Buffer:      buf,
		Pool:        pool,
		AllocatedAt: time.Now(),
		LastUsedAt:  time.Now(),
		Size:        size,
	}
	bpm.allocationMap[uintptr(unsafe.Pointer(&buf[0]))] = allocation

	pool.lastUsed = time.Now()
	bpm.stats.Timestamp = time.Now()

	return buf[:size], nil
}

// Free returns a buffer to the appropriate pool
func (bpm *BufferPoolManager) Free(buf []byte) error {
	bpm.mu.Lock()
	defer bpm.mu.Unlock()

	if len(buf) == 0 {
		return nil
	}

	// Get allocation metadata
	ptr := uintptr(unsafe.Pointer(&buf[0]))
	allocation, exists := bpm.allocationMap[ptr]
	if !exists {
		return fmt.Errorf("buffer not allocated by pool manager")
	}

	// Handle oversized buffers
	if len(buf) > int(bpm.config.MaxBufferSize) {
		return bpm.freeOversized(buf)
	}

	// Return to appropriate pool
	pool := allocation.Pool

	select {
	case pool.buffers <- buf[:cap(buf)]:
		// Successfully returned to pool
		pool.deallocations++
		bpm.stats.TotalDeallocations++

		// Update statistics
		bpm.stats.CurrentUsage -= int64(cap(buf))

	default:
		// Pool is full, let GC handle it
		bpm.stats.WastedMemory += int64(cap(buf))
	}

	// Remove from allocation map
	delete(bpm.allocationMap, ptr)

	pool.lastUsed = time.Now()
	bpm.stats.Timestamp = time.Now()

	return nil
}

// IsBufferPoolMemory checks if the buffer was allocated by the pool manager
func (bpm *BufferPoolManager) IsBufferPoolMemory(buf []byte) bool {
	bpm.mu.RLock()
	defer bpm.mu.RUnlock()

	if len(buf) == 0 {
		return false
	}

	ptr := uintptr(unsafe.Pointer(&buf[0]))
	_, exists := bpm.allocationMap[ptr]
	return exists
}

// MaxBufferSize returns the maximum buffer size managed by pools
func (bpm *BufferPoolManager) MaxBufferSize() int {
	return bpm.config.MaxBufferSize
}

// GetStats returns current buffer pool statistics
func (bpm *BufferPoolManager) GetStats() *BufferPoolStats {
	bpm.mu.RLock()
	defer bpm.mu.RUnlock()

	stats := *bpm.stats // Copy
	stats.Timestamp = time.Now()
	stats.PoolCount = len(bpm.pools)

	// Calculate current buffer count
	bufferCount := 0
	for _, pool := range bpm.pools {
		bufferCount += len(pool.buffers)
	}
	stats.BufferCount = bufferCount

	return &stats
}

// Shutdown cleanly stops the buffer pool manager
func (bpm *BufferPoolManager) Shutdown() error {
	close(bpm.shutdown)

	bpm.mu.Lock()
	defer bpm.mu.Unlock()

	// Clear all pools
	for _, pool := range bpm.pools {
		close(pool.buffers)
		for buf := range pool.buffers {
			// Let GC handle the buffers
			_ = buf
		}
	}

	bpm.pools = make(map[BufferSize]*BufferPool)
	bpm.allocationMap = make(map[uintptr]*BufferAllocation)
	bpm.stats = &BufferPoolStats{
		Timestamp: time.Now(),
	}

	return nil
}

// initializeSizeClasses creates buffer size classes using geometric progression
func (bpm *BufferPoolManager) initializeSizeClasses() {
	currentSize := bpm.config.MinBufferSize

	for currentSize <= bpm.config.MaxBufferSize {
		sizeClass := BufferSize(currentSize)
		bpm.pools[sizeClass] = bpm.createPool(sizeClass)

		// Geometric progression with factor
		currentSize = int(float64(currentSize) * bpm.config.GrowthFactor)
		if currentSize <= 0 {
			break
		}
	}
}

// createPool creates a new buffer pool for a specific size class
func (bpm *BufferPoolManager) createPool(sizeClass BufferSize) *BufferPool {
	pool := &BufferPool{
		size:     sizeClass,
		buffers:  make(chan []byte, bpm.config.MaxBuffersPerPool),
		stats:    &PoolStats{Size: sizeClass},
		lastUsed: time.Now(),
	}

	// Pre-fill pool with some buffers
	for i := 0; i < bpm.config.MaxPoolSize; i++ {
		select {
		case pool.buffers <- make([]byte, int(sizeClass)):
		default:
			break
		}
	}

	return pool
}

// getSizeClass finds the appropriate size class for a requested size
func (bpm *BufferPoolManager) getSizeClass(size int) BufferSize {
	// Find the smallest size class that fits the request
	var sizes []int
	for sizeClass := range bpm.pools {
		sizes = append(sizes, int(sizeClass))
	}

	if len(sizes) == 0 {
		return BufferSize(size)
	}

	// Sort sizes and find the best fit
	sort.Ints(sizes)
	for _, s := range sizes {
		if s >= size {
			return BufferSize(s)
		}
	}

	// Return largest available size class
	return BufferSize(sizes[len(sizes)-1])
}

// allocateOversized handles allocation of buffers larger than max size
func (bpm *BufferPoolManager) allocateOversized(size int) ([]byte, error) {
	bpm.globalPool.mu.Lock()
	defer bpm.globalPool.mu.Unlock()

	// Check if we have a cached oversized buffer
	sizeClass := BufferSize(size)
	if buffers, exists := bpm.globalPool.oversizedBuffers[sizeClass]; exists && len(buffers) > 0 {
		buf := buffers[0]
		bpm.globalPool.oversizedBuffers[sizeClass] = buffers[1:]
		bpm.globalPool.stats.CacheHits++

		// Track allocation
		allocation := &BufferAllocation{
			Buffer:      buf,
			AllocatedAt: time.Now(),
			LastUsedAt:  time.Now(),
			Size:        size,
		}
		bpm.allocationMap[uintptr(unsafe.Pointer(&buf[0]))] = allocation

		return buf[:size], nil
	}

	// Allocate new oversized buffer
	buf := make([]byte, size)
	bpm.globalPool.stats.CacheMisses++
	bpm.globalPool.stats.OversizedAllocations++
	bpm.globalPool.stats.OversizedMemory += int64(size)

	// Track allocation
	allocation := &BufferAllocation{
		Buffer:      buf,
		Pool:        nil, // Oversized buffers are not managed by regular pools
		AllocatedAt: time.Now(),
		LastUsedAt:  time.Now(),
		Size:        size,
	}
	bpm.allocationMap[uintptr(unsafe.Pointer(&buf[0]))] = allocation

	return buf, nil
}

// freeOversized handles freeing of oversized buffers
func (bpm *BufferPoolManager) freeOversized(buf []byte) error {
	bpm.globalPool.mu.Lock()
	defer bpm.globalPool.mu.Unlock()

	size := cap(buf)
	sizeClass := BufferSize(size)

	// Cache the buffer if we have space
	if len(bpm.globalPool.oversizedBuffers[sizeClass]) < 10 { // Max 10 cached per size
		bpm.globalPool.oversizedBuffers[sizeClass] = append(
			bpm.globalPool.oversizedBuffers[sizeClass],
			buf[:cap(buf)],
		)
	} else {
		// Let GC handle it
		bpm.globalPool.stats.OversizedMemory -= int64(size)
	}

	// Remove from allocation map
	ptr := uintptr(unsafe.Pointer(&buf[0]))
	delete(bpm.allocationMap, ptr)

	return nil
}

// cleanupWorker periodically cleans up idle pools and buffers
func (bpm *BufferPoolManager) cleanupWorker() {
	ticker := time.NewTicker(bpm.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-bpm.shutdown:
			return
		case <-ticker.C:
			bpm.cleanupIdlePools()
			bpm.cleanupIdleBuffers()
		}
	}
}

// cleanupIdlePools removes pools that haven't been used recently
func (bpm *BufferPoolManager) cleanupIdlePools() {
	bpm.mu.Lock()
	defer bpm.mu.Unlock()

	for sizeClass, pool := range bpm.pools {
		if time.Since(pool.lastUsed) > bpm.config.IdleTimeout {
			// Close and remove idle pool
			close(pool.buffers)
			for buf := range pool.buffers {
				// Let GC handle the buffers
				_ = buf
			}
			delete(bpm.pools, sizeClass)
		}
	}
}

// cleanupIdleBuffers removes buffers that haven't been used recently
func (bpm *BufferPoolManager) cleanupIdleBuffers() {
	bpm.mu.Lock()
	defer bpm.mu.Unlock()

	now := time.Now()
	for ptr, allocation := range bpm.allocationMap {
		if now.Sub(allocation.LastUsedAt) > bpm.config.IdleTimeout {
			// Free idle buffer
			if allocation.Pool != nil {
				select {
				case allocation.Pool.buffers <- allocation.Buffer:
				default:
					// Pool is full, let GC handle it
				}
			}
			delete(bpm.allocationMap, ptr)
		}
	}
}

// BatchAllocate allocates multiple buffers efficiently
func (bpm *BufferPoolManager) BatchAllocate(sizes []int) ([][]byte, error) {
	bpm.mu.Lock()
	defer bpm.mu.Unlock()

	results := make([][]byte, len(sizes))

	for i, size := range sizes {
		buf, err := bpm.Allocate(size, 0)
		if err != nil {
			// Free any already allocated buffers
			for j := 0; j < i; j++ {
				bpm.Free(results[j])
			}
			return nil, fmt.Errorf("batch allocation failed at index %d: %w", i, err)
		}
		results[i] = buf
	}

	return results, nil
}

// BatchFree frees multiple buffers efficiently
func (bpm *BufferPoolManager) BatchFree(buffers [][]byte) error {
	bpm.mu.Lock()
	defer bpm.mu.Unlock()

	for _, buf := range buffers {
		if err := bpm.Free(buf); err != nil {
			return fmt.Errorf("batch free failed: %w", err)
		}
	}

	return nil
}

// GetPoolStats returns statistics for a specific pool
func (bpm *BufferPoolManager) GetPoolStats(sizeClass BufferSize) (*PoolStats, error) {
	bpm.mu.RLock()
	defer bpm.mu.RUnlock()

	pool, exists := bpm.pools[sizeClass]
	if !exists {
		return nil, fmt.Errorf("pool not found for size class %d", sizeClass)
	}

	stats := *pool.stats // Copy
	stats.Available = len(pool.buffers)
	stats.Capacity = cap(pool.buffers)
	stats.HitRate = float64(pool.hits) / float64(pool.hits+pool.misses)

	return &stats, nil
}

// ResizePool adjusts the capacity of a pool
func (bpm *BufferPoolManager) ResizePool(sizeClass BufferSize, newCapacity int) error {
	bpm.mu.Lock()
	defer bpm.mu.Unlock()

	pool, exists := bpm.pools[sizeClass]
	if !exists {
		return fmt.Errorf("pool not found for size class %d", sizeClass)
	}

	// Create new channel with desired capacity
	newBuffers := make(chan []byte, newCapacity)

	// Transfer existing buffers
	close(pool.buffers)
	for buf := range pool.buffers {
		select {
		case newBuffers <- buf:
		default:
			// New capacity reached, discard excess
		}
	}

	pool.buffers = newBuffers
	return nil
}

// Defragment consolidates memory across pools
func (bpm *BufferPoolManager) Defragment() error {
	bpm.mu.Lock()
	defer bpm.mu.Unlock()

	// Implementation would consolidate fragmented memory
	// This is a placeholder for actual defragmentation logic

	return nil
}
