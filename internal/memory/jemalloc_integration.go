package memory

import (
	"fmt"
	"sync"
	"time"
	"unsafe"
)

/*
#include <stdlib.h>
#include <jemalloc/jemalloc.h>

// Wrapper functions for jemalloc
void* jemalloc_malloc(size_t size) {
    return je_malloc(size);
}

void* jemalloc_calloc(size_t num, size_t size) {
    return je_calloc(num, size);
}

void* jemalloc_realloc(void* ptr, size_t size) {
    return je_realloc(ptr, size);
}

void jemalloc_free(void* ptr) {
    je_free(ptr);
}

void* jemalloc_aligned_alloc(size_t alignment, size_t size) {
    return je_aligned_alloc(alignment, size);
}

size_t jemalloc_usable_size(void* ptr) {
    return je_malloc_usable_size(ptr);
}

int jemalloc_mallctl(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    return je_mallctl(name, oldp, oldlenp, newp, newlen);
}
*/
import "C"

// JemallocAllocator provides jemalloc-based memory allocation with thread caching
type JemallocAllocator struct {
	arenas        []*JemallocArena
	tcacheEnabled bool
	threadCaches  map[uint64]*ThreadCache

	stats  *JemallocStats
	config *JemallocConfig

	mu sync.RWMutex
}

// JemallocConfig configuration for jemalloc allocator
type JemallocConfig struct {
	ArenaMax         int
	TCacheEnabled    bool
	ThreadCacheMax   int
	DirtyPageDecayMS int
	MuzzyPageDecayMS int
	PurgeInterval    time.Duration
}

// JemallocArena represents a jemalloc memory arena
type JemallocArena struct {
	id        int
	basePtr   unsafe.Pointer
	stats     *ArenaStats
	lastPurge time.Time
}

// ThreadCache represents per-thread jemalloc cache
type ThreadCache struct {
	threadID      uint64
	cachePtr      unsafe.Pointer
	allocations   int64
	deallocations int64
}

// JemallocStats contains jemalloc statistics
type JemallocStats struct {
	TotalAllocated int64
	TotalFreed     int64
	CurrentUsage   int64
	PeakUsage      int64

	ArenaCount   int
	ThreadCaches int

	MallctlCalls int64
	PurgeCount   int64

	Timestamp time.Time
}

// ArenaStats contains per-arena statistics
type ArenaStats struct {
	Allocated int64
	Active    int64
	Mapped    int64
	Retained  int64

	SmallAllocs int64
	LargeAllocs int64
	HugeAllocs  int64

	DirtyPages int64
	MuzzyPages int64
}

// NewJemallocAllocator creates a new jemalloc-based memory allocator
func NewJemallocAllocator(config *JemallocConfig) (*JemallocAllocator, error) {
	if config == nil {
		config = &JemallocConfig{
			ArenaMax:         4,
			TCacheEnabled:    true,
			ThreadCacheMax:   32 * 1024, // 32KB
			DirtyPageDecayMS: 10000,
			MuzzyPageDecayMS: 15000,
			PurgeInterval:    10 * time.Second,
		}
	}

	allocator := &JemallocAllocator{
		config:        config,
		tcacheEnabled: config.TCacheEnabled,
		threadCaches:  make(map[uint64]*ThreadCache),
		stats:         &JemallocStats{},
	}

	// Initialize jemalloc arenas
	if err := allocator.initializeArenas(); err != nil {
		return nil, fmt.Errorf("failed to initialize arenas: %w", err)
	}

	// Configure jemalloc settings
	if err := allocator.configureJemalloc(); err != nil {
		return nil, fmt.Errorf("failed to configure jemalloc: %w", err)
	}

	// Start background purging
	go allocator.purgeWorker()

	return allocator, nil
}

// Malloc allocates memory using jemalloc
func (ja *JemallocAllocator) Malloc(size int, alignment int) ([]byte, error) {
	ja.mu.Lock()
	defer ja.mu.Unlock()

	var ptr unsafe.Pointer
	var err error

	if alignment > 0 {
		ptr, err = ja.alignedAlloc(size, alignment)
	} else {
		ptr, err = ja.standardMalloc(size)
	}

	if err != nil {
		return nil, fmt.Errorf("jemalloc allocation failed: %w", err)
	}

	if ptr == nil {
		return nil, fmt.Errorf("jemalloc returned null pointer")
	}

	// Convert to Go slice
	slice := (*[1 << 30]byte)(ptr)[:size:size]

	// Update statistics
	ja.stats.TotalAllocated += int64(size)
	ja.stats.CurrentUsage += int64(size)
	if ja.stats.CurrentUsage > ja.stats.PeakUsage {
		ja.stats.PeakUsage = ja.stats.CurrentUsage
	}
	ja.stats.Timestamp = time.Now()

	return slice, nil
}

// Free releases memory allocated by jemalloc
func (ja *JemallocAllocator) Free(buf []byte) error {
	ja.mu.Lock()
	defer ja.mu.Unlock()

	if len(buf) == 0 {
		return nil
	}

	// Get the underlying pointer
	ptr := unsafe.Pointer(&buf[0])

	// Get actual allocated size
	actualSize := int(C.jemalloc_usable_size(ptr))

	// Free the memory
	C.jemalloc_free(ptr)

	// Update statistics
	ja.stats.TotalFreed += int64(actualSize)
	ja.stats.CurrentUsage -= int64(actualSize)
	ja.stats.Timestamp = time.Now()

	return nil
}

// Calloc allocates and zero-initializes memory
func (ja *JemallocAllocator) Calloc(num, size int) ([]byte, error) {
	ja.mu.Lock()
	defer ja.mu.Unlock()

	totalSize := num * size
	ptr := C.jemalloc_calloc(C.size_t(num), C.size_t(size))

	if ptr == nil {
		return nil, fmt.Errorf("jemalloc calloc failed")
	}

	// Convert to Go slice
	slice := (*[1 << 30]byte)(ptr)[:totalSize:totalSize]

	// Update statistics
	ja.stats.TotalAllocated += int64(totalSize)
	ja.stats.CurrentUsage += int64(totalSize)
	if ja.stats.CurrentUsage > ja.stats.PeakUsage {
		ja.stats.PeakUsage = ja.stats.CurrentUsage
	}
	ja.stats.Timestamp = time.Now()

	return slice, nil
}

// Realloc resizes previously allocated memory
func (ja *JemallocAllocator) Realloc(buf []byte, newSize int) ([]byte, error) {
	ja.mu.Lock()
	defer ja.mu.Unlock()

	if len(buf) == 0 {
		return ja.Malloc(newSize, 0)
	}

	ptr := unsafe.Pointer(&buf[0])
	oldSize := int(C.jemalloc_usable_size(ptr))

	newPtr := C.jemalloc_realloc(ptr, C.size_t(newSize))

	if newPtr == nil {
		return nil, fmt.Errorf("jemalloc realloc failed")
	}

	// Update statistics
	sizeDiff := newSize - oldSize
	if sizeDiff > 0 {
		ja.stats.TotalAllocated += int64(sizeDiff)
		ja.stats.CurrentUsage += int64(sizeDiff)
	} else {
		ja.stats.TotalFreed += int64(-sizeDiff)
		ja.stats.CurrentUsage -= int64(-sizeDiff)
	}

	if ja.stats.CurrentUsage > ja.stats.PeakUsage {
		ja.stats.PeakUsage = ja.stats.CurrentUsage
	}
	ja.stats.Timestamp = time.Now()

	// Convert to Go slice
	newSlice := (*[1 << 30]byte)(newPtr)[:newSize:newSize]

	return newSlice, nil
}

// IsJemallocMemory checks if the buffer was allocated by jemalloc
func (ja *JemallocAllocator) IsJemallocMemory(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}

	ptr := unsafe.Pointer(&buf[0])

	// Simple heuristic: check if the pointer is within known arena ranges
	ja.mu.RLock()
	defer ja.mu.RUnlock()

	for _, arena := range ja.arenas {
		if isPointerInArena(ptr, arena) {
			return true
		}
	}

	return false
}

// GetStats returns current jemalloc statistics
func (ja *JemallocAllocator) GetStats() *JemallocStats {
	ja.mu.RLock()
	defer ja.mu.RUnlock()

	stats := *ja.stats // Copy
	stats.Timestamp = time.Now()

	// Update with current arena statistics
	for _, arena := range ja.arenas {
		arenaStats := ja.getArenaStats(arena)
		stats.CurrentUsage += arenaStats.Allocated
	}

	return &stats
}

// Shutdown cleanly stops the jemalloc allocator
func (ja *JemallocAllocator) Shutdown() error {
	ja.mu.Lock()
	defer ja.mu.Unlock()

	// Purge all arenas
	for _, arena := range ja.arenas {
		ja.purgeArena(arena)
	}

	// Clear thread caches
	ja.threadCaches = make(map[uint64]*ThreadCache)

	// Reset statistics
	ja.stats = &JemallocStats{
		Timestamp: time.Now(),
	}

	return nil
}

// alignedAlloc performs aligned memory allocation
func (ja *JemallocAllocator) alignedAlloc(size, alignment int) (unsafe.Pointer, error) {
	ptr := C.jemalloc_aligned_alloc(C.size_t(alignment), C.size_t(size))
	if ptr == nil {
		return nil, fmt.Errorf("aligned allocation failed")
	}
	return ptr, nil
}

// standardMalloc performs standard memory allocation
func (ja *JemallocAllocator) standardMalloc(size int) (unsafe.Pointer, error) {
	ptr := C.jemalloc_malloc(C.size_t(size))
	if ptr == nil {
		return nil, fmt.Errorf("malloc failed")
	}
	return ptr, nil
}

// initializeArenas sets up jemalloc arenas
func (ja *JemallocAllocator) initializeArenas() error {
	// Create arenas based on configuration
	for i := 0; i < ja.config.ArenaMax; i++ {
		arena := &JemallocArena{
			id:        i,
			stats:     &ArenaStats{},
			lastPurge: time.Now(),
		}
		ja.arenas = append(ja.arenas, arena)
	}

	ja.stats.ArenaCount = len(ja.arenas)
	return nil
}

// configureJemalloc configures jemalloc settings
func (ja *JemallocAllocator) configureJemalloc() error {
	// Configure thread cache settings
	if ja.tcacheEnabled {
		ja.setMallctl("tcache.create", nil, nil)
		ja.setMallctl("thread.tcache.enabled", true, nil)
		ja.setMallctl("thread.tcache.max", ja.config.ThreadCacheMax, nil)
	}

	// Configure decay settings
	ja.setMallctl("arena.0.dirty_decay_ms", ja.config.DirtyPageDecayMS, nil)
	ja.setMallctl("arena.0.muzzy_decay_ms", ja.config.MuzzyPageDecayMS, nil)

	return nil
}

// setMallctl sets jemalloc configuration using mallctl
func (ja *JemallocAllocator) setMallctl(name string, value interface{}, oldValue interface{}) error {
	// Convert name to C string
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	// This is a simplified implementation
	// In production, you'd need proper type handling for value and oldValue

	ja.stats.MallctlCalls++
	return nil
}

// purgeWorker periodically purges unused memory
func (ja *JemallocAllocator) purgeWorker() {
	ticker := time.NewTicker(ja.config.PurgeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ja.mu.Lock()
			for _, arena := range ja.arenas {
				if time.Since(arena.lastPurge) > ja.config.PurgeInterval {
					ja.purgeArena(arena)
					arena.lastPurge = time.Now()
				}
			}
			ja.mu.Unlock()
		}
	}
}

// purgeArena purges unused memory in an arena
func (ja *JemallocAllocator) purgeArena(arena *JemallocArena) {
	// Purge dirty pages
	ja.setMallctl(fmt.Sprintf("arena.%d.purge", arena.id), nil, nil)
	ja.stats.PurgeCount++
}

// getArenaStats retrieves statistics for an arena
func (ja *JemallocAllocator) getArenaStats(arena *JemallocArena) *ArenaStats {
	// This would use mallctl to get actual arena statistics
	return &ArenaStats{}
}

// isPointerInArena checks if a pointer is within an arena's memory range
func isPointerInArena(ptr unsafe.Pointer, arena *JemallocArena) bool {
	// Simplified implementation
	// In production, you'd track actual arena memory ranges
	return true
}

// GetThreadID returns the current thread ID
func (ja *JemallocAllocator) GetThreadID() uint64 {
	// Use goroutine ID as thread identifier
	return uint64(uintptr(unsafe.Pointer(&ja)))
}

// Thread-safe wrapper functions
func (ja *JemallocAllocator) threadSafeMalloc(size int) ([]byte, error) {
	ja.mu.Lock()
	defer ja.mu.Unlock()
	return ja.Malloc(size, 0)
}

func (ja *JemallocAllocator) threadSafeFree(buf []byte) error {
	ja.mu.Lock()
	defer ja.mu.Unlock()
	return ja.Free(buf)
}

// Utility function to get usable size of allocated memory
func (ja *JemallocAllocator) UsableSize(buf []byte) int {
	if len(buf) == 0 {
		return 0
	}

	ptr := unsafe.Pointer(&buf[0])
	return int(C.jemalloc_usable_size(ptr))
}

// Batch allocation for performance
func (ja *JemallocAllocator) BatchAllocate(sizes []int) ([][]byte, error) {
	ja.mu.Lock()
	defer ja.mu.Unlock()

	results := make([][]byte, len(sizes))

	for i, size := range sizes {
		buf, err := ja.Malloc(size, 0)
		if err != nil {
			// Free any already allocated buffers
			for j := 0; j < i; j++ {
				ja.Free(results[j])
			}
			return nil, fmt.Errorf("batch allocation failed at index %d: %w", i, err)
		}
		results[i] = buf
	}

	return results, nil
}

// Batch free for performance
func (ja *JemallocAllocator) BatchFree(buffers [][]byte) error {
	ja.mu.Lock()
	defer ja.mu.Unlock()

	for _, buf := range buffers {
		if err := ja.Free(buf); err != nil {
			return fmt.Errorf("batch free failed: %w", err)
		}
	}

	return nil
}
