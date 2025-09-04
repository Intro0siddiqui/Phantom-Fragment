// Package memory provides lightweight memory management utilities
package memory

import (
	"sync"
)

// BufferPool provides simple buffer pooling for performance
// This is a lightweight alternative to the complex memory discipline

type BufferPool struct {
	pools     map[int]*bufferPool
	minSize   int
	maxSize   int
	mu        sync.RWMutex
}

type bufferPool struct {
	buffers [][]byte
	mu      sync.Mutex
}

// NewBufferPool creates a new buffer pool with specified max size
func NewBufferPool(maxSize int) *BufferPool {
	return &BufferPool{
		pools:   make(map[int]*bufferPool),
		minSize: 64,
		maxSize: maxSize,
	}
}

// Allocate returns a buffer of the requested size
func (bp *BufferPool) Allocate(size int) []byte {
	if size <= 0 || size > bp.maxSize {
		return make([]byte, size)
	}

	// Round up to nearest power of 2
	poolSize := bp.roundUpPowerOfTwo(size)
	
	bp.mu.RLock()
	pool, exists := bp.pools[poolSize]
	bp.mu.RUnlock()
	
	if !exists {
		bp.mu.Lock()
		if bp.pools[poolSize] == nil {
			bp.pools[poolSize] = &bufferPool{buffers: make([][]byte, 0, 1024)}
		}
		pool = bp.pools[poolSize]
		bp.mu.Unlock()
	}

	return pool.get(poolSize)
}

// Free returns a buffer to the pool
func (bp *BufferPool) Free(buf []byte) {
	if len(buf) == 0 || len(buf) > bp.maxSize {
		return
	}

	poolSize := bp.roundUpPowerOfTwo(len(buf))
	
	bp.mu.RLock()
	pool, exists := bp.pools[poolSize]
	bp.mu.RUnlock()
	
	if exists {
		pool.put(buf)
	}
}

// get retrieves a buffer from the pool
func (p *bufferPool) get(size int) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.buffers) > 0 {
		buf := p.buffers[len(p.buffers)-1]
		p.buffers = p.buffers[:len(p.buffers)-1]
		return buf[:size]
	}

	return make([]byte, size)
}

// put returns a buffer to the pool
func (p *bufferPool) put(buf []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Reset buffer to prevent memory leaks
	for i := range buf {
		buf[i] = 0
	}
	
	if len(p.buffers) < 4096 { // Limit pool size
		p.buffers = append(p.buffers, buf)
	}
}

// roundUpPowerOfTwo rounds up to the nearest power of 2
func (bp *BufferPool) roundUpPowerOfTwo(size int) int {
	size--
	size |= size >> 1
	size |= size >> 2
	size |= size >> 4
	size |= size >> 8
	size |= size >> 16
	size++
	if size < bp.minSize {
		return bp.minSize
	}
	return size
}

// Stats returns pool statistics
func (bp *BufferPool) Stats() BufferPoolStats {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	stats := BufferPoolStats{
		Pools: len(bp.pools),
	}

	for size, pool := range bp.pools {
		pool.mu.Lock()
		stats.TotalBuffers += len(pool.buffers)
		stats.PoolSizes = append(stats.PoolSizes, size)
		pool.mu.Unlock()
	}

	return stats
}

// BufferPoolStats contains buffer pool statistics
type BufferPoolStats struct {
	Pools        int
	TotalBuffers int
	PoolSizes    []int
}

// SimpleAllocator provides a simple memory allocator interface
type SimpleAllocator struct {
	pool *BufferPool
}

// NewSimpleAllocator creates a new simple allocator
func NewSimpleAllocator(maxSize int) *SimpleAllocator {
	return &SimpleAllocator{
		pool: NewBufferPool(maxSize),
	}
}

// Malloc allocates memory
func (sa *SimpleAllocator) Malloc(size int) []byte {
	return sa.pool.Allocate(size)
}

// Free deallocates memory
func (sa *SimpleAllocator) Free(buf []byte) {
	sa.pool.Free(buf)
}

// GetStats returns allocator statistics
func (sa *SimpleAllocator) GetStats() BufferPoolStats {
	return sa.pool.Stats()
}