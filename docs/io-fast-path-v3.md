# I/O Fast Path Fragment V3 - Design Specification

## Overview

The **I/O Fast Path Fragment** leverages kernel 6.11+ io_uring capabilities and content-addressed storage to achieve 2-4× Docker I/O performance. It provides zero-copy operations, atomic writes, and intelligent caching for LLM workloads.

## Architecture Design

### Core Components

```go
type IOFastPathV3 struct {
    // io_uring integration
    ring               *IOUringContext
    fixedBuffers       [][]byte
    fixedFiles         []int
    registeredBuffers  *RegisteredBufferPool
    
    // Content-addressed storage
    casStore           *ContentAddressedStore
    dedupEngine        *DeduplicationEngine
    atomicWriter       *AtomicWriteEngine
    
    // Performance optimization
    prefetcher         *IntelligentPrefetcher
    compressionEngine  *CompressionEngine
    cacheManager       *MultiTierCache
    
    // Cross-platform support
    wasmVFS           *WasmVirtualFS
    fallbackIO        *FallbackIOHandler
    
    // Monitoring and metrics
    metrics           *IOPerformanceMetrics
    profiler          *IOProfiler
    congestionControl *IOCongestionControl
    
    // Configuration
    config            *IOFastPathConfig
}

// io_uring context with V3 enhancements
type IOUringContext struct {
    ring              *io_uring.Ring
    sqePool           *SQEPool           // Submission queue entry pool
    cqeProcessor      *CQEProcessor      // Completion queue event processor
    
    // Enhanced features (kernel 6.11+)
    atomicSupport     bool               // Atomic write support
    multiShotSupport  bool               // Multi-shot operations
    bufferRingSupport bool               // Buffer ring for zero-copy
    
    // Performance optimization
    batchProcessor    *BatchProcessor
    ioScheduler       *IOScheduler
    completionTracker *CompletionTracker
    
    // Resource management
    resourceLimiter   *IOResourceLimiter
    backpressure      *BackpressureManager
}

// Content-addressed storage with atomic operations
type ContentAddressedStore struct {
    // Storage backend
    storageBackend    StorageBackend
    indexManager      *CASIndexManager
    
    // Atomic operations (kernel 6.11+)
    atomicWriter      *AtomicWriteEngine
    transactionLog    *TransactionLog
    
    // Deduplication
    dedupEngine       *DeduplicationEngine
    hashIndex         map[string]*ContentEntry
    refCounter        map[string]int64
    
    // Performance optimization
    hotDataCache      *HotDataCache
    compressionPool   *CompressionPool
    prefetchHints     *PrefetchHintEngine
    
    // Garbage collection
    gcManager         *GarbageCollector
    cleanupScheduler  *CleanupScheduler
}
```

## io_uring Integration with Kernel 6.11+ Features

### Enhanced io_uring Operations

```go
// High-performance batch I/O operations
func (io *IOFastPathV3) BatchFileOperations(ops []FileOperation) (*BatchResult, error) {
    start := time.Now()
    
    // Phase 1: Validate and prepare operations
    preparedOps, err := io.prepareOperations(ops)
    if err != nil {
        return nil, fmt.Errorf("operation preparation failed: %w", err)
    }
    
    // Phase 2: Submit batch to io_uring
    batchID := io.ring.batchProcessor.SubmitBatch(preparedOps)
    
    // Phase 3: Wait for completion with timeout
    results, err := io.ring.completionTracker.WaitForBatch(batchID, 30*time.Second)
    if err != nil {
        return nil, fmt.Errorf("batch completion failed: %w", err)
    }
    
    // Phase 4: Process results and update metrics
    batchResult := &BatchResult{
        Operations:    len(ops),
        Successful:    0,
        Failed:        0,
        TotalBytes:    0,
        Duration:      time.Since(start),
        Results:       make([]*OperationResult, len(ops)),
    }
    
    for i, result := range results {
        batchResult.Results[i] = result
        if result.Success {
            batchResult.Successful++
            batchResult.TotalBytes += result.BytesProcessed
        } else {
            batchResult.Failed++
        }
    }
    
    // Record performance metrics
    io.metrics.RecordBatchOperation(batchResult)
    
    return batchResult, nil
}

// Atomic write operations using kernel 6.11+ features
func (io *IOFastPathV3) AtomicWrite(path string, data []byte, options *AtomicWriteOptions) error {
    if !io.ring.atomicSupport {
        // Fallback to traditional write with fsync
        return io.fallbackAtomicWrite(path, data, options)
    }
    
    // Use kernel atomic write support
    sqe := io.ring.sqePool.Get()
    defer io.ring.sqePool.Put(sqe)
    
    // Configure atomic write operation
    sqe.Opcode = io_uring.IORING_OP_WRITE_ATOMIC
    sqe.FD = options.FileDescriptor
    sqe.Addr = uintptr(unsafe.Pointer(&data[0]))
    sqe.Len = uint32(len(data))
    sqe.Offset = uint64(options.Offset)
    
    // Set atomic write flags
    sqe.Flags |= io_uring.IOSQE_ATOMIC_WRITE
    if options.SyncAfter {
        sqe.Flags |= io_uring.IOSQE_IO_DRAIN
    }
    
    // Submit and wait for completion
    completion, err := io.ring.SubmitAndWait(sqe)
    if err != nil {
        return fmt.Errorf("atomic write failed: %w", err)
    }
    
    if completion.Result < 0 {
        return fmt.Errorf("atomic write error: %d", completion.Result)
    }
    
    io.metrics.RecordAtomicWrite(len(data), time.Since(start))
    return nil
}

// Zero-copy file operations using registered buffers
func (io *IOFastPathV3) ZeroCopyRead(fd int, offset int64, size int) ([]byte, error) {
    // Get registered buffer from pool
    buffer, err := io.registeredBuffers.GetBuffer(size)
    if err != nil {
        return nil, fmt.Errorf("buffer allocation failed: %w", err)
    }
    defer io.registeredBuffers.ReturnBuffer(buffer)
    
    // Prepare io_uring operation with registered buffer
    sqe := io.ring.sqePool.Get()
    defer io.ring.sqePool.Put(sqe)
    
    sqe.Opcode = io_uring.IORING_OP_READ
    sqe.FD = int32(fd)
    sqe.Addr = uintptr(unsafe.Pointer(&buffer.Data[0]))
    sqe.Len = uint32(size)
    sqe.Offset = uint64(offset)
    sqe.Flags = io_uring.IOSQE_FIXED_BUFFER  // Use registered buffer
    sqe.BufIndex = uint16(buffer.Index)      // Buffer index in registration
    
    // Submit and wait
    completion, err := io.ring.SubmitAndWait(sqe)
    if err != nil {
        return nil, fmt.Errorf("zero-copy read failed: %w", err)
    }
    
    if completion.Result < 0 {
        return nil, fmt.Errorf("read error: %d", completion.Result)
    }
    
    // Return slice of actual data read
    bytesRead := int(completion.Result)
    result := make([]byte, bytesRead)
    copy(result, buffer.Data[:bytesRead])
    
    io.metrics.RecordZeroCopyOperation("read", bytesRead)
    return result, nil
}
```

### Multi-Shot Operations for High Throughput

```go
// Multi-shot file monitoring for hot reload scenarios
func (io *IOFastPathV3) WatchFileChanges(paths []string) (*FileWatcher, error) {
    if !io.ring.multiShotSupport {
        return io.fallbackFileWatcher(paths)
    }
    
    watcher := &FileWatcher{
        paths:        paths,
        events:       make(chan *FileEvent, 1000),
        ring:         io.ring,
        activeWatches: make(map[string]*WatchEntry),
    }
    
    // Set up multi-shot inotify operations
    for _, path := range paths {
        sqe := io.ring.sqePool.Get()
        
        sqe.Opcode = io_uring.IORING_OP_INOTIFY_WATCH
        sqe.FD = int32(watcher.inotifyFD)
        sqe.Addr = uintptr(unsafe.Pointer(unix.StringBytePtr(path)))
        sqe.Len = uint32(len(path))
        sqe.Flags = io_uring.IOSQE_MULTI_SHOT  // Multi-shot for continuous monitoring
        
        // Submit without waiting (async monitoring)
        if err := io.ring.Submit(sqe); err != nil {
            return nil, fmt.Errorf("watch setup failed for %s: %w", path, err)
        }
        
        watcher.activeWatches[path] = &WatchEntry{
            Path: path,
            SQE:  sqe,
        }
    }
    
    // Start event processing
    go watcher.processEvents()
    
    return watcher, nil
}
```

## Content-Addressed Storage with Atomic Operations

### CAS Implementation with Deduplication

```go
// Store content with automatic deduplication
func (cas *ContentAddressedStore) StoreContent(content []byte, metadata *ContentMetadata) (*ContentHash, error) {
    start := time.Now()
    
    // Phase 1: Calculate content hash
    hasher := sha256.New()
    hasher.Write(content)
    hash := hex.EncodeToString(hasher.Sum(nil))
    
    // Phase 2: Check if content already exists
    if entry, exists := cas.hashIndex[hash]; exists {
        // Content exists, increment reference count
        atomic.AddInt64(&cas.refCounter[hash], 1)
        cas.metrics.RecordDeduplication(len(content))
        
        return &ContentHash{
            Hash:     hash,
            Size:     entry.Size,
            Existing: true,
        }, nil
    }
    
    // Phase 3: Compress content if beneficial
    compressed, compressionType := cas.compressionPool.CompressIfBeneficial(content)
    
    // Phase 4: Store content atomically
    contentPath := cas.getContentPath(hash)
    if err := cas.atomicWriter.WriteAtomic(contentPath, compressed); err != nil {
        return nil, fmt.Errorf("atomic write failed: %w", err)
    }
    
    // Phase 5: Update index atomically
    entry := &ContentEntry{
        Hash:            hash,
        Size:            int64(len(content)),
        CompressedSize:  int64(len(compressed)),
        CompressionType: compressionType,
        StoragePath:     contentPath,
        CreatedAt:       start,
        Metadata:        metadata,
    }
    
    if err := cas.indexManager.UpdateIndex(hash, entry); err != nil {
        // Cleanup on index update failure
        os.Remove(contentPath)
        return nil, fmt.Errorf("index update failed: %w", err)
    }
    
    // Phase 6: Update in-memory structures
    cas.hashIndex[hash] = entry
    cas.refCounter[hash] = 1
    
    // Phase 7: Add to hot cache if frequently accessed
    if cas.hotDataCache.ShouldCache(hash, metadata) {
        cas.hotDataCache.Add(hash, content)
    }
    
    cas.metrics.RecordContentStore(len(content), len(compressed), time.Since(start))
    
    return &ContentHash{
        Hash:     hash,
        Size:     entry.Size,
        Existing: false,
    }, nil
}

// Retrieve content with intelligent caching
func (cas *ContentAddressedStore) RetrieveContent(hash string) ([]byte, error) {
    start := time.Now()
    
    // Phase 1: Check hot cache first
    if content, found := cas.hotDataCache.Get(hash); found {
        cas.metrics.RecordCacheHit("hot", len(content))
        return content, nil
    }
    
    // Phase 2: Get content entry from index
    entry, exists := cas.hashIndex[hash]
    if !exists {
        return nil, fmt.Errorf("content not found: %s", hash)
    }
    
    // Phase 3: Read compressed content
    compressed, err := cas.readContentFile(entry.StoragePath)
    if err != nil {
        return nil, fmt.Errorf("content read failed: %w", err)
    }
    
    // Phase 4: Decompress if needed
    var content []byte
    if entry.CompressionType != CompressionTypeNone {
        content, err = cas.compressionPool.Decompress(compressed, entry.CompressionType)
        if err != nil {
            return nil, fmt.Errorf("decompression failed: %w", err)
        }
    } else {
        content = compressed
    }
    
    // Phase 5: Update hot cache
    cas.hotDataCache.Add(hash, content)
    
    cas.metrics.RecordContentRetrieve(len(content), time.Since(start))
    return content, nil
}

// Atomic file operations with transaction support
type AtomicWriteEngine struct {
    transactionLog *TransactionLog
    tempDir        string
    fsyncPolicy    FsyncPolicy
}

func (awe *AtomicWriteEngine) WriteAtomic(path string, data []byte) error {
    // Phase 1: Create temporary file
    tempPath := path + ".tmp." + generateRandomSuffix()
    
    // Phase 2: Write to temporary file
    if err := awe.writeToTemp(tempPath, data); err != nil {
        return fmt.Errorf("temp write failed: %w", err)
    }
    
    // Phase 3: Sync to disk (if policy requires)
    if awe.fsyncPolicy.RequireSync {
        if err := awe.syncFile(tempPath); err != nil {
            os.Remove(tempPath)
            return fmt.Errorf("fsync failed: %w", err)
        }
    }
    
    // Phase 4: Atomic rename
    if err := os.Rename(tempPath, path); err != nil {
        os.Remove(tempPath)
        return fmt.Errorf("atomic rename failed: %w", err)
    }
    
    // Phase 5: Sync directory (ensures rename is persistent)
    if awe.fsyncPolicy.SyncDirectory {
        if err := awe.syncDirectory(filepath.Dir(path)); err != nil {
            // Already renamed, but log the warning
            log.Warnf("Directory sync failed for %s: %v", path, err)
        }
    }
    
    return nil
}
```

## Intelligent Prefetching and Caching

### Multi-Tier Cache Architecture

```go
type MultiTierCache struct {
    // Cache tiers
    l1Cache        *L1Cache         // Hot data in memory
    l2Cache        *L2Cache         // Warm data compressed in memory
    l3Cache        *L3Cache         // Cold data on fast storage
    
    // Cache coordination
    promotionEngine *PromotionEngine
    evictionPolicy  *EvictionPolicy
    prefetcher      *IntelligentPrefetcher
    
    // Performance optimization
    accessTracker   *AccessTracker
    heatMap         *HeatMap
    compressionPool *CompressionPool
    
    // Configuration
    config          *CacheConfig
}

// Intelligent prefetching based on access patterns
type IntelligentPrefetcher struct {
    // Pattern analysis
    patternAnalyzer   *AccessPatternAnalyzer
    sequentialTracker *SequentialAccessTracker
    spatialTracker    *SpatialLocalityTracker
    
    // ML prediction
    accessPredictor   *AccessPredictor
    confidenceModel   *ConfidenceModel
    
    // Prefetch execution
    prefetchQueue     *PrefetchQueue
    prefetchWorkers   []*PrefetchWorker
    
    // Performance tracking
    hitRateTracker    *HitRateTracker
    wasteTracker      *WasteTracker
}

// Predict and prefetch based on access patterns
func (ip *IntelligentPrefetcher) PredictAndPrefetch(currentAccess *AccessEvent) {
    // Phase 1: Analyze current access pattern
    pattern := ip.patternAnalyzer.AnalyzeAccess(currentAccess)
    
    // Phase 2: Generate predictions
    predictions := ip.generatePredictions(pattern, currentAccess)
    
    // Phase 3: Filter predictions by confidence
    highConfidencePredictions := ip.filterByConfidence(predictions, 0.7)
    
    // Phase 4: Queue prefetch operations
    for _, prediction := range highConfidencePredictions {
        prefetchOp := &PrefetchOperation{
            Hash:       prediction.Hash,
            Priority:   prediction.Priority,
            Confidence: prediction.Confidence,
            Deadline:   time.Now().Add(prediction.TimeWindow),
        }
        
        ip.prefetchQueue.Enqueue(prefetchOp)
    }
    
    // Phase 5: Update ML model with feedback
    go ip.updateModel(currentAccess, predictions)
}

// Sequential access detection and prefetching
func (ip *IntelligentPrefetcher) handleSequentialAccess(access *AccessEvent) {
    sequence := ip.sequentialTracker.GetSequence(access)
    if sequence == nil {
        return
    }
    
    // Predict next items in sequence
    nextItems := sequence.PredictNext(5) // Prefetch next 5 items
    
    for i, item := range nextItems {
        priority := PriorityHigh - PriorityLevel(i) // Decreasing priority
        
        prefetchOp := &PrefetchOperation{
            Hash:     item.Hash,
            Priority: priority,
            Confidence: sequence.Confidence * (0.9 - float64(i)*0.1),
            Type:     PrefetchTypeSequential,
        }
        
        ip.prefetchQueue.Enqueue(prefetchOp)
    }
}
```

## Cross-Platform Support with WebAssembly

### Wasm Virtual Filesystem

```go
type WasmVirtualFS struct {
    // Virtual filesystem
    vfsRoot         *VFSNode
    mountPoints     map[string]*MountPoint
    
    // Host filesystem bridge
    hostBridge      *HostFSBridge
    casIntegration  *CASIntegration
    
    // Performance optimization
    vfsCache        *VFSCache
    prefetchEngine  *VFSPrefetcher
    
    // WASI integration
    wasiFS          *WasiFilesystem
    permissions     *WasiPermissions
}

// High-performance VFS operations for Wasm
func (wvfs *WasmVirtualFS) ReadFile(path string) ([]byte, error) {
    // Phase 1: Resolve virtual path
    realPath, err := wvfs.resolvePath(path)
    if err != nil {
        return nil, fmt.Errorf("path resolution failed: %w", err)
    }
    
    // Phase 2: Check VFS cache
    if content, found := wvfs.vfsCache.Get(realPath); found {
        return content, nil
    }
    
    // Phase 3: Check if content is in CAS
    if hash, found := wvfs.casIntegration.GetHashForPath(realPath); found {
        content, err := wvfs.casIntegration.RetrieveContent(hash)
        if err == nil {
            wvfs.vfsCache.Set(realPath, content)
            return content, nil
        }
    }
    
    // Phase 4: Read from host filesystem through bridge
    content, err := wvfs.hostBridge.ReadFile(realPath)
    if err != nil {
        return nil, fmt.Errorf("host read failed: %w", err)
    }
    
    // Phase 5: Cache for future access
    wvfs.vfsCache.Set(realPath, content)
    
    // Phase 6: Store in CAS for deduplication
    go func() {
        wvfs.casIntegration.StoreContent(content, &ContentMetadata{
            Path:      realPath,
            VirtualPath: path,
            CreatedAt: time.Now(),
        })
    }()
    
    return content, nil
}
```

## Performance Monitoring and Optimization

### Real-Time I/O Performance Tracking

```go
type IOPerformanceMetrics struct {
    // Throughput metrics
    ReadThroughput     *ThroughputTracker
    WriteThroughput    *ThroughputTracker
    
    // Latency metrics
    ReadLatency        *LatencyTracker
    WriteLatency       *LatencyTracker
    BatchLatency       *LatencyTracker
    
    // Cache performance
    CacheHitRate       *HitRateTracker
    CacheEvictionRate  *EvictionTracker
    
    // io_uring specific
    QueueDepth         *GaugeMetric
    SubmissionRate     *RateMetric
    CompletionRate     *RateMetric
    
    // CAS performance
    DeduplicationRate  *RateMetric
    CompressionRatio   *RatioMetric
    StorageEfficiency  *EfficiencyMetric
}

// Real-time performance optimization
func (io *IOFastPathV3) OptimizePerformance() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            io.performOptimizationCycle()
        case <-io.shutdown:
            return
        }
    }
}

func (io *IOFastPathV3) performOptimizationCycle() {
    // Get current performance metrics
    metrics := io.metrics.GetCurrentMetrics()
    
    // Optimize io_uring parameters
    io.optimizeIOUring(metrics)
    
    // Optimize cache configuration
    io.optimizeCache(metrics)
    
    // Optimize prefetching
    io.optimizePrefetching(metrics)
    
    // Optimize compression
    io.optimizeCompression(metrics)
}

func (io *IOFastPathV3) optimizeIOUring(metrics *IOMetrics) {
    // Adjust queue depth based on latency and throughput
    currentQueueDepth := io.ring.GetQueueDepth()
    targetThroughput := metrics.TargetThroughput
    actualThroughput := metrics.ActualThroughput
    avgLatency := metrics.AverageLatency
    
    if actualThroughput < targetThroughput*0.9 && avgLatency < 5*time.Millisecond {
        // Increase queue depth for better throughput
        newQueueDepth := min(currentQueueDepth*2, io.config.MaxQueueDepth)
        io.ring.SetQueueDepth(newQueueDepth)
    } else if avgLatency > 10*time.Millisecond {
        // Decrease queue depth for better latency
        newQueueDepth := max(currentQueueDepth/2, io.config.MinQueueDepth)
        io.ring.SetQueueDepth(newQueueDepth)
    }
}
```

## Implementation Plan

### Phase 1: Core io_uring Integration (Week 1-2)
- [ ] Implement IOUringContext with kernel 6.11+ features
- [ ] Atomic write operations support
- [ ] Multi-shot operation handling
- [ ] Zero-copy buffer management

### Phase 2: Content-Addressed Storage (Week 2-3)
- [ ] CAS implementation with deduplication
- [ ] Atomic write engine
- [ ] Transaction log for consistency
- [ ] Garbage collection and cleanup

### Phase 3: Performance Optimization (Week 3-4)
- [ ] Multi-tier caching system
- [ ] Intelligent prefetching engine
- [ ] Real-time performance monitoring
- [ ] Cross-platform Wasm VFS support

### Phase 4: Testing and Validation (Week 4)
- [ ] I/O performance benchmarking
- [ ] Atomic operation validation
- [ ] Cross-platform compatibility testing
- [ ] Stress testing under high load

## Success Criteria

### Performance Targets
- [ ] **Throughput**: >2.5GB/s sustained I/O performance
- [ ] **Latency**: <1ms average I/O latency for cached operations
- [ ] **Deduplication**: >60% storage savings for typical workloads
- [ ] **Cache Hit Rate**: >85% for hot data access
- [ ] **Atomic Operations**: <5ms for atomic write operations

### Reliability Metrics
- [ ] **Data Consistency**: 100% atomic operation guarantees
- [ ] **Crash Recovery**: <100ms recovery time after system crash
- [ ] **Error Handling**: Graceful fallback for all failure modes
- [ ] **Cross-Platform**: <20% performance variance across platforms

### Scalability Validation
- [ ] Linear throughput scaling with additional I/O workers
- [ ] Efficient memory usage under high concurrency
- [ ] Proper backpressure handling under extreme load
- [ ] Stable performance with large CAS stores (>1TB)

The I/O Fast Path Fragment provides the high-performance I/O foundation needed to achieve Phantom Fragment V3's ambitious throughput and latency targets while maintaining data consistency and cross-platform compatibility.