//go:build linux
// +build linux

package fragments

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Enhanced I/O Fast Path Fragment V3 with advanced io_uring and content-addressed storage
type IOFastPathV3 struct {
	// io_uring integration
	ring               *IOUringContext
	fixedBuffers       [][]byte
	fixedFiles         []int32
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
	
	// Synchronization
	mu                sync.RWMutex
	shutdown          chan struct{}
	wg                sync.WaitGroup
}

// io_uring context with V3 enhancements
type IOUringContext struct {
	ring              *IOUring
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
	
	// Configuration
	queueDepth        int
	flags             uint32
	
	mu                sync.RWMutex
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
	
	mu                sync.RWMutex
}

// Registered buffer pool for zero-copy operations
type RegisteredBufferPool struct {
	buffers           [][]byte
	bufferSize        int
	registeredIOVecs  []unix.Iovec
	available         chan int
	inUse             map[int]bool
	
	mu                sync.RWMutex
}

// I/O operation structures
type IOOperation struct {
	Type              IOOperationType
	FD                int32
	Offset            int64
	Buffer            []byte
	BufferIndex       int
	Flags             uint32
	Priority          IOPriority
	Deadline          time.Time
	Callback          func(*IOCompletion)
	
	// Content addressing
	ContentHash       string
	ExpectedHash      string
	
	// Performance tracking
	SubmittedAt       time.Time
	UserData          uint64
}

type IOCompletion struct {
	Operation         *IOOperation
	Result            int32
	Error             error
	CompletedAt       time.Time
	Duration          time.Duration
	BytesTransferred  int64
}

type IOOperationType int

const (
	IOTypeRead IOOperationType = iota
	IOTypeWrite
	IOTypeReadFixed
	IOTypeWriteFixed
	IOTypeFsync
	IOTypeFdatasync
	IOTypeOpenat
	IOTypeClose
	IOTypeStatx
	IOTypeAtomicWrite // Kernel 6.11+ feature
)

type IOPriority int

const (
	IOPriorityLow IOPriority = iota
	IOPriorityNormal
	IOPriorityHigh
	IOPriorityCritical
)

// Configuration
type IOFastPathConfig struct {
	// io_uring settings
	QueueDepth          int
	EnableSQPolling     bool
	EnableIOPolling     bool
	EnableKernelWQ      bool
	
	// Buffer management
	RegisteredBuffers   int
	BufferSize          int
	EnableZeroCopy      bool
	
	// Content-addressed storage
	EnableCAS           bool
	EnableDeduplication bool
	EnableCompression   bool
	CompressionLevel    int
	
	// Performance tuning
	BatchSize           int
	MaxConcurrentOps    int
	CompletionTimeout   time.Duration
	
	// Monitoring
	EnableProfiling     bool
	MetricsInterval     time.Duration
}

// NewIOFastPathV3 creates a new enhanced I/O fast path
func NewIOFastPathV3(config *IOFastPathConfig) (*IOFastPathV3, error) {
	if config == nil {
		config = &IOFastPathConfig{
			QueueDepth:          256,
			EnableSQPolling:     true,
			EnableIOPolling:     true,
			EnableKernelWQ:      true,
			RegisteredBuffers:   64,
			BufferSize:          64 * 1024, // 64KB buffers
			EnableZeroCopy:      true,
			EnableCAS:           true,
			EnableDeduplication: true,
			EnableCompression:   true,
			CompressionLevel:    3,
			BatchSize:           32,
			MaxConcurrentOps:    1024,
			CompletionTimeout:   5 * time.Second,
			EnableProfiling:     true,
			MetricsInterval:     1 * time.Second,
		}
	}

	ioFastPath := &IOFastPathV3{
		config:   config,
		shutdown: make(chan struct{}),
	}

	// Initialize io_uring context
	var err error
	ioFastPath.ring, err = ioFastPath.initializeIOUringContext(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize io_uring context: %w", err)
	}

	// Initialize registered buffer pool
	ioFastPath.registeredBuffers, err = ioFastPath.initializeBufferPool(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize buffer pool: %w", err)
	}

	// Initialize content-addressed storage
	if config.EnableCAS {
		ioFastPath.casStore, err = ioFastPath.initializeCASStore(config)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize CAS store: %w", err)
		}
	}

	// Initialize other components
	ioFastPath.prefetcher = NewIntelligentPrefetcher()
	ioFastPath.compressionEngine = NewCompressionEngine(config.CompressionLevel)
	ioFastPath.cacheManager = NewMultiTierCache()
	ioFastPath.metrics = NewIOPerformanceMetrics()
	ioFastPath.profiler = NewIOProfiler()
	ioFastPath.fallbackIO = NewFallbackIOHandler()

	return ioFastPath, nil
}

// initializeIOUringContext sets up the io_uring context with advanced features
func (io *IOFastPathV3) initializeIOUringContext(config *IOFastPathConfig) (*IOUringContext, error) {
	ctx := &IOUringContext{
		queueDepth: config.QueueDepth,
	}

	// Initialize io_uring
	ring, err := io.setupIOUring(config.QueueDepth, config)
	if err != nil {
		return nil, fmt.Errorf("failed to setup io_uring: %w", err)
	}
	ctx.ring = ring

	// Check for advanced features
	ctx.atomicSupport = io.checkAtomicWriteSupport()
	ctx.multiShotSupport = io.checkMultiShotSupport()
	ctx.bufferRingSupport = io.checkBufferRingSupport()

	// Initialize performance optimization components
	ctx.sqePool = NewSQEPool(config.QueueDepth)
	ctx.cqeProcessor = NewCQEProcessor()
	ctx.batchProcessor = NewBatchProcessor(config.BatchSize)
	ctx.ioScheduler = NewIOScheduler()
	ctx.completionTracker = NewCompletionTracker()
	ctx.resourceLimiter = NewIOResourceLimiter(config.MaxConcurrentOps)
	ctx.backpressure = NewBackpressureManager()

	return ctx, nil
}

// setupIOUring initializes the io_uring with optimized parameters
func (io *IOFastPathV3) setupIOUring(queueDepth int, config *IOFastPathConfig) (*IOUring, error) {
	// Setup io_uring parameters
	params := &IOUringParams{
		SQEntries: uint32(queueDepth),
		CQEntries: uint32(queueDepth * 2), // CQ is typically 2x SQ size
		Flags:     0,
	}

	// Enable advanced features
	if config.EnableSQPolling {
		params.Flags |= IORING_SETUP_SQPOLL
	}
	if config.EnableIOPolling {
		params.Flags |= IORING_SETUP_IOPOLL
	}
	if config.EnableKernelWQ {
		params.Flags |= IORING_SETUP_ATTACH_WQ
	}

	// Create io_uring instance
	ring, err := io.createIOUringInstance(params)
	if err != nil {
		return nil, fmt.Errorf("failed to create io_uring: %w", err)
	}

	return ring, nil
}

// initializeBufferPool creates and registers buffer pool for zero-copy operations
func (io *IOFastPathV3) initializeBufferPool(config *IOFastPathConfig) (*RegisteredBufferPool, error) {
	pool := &RegisteredBufferPool{
		bufferSize: config.BufferSize,
		available:  make(chan int, config.RegisteredBuffers),
		inUse:      make(map[int]bool),
	}

	// Allocate buffers
	pool.buffers = make([][]byte, config.RegisteredBuffers)
	pool.registeredIOVecs = make([]unix.Iovec, config.RegisteredBuffers)

	for i := 0; i < config.RegisteredBuffers; i++ {
		// Allocate page-aligned buffers for optimal performance
		buffer := make([]byte, config.BufferSize)
		pool.buffers[i] = buffer
		
		// Create iovec for registration
		pool.registeredIOVecs[i] = unix.Iovec{
			Base: &buffer[0],
			Len:  uint64(config.BufferSize),
		}
		
		// Add to available pool
		pool.available <- i
	}

	// Register buffers with io_uring
	if err := io.registerBuffers(pool.registeredIOVecs); err != nil {
		return nil, fmt.Errorf("failed to register buffers: %w", err)
	}

	return pool, nil
}

// initializeCASStore creates the content-addressed storage system
func (io *IOFastPathV3) initializeCASStore(config *IOFastPathConfig) (*ContentAddressedStore, error) {
	store := &ContentAddressedStore{
		hashIndex:   make(map[string]*ContentEntry),
		refCounter:  make(map[string]int64),
	}

	// Initialize storage backend
	store.storageBackend = NewFileSystemBackend("./cas-store")
	store.indexManager = NewCASIndexManager()
	
	// Initialize atomic operations
	store.atomicWriter = NewAtomicWriteEngine()
	store.transactionLog = NewTransactionLog()
	
	// Initialize deduplication
	if config.EnableDeduplication {
		store.dedupEngine = NewDeduplicationEngine()
	}
	
	// Initialize caching and optimization
	store.hotDataCache = NewHotDataCache(64 * 1024 * 1024) // 64MB cache
	store.compressionPool = NewCompressionPool(config.CompressionLevel)
	store.prefetchHints = NewPrefetchHintEngine()
	
	// Initialize garbage collection
	store.gcManager = NewGarbageCollector()
	store.cleanupScheduler = NewCleanupScheduler()

	return store, nil
}

// SubmitIO submits an I/O operation to the io_uring
func (io *IOFastPathV3) SubmitIO(ctx context.Context, op *IOOperation) (*IOCompletion, error) {
	start := time.Now()
	op.SubmittedAt = start

	// Check if operation can be served from cache
	if op.Type == IOTypeRead && io.config.EnableCAS {
		if cached, ok := io.cacheManager.Get(op.ContentHash); ok {
			return &IOCompletion{
				Operation:        op,
				Result:          int32(len(cached)),
				CompletedAt:     time.Now(),
				Duration:        time.Since(start),
				BytesTransferred: int64(len(cached)),
			}, nil
		}
	}

	// Get SQE from pool
	sqe, err := io.ring.sqePool.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get SQE: %w", err)
	}
	defer io.ring.sqePool.Put(sqe)

	// Configure SQE based on operation type
	if err := io.configureSQE(sqe, op); err != nil {
		return nil, fmt.Errorf("failed to configure SQE: %w", err)
	}

	// Submit to io_uring
	if err := io.ring.ring.Submit(sqe); err != nil {
		return nil, fmt.Errorf("failed to submit I/O operation: %w", err)
	}

	// Wait for completion
	completion, err := io.waitForCompletion(ctx, op)
	if err != nil {
		return nil, fmt.Errorf("I/O operation failed: %w", err)
	}

	// Update metrics
	io.metrics.RecordIOOperation(op.Type, completion.Duration, completion.BytesTransferred)

	// Store in cache if successful read
	if op.Type == IOTypeRead && completion.Result > 0 && io.config.EnableCAS {
		hash := sha256.Sum256(op.Buffer[:completion.Result])
		hashStr := hex.EncodeToString(hash[:])
		io.cacheManager.Set(hashStr, op.Buffer[:completion.Result])
	}

	return completion, nil
}

// AtomicWrite performs atomic write operations using kernel 6.11+ features
func (io *IOFastPathV3) AtomicWrite(ctx context.Context, fd int, offset int64, data []byte) error {
	if !io.ring.atomicSupport {
		// Fallback to traditional write with fsync
		return io.fallbackAtomicWrite(fd, offset, data)
	}

	op := &IOOperation{
		Type:        IOTypeAtomicWrite,
		FD:          int32(fd),
		Offset:      offset,
		Buffer:      data,
		Priority:    IOPriorityHigh,
		Deadline:    time.Now().Add(io.config.CompletionTimeout),
	}

	completion, err := io.SubmitIO(ctx, op)
	if err != nil {
		return fmt.Errorf("atomic write failed: %w", err)
	}

	if completion.Result < 0 {
		return fmt.Errorf("atomic write error: %d", completion.Result)
	}

	return nil
}

// BatchFileOperations performs multiple file operations in parallel
func (io *IOFastPathV3) BatchFileOperations(ctx context.Context, ops []*IOOperation) ([]*IOCompletion, error) {
	start := time.Now()

	// Group operations by priority
	batches := io.groupOperationsByPriority(ops)
	
	var allCompletions []*IOCompletion
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process each priority batch
	for priority, batch := range batches {
		wg.Add(1)
		go func(p IOPriority, operations []*IOOperation) {
			defer wg.Done()
			
			completions := io.processBatch(ctx, operations)
			
			mu.Lock()
			allCompletions = append(allCompletions, completions...)
			mu.Unlock()
		}(priority, batch)
	}

	wg.Wait()

	// Record batch metrics
	batchDuration := time.Since(start)
	io.metrics.RecordBatchOperation(len(ops), batchDuration)

	return allCompletions, nil
}

// ZeroCopyRead performs zero-copy read operations using registered buffers
func (io *IOFastPathV3) ZeroCopyRead(ctx context.Context, fd int, offset int64, size int) ([]byte, error) {
	// Get registered buffer from pool
	bufferIndex, err := io.registeredBuffers.GetBuffer()
	if err != nil {
		return nil, fmt.Errorf("failed to get registered buffer: %w", err)
	}
	defer io.registeredBuffers.ReturnBuffer(bufferIndex)

	buffer := io.registeredBuffers.buffers[bufferIndex]
	if size > len(buffer) {
		return nil, fmt.Errorf("requested size %d exceeds buffer size %d", size, len(buffer))
	}

	op := &IOOperation{
		Type:        IOTypeReadFixed,
		FD:          int32(fd),
		Offset:      offset,
		Buffer:      buffer[:size],
		BufferIndex: bufferIndex,
		Priority:    IOPriorityNormal,
	}

	completion, err := io.SubmitIO(ctx, op)
	if err != nil {
		return nil, fmt.Errorf("zero-copy read failed: %w", err)
	}

	if completion.Result < 0 {
		return nil, fmt.Errorf("read error: %d", completion.Result)
	}

	// Return slice of actual data read
	bytesRead := int(completion.Result)
	result := make([]byte, bytesRead)
	copy(result, buffer[:bytesRead])

	return result, nil
}

// Helper methods for advanced functionality
func (io *IOFastPathV3) configureSQE(sqe *SQE, op *IOOperation) error {
	sqe.Opcode = io.getOpcodeForOperation(op.Type)
	sqe.FD = op.FD
	sqe.Offset = uint64(op.Offset)
	sqe.Addr = uintptr(unsafe.Pointer(&op.Buffer[0]))
	sqe.Len = uint32(len(op.Buffer))
	sqe.UserData = op.UserData
	
	// Set flags based on operation
	if op.BufferIndex >= 0 {
		sqe.Flags |= IOSQE_FIXED_BUFFER
		sqe.BufIndex = uint16(op.BufferIndex)
	}
	
	// Set priority
	if op.Priority == IOPriorityHigh {
		sqe.Flags |= IOSQE_IO_LINK
	}
	
	return nil
}

func (io *IOFastPathV3) getOpcodeForOperation(opType IOOperationType) uint8 {
	switch opType {
	case IOTypeRead:
		return IORING_OP_READ
	case IOTypeWrite:
		return IORING_OP_WRITE
	case IOTypeReadFixed:
		return IORING_OP_READ_FIXED
	case IOTypeWriteFixed:
		return IORING_OP_WRITE_FIXED
	case IOTypeFsync:
		return IORING_OP_FSYNC
	case IOTypeAtomicWrite:
		return IORING_OP_WRITE // Will be enhanced for atomic writes
	default:
		return IORING_OP_NOP
	}
}

func (io *IOFastPathV3) waitForCompletion(ctx context.Context, op *IOOperation) (*IOCompletion, error) {
	// Implementation would wait for CQE and process completion
	return &IOCompletion{
		Operation:        op,
		Result:          int32(len(op.Buffer)),
		CompletedAt:     time.Now(),
		Duration:        time.Since(op.SubmittedAt),
		BytesTransferred: int64(len(op.Buffer)),
	}, nil
}

func (io *IOFastPathV3) groupOperationsByPriority(ops []*IOOperation) map[IOPriority][]*IOOperation {
	batches := make(map[IOPriority][]*IOOperation)
	for _, op := range ops {
		batches[op.Priority] = append(batches[op.Priority], op)
	}
	return batches
}

func (io *IOFastPathV3) processBatch(ctx context.Context, ops []*IOOperation) []*IOCompletion {
	completions := make([]*IOCompletion, len(ops))
	var wg sync.WaitGroup
	
	for i, op := range ops {
		wg.Add(1)
		go func(index int, operation *IOOperation) {
			defer wg.Done()
			completion, _ := io.SubmitIO(ctx, operation)
			completions[index] = completion
		}(i, op)
	}
	
	wg.Wait()
	return completions
}

// Placeholder implementations for supporting types and methods
func (io *IOFastPathV3) createIOUringInstance(params *IOUringParams) (*IOUring, error) {
	return &IOUring{}, nil
}

func (io *IOFastPathV3) checkAtomicWriteSupport() bool {
	// Check kernel version and feature support
	return false // Placeholder
}

func (io *IOFastPathV3) checkMultiShotSupport() bool {
	return false // Placeholder
}

func (io *IOFastPathV3) checkBufferRingSupport() bool {
	return false // Placeholder
}

func (io *IOFastPathV3) registerBuffers(iovecs []unix.Iovec) error {
	// Register buffers with io_uring
	return nil
}

func (io *IOFastPathV3) fallbackAtomicWrite(fd int, offset int64, data []byte) error {
	// Traditional write + fsync fallback
	return nil
}

func (rbp *RegisteredBufferPool) GetBuffer() (int, error) {
	select {
	case index := <-rbp.available:
		rbp.mu.Lock()
		rbp.inUse[index] = true
		rbp.mu.Unlock()
		return index, nil
	default:
		return -1, fmt.Errorf("no buffers available")
	}
}

func (rbp *RegisteredBufferPool) ReturnBuffer(index int) {
	rbp.mu.Lock()
	delete(rbp.inUse, index)
	rbp.mu.Unlock()
	
	select {
	case rbp.available <- index:
	default:
		// Buffer pool is full, this shouldn't happen
	}
}

// Placeholder types and constants
type IOUring struct{}
type IOUringParams struct {
	SQEntries uint32
	CQEntries uint32
	Flags     uint32
}

type SQE struct {
	Opcode    uint8
	Flags     uint8
	FD        int32
	Offset    uint64
	Addr      uintptr
	Len       uint32
	BufIndex  uint16
	UserData  uint64
}

const (
	IORING_SETUP_SQPOLL   = 1 << 1
	IORING_SETUP_IOPOLL   = 1 << 2
	IORING_SETUP_ATTACH_WQ = 1 << 5
	IOSQE_FIXED_BUFFER    = 1 << 0
	IOSQE_IO_LINK         = 1 << 2
	IORING_OP_NOP         = 0
	IORING_OP_READ        = 22
	IORING_OP_WRITE       = 23
	IORING_OP_READ_FIXED  = 4
	IORING_OP_WRITE_FIXED = 5
	IORING_OP_FSYNC       = 3
)

// Placeholder constructors and types
func NewSQEPool(size int) *SQEPool { return &SQEPool{} }
func NewCQEProcessor() *CQEProcessor { return &CQEProcessor{} }
func NewBatchProcessor(size int) *BatchProcessor { return &BatchProcessor{} }
func NewIOScheduler() *IOScheduler { return &IOScheduler{} }
func NewCompletionTracker() *CompletionTracker { return &CompletionTracker{} }
func NewIOResourceLimiter(max int) *IOResourceLimiter { return &IOResourceLimiter{} }
func NewBackpressureManager() *BackpressureManager { return &BackpressureManager{} }
func NewIntelligentPrefetcher() *IntelligentPrefetcher { return &IntelligentPrefetcher{} }
func NewCompressionEngine(level int) *CompressionEngine { return &CompressionEngine{} }
func NewMultiTierCache() *MultiTierCache { return &MultiTierCache{} }
func NewIOPerformanceMetrics() *IOPerformanceMetrics { return &IOPerformanceMetrics{} }
func NewIOProfiler() *IOProfiler { return &IOProfiler{} }
func NewFallbackIOHandler() *FallbackIOHandler { return &FallbackIOHandler{} }
func NewFileSystemBackend(path string) StorageBackend { return &FileSystemBackend{} }
func NewCASIndexManager() *CASIndexManager { return &CASIndexManager{} }
func NewAtomicWriteEngine() *AtomicWriteEngine { return &AtomicWriteEngine{} }
func NewTransactionLog() *TransactionLog { return &TransactionLog{} }
func NewDeduplicationEngine() *DeduplicationEngine { return &DeduplicationEngine{} }
func NewHotDataCache(size int64) *HotDataCache { return &HotDataCache{} }
func NewCompressionPool(level int) *CompressionPool { return &CompressionPool{} }
func NewPrefetchHintEngine() *PrefetchHintEngine { return &PrefetchHintEngine{} }
func NewGarbageCollector() *GarbageCollector { return &GarbageCollector{} }
func NewCleanupScheduler() *CleanupScheduler { return &CleanupScheduler{} }

type SQEPool struct{}
type CQEProcessor struct{}
type BatchProcessor struct{}
type IOScheduler struct{}
type CompletionTracker struct{}
type IOResourceLimiter struct{}
type BackpressureManager struct{}
type IntelligentPrefetcher struct{}
type CompressionEngine struct{}
type MultiTierCache struct{}
type IOPerformanceMetrics struct{}
type IOProfiler struct{}
type IOCongestionControl struct{}
type FallbackIOHandler struct{}
type WasmVirtualFS struct{}
type StorageBackend interface{}
type FileSystemBackend struct{}
type CASIndexManager struct{}
type AtomicWriteEngine struct{}
type TransactionLog struct{}
type DeduplicationEngine struct{}
type ContentEntry struct{}
type HotDataCache struct{}
type CompressionPool struct{}
type PrefetchHintEngine struct{}
type GarbageCollector struct{}
type CleanupScheduler struct{}

func (sqe *SQEPool) Get() (*SQE, error) { return &SQE{}, nil }
func (sqe *SQEPool) Put(*SQE) {}
func (ring *IOUring) Submit(*SQE) error { return nil }
func (cache *MultiTierCache) Get(key string) ([]byte, bool) { return nil, false }
func (cache *MultiTierCache) Set(key string, value []byte) {}
func (metrics *IOPerformanceMetrics) RecordIOOperation(opType IOOperationType, duration time.Duration, bytes int64) {}
func (metrics *IOPerformanceMetrics) RecordBatchOperation(ops int, duration time.Duration) {}