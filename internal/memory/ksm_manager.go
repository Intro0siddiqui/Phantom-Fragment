package memory

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// KSMManager manages Kernel Samepage Merging for memory deduplication
type KSMManager struct {
	enabled     bool
	initialized bool

	// KSM control paths
	ksmDir          string
	pagesToScanPath string
	sleepMillisPath string
	mergeAcrossPath string

	// Statistics
	stats  *KSMStats
	config *KSMConfig

	mu            sync.RWMutex
	shutdown      chan struct{}
	workerRunning bool

	// Memory tracking
	managedRegions map[uintptr]*KSMRegion
	pageHashes     map[uint64][]*KSMRegion // Hash -> regions with same content

	// Performance tracking
	lastScanTime   time.Time
	lastMergeCount int64
}

// KSMConfig contains KSM configuration parameters
type KSMConfig struct {
	Enabled          bool
	PagesToScan      int
	SleepMillis      int
	MergeAcrossNodes bool
	ScanInterval     time.Duration
	MinPagesToMerge  int
	MaxPagesToMerge  int

	// Advanced settings
	UseMADV_MERGEABLE bool
	UsePRCTL          bool
	AutoTune          bool

	// Memory pressure thresholds
	LowMemoryThreshold  float64 // 0.0-1.0
	HighMemoryThreshold float64 // 0.0-1.0
}

// KSMStats contains KSM statistics
type KSMStats struct {
	PagesShared   int64
	PagesSharing  int64
	PagesUnshared int64
	PagesVolatile int64
	FullScans     int64

	MergedPages int64
	SavedMemory int64 // bytes
	ScanTime    time.Duration

	RegionCount   int64
	ActiveRegions int64

	LastScan  time.Time
	LastMerge time.Time

	// Performance metrics
	ScanRate        float64 // pages/second
	MergeEfficiency float64 // 0.0-1.0
	MemorySavings   float64 // percentage
}

// KSMRegion represents a memory region managed by KSM
type KSMRegion struct {
	StartAddr uintptr
	Size      int
	PageCount int

	MergedPages   int
	SharedPages   int
	UnsharedPages int

	LastScanned time.Time
	LastMerged  time.Time

	Flags     int
	ProcessID int

	// Hash tracking
	PageHashes []uint64
	HashMap    map[uint64]int // hash -> count
}

// KSMRegionInfo contains information about a KSM region
type KSMRegionInfo struct {
	StartAddr    uintptr
	Size         int
	MergedPages  int
	SharedPages  int
	Savings      int64
	Efficiency   float64
	LastActivity time.Time
}

// NewKSMManager creates a new KSM manager
type NewKSMManager func() (*KSMManager, error)

// DefaultKSMConfig returns default KSM configuration
func DefaultKSMConfig() *KSMConfig {
	return &KSMConfig{
		Enabled:          true,
		PagesToScan:      100,
		SleepMillis:      20,
		MergeAcrossNodes: true,
		ScanInterval:     30 * time.Second,
		MinPagesToMerge:  2,
		MaxPagesToMerge:  1000,

		UseMADV_MERGEABLE: true,
		UsePRCTL:          false,
		AutoTune:          true,

		LowMemoryThreshold:  0.7, // 70% memory usage
		HighMemoryThreshold: 0.9, // 90% memory usage
	}
}

// NewKSMManager creates a new KSM manager instance
func NewKSMManagerWithConfig(config *KSMConfig) (*KSMManager, error) {
	ksm := &KSMManager{
		config:         config,
		stats:          &KSMStats{},
		shutdown:       make(chan struct{}),
		managedRegions: make(map[uintptr]*KSMRegion),
		pageHashes:     make(map[uint64][]*KSMRegion),
		lastScanTime:   time.Now(),
	}

	// Initialize KSM directory paths
	ksm.ksmDir = "/sys/kernel/mm/ksm"
	ksm.pagesToScanPath = filepath.Join(ksm.ksmDir, "pages_to_scan")
	ksm.sleepMillisPath = filepath.Join(ksm.ksmDir, "sleep_millisecs")
	ksm.mergeAcrossPath = filepath.Join(ksm.ksmDir, "merge_across_nodes")

	// Check if KSM is available
	if err := ksm.checkKSMAvailable(); err != nil {
		if config.Enabled {
			return nil, fmt.Errorf("KSM not available: %w", err)
		}
		// KSM not available but not required
		ksm.enabled = false
		return ksm, nil
	}

	// Configure KSM
	if err := ksm.configureKSM(); err != nil {
		return nil, fmt.Errorf("failed to configure KSM: %w", err)
	}

	ksm.enabled = true
	ksm.initialized = true

	// Start background worker if enabled
	if config.Enabled {
		go ksm.backgroundWorker()
	}

	return ksm, nil
}

// Enable KSM for a memory region
func (ksm *KSMManager) EnableForRegion(startAddr uintptr, size int, flags int) error {
	if !ksm.enabled {
		return fmt.Errorf("KSM not enabled")
	}

	ksm.mu.Lock()
	defer ksm.mu.Unlock()

	// Check if region is already managed
	if _, exists := ksm.managedRegions[startAddr]; exists {
		return fmt.Errorf("region already managed by KSM")
	}

	// Mark pages as mergeable using madvise
	if ksm.config.UseMADV_MERGEABLE {
		// Convert to byte slice for madvise
		region := (*[1 << 30]byte)(unsafe.Pointer(startAddr))[:size]

		// Use MADV_MERGEABLE to mark pages for merging (Linux only)
		if runtime.GOOS == "linux" {
			err := unix.Madvise(region, unix.MADV_MERGEABLE)
			if err != nil {
				return fmt.Errorf("madvise MADV_MERGEABLE failed: %w", err)
			}
		} else {
			// Windows doesn't support madvise, log a warning but continue
			fmt.Printf("Warning: MADV_MERGEABLE not supported on %s, KSM functionality limited\n", runtime.GOOS)
		}
	}

	// Create region tracking
	pageCount := size / os.Getpagesize()
	if size%os.Getpagesize() != 0 {
		pageCount++
	}

	region := &KSMRegion{
		StartAddr:   startAddr,
		Size:        size,
		PageCount:   pageCount,
		Flags:       flags,
		ProcessID:   os.Getpid(),
		PageHashes:  make([]uint64, pageCount),
		HashMap:     make(map[uint64]int),
		LastScanned: time.Now(),
	}

	ksm.managedRegions[startAddr] = region
	ksm.stats.RegionCount++
	ksm.stats.ActiveRegions++

	// Initial scan to populate hashes
	ksm.scanRegion(region)

	return nil
}

// Disable KSM for a memory region
func (ksm *KSMManager) DisableForRegion(startAddr uintptr) error {
	if !ksm.enabled {
		return fmt.Errorf("KSM not enabled")
	}

	ksm.mu.Lock()
	defer ksm.mu.Unlock()

	region, exists := ksm.managedRegions[startAddr]
	if !exists {
		return fmt.Errorf("region not managed by KSM")
	}

	// Mark pages as unmergeable (Linux only)
	if ksm.config.UseMADV_MERGEABLE && runtime.GOOS == "linux" {
		regionSlice := (*[1 << 30]byte)(unsafe.Pointer(startAddr))[:region.Size]
		err := unix.Madvise(regionSlice, unix.MADV_UNMERGEABLE)
		if err != nil {
			return fmt.Errorf("madvise MADV_UNMERGEABLE failed: %w", err)
		}
	}

	// Remove from tracking
	delete(ksm.managedRegions, startAddr)

	// Remove from page hashes
	for _, hash := range region.PageHashes {
		if regions, exists := ksm.pageHashes[hash]; exists {
			for i, r := range regions {
				if r.StartAddr == startAddr {
					ksm.pageHashes[hash] = append(regions[:i], regions[i+1:]...)
					break
				}
			}
			if len(ksm.pageHashes[hash]) == 0 {
				delete(ksm.pageHashes, hash)
			}
		}
	}

	ksm.stats.ActiveRegions--
	if ksm.stats.ActiveRegions < 0 {
		ksm.stats.ActiveRegions = 0
	}

	return nil
}

// ScanAllRegions performs a full scan of all managed regions
func (ksm *KSMManager) ScanAllRegions() (int64, error) {
	if !ksm.enabled {
		return 0, fmt.Errorf("KSM not enabled")
	}

	ksm.mu.Lock()
	defer ksm.mu.Unlock()

	startTime := time.Now()
	mergedPages := int64(0)

	for _, region := range ksm.managedRegions {
		merged := ksm.scanRegion(region)
		mergedPages += int64(merged)
	}

	// Update statistics
	scanTime := time.Since(startTime)
	ksm.stats.FullScans++
	ksm.stats.ScanTime += scanTime
	ksm.stats.MergedPages += mergedPages
	ksm.stats.LastScan = time.Now()

	if len(ksm.managedRegions) > 0 {
		ksm.stats.ScanRate = float64(ksm.getTotalPages()) / scanTime.Seconds()
	}

	ksm.lastScanTime = time.Now()
	ksm.lastMergeCount = mergedPages

	return mergedPages, nil
}

// GetStats returns current KSM statistics
func (ksm *KSMManager) GetStats() *KSMStats {
	ksm.mu.RLock()
	defer ksm.mu.RUnlock()

	stats := *ksm.stats // Copy
	stats.LastScan = ksm.lastScanTime

	// Calculate memory savings
	stats.SavedMemory = ksm.calculateSavedMemory()
	stats.MemorySavings = ksm.calculateMemorySavingsPercentage()

	return &stats
}

// GetRegionInfo returns information about all managed regions
func (ksm *KSMManager) GetRegionInfo() []KSMRegionInfo {
	ksm.mu.RLock()
	defer ksm.mu.RUnlock()

	var regions []KSMRegionInfo
	for _, region := range ksm.managedRegions {
		info := KSMRegionInfo{
			StartAddr:    region.StartAddr,
			Size:         region.Size,
			MergedPages:  region.MergedPages,
			SharedPages:  region.SharedPages,
			Savings:      int64(region.MergedPages) * int64(os.Getpagesize()),
			Efficiency:   float64(region.MergedPages) / float64(region.PageCount),
			LastActivity: region.LastScanned,
		}
		regions = append(regions, info)
	}

	// Sort by savings (descending)
	sort.Slice(regions, func(i, j int) bool {
		return regions[i].Savings > regions[j].Savings
	})

	return regions
}

// Shutdown stops the KSM manager
func (ksm *KSMManager) Shutdown() error {
	if !ksm.enabled {
		return nil
	}

	close(ksm.shutdown)

	// Disable all regions
	ksm.mu.Lock()
	defer ksm.mu.Unlock()

	for startAddr := range ksm.managedRegions {
		ksm.DisableForRegion(startAddr)
	}

	ksm.managedRegions = make(map[uintptr]*KSMRegion)
	ksm.pageHashes = make(map[uint64][]*KSMRegion)
	ksm.workerRunning = false

	return nil
}

// IsEnabled returns whether KSM is enabled
func (ksm *KSMManager) IsEnabled() bool {
	return ksm.enabled && ksm.initialized
}

// AutoTune adjusts KSM parameters based on system load
func (ksm *KSMManager) AutoTune() error {
	if !ksm.enabled || !ksm.config.AutoTune {
		return nil
	}

	// Get system memory usage
	memInfo, err := getSystemMemoryInfo()
	if err != nil {
		return fmt.Errorf("failed to get memory info: %w", err)
	}

	// Calculate memory usage percentage
	usage := float64(memInfo.Used) / float64(memInfo.Total)

	// Adjust pages to scan based on memory pressure
	newPagesToScan := ksm.config.PagesToScan

	if usage > ksm.config.HighMemoryThreshold {
		// High memory pressure - scan more aggressively
		newPagesToScan = min(newPagesToScan*2, 1000)
	} else if usage < ksm.config.LowMemoryThreshold {
		// Low memory pressure - scan less aggressively
		newPagesToScan = max(newPagesToScan/2, 10)
	}

	// Adjust sleep time based on scan rate
	if ksm.stats.ScanRate > 1000 {
		// Fast scanning, sleep less
		newSleepMillis := max(ksm.config.SleepMillis/2, 1)
		if err := ksm.writeKSMValue(ksm.sleepMillisPath, newSleepMillis); err != nil {
			return err
		}
		ksm.config.SleepMillis = newSleepMillis
	}

	// Update pages to scan if changed
	if newPagesToScan != ksm.config.PagesToScan {
		if err := ksm.writeKSMValue(ksm.pagesToScanPath, newPagesToScan); err != nil {
			return err
		}
		ksm.config.PagesToScan = newPagesToScan
	}

	return nil
}

// backgroundWorker runs the KSM background scanning
func (ksm *KSMManager) backgroundWorker() {
	ksm.workerRunning = true
	defer func() { ksm.workerRunning = false }()

	ticker := time.NewTicker(ksm.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ksm.shutdown:
			return
		case <-ticker.C:
			// Perform scan
			ksm.ScanAllRegions()

			// Auto-tune if enabled
			if ksm.config.AutoTune {
				ksm.AutoTune()
			}
		}
	}
}

// scanRegion scans a single region for duplicate pages
func (ksm *KSMManager) scanRegion(region *KSMRegion) int {
	merged := 0
	pageSize := os.Getpagesize()

	for i := 0; i < region.PageCount; i++ {
		offset := i * pageSize
		if offset >= region.Size {
			break
		}

		// Get page content hash
		pageAddr := region.StartAddr + uintptr(offset)
		pageData := (*[1 << 30]byte)(unsafe.Pointer(pageAddr))[:pageSize]

		hash := hashPage(pageData)

		// Update region tracking
		oldHash := region.PageHashes[i]
		region.PageHashes[i] = hash

		// Update hash counts
		if oldHash != 0 {
			region.HashMap[oldHash]--
			if region.HashMap[oldHash] <= 0 {
				delete(region.HashMap, oldHash)
			}
		}

		region.HashMap[hash]++

		// Check for merging opportunities
		if existingRegions, exists := ksm.pageHashes[hash]; exists && len(existingRegions) > 0 {
			// This page can be merged
			merged++
			region.MergedPages++
			region.SharedPages++

			// Update global statistics
			ksm.stats.PagesShared++
			ksm.stats.PagesSharing++
		} else {
			// Unique page
			region.UnsharedPages++
			ksm.stats.PagesUnshared++
		}

		// Update global page hash tracking
		if oldHash != 0 {
			// Remove from old hash tracking
			if regions, exists := ksm.pageHashes[oldHash]; exists {
				for j, r := range regions {
					if r.StartAddr == region.StartAddr && i == j {
						ksm.pageHashes[oldHash] = append(regions[:j], regions[j+1:]...)
						break
					}
				}
				if len(ksm.pageHashes[oldHash]) == 0 {
					delete(ksm.pageHashes, oldHash)
				}
			}
		}

		// Add to new hash tracking
		ksm.pageHashes[hash] = append(ksm.pageHashes[hash], region)
	}

	region.LastScanned = time.Now()
	region.LastMerged = time.Now()

	return merged
}

// checkKSMAvailable checks if KSM is available on the system
func (ksm *KSMManager) checkKSMAvailable() error {
	// Check if KSM directory exists
	if _, err := os.Stat(ksm.ksmDir); os.IsNotExist(err) {
		return fmt.Errorf("KSM not supported by kernel")
	}

	// Check if control files exist
	requiredFiles := []string{
		ksm.pagesToScanPath,
		ksm.sleepMillisPath,
		ksm.mergeAcrossPath,
		filepath.Join(ksm.ksmDir, "pages_shared"),
		filepath.Join(ksm.ksmDir, "pages_sharing"),
		filepath.Join(ksm.ksmDir, "pages_unshared"),
		filepath.Join(ksm.ksmDir, "full_scans"),
	}

	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return fmt.Errorf("KSM control file %s not found", file)
		}
	}

	return nil
}

// configureKSM sets up KSM with the configured parameters
func (ksm *KSMManager) configureKSM() error {
	// Set pages to scan
	if err := ksm.writeKSMValue(ksm.pagesToScanPath, ksm.config.PagesToScan); err != nil {
		return err
	}

	// Set sleep milliseconds
	if err := ksm.writeKSMValue(ksm.sleepMillisPath, ksm.config.SleepMillis); err != nil {
		return err
	}

	// Set merge across nodes
	mergeAcross := 0
	if ksm.config.MergeAcrossNodes {
		mergeAcross = 1
	}
	if err := ksm.writeKSMValue(ksm.mergeAcrossPath, mergeAcross); err != nil {
		return err
	}

	return nil
}

// writeKSMValue writes a value to a KSM control file
func (ksm *KSMManager) writeKSMValue(path string, value int) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer file.Close()

	_, err = file.WriteString(strconv.Itoa(value))
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", path, err)
	}

	return nil
}

// readKSMValue reads a value from a KSM control file
func (ksm *KSMManager) readKSMValue(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read %s: %w", path, err)
	}

	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid value in %s: %w", path, err)
	}

	return value, nil
}

// calculateSavedMemory calculates total memory saved by KSM
func (ksm *KSMManager) calculateSavedMemory() int64 {
	pageSize := int64(os.Getpagesize())

	// Each merged page saves (n-1) * page_size bytes
	// where n is the number of identical pages
	totalSaved := int64(0)

	for hash, regions := range ksm.pageHashes {
		if len(regions) > 1 {
			totalSaved += int64(len(regions)-1) * pageSize
		}
		_ = hash // Avoid unused variable warning
	}

	return totalSaved
}

// calculateMemorySavingsPercentage calculates memory savings percentage
func (ksm *KSMManager) calculateMemorySavingsPercentage() float64 {
	totalPages := ksm.getTotalPages()
	if totalPages == 0 {
		return 0.0
	}

	saved := ksm.calculateSavedMemory()
	totalMemory := int64(totalPages) * int64(os.Getpagesize())

	return float64(saved) / float64(totalMemory) * 100.0
}

// getTotalPages returns total number of pages managed
func (ksm *KSMManager) getTotalPages() int {
	total := 0
	for _, region := range ksm.managedRegions {
		total += region.PageCount
	}
	return total
}

// hashPage calculates a hash of page content
func hashPage(data []byte) uint64 {
	// Simple hash function for demonstration
	// In production, use a proper hash function like xxHash
	var hash uint64 = 14695981039346656037
	for _, b := range data {
		hash ^= uint64(b)
		hash *= 1099511628211
	}
	return hash
}

// getSystemMemoryInfo returns system memory information
func getSystemMemoryInfo() (*MemoryInfo, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var memInfo MemoryInfo
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

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// MemoryInfo contains system memory information
type MemoryInfo struct {
	Total     uint64
	Free      uint64
	Available uint64
	Used      uint64
	Buffers   uint64
	Cached    uint64
}
