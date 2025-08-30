//go:build linux
// +build linux

package fragments

import (
	"fmt"
	"sync"
	"time"
)

// ModularFragmentManager manages the entire modular fragment system
type ModularFragmentManager struct {
	library      *UnifiedOSLibrary
	analyzer     *TaskAnalyzer
	composer     *FragmentComposer
	loader       *ComponentLoader
	
	// Core fragment (always available)
	coreFragment *CoreFragment
	
	// Statistics and monitoring
	stats        *FragmentStats
	mu           sync.RWMutex
}

// CoreFragment represents the minimal core fragment (3MB)
type CoreFragment struct {
	ID           string
	Size         int64
	Capabilities []Capability
	CreatedAt    time.Time
}

// FragmentStats tracks system statistics
type FragmentStats struct {
	TotalTasksProcessed    int64
	TotalFragmentsCreated  int64
	TotalMemoryUsed        int64
	AverageLoadTime        time.Duration
	CacheHitRate           float64
	LastUpdated            time.Time
	
	mu sync.RWMutex
}

// NewModularFragmentManager creates a new modular fragment manager
func NewModularFragmentManager() (*ModularFragmentManager, error) {
	// Initialize components
	library := NewUnifiedOSLibrary()
	analyzer := NewTaskAnalyzer()
	composer := NewFragmentComposer(library, analyzer)
	loader := NewComponentLoader(library)
	
	// Create core fragment
	coreFragment := &CoreFragment{
		ID:    "core-fragment",
		Size:  3 * 1024 * 1024, // 3MB
		Capabilities: []Capability{
			// Core capabilities are always available
		},
		CreatedAt: time.Now(),
	}
	
	manager := &ModularFragmentManager{
		library:      library,
		analyzer:     analyzer,
		composer:     composer,
		loader:       loader,
		coreFragment: coreFragment,
		stats:        &FragmentStats{},
	}
	
	// Preload commonly used components
	go manager.preloadCommonComponents()
	
	return manager, nil
}

// ProcessTask processes a task and returns the appropriate fragment
func (mfm *ModularFragmentManager) ProcessTask(task *Task) (*ComposedFragment, error) {
	start := time.Now()
	
	// Update statistics
	mfm.updateStats(func(stats *FragmentStats) {
		stats.TotalTasksProcessed++
	})
	
	// Analyze task complexity
	complexity := mfm.analyzer.AnalyzeTaskComplexity(task)
	
	// Handle simple tasks with core fragment only
	if complexity == SIMPLE {
		return mfm.createCoreOnlyFragment(task), nil
	}
	
	// Compose fragment for complex tasks
	fragment, err := mfm.composer.ComposeForTask(task)
	if err != nil {
		return nil, fmt.Errorf("failed to compose fragment: %w", err)
	}
	
	// Load required components
	err = mfm.loadRequiredComponents(fragment)
	if err != nil {
		return nil, fmt.Errorf("failed to load components: %w", err)
	}
	
	// Update statistics
	loadTime := time.Since(start)
	mfm.updateStats(func(stats *FragmentStats) {
		stats.TotalFragmentsCreated++
		stats.AverageLoadTime = (stats.AverageLoadTime + loadTime) / 2
		stats.TotalMemoryUsed += fragment.TotalSize
	})
	
	return fragment, nil
}

// createCoreOnlyFragment creates a fragment with just the core capabilities
func (mfm *ModularFragmentManager) createCoreOnlyFragment(task *Task) *ComposedFragment {
	return &ComposedFragment{
		ID:           fmt.Sprintf("core-%s-%d", task.Command, time.Now().UnixNano()),
		Components:   []*FragmentComponent{}, // No additional components
		TotalSize:    mfm.coreFragment.Size,
		Capabilities: make(map[Capability]bool),
		CreatedAt:    time.Now(),
		LoadTime:     0, // Core is always available
	}
}

// loadRequiredComponents loads all components required by a fragment
func (mfm *ModularFragmentManager) loadRequiredComponents(fragment *ComposedFragment) error {
	var componentNames []string
	for _, component := range fragment.Components {
		componentNames = append(componentNames, component.Name)
	}
	
	_, err := mfm.loader.LoadComponents(componentNames)
	return err
}

// GetSystemInfo returns comprehensive system information
func (mfm *ModularFragmentManager) GetSystemInfo() map[string]interface{} {
	mfm.mu.RLock()
	defer mfm.mu.RUnlock()
	
	// Get library information
	libraryInfo := map[string]interface{}{
		"total_components": len(mfm.library.ListComponents()),
		"components":       mfm.library.ListComponents(),
	}
	
	// Get loader statistics
	loaderStats := mfm.loader.GetLoadStats()
	
	// Get cache statistics
	cacheStats := mfm.composer.cache.GetCacheStats()
	
	// Get system statistics
	systemStats := mfm.getSystemStats()
	
	return map[string]interface{}{
		"core_fragment": map[string]interface{}{
			"id":           mfm.coreFragment.ID,
			"size":         mfm.coreFragment.Size,
			"size_mb":      float64(mfm.coreFragment.Size) / (1024 * 1024),
			"capabilities": mfm.coreFragment.Capabilities,
			"created_at":   mfm.coreFragment.CreatedAt,
		},
		"library":       libraryInfo,
		"loader_stats":  loaderStats,
		"cache_stats":   cacheStats,
		"system_stats":  systemStats,
	}
}

// GetComponentInfo returns detailed information about a specific component
func (mfm *ModularFragmentManager) GetComponentInfo(componentName string) (map[string]interface{}, error) {
	// Get component from library
	info, err := mfm.library.GetComponentInfo(componentName)
	if err != nil {
		return nil, err
	}
	
	// Add loading status
	loaded, isLoaded := mfm.loader.GetLoadedComponent(componentName)
	if isLoaded {
		info["loaded"] = true
		info["loaded_at"] = loaded.LoadedAt
		info["load_time"] = loaded.LoadTime
		info["memory_usage"] = loaded.MemoryUsage
	} else {
		info["loaded"] = false
	}
	
	return info, nil
}

// ListAvailableComponents returns all available components with their status
func (mfm *ModularFragmentManager) ListAvailableComponents() map[string]interface{} {
	components := mfm.library.ListComponents()
	result := make(map[string]interface{})
	
	for name, component := range components {
		loaded, isLoaded := mfm.loader.GetLoadedComponent(name)
		
		componentInfo := map[string]interface{}{
			"name":         component.Name,
			"size":         component.Size,
			"size_mb":      float64(component.Size) / (1024 * 1024),
			"capabilities": component.Capabilities,
			"description":  component.Description,
			"loaded":       isLoaded,
		}
		
		if isLoaded {
			componentInfo["loaded_at"] = loaded.LoadedAt
			componentInfo["load_time"] = loaded.LoadTime
		}
		
		result[name] = componentInfo
	}
	
	return result
}

// PreloadComponent preloads a specific component
func (mfm *ModularFragmentManager) PreloadComponent(componentName string) error {
	_, err := mfm.loader.LoadComponent(componentName)
	return err
}

// UnloadComponent unloads a specific component
func (mfm *ModularFragmentManager) UnloadComponent(componentName string) error {
	return mfm.loader.UnloadComponent(componentName)
}

// CleanupUnusedComponents cleans up unused components
func (mfm *ModularFragmentManager) CleanupUnusedComponents() error {
	return mfm.loader.CleanupUnusedComponents()
}

// GetPerformanceMetrics returns performance metrics
func (mfm *ModularFragmentManager) GetPerformanceMetrics() map[string]interface{} {
	mfm.mu.RLock()
	defer mfm.mu.RUnlock()
	
	loaderStats := mfm.loader.GetLoadStats()
	cacheStats := mfm.composer.cache.GetCacheStats()
	
	return map[string]interface{}{
		"tasks_processed":     mfm.stats.TotalTasksProcessed,
		"fragments_created":   mfm.stats.TotalFragmentsCreated,
		"total_memory_used":   mfm.stats.TotalMemoryUsed,
		"total_memory_mb":     float64(mfm.stats.TotalMemoryUsed) / (1024 * 1024),
		"average_load_time":   mfm.stats.AverageLoadTime,
		"cache_hit_rate":      mfm.stats.CacheHitRate,
		"loaded_components":   loaderStats["loaded_count"],
		"cached_fragments":    cacheStats["fragment_count"],
		"last_updated":        mfm.stats.LastUpdated,
	}
}

// preloadCommonComponents preloads commonly used components
func (mfm *ModularFragmentManager) preloadCommonComponents() {
	// Preload network components as they're commonly used
	commonComponents := []string{
		"tcp-stack",
		"dns-resolver",
		"socket-api",
	}
	
	err := mfm.loader.PreloadComponents(commonComponents)
	if err != nil {
		fmt.Printf("Failed to preload common components: %v\n", err)
	}
}

// updateStats updates statistics in a thread-safe manner
func (mfm *ModularFragmentManager) updateStats(updateFunc func(*FragmentStats)) {
	mfm.stats.mu.Lock()
	defer mfm.stats.mu.Unlock()
	
	updateFunc(mfm.stats)
	mfm.stats.LastUpdated = time.Now()
}

// getSystemStats returns current system statistics
func (mfm *ModularFragmentManager) getSystemStats() map[string]interface{} {
	mfm.stats.mu.RLock()
	defer mfm.stats.mu.RUnlock()
	
	return map[string]interface{}{
		"total_tasks_processed":   mfm.stats.TotalTasksProcessed,
		"total_fragments_created": mfm.stats.TotalFragmentsCreated,
		"total_memory_used":       mfm.stats.TotalMemoryUsed,
		"total_memory_mb":         float64(mfm.stats.TotalMemoryUsed) / (1024 * 1024),
		"average_load_time":       mfm.stats.AverageLoadTime,
		"cache_hit_rate":          mfm.stats.CacheHitRate,
		"last_updated":            mfm.stats.LastUpdated,
	}
}

// Shutdown gracefully shuts down the fragment manager
func (mfm *ModularFragmentManager) Shutdown() error {
	// Cleanup unused components
	err := mfm.CleanupUnusedComponents()
	if err != nil {
		return fmt.Errorf("failed to cleanup components: %w", err)
	}
	
	// Clear cache
	mfm.composer.cache.Clear()
	
	return nil
}