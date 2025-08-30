//go:build linux
// +build linux

package fragments

import (
	"fmt"
	"sync"
	"time"
)

// ComposedFragment represents a dynamically composed fragment
type ComposedFragment struct {
	ID           string
	Components   []*FragmentComponent
	TotalSize    int64
	Capabilities map[Capability]bool
	CreatedAt    time.Time
	LoadTime     time.Duration
}

// FragmentComposer handles dynamic composition of fragments
type FragmentComposer struct {
	library *UnifiedOSLibrary
	analyzer *TaskAnalyzer
	cache   *FragmentCache
	mu      sync.RWMutex
}

// FragmentCache caches composed fragments for reuse
type FragmentCache struct {
	fragments map[string]*ComposedFragment
	mu        sync.RWMutex
}

// NewFragmentComposer creates a new fragment composer
func NewFragmentComposer(library *UnifiedOSLibrary, analyzer *TaskAnalyzer) *FragmentComposer {
	return &FragmentComposer{
		library:  library,
		analyzer: analyzer,
		cache:    NewFragmentCache(),
	}
}

// NewFragmentCache creates a new fragment cache
func NewFragmentCache() *FragmentCache {
	return &FragmentCache{
		fragments: make(map[string]*ComposedFragment),
	}
}

// ComposeForTask creates a composed fragment for a specific task
func (fc *FragmentComposer) ComposeForTask(task *Task) (*ComposedFragment, error) {
	start := time.Now()
	
	// Check cache first
	cacheKey := fc.generateCacheKey(task)
	if cached := fc.cache.Get(cacheKey); cached != nil {
		return cached, nil
	}
	
	// Analyze task requirements
	capabilities := fc.analyzer.AnalyzeTask(task)
	
	// Find components that provide required capabilities
	selectedComponents, err := fc.selectComponents(capabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to select components: %w", err)
	}
	
	// Compose the fragment
	fragment, err := fc.composeFragment(selectedComponents, capabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to compose fragment: %w", err)
	}
	
	// Set metadata
	fragment.ID = fc.generateFragmentID(task)
	fragment.CreatedAt = time.Now()
	fragment.LoadTime = time.Since(start)
	
	// Cache the result
	fc.cache.Set(cacheKey, fragment)
	
	return fragment, nil
}

// selectComponents selects the minimal set of components for required capabilities
func (fc *FragmentComposer) selectComponents(capabilities map[Capability]bool) ([]*FragmentComponent, error) {
	var selectedComponents []*FragmentComponent
	selectedMap := make(map[string]bool) // Prevent duplicates
	
	// For each required capability, find a component that provides it
	for capability := range capabilities {
		components := fc.library.FindComponentsByCapability(capability)
		if len(components) == 0 {
			return nil, fmt.Errorf("no component found for capability: %s", capability)
		}
		
		// Select the first (smallest) component that provides this capability
		// In a real implementation, you might want to optimize for size or load time
		selectedComponent := components[0]
		if !selectedMap[selectedComponent.Name] {
			selectedComponents = append(selectedComponents, selectedComponent)
			selectedMap[selectedComponent.Name] = true
		}
	}
	
	return selectedComponents, nil
}

// composeFragment creates a composed fragment from selected components
func (fc *FragmentComposer) composeFragment(components []*FragmentComponent, capabilities map[Capability]bool) (*ComposedFragment, error) {
	// Calculate total size
	var totalSize int64
	for _, component := range components {
		totalSize += component.Size
	}
	
	// Create composed fragment
	fragment := &ComposedFragment{
		Components:   components,
		TotalSize:    totalSize,
		Capabilities: capabilities,
	}
	
	return fragment, nil
}

// generateCacheKey creates a cache key for a task
func (fc *FragmentComposer) generateCacheKey(task *Task) string {
	// Simple cache key based on command and arguments
	// In a real implementation, you might want to hash the full command
	args := ""
	if len(task.Args) > 0 {
		args = fmt.Sprintf("_%v", task.Args)
	}
	return fmt.Sprintf("%s%s", task.Command, args)
}

// generateFragmentID creates a unique ID for a fragment
func (fc *FragmentComposer) generateFragmentID(task *Task) string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("fragment_%s_%d", task.Command, timestamp)
}

// GetFragmentInfo returns detailed information about a composed fragment
func (fc *FragmentComposer) GetFragmentInfo(fragment *ComposedFragment) map[string]interface{} {
	componentInfo := make([]map[string]interface{}, len(fragment.Components))
	for i, component := range fragment.Components {
		componentInfo[i] = map[string]interface{}{
			"name":         component.Name,
			"size":         component.Size,
			"size_mb":      float64(component.Size) / (1024 * 1024),
			"capabilities": component.Capabilities,
			"load_time":    component.LoadTime,
		}
	}
	
	return map[string]interface{}{
		"id":           fragment.ID,
		"total_size":   fragment.TotalSize,
		"total_size_mb": float64(fragment.TotalSize) / (1024 * 1024),
		"components":   componentInfo,
		"capabilities": fragment.Capabilities,
		"created_at":   fragment.CreatedAt,
		"load_time":    fragment.LoadTime,
	}
}

// OptimizeFragment optimizes a fragment for better performance
func (fc *FragmentComposer) OptimizeFragment(fragment *ComposedFragment) (*ComposedFragment, error) {
	// In a real implementation, this would:
	// 1. Remove redundant components
	// 2. Optimize component ordering
	// 3. Pre-load frequently used components
	// 4. Compress components if beneficial
	
	// For now, return the fragment as-is
	return fragment, nil
}

// FragmentCache methods

// Get retrieves a fragment from cache
func (fc *FragmentCache) Get(key string) *ComposedFragment {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	
	return fc.fragments[key]
}

// Set stores a fragment in cache
func (fc *FragmentCache) Set(key string, fragment *ComposedFragment) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	
	fc.fragments[key] = fragment
}

// Clear removes all fragments from cache
func (fc *FragmentCache) Clear() {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	
	fc.fragments = make(map[string]*ComposedFragment)
}

// Size returns the number of cached fragments
func (fc *FragmentCache) Size() int {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	
	return len(fc.fragments)
}

// List returns all cached fragment keys
func (fc *FragmentCache) List() []string {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	
	keys := make([]string, 0, len(fc.fragments))
	for key := range fc.fragments {
		keys = append(keys, key)
	}
	
	return keys
}

// Remove removes a specific fragment from cache
func (fc *FragmentCache) Remove(key string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	
	delete(fc.fragments, key)
}

// GetCacheStats returns cache statistics
func (fc *FragmentCache) GetCacheStats() map[string]interface{} {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	
	var totalSize int64
	for _, fragment := range fc.fragments {
		totalSize += fragment.TotalSize
	}
	
	return map[string]interface{}{
		"fragment_count": len(fc.fragments),
		"total_size":     totalSize,
		"total_size_mb":  float64(totalSize) / (1024 * 1024),
	}
}