package orchestrator

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// NUMA topology manager for optimal container placement
type NUMATopologyManager struct {
	topology   *NUMATopology
	cpuInfo    *CPUInfo
	memoryInfo *MemoryInfo

	// Performance tracking
	nodePerformance map[int]*NodePerformanceHistory

	// Dynamic optimization
	rebalancer *NUMARebalancer
	optimizer  *PlacementOptimizer

	// Configuration
	config *NUMAConfig
}

// CPU information for NUMA awareness
type CPUInfo struct {
	CPUCount       int
	CoresPerSocket int
	ThreadsPerCore int
	SocketCount    int
	CPUToNode      map[int]int
	NodeToCPUs     map[int][]int
	CPUFrequency   map[int]int64   // CPU ID -> frequency in Hz
	CPUCapacity    map[int]float64 // CPU ID -> capacity (0.0-1.0)
}

// Memory information per NUMA node
type MemoryInfo struct {
	NodeMemory  map[int]*NodeMemoryInfo
	TotalMemory int64
	HugePages   *HugePagesInfo
}

type NodeMemoryInfo struct {
	NodeID          int
	TotalMemory     int64
	FreeMemory      int64
	AvailableMemory int64
	CachedMemory    int64
	BufferedMemory  int64
	LastUpdate      time.Time
}

type HugePagesInfo struct {
	HugePageSize   int64
	TotalHugePages int
	FreeHugePages  int
	NodeHugePages  map[int]int
}

// Node performance history for placement optimization
type NodePerformanceHistory struct {
	NodeID            int
	CPUUtilization    []float64       // Historical CPU utilization
	MemoryUtilization []float64       // Historical memory utilization
	IOUtilization     []float64       // Historical I/O utilization
	SpawnLatency      []time.Duration // Historical spawn latencies
	ContainerCount    []int           // Historical container counts

	// Performance metrics
	AvgCPUUtil      float64
	AvgMemoryUtil   float64
	AvgIOUtil       float64
	AvgSpawnLatency time.Duration

	// Trend analysis
	CPUTrend         TrendDirection
	MemoryTrend      TrendDirection
	PerformanceTrend TrendDirection

	LastUpdate time.Time
}

type TrendDirection int

const (
	TrendStable TrendDirection = iota
	TrendIncreasing
	TrendDecreasing
	TrendVolatile
)

// NUMA configuration
type NUMAConfig struct {
	EnableBalancing    bool
	BalancingInterval  time.Duration
	RebalanceThreshold float64
	PreferLocalMemory  bool
	EnableCPUAffinity  bool
	EnableMemoryPolicy bool

	// Performance tuning
	MaxContainersPerNode    int
	CPUUtilizationTarget    float64
	MemoryUtilizationTarget float64

	// History tracking
	HistorySize     int
	MetricsInterval time.Duration
}

// NewNUMATopologyManager creates a new NUMA topology manager
func NewNUMATopologyManager(config *NUMAConfig) (*NUMATopologyManager, error) {
	if config == nil {
		config = &NUMAConfig{
			EnableBalancing:         true,
			BalancingInterval:       30 * time.Second,
			RebalanceThreshold:      0.8,
			PreferLocalMemory:       true,
			EnableCPUAffinity:       true,
			EnableMemoryPolicy:      true,
			MaxContainersPerNode:    20,
			CPUUtilizationTarget:    0.75,
			MemoryUtilizationTarget: 0.80,
			HistorySize:             100,
			MetricsInterval:         5 * time.Second,
		}
	}

	manager := &NUMATopologyManager{
		config:          config,
		nodePerformance: make(map[int]*NodePerformanceHistory),
	}

	// Discover NUMA topology
	var err error // Declare err here for shadowing
	manager.topology, err = manager.discoverNUMATopology()
	if err != nil {
		return nil, fmt.Errorf("NUMA topology discovery failed: %w", err)
	}

	// Discover CPU information
	manager.cpuInfo, err = manager.discoverCPUInfo()
	if err != nil {
		return nil, fmt.Errorf("CPU info discovery failed: %w", err)
	}

	// Discover memory information
	manager.memoryInfo, err = manager.discoverMemoryInfo()
	if err != nil {
		return nil, fmt.Errorf("memory info discovery failed: %w", err)
	}

	// Initialize performance tracking
	manager.initializePerformanceTracking()

	// Initialize optimization components
	manager.rebalancer = NewNUMARebalancer(manager.topology, config)
	manager.optimizer = NewPlacementOptimizer(manager.topology, manager.nodePerformance)

	return manager, nil
}

// discoverNUMATopology discovers the system's NUMA topology
func (nm *NUMATopologyManager) discoverNUMATopology() (*NUMATopology, error) {
	topology := &NUMATopology{
		nodes:           make([]*NUMANode, 0),
		cpuToNode:       make(map[int]int),
		nodeUtilization: make(map[int]*NodeUtilization),
		processAffinity: make(map[string]int),
	}

	// Check if NUMA is available
	numaPath := "/sys/devices/system/node"
	if _, err := os.Stat(numaPath); os.IsNotExist(err) {
		// No NUMA support, create single node
		node := &NUMANode{
			ID:          0,
			CPUs:        make([]int, 0),
			Available:   true,
			Utilization: &NodeUtilization{},
		}
		topology.nodes = append(topology.nodes, node)
		topology.nodeCount = 1
		return topology, nil
	}

	// Discover NUMA nodes
	nodeEntries, err := os.ReadDir(numaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read NUMA nodes: %w", err)
	}

	for _, entry := range nodeEntries {
		if !strings.HasPrefix(entry.Name(), "node") {
			continue
		}

		nodeIDStr := strings.TrimPrefix(entry.Name(), "node")
		nodeID, err := strconv.Atoi(nodeIDStr)
		if err != nil {
			continue
		}

		node, err := nm.discoverNUMANode(nodeID)
		if err != nil {
			fmt.Printf("Warning: failed to discover node %d: %v\n", nodeID, err)
			continue
		}

		topology.nodes = append(topology.nodes, node)
		topology.nodeUtilization[nodeID] = node.Utilization

		// Map CPUs to nodes
		for _, cpu := range node.CPUs {
			topology.cpuToNode[cpu] = nodeID
		}
	}

	topology.nodeCount = len(topology.nodes)

	// Discover memory distances
	var err2 error // Use a new variable to avoid shadowing
	topology.memoryDistances, err2 = nm.discoverMemoryDistances(topology.nodeCount)
	if err2 != nil {
		fmt.Printf("Warning: failed to discover memory distances: %v\n", err2)
	}

	return topology, nil
}

// discoverNUMANode discovers information about a specific NUMA node
func (nm *NUMATopologyManager) discoverNUMANode(nodeID int) (*NUMANode, error) {
	nodePath := fmt.Sprintf("/sys/devices/system/node/node%d", nodeID)

	node := &NUMANode{
		ID:          nodeID,
		CPUs:        make([]int, 0),
		Available:   true,
		Utilization: &NodeUtilization{},
	}

	// Discover CPUs for this node
	cpulistPath := filepath.Join(nodePath, "cpulist")
	cpulist, err := os.ReadFile(cpulistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cpulist: %w", err)
	}

	cpus, err := nm.parseCPUList(strings.TrimSpace(string(cpulist)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CPU list: %w", err)
	}
	node.CPUs = cpus

	// Discover memory for this node
	meminfoPath := filepath.Join(nodePath, "meminfo")
	meminfo, err := os.ReadFile(meminfoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read meminfo: %w", err)
	}

	memory, err := nm.parseNodeMemInfo(string(meminfo))
	if err != nil {
		return nil, fmt.Errorf("failed to parse meminfo: %w", err)
	}
	node.Memory = memory

	return node, nil
}

// parseCPUList parses CPU list format (e.g., "0-3,8-11")
func (nm *NUMATopologyManager) parseCPUList(cpulist string) ([]int, error) {
	var cpus []int

	parts := strings.Split(cpulist, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// Range format (e.g., "0-3")
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid CPU range: %s", part)
			}

			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start CPU: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end CPU: %s", rangeParts[1])
			}

			for cpu := start; cpu <= end; cpu++ {
				cpus = append(cpus, cpu)
			}
		} else {
			// Single CPU
			cpu, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CPU: %s", part)
			}
			cpus = append(cpus, cpu)
		}
	}

	return cpus, nil
}

// parseNodeMemInfo parses NUMA node memory information
func (nm *NUMATopologyManager) parseNodeMemInfo(meminfo string) (int64, error) {
	scanner := bufio.NewScanner(strings.NewReader(meminfo))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Node ") && strings.Contains(line, "MemTotal:") {
			// Example: "Node 0 MemTotal:       16777216 kB"
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				memKB, err := strconv.ParseInt(parts[3], 10, 64)
				if err == nil {
					return memKB * 1024, nil // Convert KB to bytes
				}
			}
		}
	}

	return 0, fmt.Errorf("MemTotal not found in meminfo")
}

// discoverMemoryDistances discovers NUMA memory access distances
func (nm *NUMATopologyManager) discoverMemoryDistances(nodeCount int) ([][]int, error) {
	distances := make([][]int, nodeCount)
	for i := range distances {
		distances[i] = make([]int, nodeCount)
	}

	for nodeID := 0; nodeID < nodeCount; nodeID++ {
		distancePath := fmt.Sprintf("/sys/devices/system/node/node%d/distance", nodeID)
		distanceData, err := os.ReadFile(distancePath)
		if err != nil {
			continue
		}

		distanceStr := strings.TrimSpace(string(distanceData))
		distanceParts := strings.Fields(distanceStr)

		for i, part := range distanceParts {
			if i >= nodeCount {
				break
			}
			distance, err := strconv.Atoi(part)
			if err == nil {
				distances[nodeID][i] = distance
			}
		}
	}

	return distances, nil
}

// discoverCPUInfo discovers detailed CPU information
func (nm *NUMATopologyManager) discoverCPUInfo() (*CPUInfo, error) {
	cpuInfo := &CPUInfo{
		CPUToNode:    make(map[int]int),
		NodeToCPUs:   make(map[int][]int),
		CPUFrequency: make(map[int]int64),
		CPUCapacity:  make(map[int]float64),
	}

	// Read /proc/cpuinfo
	cpuinfoData, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/cpuinfo: %w", err)
	}

	err = nm.parseCPUInfo(string(cpuinfoData), cpuInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CPU info: %w", err)
	}

	// Map CPUs to NUMA nodes
	for nodeID, node := range nm.topology.nodes {
		for _, cpu := range node.CPUs {
			cpuInfo.CPUToNode[cpu] = nodeID
			cpuInfo.NodeToCPUs[nodeID] = append(cpuInfo.NodeToCPUs[nodeID], cpu)
		}
	}

	return cpuInfo, nil
}

// parseCPUInfo parses /proc/cpuinfo
func (nm *NUMATopologyManager) parseCPUInfo(cpuinfo string, info *CPUInfo) error {
	scanner := bufio.NewScanner(strings.NewReader(cpuinfo))

	cpuID := -1

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "processor":
			id, err := strconv.Atoi(value)
			if err == nil {
				cpuID = id
				info.CPUCount = max(info.CPUCount, id+1)
			}
		case "cpu MHz":
			if cpuID >= 0 {
				freq, err := strconv.ParseFloat(value, 64)
				if err == nil {
					info.CPUFrequency[cpuID] = int64(freq * 1000000) // Convert MHz to Hz
				}
			}
		case "cpu cores":
			cores, err := strconv.Atoi(value)
			if err == nil {
				info.CoresPerSocket = cores
			}
		case "siblings":
			siblings, err := strconv.Atoi(value)
			if err == nil && info.CoresPerSocket > 0 {
				info.ThreadsPerCore = siblings / info.CoresPerSocket
			}
		}
	}

	// Calculate socket count
	if info.CoresPerSocket > 0 && info.ThreadsPerCore > 0 {
		info.SocketCount = info.CPUCount / (info.CoresPerSocket * info.ThreadsPerCore)
	}

	return nil
}

// discoverMemoryInfo discovers system memory information
func (nm *NUMATopologyManager) discoverMemoryInfo() (*MemoryInfo, error) {
	memInfo := &MemoryInfo{
		NodeMemory: make(map[int]*NodeMemoryInfo),
	}

	// Discover per-node memory information
	for _, node := range nm.topology.nodes {
		nodeMemInfo, err := nm.discoverNodeMemoryInfo(node.ID)
		if err != nil {
			fmt.Printf("Warning: failed to discover memory info for node %d: %v\n", node.ID, err)
			continue
		}
		memInfo.NodeMemory[node.ID] = nodeMemInfo
		memInfo.TotalMemory += nodeMemInfo.TotalMemory
	}

	// Discover hugepage information
	hugePagesInfo, err := nm.discoverHugePagesInfo()
	if err != nil {
		fmt.Printf("Warning: failed to discover hugepage info: %v\n", err)
	} else {
		memInfo.HugePages = hugePagesInfo
	}

	return memInfo, nil
}

// discoverNodeMemoryInfo discovers memory information for a specific node
func (nm *NUMATopologyManager) discoverNodeMemoryInfo(nodeID int) (*NodeMemoryInfo, error) {
	meminfoPath := fmt.Sprintf("/sys/devices/system/node/node%d/meminfo", nodeID)
	meminfo, err := os.ReadFile(meminfoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read meminfo: %w", err)
	}

	nodeMemInfo := &NodeMemoryInfo{
		NodeID:     nodeID,
		LastUpdate: time.Now(),
	}

	scanner := bufio.NewScanner(strings.NewReader(string(meminfo)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}

		key := parts[2]      // e.g., "MemTotal:"
		valueStr := parts[3] // e.g., "16777216"

		value, err := strconv.ParseInt(valueStr, 10, 64)
		if err != nil {
			continue
		}
		value *= 1024 // Convert KB to bytes

		switch key {
		case "MemTotal:":
			nodeMemInfo.TotalMemory = value
		case "MemFree:":
			nodeMemInfo.FreeMemory = value
		case "MemAvailable:":
			nodeMemInfo.AvailableMemory = value
		case "Cached:":
			nodeMemInfo.CachedMemory = value
		case "Buffers:":
			nodeMemInfo.BufferedMemory = value
		}
	}

	return nodeMemInfo, nil
}

// discoverHugePagesInfo discovers hugepage information
func (nm *NUMATopologyManager) discoverHugePagesInfo() (*HugePagesInfo, error) {
	hugePagesInfo := &HugePagesInfo{
		NodeHugePages: make(map[int]int),
	}

	// Read hugepage size
	hugepageSizePath := "/proc/meminfo"
	meminfo, err := os.ReadFile(hugepageSizePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/meminfo: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(meminfo)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Hugepagesize:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				size, err := strconv.ParseInt(parts[1], 10, 64)
				if err == nil {
					hugePagesInfo.HugePageSize = size * 1024 // Convert KB to bytes
				}
			}
		} else if strings.HasPrefix(line, "HugePages_Total:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				total, err := strconv.Atoi(parts[1])
				if err == nil {
					hugePagesInfo.TotalHugePages = total
				}
			}
		} else if strings.HasPrefix(line, "HugePages_Free:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				free, err := strconv.Atoi(parts[1])
				if err == nil {
					hugePagesInfo.FreeHugePages = free
				}
			}
		}
	}

	return hugePagesInfo, nil
}

// initializePerformanceTracking initializes performance tracking for all nodes
func (nm *NUMATopologyManager) initializePerformanceTracking() {
	for _, node := range nm.topology.nodes {
		nm.nodePerformance[node.ID] = &NodePerformanceHistory{
			NodeID:            node.ID,
			CPUUtilization:    make([]float64, 0, nm.config.HistorySize),
			MemoryUtilization: make([]float64, 0, nm.config.HistorySize),
			IOUtilization:     make([]float64, 0, nm.config.HistorySize),
			SpawnLatency:      make([]time.Duration, 0, nm.config.HistorySize),
			ContainerCount:    make([]int, 0, nm.config.HistorySize),
			LastUpdate:        time.Now(),
		}
	}
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Placeholder types and constructors
type NUMARebalancer struct{}
type PlacementOptimizer struct{}

func NewNUMARebalancer(topology *NUMATopology, config *NUMAConfig) *NUMARebalancer {
	return &NUMARebalancer{}
}

func NewPlacementOptimizer(topology *NUMATopology, perf map[int]*NodePerformanceHistory) *PlacementOptimizer {
	return &PlacementOptimizer{}
}
