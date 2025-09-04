// Package numa provides NUMA topology discovery and management
package numa

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Topology represents the system's NUMA topology
type Topology struct {
	Nodes       []*Node
	CPUToNode   map[int]int
	NodeToCPUs  map[int][]int
	MemoryDistances [][]int
}

// Node represents a NUMA node
type Node struct {
	ID        int
	CPUs      []int
	Memory    int64 // bytes
	Available bool
}

// NewTopology creates a new NUMA topology instance
func NewTopology() *Topology {
	t := &Topology{
		CPUToNode:  make(map[int]int),
		NodeToCPUs: make(map[int][]int),
	}
	t.discover()
	return t
}

// discover performs NUMA topology discovery
func (t *Topology) discover() {
	numaPath := "/sys/devices/system/node"
	if _, err := os.Stat(numaPath); os.IsNotExist(err) {
		// Single node fallback
		t.Nodes = []*Node{&Node{ID: 0, Available: true}}
		return
	}

	entries, _ := os.ReadDir(numaPath)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "node") {
			continue
		}

		nodeIDStr := strings.TrimPrefix(entry.Name(), "node")
		nodeID, _ := strconv.Atoi(nodeIDStr)
		
		node := t.discoverNode(nodeID)
		if node != nil {
			t.Nodes = append(t.Nodes, node)
			
			// Map CPUs to node
			for _, cpu := range node.CPUs {
				t.CPUToNode[cpu] = nodeID
				t.NodeToCPUs[nodeID] = append(t.NodeToCPUs[nodeID], cpu)
			}
		}
	}
}

// discoverNode discovers information about a specific NUMA node
func (t *Topology) discoverNode(nodeID int) *Node {
	nodePath := fmt.Sprintf("/sys/devices/system/node/node%d", nodeID)
	
	node := &Node{
		ID:        nodeID,
		CPUs:      []int{},
		Available: true,
	}

	// Get CPUs
	cpulistPath := filepath.Join(nodePath, "cpulist")
	if data, err := os.ReadFile(cpulistPath); err == nil {
		cpus := t.parseCPUList(strings.TrimSpace(string(data)))
		node.CPUs = cpus
	}

	// Get memory
	meminfoPath := filepath.Join(nodePath, "meminfo")
	if data, err := os.ReadFile(meminfoPath); err == nil {
		memory := t.parseNodeMemInfo(string(data))
		node.Memory = memory
	}

	return node
}

// parseCPUList parses CPU list format (e.g., "0-3,8-11")
func (t *Topology) parseCPUList(cpulist string) []int {
	var cpus []int
	
	for _, part := range strings.Split(cpulist, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])
				for cpu := start; cpu <= end; cpu++ {
					cpus = append(cpus, cpu)
				}
			}
		} else {
			cpu, _ := strconv.Atoi(part)
			cpus = append(cpus, cpu)
		}
	}
	
	return cpus
}

// parseNodeMemInfo parses NUMA node memory information
func (t *Topology) parseNodeMemInfo(meminfo string) int64 {
	scanner := bufio.NewScanner(strings.NewReader(meminfo))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Node ") && strings.Contains(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				memKB, _ := strconv.ParseInt(parts[3], 10, 64)
				return memKB * 1024 // Convert KB to bytes
			}
		}
	}
	return 0
}

// GetCPUsForNode returns CPUs for a specific NUMA node
func (t *Topology) GetCPUsForNode(nodeID int) []int {
	return t.NodeToCPUs[nodeID]
}

// GetNodeForCPU returns the NUMA node for a specific CPU
func (t *Topology) GetNodeForCPU(cpuID int) int {
	return t.CPUToNode[cpuID]
}

// GetTotalMemory returns total memory across all nodes
func (t *Topology) GetTotalMemory() int64 {
	var total int64
	for _, node := range t.Nodes {
		total += node.Memory
	}
	return total
}

// GetMemoryForNode returns memory for a specific NUMA node
func (t *Topology) GetMemoryForNode(nodeID int) int64 {
	for _, node := range t.Nodes {
		if node.ID == nodeID {
			return node.Memory
		}
	}
	return 0
}

// IsNUMAAvailable returns true if NUMA topology is detected
func IsNUMAAvailable() bool {
	_, err := os.Stat("/sys/devices/system/node")
	return err == nil
}