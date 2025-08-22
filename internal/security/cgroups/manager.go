package cgroups

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Manager handles cgroup operations
type Manager struct {
	cgroupPath string
	metrics    MetricsCollector
}

// MetricsCollector interface for recording metrics
type MetricsCollector interface {
	RecordOOM(containerID string)
}

// NewManager creates a new cgroup manager
func NewManager(containerID string) *Manager {
	return &Manager{
		cgroupPath: filepath.Join("/sys/fs/cgroup", containerID),
	}
}

// SetMetricsCollector sets the metrics collector for the cgroup manager
func (m *Manager) SetMetricsCollector(metrics MetricsCollector) {
	m.metrics = metrics
}

// Create creates a new cgroup
func (m *Manager) Create() error {
	if err := os.MkdirAll(m.cgroupPath, 0755); err != nil {
		return err
	}

	// Start monitoring memory events in a goroutine
	go m.monitorMemoryEvents()

	return nil
}

// SetMemoryLimit sets the memory limit for the cgroup
func (m *Manager) SetMemoryLimit(limitMB int) error {
	return writeFile(filepath.Join(m.cgroupPath, "memory.max"), fmt.Sprintf("%dM", limitMB))
}

// SetCPULimit sets the CPU limit for the cgroup
func (m *Manager) SetCPULimit(limitCores int) error {
	// This is a simplified implementation
	// In reality, CPU limiting with cgroups v2 is more complex
	return writeFile(filepath.Join(m.cgroupPath, "cpu.max"), fmt.Sprintf("%d %d", limitCores*100000, 100000))
}

// SetPIDLimit sets the PID limit for the cgroup
func (m *Manager) SetPIDLimit(limit int) error {
	return writeFile(filepath.Join(m.cgroupPath, "pids.max"), strconv.Itoa(limit))
}

// AddProcess adds a process to the cgroup
func (m *Manager) AddProcess(pid int) error {
	return writeFile(filepath.Join(m.cgroupPath, "cgroup.procs"), strconv.Itoa(pid))
}

// Destroy removes the cgroup
func (m *Manager) Destroy() error {
	return os.RemoveAll(m.cgroupPath)
}

// monitorMemoryEvents monitors the memory.events file for OOM events
func (m *Manager) monitorMemoryEvents() {
	// Only monitor if metrics collector is set
	if m.metrics == nil {
		return
	}

	// Path to the memory.events file
	memoryEventsPath := filepath.Join(m.cgroupPath, "memory.events")

	// Keep track of the last seen OOM count
	lastOOMCount := 0

	// Check the memory.events file every second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Check if the cgroup still exists
		if _, err := os.Stat(m.cgroupPath); os.IsNotExist(err) {
			// Cgroup no longer exists, stop monitoring
			return
		}

		// Read the memory.events file
		file, err := os.Open(memoryEventsPath)
		if err != nil {
			// File may not exist yet, continue monitoring
			continue
		}

		// Parse the file to get the OOM count
		scanner := bufio.NewScanner(file)
		currentOOMCount := 0

		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "oom ") {
				// Extract the OOM count
				_, err := fmt.Sscanf(line, "oom %d", &currentOOMCount)
				if err != nil {
					// Error parsing, continue monitoring
					break
				}

				// Check if the OOM count has increased
				if currentOOMCount > lastOOMCount {
					// Record the OOM event
					m.metrics.RecordOOM(filepath.Base(m.cgroupPath))
					lastOOMCount = currentOOMCount
				}

				// Stop parsing after finding the OOM count
				break
			}
		}

		// Close the file
		file.Close()
	}
}

// writeFile writes content to a file
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
