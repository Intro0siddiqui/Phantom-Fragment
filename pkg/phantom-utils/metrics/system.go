// Package metrics provides system monitoring and performance metrics
package metrics

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SystemMetrics contains system metrics
type SystemMetrics struct {
	cpuUsage    float64
	memoryUsage float64
	diskUsage   float64
	lastUpdate  time.Time
	mu          sync.RWMutex
}

// NewSystemCollector creates a new system metrics collector
func NewSystemCollector() *SystemCollector {
	return &SystemCollector{
		metrics: &SystemMetrics{
			lastUpdate: time.Now(),
		},
	}
}

// GetCPUMetrics returns CPU usage metrics
func (sc *SystemCollector) GetCPUMetrics() CPUMetrics {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return CPUMetrics{
		UsagePercent: sc.metrics.cpuUsage,
		Timestamp:    sc.metrics.lastUpdate,
	}
}

// GetMemoryMetrics returns memory usage metrics
func (sc *SystemCollector) GetMemoryMetrics() MemoryMetrics {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return MemoryMetrics{
		UsagePercent: sc.metrics.memoryUsage,
		Timestamp:    sc.metrics.lastUpdate,
	}
}

// GetPSIMetrics returns PSI (Pressure Stall Information) metrics
func (sc *SystemCollector) GetPSIMetrics() PSIMetrics {
	return readPSIMetrics()
}

// CPUMetrics contains CPU-related metrics
type CPUMetrics struct {
	UsagePercent float64
	Timestamp    time.Time
}

// MemoryMetrics contains memory-related metrics
type MemoryMetrics struct {
	UsagePercent float64
	Timestamp    time.Time
}

// PSIMetrics contains PSI (Pressure Stall Information) metrics
type PSIMetrics struct {
	CPUStall    float64
	MemoryStall float64
	IOStall     float64
	SomeStall   float64
	FullStall   float64
	Timestamp   time.Time
}

// SystemCollector collects system metrics
type SystemCollector struct {
	metrics *SystemMetrics
	mu      sync.RWMutex
}

// readPSIMetrics reads PSI metrics from /proc/pressure/
func readPSIMetrics() PSIMetrics {
	psi := PSIMetrics{
		Timestamp: time.Now(),
	}

	// Read CPU pressure
	if data, err := os.ReadFile("/proc/pressure/cpu"); err == nil {
		psi.CPUStall = parsePSILine(string(data))
	}

	// Read memory pressure
	if data, err := os.ReadFile("/proc/pressure/memory"); err == nil {
		psi.MemoryStall = parsePSILine(string(data))
	}

	// Read IO pressure
	if data, err := os.ReadFile("/proc/pressure/io"); err == nil {
		psi.IOStall = parsePSILine(string(data))
	}

	return psi
}

// parsePSILine parses a single PSI line
func parsePSILine(line string) float64 {
	// Format: some avg10=0.00 avg60=0.00 avg300=0.00 total=0
	parts := strings.Fields(line)
	for _, part := range parts {
		if strings.HasPrefix(part, "avg10=") {
			if value, err := strconv.ParseFloat(strings.TrimPrefix(part, "avg10="), 64); err == nil {
				return value
			}
		}
	}
	return 0.0
}

// IsPSIAvailable returns true if PSI is available on the system
func IsPSIAvailable() bool {
	_, err := os.Stat("/proc/pressure")
	return err == nil
}

// GetSystemInfo returns basic system information
func GetSystemInfo() SystemInfo {
	info := SystemInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
		CPUs: runtime.NumCPU(),
	}

	// Get memory info
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		info = parseMemInfo(info, string(data))
	}

	return info
}

// SystemInfo contains basic system information
type SystemInfo struct {
	OS      string
	Arch    string
	CPUs    int
	Memory  int64
	Version string
}

// parseMemInfo parses /proc/meminfo
func parseMemInfo(info SystemInfo, data string) SystemInfo {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if memKB, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					info.Memory = memKB * 1024
				}
			}
		}
	}
	return info
}

// PerformanceTracker tracks performance metrics over time
type PerformanceTracker struct {
	history []PerformanceSample
	maxSize int
	mu      sync.Mutex
}

// PerformanceSample contains a single performance measurement
type PerformanceSample struct {
	Timestamp time.Time
	CPUPercent float64
	MemoryPercent float64
	IOPercent float64
}

// NewPerformanceTracker creates a new performance tracker
func NewPerformanceTracker(maxHistory int) *PerformanceTracker {
	return &PerformanceTracker{
		history: make([]PerformanceSample, 0, maxHistory),
		maxSize: maxHistory,
	}
}

// AddSample adds a new performance sample
func (pt *PerformanceTracker) AddSample(sample PerformanceSample) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.history = append(pt.history, sample)
	if len(pt.history) > pt.maxSize {
		pt.history = pt.history[1:]
	}
}

// GetAverage returns the average performance over the last N samples
func (pt *PerformanceTracker) GetAverage(samples int) PerformanceSample {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if len(pt.history) == 0 {
		return PerformanceSample{}
	}

	if samples > len(pt.history) {
		samples = len(pt.history)
	}

	var avg PerformanceSample
	start := len(pt.history) - samples

	for i := start; i < len(pt.history); i++ {
		avg.CPUPercent += pt.history[i].CPUPercent
		avg.MemoryPercent += pt.history[i].MemoryPercent
		avg.IOPercent += pt.history[i].IOPercent
	}

	count := float64(samples)
	avg.CPUPercent /= count
	avg.MemoryPercent /= count
	avg.IOPercent /= count

	return avg
}