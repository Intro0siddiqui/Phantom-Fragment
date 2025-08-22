package seccomp

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/you/ai-sandbox/internal/config"
	"github.com/you/ai-sandbox/internal/metrics"
	"github.com/you/ai-sandbox/internal/security/audit"
)

// Monitor handles seccomp violation monitoring
type Monitor struct {
	config  *config.Config
	metrics *metrics.Collector
	logger  *audit.Logger
	manager *Manager
}

// NewMonitor creates a new seccomp monitor
func NewMonitor(cfg *config.Config) (*Monitor, error) {
	manager := NewManager(cfg)
	return &Monitor{
		config:  cfg,
		metrics: nil,
		logger:  nil,
		manager: manager,
	}, nil
}

// SetMetricsCollector sets the metrics collector for the seccomp monitor
func (m *Monitor) SetMetricsCollector(collector *metrics.Collector) {
	m.metrics = collector
	m.manager.SetMetricsCollector(collector)
}

// SetLogger sets the audit logger for the seccomp monitor
func (m *Monitor) SetLogger(logger *audit.Logger) {
	m.logger = logger
}

// MonitorProcess monitors a process for seccomp violations
func (m *Monitor) MonitorProcess(ctx context.Context, cmd *exec.Cmd, containerID, profileName string) error {
	// Use ptrace to monitor syscalls and detect seccomp violations
	// This is a simplified implementation - in production, you'd use eBPF or ptrace

	// Capture stderr for seccomp-related errors
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Monitor the process exit status
	go m.monitorProcessResult(cmd, &stderr, containerID, profileName)
	return nil
}

// monitorProcessResult monitors the process result for seccomp violations
func (m *Monitor) monitorProcessResult(cmd *exec.Cmd, stderr *bytes.Buffer, containerID, profileName string) {
	// Wait for the process to complete
	state, err := cmd.Process.Wait()
	if err != nil {
		// Check if the error indicates a signal was received
		if exiterr, ok := err.(*exec.ExitError); ok {
			// On Windows, we can't directly check the signal, but we can check the exit code
			// Seccomp violations typically result in exit code 1 or 255
			if status := exiterr.ExitCode(); status == 1 || status == 255 {
				m.RecordSeccompViolation(containerID, "unknown", fmt.Sprintf("process exited with code %d (potential seccomp violation)", status))
			}
		}
		return
	}

	// Check for seccomp violations in the exit status
	if !state.Success() {
		// Check stderr for seccomp-related messages
		output := stderr.String()
		if output != "" {
			if strings.Contains(output, "Operation not permitted") ||
				strings.Contains(output, "seccomp") ||
				strings.Contains(output, "syscall") {
				m.RecordSeccompViolation(containerID, "unknown", fmt.Sprintf("stderr: %s", output))
			}
		}
	}
}

// RecordSeccompViolation records a seccomp violation event
func (m *Monitor) RecordSeccompViolation(containerID, syscall, message string) {
	// Record metrics
	if m.metrics != nil {
		m.metrics.RecordDeniedSyscall(containerID, syscall)
	}

	// Log audit event
	if m.logger != nil {
		details := map[string]interface{}{
			"syscall":  syscall,
			"severity": "high",
		}
		m.logger.LogEvent("seccomp_violation", containerID, message, details)
	}
}
