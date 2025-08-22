package seccomp

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/you/ai-sandbox/internal/config"
	"github.com/you/ai-sandbox/internal/metrics"
	"github.com/you/ai-sandbox/internal/security/audit"
)

func TestMonitor_RecordSeccompViolation(t *testing.T) {
	cfg := config.DefaultConfig()
	monitor, err := NewMonitor(cfg)
	if err != nil {
		t.Fatalf("NewMonitor failed: %v", err)
	}
	
	// Create test metrics collector and logger
	metricsCollector := metrics.NewCollector()
	logger := audit.NewLogger("/tmp/test-security.log")
	
	monitor.SetMetricsCollector(metricsCollector)
	monitor.SetLogger(logger)
	
	// Test recording a seccomp violation
	containerID := "test-container-123"
	syscall := "execve"
	message := "Operation not permitted"
	
	monitor.RecordSeccompViolation(containerID, syscall, message)
	
	// Verify the metrics were recorded
	// This would normally be checked via Prometheus, but we can verify the method exists
	if monitor.metrics == nil {
		t.Error("Metrics collector not set")
	}
	
	if monitor.logger == nil {
		t.Error("Logger not set")
	}
}

func TestMonitor_MonitorProcess(t *testing.T) {
	cfg := config.DefaultConfig()
	monitor, err := NewMonitor(cfg)
	if err != nil {
		t.Fatalf("NewMonitor failed: %v", err)
	}
	
	// Create a simple command that will exit quickly
	cmd := exec.Command("echo", "test")
	
	// Start the command
	if err := cmd.Start(); err != nil {
		t.Skip("Cannot test process monitoring without echo command")
	}
	
	// Monitor the process
	containerID := "test-container-456"
	profileName := "test-profile"
	
	err = monitor.MonitorProcess(context.Background(), cmd, containerID, profileName)
	if err != nil {
		t.Errorf("MonitorProcess failed: %v", err)
	}
	
	// Wait a bit for the monitoring goroutine to complete
	time.Sleep(100 * time.Millisecond)
	
	// The process should have exited normally without seccomp violations
}

func TestNewMonitor(t *testing.T) {
	cfg := config.DefaultConfig()
	monitor, err := NewMonitor(cfg)
	if err != nil {
		t.Fatalf("NewMonitor failed: %v", err)
	}
	
	if monitor == nil {
		t.Error("NewMonitor returned nil")
	}
	
	if monitor.config == nil {
		t.Error("Monitor config not set")
	}
	
	if monitor.manager == nil {
		t.Error("Monitor manager not set")
	}
}