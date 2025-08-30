package seccomp

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phantom-fragment/phantom-fragment/internal/config"
	"github.com/phantom-fragment/phantom-fragment/internal/metrics"
	"github.com/phantom-fragment/phantom-fragment/internal/security/audit"
)

// SyscallViolation represents a detected syscall violation
type SyscallViolation struct {
	ContainerID   string
	SyscallName   string
	SyscallNumber int
	PID           int
	Timestamp     time.Time
	Severity      string
	Message       string
	ProfileName   string
	Action        string // KILL, TRAP, ERRNO, etc.
}

// Monitor handles seccomp violation monitoring with enhanced capabilities
type Monitor struct {
	config  *config.Config
	metrics *metrics.Collector
	logger  *audit.Logger
	manager *Manager

	// Enhanced monitoring
	violationChan chan SyscallViolation
	monitoring    bool
	mu            sync.RWMutex

	// Syscall filtering and analysis
	syscallPatterns   map[string]*regexp.Regexp
	dangerousSyscalls map[string]string
	violationStats    map[string]int
	statsMutex        sync.RWMutex
}

// NewMonitor creates a new enhanced seccomp monitor
func NewMonitor(cfg *config.Config) (*Monitor, error) {
	manager := NewManager(cfg)

	monitor := &Monitor{
		config:            cfg,
		metrics:           nil,
		logger:            nil,
		manager:           manager,
		violationChan:     make(chan SyscallViolation, 100),
		monitoring:        false,
		syscallPatterns:   initSyscallPatterns(),
		dangerousSyscalls: initDangerousSyscalls(),
		violationStats:    make(map[string]int),
	}

	// Start violation processing goroutine
	go monitor.processViolations()

	return monitor, nil
}

// initSyscallPatterns initializes regex patterns for syscall detection
func initSyscallPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"seccomp_violation": regexp.MustCompile(`seccomp.*violation.*syscall\s+(\w+)\s*\((\d+)\)`),
		"denied_syscall":    regexp.MustCompile(`Operation not permitted.*syscall\s+(\w+)`),
		"ptrace_syscall":    regexp.MustCompile(`ptrace.*syscall\s+(\d+)`),
		"audit_syscall":     regexp.MustCompile(`audit.*syscall=(\d+).*name=(\w+)`),
		"bpf_violation":     regexp.MustCompile(`bpf.*denied.*syscall\s+(\w+)`),
	}
}

// initDangerousSyscalls maps syscall names to their risk levels
func initDangerousSyscalls() map[string]string {
	return map[string]string{
		// Critical system calls
		"execve":     "critical",
		"execveat":   "critical",
		"ptrace":     "critical",
		"mount":      "critical",
		"umount":     "critical",
		"umount2":    "critical",
		"chroot":     "critical",
		"pivot_root": "critical",
		"reboot":     "critical",
		"syslog":     "critical",
		"kexec_load": "critical",

		// High-risk networking
		"socket":   "high",
		"bind":     "high",
		"listen":   "high",
		"accept":   "high",
		"connect":  "high",
		"sendto":   "high",
		"recvfrom": "high",

		// File system manipulation
		"unlink":   "medium",
		"unlinkat": "medium",
		"rmdir":    "medium",
		"chmod":    "medium",
		"chown":    "medium",
		"fchown":   "medium",
		"lchown":   "medium",

		// Process control
		"kill":     "medium",
		"tkill":    "medium",
		"tgkill":   "medium",
		"setuid":   "medium",
		"setgid":   "medium",
		"setreuid": "medium",
		"setregid": "medium",
	}
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

// MonitorProcess monitors a process for seccomp violations with enhanced detection
func (m *Monitor) MonitorProcess(ctx context.Context, cmd *exec.Cmd, containerID, profileName string) error {
	m.mu.Lock()
	m.monitoring = true
	m.mu.Unlock()

	// Capture both stdout and stderr for analysis
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	// Enhanced monitoring with multiple detection methods
	go m.monitorProcessAdvanced(ctx, cmd, &stderr, &stdout, containerID, profileName)

	// Start real-time log monitoring if available
	go m.monitorSystemLogs(ctx, containerID, profileName)

	return nil
}

// monitorProcessAdvanced provides enhanced process monitoring with detailed analysis
func (m *Monitor) monitorProcessAdvanced(ctx context.Context, cmd *exec.Cmd, stderr, stdout *bytes.Buffer, containerID, profileName string) {
	defer func() {
		m.mu.Lock()
		m.monitoring = false
		m.mu.Unlock()
	}()

	// Wait for the process to complete or context cancellation
	processDone := make(chan error, 1)
	go func() {
		processDone <- cmd.Wait()
	}()

	select {
	case err := <-processDone:
		m.analyzeProcessExit(err, stderr, stdout, containerID, profileName)
	case <-ctx.Done():
		// Context cancelled, process might still be running
		m.handleProcessTimeout(cmd, containerID, profileName)
	}
}

// analyzeProcessExit performs detailed analysis of process exit conditions
func (m *Monitor) analyzeProcessExit(err error, stderr, stdout *bytes.Buffer, containerID, profileName string) {
	stderrOutput := stderr.String()
	stdoutOutput := stdout.String()

	if err != nil {
		// Analyze exit error for seccomp violations
		if exiterr, ok := err.(*exec.ExitError); ok {
			exitCode := exiterr.ExitCode()

			// Different exit codes indicate different types of violations
			switch exitCode {
			case 1:
				m.analyzeViolationType("general_error", stderrOutput, containerID, profileName)
			case 125:
				m.analyzeViolationType("docker_error", stderrOutput, containerID, profileName)
			case 126:
				m.analyzeViolationType("permission_denied", stderrOutput, containerID, profileName)
			case 127:
				m.analyzeViolationType("command_not_found", stderrOutput, containerID, profileName)
			case 128:
				m.analyzeViolationType("invalid_exit", stderrOutput, containerID, profileName)
			case 137:
				m.analyzeViolationType("sigkill", stderrOutput, containerID, profileName)
			case 139:
				m.analyzeViolationType("sigsegv", stderrOutput, containerID, profileName)
			default:
				m.analyzeViolationType("unknown_error", fmt.Sprintf("Exit code: %d\n%s", exitCode, stderrOutput), containerID, profileName)
			}
		}
	}

	// Analyze output for seccomp-specific patterns
	m.analyzeSyscallOutput(stderrOutput, containerID, profileName)
	m.analyzeSyscallOutput(stdoutOutput, containerID, profileName)
}

// analyzeViolationType determines the type and severity of violations
func (m *Monitor) analyzeViolationType(violationType, output, containerID, profileName string) {
	violation := SyscallViolation{
		ContainerID: containerID,
		Timestamp:   time.Now(),
		ProfileName: profileName,
		Message:     fmt.Sprintf("Process violation: %s", violationType),
		Action:      "DETECTED",
	}

	// Set severity based on violation type
	switch violationType {
	case "sigkill", "sigsegv":
		violation.Severity = "critical"
	case "permission_denied":
		violation.Severity = "high"
	case "command_not_found", "docker_error":
		violation.Severity = "medium"
	default:
		violation.Severity = "low"
	}

	// Analyze output for specific syscalls
	if syscallName := m.extractSyscallFromOutput(output); syscallName != "" {
		violation.SyscallName = syscallName
		if severity, exists := m.dangerousSyscalls[syscallName]; exists {
			violation.Severity = severity
		}
	}

	// Send violation to processing channel
	select {
	case m.violationChan <- violation:
	default:
		// Channel full, log directly
		m.RecordSeccompViolation(containerID, violation.SyscallName, violation.Message)
	}
}

// analyzeSyscallOutput analyzes process output for syscall violations
func (m *Monitor) analyzeSyscallOutput(output, containerID, profileName string) {
	if output == "" {
		return
	}

	// Check for common seccomp violation patterns
	violationPatterns := []struct {
		pattern     string
		severity    string
		description string
	}{
		{"Operation not permitted", "high", "Syscall denied by seccomp"},
		{"seccomp", "high", "Seccomp violation detected"},
		{"syscall", "medium", "Syscall-related message"},
		{"SIGKILL", "critical", "Process killed by signal"},
		{"SIGSYS", "critical", "Bad system call"},
		{"audit", "medium", "Audit subsystem message"},
		{"bpf", "high", "BPF filter violation"},
		{"ptrace", "high", "Ptrace operation detected"},
	}

	for _, vp := range violationPatterns {
		if strings.Contains(strings.ToLower(output), strings.ToLower(vp.pattern)) {
			violation := SyscallViolation{
				ContainerID: containerID,
				Timestamp:   time.Now(),
				Severity:    vp.severity,
				Message:     fmt.Sprintf("%s: %s", vp.description, strings.TrimSpace(output)),
				ProfileName: profileName,
				Action:      "PATTERN_MATCH",
			}

			// Try to extract specific syscall information
			if syscall := m.extractSyscallFromOutput(output); syscall != "" {
				violation.SyscallName = syscall
			}

			select {
			case m.violationChan <- violation:
			default:
				m.RecordSeccompViolation(containerID, violation.SyscallName, violation.Message)
			}
		}
	}
}

// extractSyscallFromOutput attempts to extract syscall names from output
func (m *Monitor) extractSyscallFromOutput(output string) string {
	for name, pattern := range m.syscallPatterns {
		matches := pattern.FindStringSubmatch(output)
		if len(matches) > 1 {
			// Different patterns have syscall info in different positions
			switch name {
			case "seccomp_violation":
				if len(matches) > 1 {
					return matches[1] // Syscall name
				}
			case "denied_syscall":
				if len(matches) > 1 {
					return matches[1] // Syscall name
				}
			case "audit_syscall":
				if len(matches) > 2 {
					return matches[2] // Syscall name from audit log
				}
			case "ptrace_syscall":
				if len(matches) > 1 {
					// Convert syscall number to name if possible
					if num, err := strconv.Atoi(matches[1]); err == nil {
						return fmt.Sprintf("syscall_%d", num)
					}
				}
			}
		}
	}

	// Try simple pattern matching for common syscalls
	commonSyscalls := []string{
		"execve", "ptrace", "mount", "umount", "chroot", "socket",
		"bind", "listen", "accept", "connect", "kill", "chmod", "chown",
	}

	outputLower := strings.ToLower(output)
	for _, syscall := range commonSyscalls {
		if strings.Contains(outputLower, syscall) {
			return syscall
		}
	}

	return ""
}

// handleProcessTimeout handles cases where process monitoring times out
func (m *Monitor) handleProcessTimeout(cmd *exec.Cmd, containerID, profileName string) {
	violation := SyscallViolation{
		ContainerID: containerID,
		Timestamp:   time.Now(),
		Severity:    "medium",
		Message:     "Process monitoring timeout - potential hanging or infinite loop",
		ProfileName: profileName,
		Action:      "TIMEOUT",
	}

	select {
	case m.violationChan <- violation:
	default:
		m.RecordSeccompViolation(containerID, "", violation.Message)
	}
}

// monitorSystemLogs monitors system logs for seccomp violations (Linux-specific)
func (m *Monitor) monitorSystemLogs(ctx context.Context, containerID, profileName string) {
	// This would typically monitor /var/log/audit/audit.log or dmesg
	// For cross-platform compatibility, we'll implement a basic version

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check for system-level seccomp violations
			m.checkSystemViolations(containerID, profileName)
		}
	}
}

// checkSystemViolations checks system logs for violations
func (m *Monitor) checkSystemViolations(containerID, profileName string) {
	// This is a placeholder for system-level monitoring
	// In a real implementation, this would:
	// 1. Parse audit logs
	// 2. Monitor dmesg output
	// 3. Check for BPF program violations
	// 4. Monitor container runtime logs
}

// processViolations processes violations in the background
func (m *Monitor) processViolations() {
	for violation := range m.violationChan {
		m.handleViolation(violation)
	}
}

// handleViolation processes a single violation with enhanced analysis
func (m *Monitor) handleViolation(violation SyscallViolation) {
	// Update statistics
	m.updateViolationStats(violation)

	// Determine response action based on severity
	action := m.determineResponseAction(violation)

	// Record the violation with enhanced details
	details := map[string]interface{}{
		"syscall":     violation.SyscallName,
		"syscall_num": violation.SyscallNumber,
		"pid":         violation.PID,
		"severity":    violation.Severity,
		"profile":     violation.ProfileName,
		"action":      violation.Action,
		"response":    action,
		"timestamp":   violation.Timestamp,
	}

	// Record metrics
	if m.metrics != nil {
		m.metrics.RecordDeniedSyscall(violation.ContainerID, violation.SyscallName)
	}

	// Log audit event with enhanced details
	if m.logger != nil {
		m.logger.LogEvent("seccomp_violation_enhanced", violation.ContainerID, violation.Message, details)
	}

	// Take response action if needed
	m.executeResponseAction(violation, action)
}

// updateViolationStats updates violation statistics
func (m *Monitor) updateViolationStats(violation SyscallViolation) {
	m.statsMutex.Lock()
	defer m.statsMutex.Unlock()

	// Update per-syscall statistics
	if violation.SyscallName != "" {
		m.violationStats[violation.SyscallName]++
	}

	// Update per-severity statistics
	m.violationStats[fmt.Sprintf("severity_%s", violation.Severity)]++

	// Update per-container statistics
	m.violationStats[fmt.Sprintf("container_%s", violation.ContainerID)]++
}

// determineResponseAction determines what action to take for a violation
func (m *Monitor) determineResponseAction(violation SyscallViolation) string {
	switch violation.Severity {
	case "critical":
		return "KILL_CONTAINER"
	case "high":
		// Check if this is a repeated violation
		m.statsMutex.RLock()
		count := m.violationStats[violation.SyscallName]
		m.statsMutex.RUnlock()

		if count > 3 {
			return "KILL_CONTAINER"
		}
		return "ALERT"
	case "medium":
		return "LOG"
	default:
		return "MONITOR"
	}
}

// executeResponseAction executes the determined response action
func (m *Monitor) executeResponseAction(violation SyscallViolation, action string) {
	switch action {
	case "KILL_CONTAINER":
		// This would typically send a signal to terminate the container
		m.logCriticalViolation(violation)
	case "ALERT":
		// Send immediate alert to security team
		m.sendSecurityAlert(violation)
	case "LOG":
		// Already logged, no additional action
	case "MONITOR":
		// Continue monitoring, no immediate action
	}
}

// logCriticalViolation logs critical violations that require immediate attention
func (m *Monitor) logCriticalViolation(violation SyscallViolation) {
	if m.logger != nil {
		m.logger.LogSecurityViolation(violation.ContainerID, "critical_seccomp_violation",
			fmt.Sprintf("CRITICAL: %s", violation.Message),
			map[string]interface{}{
				"syscall":         violation.SyscallName,
				"severity":        violation.Severity,
				"response":        "KILL_CONTAINER",
				"profile":         violation.ProfileName,
				"requires_action": true,
			})
	}
}

// sendSecurityAlert sends security alerts for high-severity violations
func (m *Monitor) sendSecurityAlert(violation SyscallViolation) {
	// This would typically integrate with alerting systems
	// For now, we'll log it as a high-priority event
	if m.logger != nil {
		m.logger.LogSecurityViolation(violation.ContainerID, "high_priority_alert",
			fmt.Sprintf("HIGH PRIORITY: %s", violation.Message),
			map[string]interface{}{
				"syscall":  violation.SyscallName,
				"severity": violation.Severity,
				"alert":    true,
				"profile":  violation.ProfileName,
			})
	}
}

// GetViolationStats returns current violation statistics
func (m *Monitor) GetViolationStats() map[string]int {
	m.statsMutex.RLock()
	defer m.statsMutex.RUnlock()

	stats := make(map[string]int)
	for k, v := range m.violationStats {
		stats[k] = v
	}
	return stats
}

// IsMonitoring returns whether the monitor is currently active
func (m *Monitor) IsMonitoring() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.monitoring
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
