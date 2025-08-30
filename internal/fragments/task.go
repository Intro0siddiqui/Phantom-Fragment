//go:build linux
// +build linux

package fragments

import (
	"time"
)

// Task represents a task to be executed in a fragment
type Task struct {
	Command     string            // The command to execute
	Args        []string          // Command arguments
	Environment map[string]string // Environment variables
	Workdir     string            // Working directory
	Timeout     time.Duration     // Execution timeout
	Priority    TaskPriority      // Task priority
	Metadata    map[string]interface{} // Additional metadata
}

// TaskPriority represents the priority of a task
type TaskPriority int

const (
	TaskPriorityLow TaskPriority = iota
	TaskPriorityNormal
	TaskPriorityHigh
	TaskPriorityCritical
)

// String returns a string representation of task priority
func (tp TaskPriority) String() string {
	switch tp {
	case TaskPriorityLow:
		return "low"
	case TaskPriorityNormal:
		return "normal"
	case TaskPriorityHigh:
		return "high"
	case TaskPriorityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// NewTask creates a new task with default values
func NewTask(command string, args ...string) *Task {
	return &Task{
		Command:     command,
		Args:        args,
		Environment: make(map[string]string),
		Workdir:     "/",
		Timeout:     30 * time.Second,
		Priority:    TaskPriorityNormal,
		Metadata:    make(map[string]interface{}),
	}
}

// SetEnvironment sets environment variables for the task
func (t *Task) SetEnvironment(env map[string]string) *Task {
	t.Environment = env
	return t
}

// SetWorkdir sets the working directory for the task
func (t *Task) SetWorkdir(workdir string) *Task {
	t.Workdir = workdir
	return t
}

// SetTimeout sets the execution timeout for the task
func (t *Task) SetTimeout(timeout time.Duration) *Task {
	t.Timeout = timeout
	return t
}

// SetPriority sets the priority for the task
func (t *Task) SetPriority(priority TaskPriority) *Task {
	t.Priority = priority
	return t
}

// SetMetadata sets additional metadata for the task
func (t *Task) SetMetadata(key string, value interface{}) *Task {
	if t.Metadata == nil {
		t.Metadata = make(map[string]interface{})
	}
	t.Metadata[key] = value
	return t
}

// GetFullCommand returns the full command with arguments
func (t *Task) GetFullCommand() string {
	if len(t.Args) == 0 {
		return t.Command
	}
	
	// Simple concatenation - in a real implementation you might want proper escaping
	fullCommand := t.Command
	for _, arg := range t.Args {
		fullCommand += " " + arg
	}
	
	return fullCommand
}

// IsNetworkTask checks if this task requires network capabilities
func (t *Task) IsNetworkTask() bool {
	// Simple heuristic - in a real implementation you'd use the TaskAnalyzer
	networkCommands := []string{"curl", "wget", "ssh", "telnet", "netcat", "nc", "ping"}
	command := t.Command
	
	for _, netCmd := range networkCommands {
		if command == netCmd {
			return true
		}
	}
	
	return false
}

// IsSystemTask checks if this task requires system administration capabilities
func (t *Task) IsSystemTask() bool {
	// Simple heuristic
	systemCommands := []string{"systemctl", "service", "init", "systemd", "mount", "umount"}
	command := t.Command
	
	for _, sysCmd := range systemCommands {
		if command == sysCmd {
			return true
		}
	}
	
	return false
}

// RequiresRoot checks if this task requires root privileges
func (t *Task) RequiresRoot() bool {
	// Simple heuristic
	rootCommands := []string{"systemctl", "mount", "umount", "fdisk", "mkfs", "iptables"}
	command := t.Command
	
	for _, rootCmd := range rootCommands {
		if command == rootCmd {
			return true
		}
	}
	
	return false
}

// GetEstimatedComplexity returns an estimated complexity for the task
func (t *Task) GetEstimatedComplexity() TaskComplexity {
	if t.IsNetworkTask() {
		return NETWORK
	}
	
	if t.IsSystemTask() {
		return OS_SERVICES
	}
	
	if t.RequiresRoot() {
		return ADVANCED
	}
	
	return SIMPLE
}

// Validate validates the task configuration
func (t *Task) Validate() error {
	if t.Command == "" {
		return fmt.Errorf("command cannot be empty")
	}
	
	if t.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	
	if t.Workdir == "" {
		return fmt.Errorf("workdir cannot be empty")
	}
	
	return nil
}

// Clone creates a copy of the task
func (t *Task) Clone() *Task {
	clone := &Task{
		Command:     t.Command,
		Args:        make([]string, len(t.Args)),
		Environment: make(map[string]string),
		Workdir:     t.Workdir,
		Timeout:     t.Timeout,
		Priority:    t.Priority,
		Metadata:    make(map[string]interface{}),
	}
	
	// Copy arguments
	copy(clone.Args, t.Args)
	
	// Copy environment variables
	for k, v := range t.Environment {
		clone.Environment[k] = v
	}
	
	// Copy metadata
	for k, v := range t.Metadata {
		clone.Metadata[k] = v
	}
	
	return clone
}

// String returns a string representation of the task
func (t *Task) String() string {
	return fmt.Sprintf("Task{Command: %s, Args: %v, Priority: %s, Timeout: %v}", 
		t.Command, t.Args, t.Priority, t.Timeout)
}