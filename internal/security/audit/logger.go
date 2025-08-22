package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Event represents a security audit event
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	ContainerID string  `json:"container_id,omitempty"`
	Message   string    `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Logger handles security audit logging
type Logger struct {
	filePath string
}

// NewLogger creates a new audit logger
func NewLogger(filePath string) *Logger {
	return &Logger{
		filePath: filePath,
	}
}

// LogEvent logs a security event
func (l *Logger) LogEvent(eventType, containerID, message string, details map[string]interface{}) error {
	event := Event{
		Timestamp: time.Now(),
		EventType: eventType,
		ContainerID: containerID,
		Message:   message,
		Details:   details,
	}

	// Convert event to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Append to log file
	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write to log file: %w", err)
	}

	return nil
}

// LogContainerCreation logs a container creation event
func (l *Logger) LogContainerCreation(containerID string, details map[string]interface{}) error {
	return l.LogEvent("container_creation", containerID, "Container created", details)
}

// LogContainerExecution logs a container execution event
func (l *Logger) LogContainerExecution(containerID string, details map[string]interface{}) error {
	return l.LogEvent("container_execution", containerID, "Container executed", details)
}

// LogContainerDestruction logs a container destruction event
func (l *Logger) LogContainerDestruction(containerID string, details map[string]interface{}) error {
	return l.LogEvent("container_destruction", containerID, "Container destroyed", details)
}

// LogSecurityViolation logs a security violation event
func (l *Logger) LogSecurityViolation(containerID, violationType, message string, details map[string]interface{}) error {
	return l.LogEvent("security_violation", containerID, message, details)
}