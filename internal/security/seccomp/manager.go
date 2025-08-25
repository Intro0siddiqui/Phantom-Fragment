package seccomp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/phantom-fragment/phantom-fragment/internal/config"
	"github.com/phantom-fragment/phantom-fragment/internal/metrics"
)

// Profile represents a seccomp profile
type Profile struct {
	DefaultAction string    `json:"defaultAction"`
	Architectures []string  `json:"architectures"`
	Syscalls      []Syscall `json:"syscalls"`
}

// Syscall represents a syscall in a seccomp profile
type Syscall struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// Manager handles seccomp profiles
type Manager struct {
	config  *config.Config
	metrics *metrics.Collector
}

// NewManager creates a new seccomp manager
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		config:  cfg,
		metrics: nil,
	}
}

// SetMetricsCollector sets the metrics collector for the seccomp manager
func (m *Manager) SetMetricsCollector(collector *metrics.Collector) {
	m.metrics = collector
}

// LoadProfile loads a seccomp profile from a file
func (m *Manager) LoadProfile(profileName string) (*Profile, error) {
	profilePath := filepath.Join(m.config.Security.Seccomp.Dir, profileName+".json")
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile file: %w", err)
	}

	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile JSON: %w", err)
	}

	return &profile, nil
}

// ApplyProfile applies a seccomp profile to a process
// This is a placeholder implementation - actual implementation would depend on the container runtime
func (m *Manager) ApplyProfile(ctx context.Context, profile *Profile) error {
	// In a real implementation, this would interface with the container runtime
	// to apply the seccomp profile to the container process
	// For example, with bubblewrap or Docker, this would involve passing
	// the profile as a parameter to the container creation command
	return nil
}

// RecordDeniedSyscall records a denied system call event
func (m *Manager) RecordDeniedSyscall(containerID, syscall string) {
	if m.metrics != nil {
		m.metrics.RecordDeniedSyscall(containerID, syscall)
	}
}

// GetDefaultProfile returns the default seccomp profile
func (m *Manager) GetDefaultProfile() (*Profile, error) {
	return m.LoadProfile("default")
}

// ListProfiles returns a list of available seccomp profiles
func (m *Manager) ListProfiles() ([]string, error) {
	entries, err := os.ReadDir(m.config.Security.Seccomp.Dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read profiles directory: %w", err)
	}

	profiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) == ".json" {
			profiles = append(profiles, name[:len(name)-5]) // Remove .json extension
		}
	}

	return profiles, nil
}
