package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Global   GlobalConfig   `yaml:"global"`
	Profiles []Profile      `yaml:"profiles"`
	Logging  LoggingConfig  `yaml:"logging"`
	Security SecurityConfig `yaml:"security"`
}

// GlobalConfig contains global settings
type GlobalConfig struct {
	CacheDir      string `yaml:"cache_dir"`
	DefaultDriver string `yaml:"default_driver"`
	Timeout       int    `yaml:"timeout"`
}

// Profile represents a sandbox configuration profile
type Profile struct {
	Name         string            `yaml:"name"`
	Driver       string            `yaml:"driver"`
	CPU          string            `yaml:"cpu"`
	Memory       string            `yaml:"memory"`
	Network      NetworkConfig     `yaml:"network"`
	Mounts       []MountConfig     `yaml:"mounts"`
	Environment  map[string]string `yaml:"environment"`
	WorkingDir   string            `yaml:"working_dir"`
	Seccomp      string            `yaml:"seccomp"`
	Capabilities []string          `yaml:"capabilities"`
	Timeout      int               `yaml:"timeout"`
}

// NetworkConfig defines network settings
type NetworkConfig struct {
	Enabled bool     `yaml:"enabled"`
	Allow   []string `yaml:"allow"`
	Deny    []string `yaml:"deny"`
}

// MountConfig defines mount point configuration
type MountConfig struct {
	Source string `yaml:"source"`
	Target string `yaml:"target"`
	Mode   string `yaml:"mode"` // "ro" or "rw"
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

// SeccompConfig contains seccomp-related configuration
type SeccompConfig struct {
	Enabled bool   `yaml:"enabled"`
	Dir     string `yaml:"dir"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	UserNamespaces bool          `yaml:"user_namespaces"`
	Seccomp        SeccompConfig `yaml:"seccomp"`
	AppArmor       bool          `yaml:"apparmor"`
	SELinux        bool          `yaml:"selinux"`
}

// DefaultConfig returns a new default configuration
func DefaultConfig() *Config {
	return &Config{
		Global: GlobalConfig{
			CacheDir:      "",
			DefaultDriver: "bwrap",
			Timeout:       300,
		},
		Profiles: []Profile{
			{
				Name:   "default",
				Driver: "bwrap",
				CPU:    "1",
				Memory: "512m",
				Network: NetworkConfig{
					Enabled: false,
					Allow:   []string{},
					Deny:    []string{},
				},
				Mounts: []MountConfig{
					{
						Source: ".",
						Target: "/workspace",
						Mode:   "rw",
					},
				},
				Environment: map[string]string{
					"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				},
				WorkingDir:   "/workspace",
				Seccomp:      "default",
				Capabilities: []string{},
				Timeout:      300,
			},
			{
				Name:   "python-dev",
				Driver: "bwrap",
				CPU:    "2",
				Memory: "1g",
				Network: NetworkConfig{
					Enabled: true,
					Allow:   []string{"pypi.org", "pythonhosted.org"},
					Deny:    []string{},
				},
				Mounts: []MountConfig{
					{
						Source: ".",
						Target: "/workspace",
						Mode:   "rw",
					},
					{
						Source: "./requirements.txt",
						Target: "/workspace/requirements.txt",
						Mode:   "ro",
					},
				},
				Environment: map[string]string{
					"PATH":             "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"PYTHONUNBUFFERED": "1",
					"PYTHONPATH":       "/workspace",
				},
				WorkingDir:   "/workspace",
				Seccomp:      "python",
				Capabilities: []string{"CAP_NET_BIND_SERVICE"},
				Timeout:      600,
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			File:   "",
		},
		Security: SecurityConfig{
			UserNamespaces: true,
			Seccomp: SeccompConfig{
				Enabled: true,
				Dir:     "", // Will be set dynamically during initialization
			},
			AppArmor: false,
			SELinux:  false,
		},
	}
}

// LoadProfile loads a profile from file
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile: %w", err)
	}

	var profile Profile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile: %w", err)
	}

	return &profile, nil
}

// SaveProfile saves a profile to file
func (c *Config) SaveProfile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	data, err := yaml.Marshal(c.Profiles[0])
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	return nil
}

// Initialize sets up the configuration directory and files
func Initialize(configDir string) error {
	if configDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir = filepath.Join(homeDir, ".aisbx")
	}

	// Create config directory
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create profiles directory
	profilesDir := filepath.Join(configDir, "profiles")
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory: %w", err)
	}

	// Create seccomp profiles directory
	seccompDir := filepath.Join(configDir, "seccomp", "profiles")
	if err := os.MkdirAll(seccompDir, 0755); err != nil {
		return fmt.Errorf("failed to create seccomp profiles directory: %w", err)
	}

	// Create default config file if it doesn't exist
	configFile := filepath.Join(configDir, "config.yaml")
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		cfg := DefaultConfig()
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		if err := os.WriteFile(configFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}
	}

	return nil
}

// GetProfile returns a profile by name
func (c *Config) GetProfile(name string) (*Profile, error) {
	for _, profile := range c.Profiles {
		if profile.Name == name {
			return &profile, nil
		}
	}
	return nil, fmt.Errorf("profile '%s' not found", name)
}
