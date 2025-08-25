package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/phantom-fragment/phantom-fragment/internal/config"
)

// Profile represents a security configuration profile
type Profile struct {
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Security    SecurityConfig    `yaml:"security" json:"security"`
	Resources   ResourceLimits    `yaml:"resources" json:"resources"`
	Network     NetworkPolicy     `yaml:"network" json:"network"`
	Filesystem  FilesystemConfig  `yaml:"filesystem" json:"filesystem"`
	Environment map[string]string `yaml:"environment" json:"environment"`
}

// SecurityConfig defines security policies
type SecurityConfig struct {
	SeccompProfile string   `yaml:"seccomp_profile" json:"seccomp_profile"`
	AppArmorPolicy string   `yaml:"apparmor_policy" json:"apparmor_policy"`
	Capabilities   []string `yaml:"capabilities" json:"capabilities"`
	NoNewPrivs     bool     `yaml:"no_new_privs" json:"no_new_privs"`
	DropCaps       []string `yaml:"drop_caps" json:"drop_caps"`
}

// ResourceLimits defines resource constraints
type ResourceLimits struct {
	CPU          string `yaml:"cpu" json:"cpu"`
	Memory       string `yaml:"memory" json:"memory"`
	Pids         int    `yaml:"pids" json:"pids"`
	FileSize     string `yaml:"file_size" json:"file_size"`
	OpenFiles    int    `yaml:"open_files" json:"open_files"`
	CoreDumpSize string `yaml:"core_dump_size" json:"core_dump_size"`
}

// NetworkPolicy defines network restrictions
type NetworkPolicy struct {
	Mode      string   `yaml:"mode" json:"mode"` // none, loopback, restricted
	Allow     []string `yaml:"allow" json:"allow"`
	Deny      []string `yaml:"deny" json:"deny"`
	Ports     []int    `yaml:"ports" json:"ports"`
	Protocols []string `yaml:"protocols" json:"protocols"`
}

// FilesystemConfig defines filesystem restrictions
type FilesystemConfig struct {
	ReadOnlyPaths  []string          `yaml:"read_only_paths" json:"read_only_paths"`
	WritablePaths  []string          `yaml:"writable_paths" json:"writable_paths"`
	MaskedPaths    []string          `yaml:"masked_paths" json:"masked_paths"`
	MountFlags     []string          `yaml:"mount_flags" json:"mount_flags"`
	TmpfsSize      string            `yaml:"tmpfs_size" json:"tmpfs_size"`
	Secrets        map[string]string `yaml:"secrets" json:"secrets"`
}

// ProfileManager manages security profiles
var ProfileManager *Manager

func init() {
	ProfileManager = &Manager{
		profilesDir: filepath.Join(config.GetConfigDir(), "profiles"),
		cache:       make(map[string]*Profile),
	}
}

// Manager handles profile operations
type Manager struct {
	profilesDir string
	cache       map[string]*Profile
}

// LoadProfile loads a security profile by name
func (m *Manager) LoadProfile(name string) (*Profile, error) {
	if profile, exists := m.cache[name]; exists {
		return profile, nil
	}

	profilePath := filepath.Join(m.profilesDir, name+".yaml")
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		// Try JSON format
		profilePath = filepath.Join(m.profilesDir, name+".json")
	}

	data, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile %s: %w", name, err)
	}

	var profile Profile
	if strings.HasSuffix(profilePath, ".json") {
		err = json.Unmarshal(data, &profile)
	} else {
		// YAML parsing would require additional dependency
		// For now, support JSON format
		err = json.Unmarshal(data, &profile)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse profile %s: %w", name, err)
	}

	if profile.Name == "" {
		profile.Name = name
	}

	m.cache[name] = &profile
	return &profile, nil
}

// SaveProfile saves a security profile to disk
func (m *Manager) SaveProfile(profile *Profile) error {
	if err := os.MkdirAll(m.profilesDir, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory: %w", err)
	}

	profilePath := filepath.Join(m.profilesDir, profile.Name+".json")
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	if err := os.WriteFile(profilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	m.cache[profile.Name] = profile
	return nil
}

// ListProfiles returns all available profile names
func (m *Manager) ListProfiles() ([]string, error) {
	if err := os.MkdirAll(m.profilesDir, 0755); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(m.profilesDir)
	if err != nil {
		return nil, err
	}

	var profiles []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".yaml") {
			profiles = append(profiles, strings.TrimSuffix(name, filepath.Ext(name)))
		}
	}

	return profiles, nil
}

// GetDefaultProfiles returns pre-configured security profiles
func GetDefaultProfiles() map[string]*Profile {
	return map[string]*Profile{
		"strict": {
			Name:        "strict",
			Description: "Maximum security profile for untrusted code",
			Security: SecurityConfig{
				SeccompProfile: "strict.json",
				AppArmorPolicy: "strict",
				Capabilities:   []string{},
				NoNewPrivs:     true,
				DropCaps:       []string{"ALL"},
			},
			Resources: ResourceLimits{
				CPU:    "1",
				Memory: "512m",
				Pids:   100,
			},
			Network: NetworkPolicy{
				Mode: "none",
			},
			Filesystem: FilesystemConfig{
				ReadOnlyPaths: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"},
				WritablePaths: []string{"/tmp", "/var/tmp"},
				MaskedPaths:   []string{"/proc/kcore", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats"},
				TmpfsSize:     "100m",
			},
			Environment: map[string]string{
				"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		},
		"dev": {
			Name:        "dev",
			Description: "Development profile with relaxed security",
			Security: SecurityConfig{
				SeccompProfile: "dev.json",
				AppArmorPolicy: "dev",
				Capabilities:   []string{"CAP_NET_BIND_SERVICE"},
				NoNewPrivs:     false,
				DropCaps:       []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN"},
			},
			Resources: ResourceLimits{
				CPU:    "2",
				Memory: "2g",
				Pids:   1000,
			},
			Network: NetworkPolicy{
				Mode:  "restricted",
				Allow: []string{"github.com", "pypi.org", "npmjs.org"},
				Ports: []int{80, 443, 3000, 8000, 8080},
			},
			Filesystem: FilesystemConfig{
				ReadOnlyPaths: []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"},
				WritablePaths: []string{"/tmp", "/var/tmp", "/workspace"},
				TmpfsSize:     "500m",
			},
			Environment: map[string]string{
				"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"HOME": "/workspace",
			},
		},
		"python": {
			Name:        "python",
			Description: "Python development profile",
			Security: SecurityConfig{
				SeccompProfile: "python.json",
				AppArmorPolicy: "python",
				Capabilities:   []string{"CAP_NET_BIND_SERVICE"},
				NoNewPrivs:     true,
				DropCaps:       []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_MKNOD"},
			},
			Resources: ResourceLimits{
				CPU:    "1.5",
				Memory: "1g",
				Pids:   500,
			},
			Network: NetworkPolicy{
				Mode:  "restricted",
				Allow: []string{"pypi.org", "pythonhosted.org", "github.com"},
				Ports: []int{80, 443, 8000, 8080},
			},
			Filesystem: FilesystemConfig{
				ReadOnlyPaths: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"},
				WritablePaths: []string{"/tmp", "/var/tmp", "/workspace", "/home/user/.cache"},
				TmpfsSize:     "300m",
			},
			Environment: map[string]string{
				"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"PYTHONPATH": "/workspace",
				"PYTHONUNBUFFERED": "1",
			},
		},
	}
}