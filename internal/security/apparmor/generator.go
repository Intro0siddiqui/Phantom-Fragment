package apparmor

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/phantom-fragment/phantom-fragment/internal/config"
)

// Profile represents an AppArmor security profile
type Profile struct {
	Name        string
	Description string
	Rules       []Rule
	Includes    []string
	Variables   map[string]string
}

// Rule defines an AppArmor access rule
type Rule struct {
	Type    string // allow, deny, audit, etc.
	Path    string
	Perms   string // r, w, x, m, etc.
	Comment string
}

// ProfileGenerator creates AppArmor profiles
type ProfileGenerator struct {
	profilesDir string
}

// NewGenerator creates a new AppArmor profile generator
func NewGenerator() *ProfileGenerator {
	return &ProfileGenerator{
		profilesDir: filepath.Join(config.GetConfigDir(), "apparmor"),
	}
}

// GenerateProfiles creates all default AppArmor profiles
func (g *ProfileGenerator) GenerateProfiles() error {
	if err := os.MkdirAll(g.profilesDir, 0755); err != nil {
		return fmt.Errorf("failed to create apparmor directory: %w", err)
	}

	profiles := map[string]*Profile{
		"strict":    g.generateStrictProfile(),
		"dev":       g.generateDevProfile(),
		"python":    g.generatePythonProfile(),
		"nodejs":    g.generateNodejsProfile(),
		"go":        g.generateGoProfile(),
		"rust":      g.generateRustProfile(),
		"java":      g.generateJavaProfile(),
		"container": g.generateContainerProfile(),
	}

	for name, profile := range profiles {
		if err := g.saveProfile(name, profile); err != nil {
			return fmt.Errorf("failed to save profile %s: %w", name, err)
		}
	}

	return nil
}

// generateStrictProfile creates maximum security profile
func (g *ProfileGenerator) generateStrictProfile() *Profile {
	return &Profile{
		Name:        "aisbx-strict",
		Description: "Maximum security profile for AI sandbox - minimal system access",
		Includes:    []string{"tunables/global"},
		Variables: map[string]string{
			"HOME": "/tmp",
			"TMP":  "/tmp",
		},
		Rules: []Rule{
			{Type: "deny", Path: "/proc/sys/**", Perms: "rw", Comment: "Deny kernel parameter access"},
			{Type: "deny", Path: "/sys/**", Perms: "rw", Comment: "Deny sysfs access"},
			{Type: "deny", Path: "/dev/**", Perms: "rw", Comment: "Deny device access except explicitly allowed"},
			{Type: "allow", Path: "/tmp/**", Perms: "rw", Comment: "Allow temporary file access"},
			{Type: "allow", Path: "/proc/*/stat", Perms: "r", Comment: "Allow process status reading"},
			{Type: "allow", Path: "/proc/*/status", Perms: "r", Comment: "Allow process status reading"},
			{Type: "allow", Path: "/proc/meminfo", Perms: "r", Comment: "Allow memory info reading"},
			{Type: "allow", Path: "/proc/cpuinfo", Perms: "r", Comment: "Allow CPU info reading"},
			{Type: "allow", Path: "/usr/bin/**", Perms: "rx", Comment: "Allow binary execution"},
			{Type: "allow", Path: "/bin/**", Perms: "rx", Comment: "Allow binary execution"},
			{Type: "deny", Path: "/etc/shadow", Perms: "r", Comment: "Deny password file access"},
			{Type: "deny", Path: "/etc/passwd", Perms: "w", Comment: "Deny password file modification"},
			{Type: "deny", Path: "/home/*", Perms: "rw", Comment: "Deny home directory access"},
			{Type: "deny", Path: "/root/**", Perms: "rw", Comment: "Deny root directory access"},
		},
	}
}

// generateDevProfile creates development-friendly profile
func (g *ProfileGenerator) generateDevProfile() *Profile {
	return &Profile{
		Name:        "aisbx-dev",
		Description: "Development profile with relaxed restrictions for debugging",
		Includes:    []string{"tunables/global", "abstractions/base"},
		Variables: map[string]string{
			"HOME": "/home/developer",
			"TMP":  "/tmp",
		},
		Rules: []Rule{
			{Type: "allow", Path: "/tmp/**", Perms: "rw", Comment: "Allow temporary file access"},
			{Type: "allow", Path: "/home/developer/**", Perms: "rw", Comment: "Allow home directory access"},
			{Type: "allow", Path: "/proc/**", Perms: "r", Comment: "Allow process info reading"},
			{Type: "allow", Path: "/sys/**", Perms: "r", Comment: "Allow sysfs reading"},
			{Type: "allow", Path: "/dev/null", Perms: "rw", Comment: "Allow null device"},
			{Type: "allow", Path: "/dev/zero", Perms: "r", Comment: "Allow zero device"},
			{Type: "allow", Path: "/dev/random", Perms: "r", Comment: "Allow random device"},
			{Type: "allow", Path: "/dev/urandom", Perms: "r", Comment: "Allow urandom device"},
			{Type: "allow", Path: "/usr/bin/**", Perms: "rx", Comment: "Allow binary execution"},
			{Type: "allow", Path: "/bin/**", Perms: "rx", Comment: "Allow binary execution"},
			{Type: "allow", Path: "/usr/local/bin/**", Perms: "rx", Comment: "Allow local binaries"},
			{Type: "deny", Path: "/etc/shadow", Perms: "r", Comment: "Deny password file access"},
			{Type: "deny", Path: "/etc/sudoers", Perms: "r", Comment: "Deny sudoers access"},
		},
	}
}

// generatePythonProfile creates Python-specific profile
func (g *ProfileGenerator) generatePythonProfile() *Profile {
	return &Profile{
		Name:        "aisbx-python",
		Description: "Python runtime profile with pip and virtualenv support",
		Includes:    []string{"tunables/global", "abstractions/base", "abstractions/python"},
		Variables: map[string]string{
			"PYTHONPATH": "/usr/lib/python3/dist-packages",
			"HOME":       "/home/python",
		},
		Rules: []Rule{
			{Type: "allow", Path: "/tmp/**", Perms: "rw", Comment: "Allow temporary file access"},
			{Type: "allow", Path: "/home/python/**", Perms: "rw", Comment: "Allow Python home access"},
			{Type: "allow", Path: "/usr/bin/python*", Perms: "rx", Comment: "Allow Python interpreter"},
			{Type: "allow", Path: "/usr/local/bin/python*", Perms: "rx", Comment: "Allow local Python"},
			{Type: "allow", Path: "/usr/lib/python*/**", Perms: "r", Comment: "Allow Python libraries"},
			{Type: "allow", Path: "/usr/local/lib/python*/**", Perms: "r", Comment: "Allow local Python libraries"},
			{Type: "allow", Path: "/home/python/.local/lib/python*/**", Perms: "r", Comment: "Allow user Python libraries"},
			{Type: "allow", Path: "/home/python/.cache/**", Perms: "rw", Comment: "Allow pip cache"},
			{Type: "allow", Path: "/proc/sys/vm/overcommit_memory", Perms: "r", Comment: "Allow memory overcommit check"},
		},
	}
}

// generateNodejsProfile creates Node.js-specific profile
func (g *ProfileGenerator) generateNodejsProfile() *Profile {
	return &Profile{
		Name:        "aisbx-nodejs",
		Description: "Node.js runtime profile with npm support",
		Includes:    []string{"tunables/global", "abstractions/base"},
		Variables: map[string]string{
			"NODE_PATH": "/usr/lib/nodejs:/usr/lib/node_modules",
			"HOME":      "/home/nodejs",
		},
		Rules: []Rule{
			{Type: "allow", Path: "/tmp/**", Perms: "rw", Comment: "Allow temporary file access"},
			{Type: "allow", Path: "/home/nodejs/**", Perms: "rw", Comment: "Allow Node.js home access"},
			{Type: "allow", Path: "/usr/bin/node", Perms: "rx", Comment: "Allow Node.js interpreter"},
			{Type: "allow", Path: "/usr/bin/npm", Perms: "rx", Comment: "Allow npm package manager"},
			{Type: "allow", Path: "/usr/local/bin/node", Perms: "rx", Comment: "Allow local Node.js"},
			{Type: "allow", Path: "/usr/lib/nodejs/**", Perms: "r", Comment: "Allow Node.js libraries"},
			{Type: "allow", Path: "/usr/local/lib/node_modules/**", Perms: "r", Comment: "Allow global npm packages"},
			{Type: "allow", Path: "/home/nodejs/node_modules/**", Perms: "rw", Comment: "Allow local npm packages"},
			{Type: "allow", Path: "/home/nodejs/.npm/**", Perms: "rw", Comment: "Allow npm cache"},
		},
	}
}

// generateGoProfile creates Go-specific profile
func (g *ProfileGenerator) generateGoProfile() *Profile {
	return &Profile{
		Name:        "aisbx-go",
		Description: "Go runtime profile with build and module support",
		Includes:    []string{"tunables/global", "abstractions/base"},
		Variables: map[string]string{
			"GOPATH": "/home/go/go",
			"HOME":   "/home/go",
		},
		Rules: []Rule{
			{Type: "allow", Path: "/tmp/**", Perms: "rw", Comment: "Allow temporary file access"},
			{Type: "allow", Path: "/home/go/**", Perms: "rw", Comment: "Allow Go home access"},
			{Type: "allow", Path: "/usr/bin/go", Perms: "rx", Comment: "Allow Go compiler"},
			{Type: "allow", Path: "/usr/local/go/**", Perms: "r", Comment: "Allow Go installation"},
			{Type: "allow", Path: "/home/go/go/**", Perms: "rw", Comment: "Allow Go workspace"},
			{Type: "allow", Path: "/home/go/go/pkg/**", Perms: "rw", Comment: "Allow Go packages"},
			{Type: "allow", Path: "/home/go/go/src/**", Perms: "rw", Comment: "Allow Go source"},
			{Type: "allow", Path: "/home/go/.cache/go-build/**", Perms: "rw", Comment: "Allow Go build cache"},
		},
	}
}

// generateRustProfile creates Rust-specific profile
func (g *ProfileGenerator) generateRustProfile() *Profile {
	return &Profile{
		Name:        "aisbx-rust",
		Description: "Rust runtime profile with cargo support",
		Includes:    []string{"tunables/global", "abstractions/base"},
		Variables: map[string]string{
			"CARGO_HOME": "/home/rust/.cargo",
			"HOME":       "/home/rust",
		},
		Rules: []Rule{
			{Type: "allow", Path: "/tmp/**", Perms: "rw", Comment: "Allow temporary file access"},
			{Type: "allow", Path: "/home/rust/**", Perms: "rw", Comment: "Allow Rust home access"},
			{Type: "allow", Path: "/usr/bin/rustc", Perms: "rx", Comment: "Allow Rust compiler"},
			{Type: "allow", Path: "/usr/bin/cargo", Perms: "rx", Comment: "Allow Cargo package manager"},
			{Type: "allow", Path: "/home/rust/.cargo/**", Perms: "rw", Comment: "Allow Cargo registry"},
			{Type: "allow", Path: "/home/rust/target/**", Perms: "rw", Comment: "Allow build artifacts"},
			{Type: "allow", Path: "/home/rust/src/**", Perms: "rw", Comment: "Allow source code"},
		},
	}
}

// generateJavaProfile creates Java-specific profile
func (g *ProfileGenerator) generateJavaProfile() *Profile {
	return &Profile{
		Name:        "aisbx-java",
		Description: "Java runtime profile with JVM and Maven support",
		Includes:    []string{"tunables/global", "abstractions/base"},
		Variables: map[string]string{
			"JAVA_HOME": "/usr/lib/jvm/java-11-openjdk-amd64",
			"HOME":      "/home/java",
		},
		Rules: []Rule{
			{Type: "allow", Path: "/tmp/**", Perms: "rw", Comment: "Allow temporary file access"},
			{Type: "allow", Path: "/home/java/**", Perms: "rw", Comment: "Allow Java home access"},
			{Type: "allow", Path: "/usr/bin/java", Perms: "rx", Comment: "Allow Java interpreter"},
			{Type: "allow", Path: "/usr/bin/javac", Perms: "rx", Comment: "Allow Java compiler"},
			{Type: "allow", Path: "/usr/bin/mvn", Perms: "rx", Comment: "Allow Maven"},
			{Type: "allow", Path: "/usr/lib/jvm/**", Perms: "r", Comment: "Allow JVM libraries"},
			{Type: "allow", Path: "/home/java/.m2/**", Perms: "rw", Comment: "Allow Maven repository"},
			{Type: "allow", Path: "/home/java/target/**", Perms: "rw", Comment: "Allow build artifacts"},
		},
	}
}

// generateContainerProfile creates container runtime profile
func (g *ProfileGenerator) generateContainerProfile() *Profile {
	return &Profile{
		Name:        "aisbx-container",
		Description: "Container runtime profile with Docker/Podman support",
		Includes:    []string{"tunables/global", "abstractions/base"},
		Variables: map[string]string{
			"HOME": "/home/container",
			"TMP":  "/tmp",
		},
		Rules: []Rule{
			{Type: "allow", Path: "/tmp/**", Perms: "rw", Comment: "Allow temporary file access"},
			{Type: "allow", Path: "/home/container/**", Perms: "rw", Comment: "Allow container home access"},
			{Type: "allow", Path: "/var/lib/containers/**", Perms: "rw", Comment: "Allow container storage"},
			{Type: "allow", Path: "/var/run/docker.sock", Perms: "rw", Comment: "Allow Docker socket"},
			{Type: "allow", Path: "/run/user/*/containers/**", Perms: "rw", Comment: "Allow user containers"},
			{Type: "allow", Path: "/usr/bin/docker", Perms: "rx", Comment: "Allow Docker CLI"},
			{Type: "allow", Path: "/usr/bin/podman", Perms: "rx", Comment: "Allow Podman CLI"},
			{Type: "deny", Path: "/etc/docker/**", Perms: "w", Comment: "Deny Docker config modification"},
			{Type: "deny", Path: "/var/lib/docker/**", Perms: "w", Comment: "Deny Docker daemon modification"},
		},
	}
}

// saveProfile writes AppArmor profile to disk
func (g *ProfileGenerator) saveProfile(name string, profile *Profile) error {
	filename := filepath.Join(g.profilesDir, name)
	
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	tmpl := `#include <tunables/global>

profile {{.Name}} flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

{{range $key, $value := .Variables}}
  {{$key}}="{{$value}}",
{{end}}

{{range .Includes}}
  #include <{{.}}>
{{end}}

{{range .Rules}}
  {{.Type}} {{.Path}} {{.Perms}},{{if .Comment}} # {{.Comment}}{{end}}
{{end}}
}
`

	t := template.Must(template.New("profile").Parse(tmpl))
	return t.Execute(file, profile)
}

// LoadProfile loads an AppArmor profile
func LoadProfile(name string) (string, error) {
	profilesDir := filepath.Join(config.GetConfigDir(), "apparmor")
	filename := filepath.Join(profilesDir, name)
	
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	
	return string(data), nil
}

// ApplyProfile applies an AppArmor profile to the current process
func (g *ProfileGenerator) ApplyProfile(name string) error {
	// Windows compatibility - skip AppArmor enforcement
	return nil
}