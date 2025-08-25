//go:build !linux
// +build !linux

package landlock

import (
	"fmt"
)

// PolicyCompiler compiles Landlock policies for AOT application
type PolicyCompiler struct {
	supportedVersion int
	capabilities     uint64
}

// CompiledRules represents pre-compiled Landlock rules
type CompiledRules struct {
	RulesetFD int
	Rules     []CompiledRule
	Applied   bool
}

type CompiledRule struct {
	Path        string
	AccessRights uint64
}

// FilesystemRule represents a filesystem access rule
type FilesystemRule struct {
	Path   string
	Access AccessType
}

type AccessType int

const (
	AccessReadOnly AccessType = iota
	AccessReadWrite
	AccessExecute
)

// NewPolicyCompiler creates a new Landlock policy compiler
func NewPolicyCompiler() (*PolicyCompiler, error) {
	return nil, fmt.Errorf("Landlock is only supported on Linux")
}

// CompileRules compiles a set of filesystem access rules
func (pc *PolicyCompiler) CompileRules(rules []FilesystemRule) (*CompiledRules, error) {
	return nil, fmt.Errorf("Landlock is only supported on Linux")
}

// ApplyToPID applies compiled Landlock rules to a specific process
func (cr *CompiledRules) ApplyToPID(pid int) error {
	return fmt.Errorf("Landlock is only supported on Linux")
}

// ApplyToSelf applies the Landlock rules to the current process
func (cr *CompiledRules) ApplyToSelf() error {
	return fmt.Errorf("Landlock is only supported on Linux")
}

// convertAccessRights converts high-level access types to Landlock constants
func (pc *PolicyCompiler) convertAccessRights(access AccessType) uint64 {
	return 0
}

// Cleanup releases resources associated with compiled rules
func (cr *CompiledRules) Cleanup() error {
	return nil
}

// GetCompiledRules returns cached compiled rules for a profile
func (pc *PolicyCompiler) GetCompiledRules(profile string) *CompiledRules {
	return nil
}