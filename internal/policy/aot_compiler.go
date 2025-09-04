package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/phantom-fragment/phantom-fragment/internal/security/landlock"
	"github.com/phantom-fragment/phantom-fragment/internal/security/seccomp"
)

// AOT Policy Compiler for zero-overhead runtime enforcement
type AOTPolicyCompiler struct {
	// Core generators
	seccompGenerator  *seccomp.BPFGenerator
	landlockGenerator *landlock.PolicyCompiler
	bpfLSMGenerator   *BPFLSMGenerator
	cgroupGenerator   *CgroupConfigGenerator
	wasmGenerator     *WasmPolicyGenerator

	// Optimization and caching
	optimizer    *PolicyOptimizer
	cacheManager *PolicyCacheManager
	validator    *PolicyValidator

	// Configuration
	config *CompilerConfig
}

// Policy DSL structure matching the YAML format
type PolicyDSL struct {
	Profile     string               `yaml:"profile"`
	Mode        string               `yaml:"mode"`
	Runtime     string               `yaml:"runtime"`
	Security    SecurityPolicyDSL    `yaml:"security"`
	Performance PerformancePolicyDSL `yaml:"performance"`
	Resources   ResourcePolicyDSL    `yaml:"resources"`
	Network     NetworkPolicyDSL     `yaml:"network"`
	Adaptive    AdaptivePolicyDSL    `yaml:"adaptive"`
}

type SecurityPolicyDSL struct {
	Level        string            `yaml:"level"`
	Capabilities []string          `yaml:"capabilities"`
	Seccomp      SeccompPolicyDSL  `yaml:"seccomp"`
	Landlock     LandlockPolicyDSL `yaml:"landlock"`
	BPFLSM       BPFLSMPolicyDSL   `yaml:"bpf_lsm"`
}

type SeccompPolicyDSL struct {
	Default string   `yaml:"default"`
	Allow   []string `yaml:"allow"`
	Deny    []string `yaml:"deny"`
}

type LandlockPolicyDSL struct {
	Enabled bool                  `yaml:"enabled"`
	Paths   []LandlockPathRuleDSL `yaml:"paths"`
}

type LandlockPathRuleDSL struct {
	Path   string `yaml:"path"`
	Access string `yaml:"access"`
}

type BPFLSMPolicyDSL struct {
	FileOpen   string `yaml:"file_open"`
	TaskCreate string `yaml:"task_create"`
	NetConnect string `yaml:"net_connect"`
}

type PerformancePolicyDSL struct {
	Zygote          bool   `yaml:"zygote"`
	IOMode          string `yaml:"io_mode"`
	MemoryAllocator string `yaml:"memory_allocator"`
	CPUAffinity     string `yaml:"cpu_affinity"`
	Prefetch        string `yaml:"prefetch"`
}

type ResourcePolicyDSL struct {
	Memory  string `yaml:"memory"`
	CPU     string `yaml:"cpu"`
	PIDs    int    `yaml:"pids"`
	Disk    string `yaml:"disk"`
	Timeout string `yaml:"timeout"`
}

type NetworkPolicyDSL struct {
	Mode     string   `yaml:"mode"`
	DNS      string   `yaml:"dns"`
	Outbound []string `yaml:"outbound"`
}

type AdaptivePolicyDSL struct {
	AutoUpgrade   string               `yaml:"auto_upgrade"`
	AutoDowngrade string               `yaml:"auto_downgrade"`
	Triggers      []AdaptiveTriggerDSL `yaml:"triggers"`
}

type AdaptiveTriggerDSL struct {
	Condition string `yaml:"condition"`
	Action    string `yaml:"action"`
}

// Compiled policy output
type CompiledPolicy struct {
	// Core policy components
	ProfileName    string
	PolicyHash     string
	SeccompBPF     []byte
	LandlockRules  *landlock.CompiledRules
	BPFLSMPrograms map[string][]byte
	CgroupConfig   *CgroupConfig
	WasmPolicy     *WasmPolicy

	// Metadata
	CompiledAt      time.Time
	CompilationTime time.Duration
	OptimizerStats  *OptimizerStats
}

// Compiler configuration
type CompilerConfig struct {
	CacheDir            string
	MaxCompilationTime  time.Duration
	OptimizationLevel   int
	TargetKernelVersion string
	EnableCrossCompile  bool
}

// NewAOTPolicyCompiler creates a new policy compiler
func NewAOTPolicyCompiler(config *CompilerConfig) (*AOTPolicyCompiler, error) {
	if config == nil {
		config = &CompilerConfig{
			CacheDir:            "/tmp/phantom-fragment/policy-cache",
			MaxCompilationTime:  50 * time.Millisecond,
			OptimizationLevel:   2,
			TargetKernelVersion: "6.11",
			EnableCrossCompile:  true,
		}
	}

	compiler := &AOTPolicyCompiler{
		config: config,
	}

	// Initialize generators
	var err error
	compiler.seccompGenerator, err = seccomp.NewBPFGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize seccomp generator: %w", err)
	}

	compiler.landlockGenerator, err = landlock.NewPolicyCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize landlock generator: %w", err)
	}

	compiler.bpfLSMGenerator = NewBPFLSMGenerator()
	compiler.cgroupGenerator = NewCgroupConfigGenerator()
	compiler.wasmGenerator = NewWasmPolicyGenerator()

	// Initialize optimization and caching
	compiler.optimizer = NewPolicyOptimizer(config.OptimizationLevel)
	compiler.cacheManager = NewPolicyCacheManager(config.CacheDir)
	compiler.validator = NewPolicyValidator()

	return compiler, nil
}

// CompilePolicy compiles a YAML policy DSL to optimized kernel bytecode
func (apc *AOTPolicyCompiler) CompilePolicy(yamlContent string) (*CompiledPolicy, error) {
	start := time.Now()

	// Set compilation timeout
	// ctx, cancel := context.WithTimeout(context.Background(), apc.config.MaxCompilationTime)
	// defer cancel()

	// Phase 1: Parse and validate YAML
	var policyDSL PolicyDSL
	if err := yaml.Unmarshal([]byte(yamlContent), &policyDSL); err != nil {
		return nil, fmt.Errorf("YAML parsing failed: %w", err)
	}

	if err := apc.validator.Validate(&policyDSL); err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}

	// Calculate policy hash for caching
	policyHash := apc.calculatePolicyHash(yamlContent)

	// Check cache first
	if cached, found := apc.cacheManager.Get(policyHash); found {
		return cached, nil
	}

	// Phase 2: Optimize policy
	optimized, stats, err := apc.optimizer.Optimize(&policyDSL)
	if err != nil {
		return nil, fmt.Errorf("policy optimization failed: %w", err)
	}

	// Phase 3: Generate compiled components
	compiled := &CompiledPolicy{
		ProfileName:    policyDSL.Profile,
		PolicyHash:     policyHash,
		CompiledAt:     start,
		OptimizerStats: stats,
	}

	// Generate seccomp BPF
	if optimized.Security.Seccomp.Default != "" {
		// Convert policy DSL to seccomp package type
		seccompPolicy := &seccomp.SeccompPolicyDSL{
			Default: optimized.Security.Seccomp.Default,
			Allow:   optimized.Security.Seccomp.Allow,
			Deny:    optimized.Security.Seccomp.Deny,
		}
		compiled.SeccompBPF, err = apc.seccompGenerator.Generate(seccompPolicy)
		if err != nil {
			return nil, fmt.Errorf("seccomp BPF generation failed: %w", err)
		}
	}

	// Generate Landlock rules
	if optimized.Security.Landlock.Enabled {
		landlockRules := make([]landlock.FilesystemRule, len(optimized.Security.Landlock.Paths))
		for i, path := range optimized.Security.Landlock.Paths {
			landlockRules[i] = landlock.FilesystemRule{
				Path:   path.Path,
				Access: apc.convertLandlockAccess(path.Access),
			}
		}

		compiled.LandlockRules, err = apc.landlockGenerator.CompileRules(policyDSL.Profile, landlockRules)
		if err != nil {
			return nil, fmt.Errorf("landlock rules compilation failed: %w", err)
		}
	}

	// Generate BPF-LSM programs
	if optimized.Security.BPFLSM.FileOpen != "" || optimized.Security.BPFLSM.TaskCreate != "" {
		compiled.BPFLSMPrograms, err = apc.bpfLSMGenerator.Generate(&optimized.Security.BPFLSM)
		if err != nil {
			return nil, fmt.Errorf("BPF-LSM program generation failed: %w", err)
		}
	}

	// Generate cgroup configuration
	compiled.CgroupConfig, err = apc.cgroupGenerator.Generate(&optimized.Resources)
	if err != nil {
		return nil, fmt.Errorf("cgroup config generation failed: %w", err)
	}

	// Generate WebAssembly policy if needed
	if optimized.Runtime == "wasm" || optimized.Runtime == "auto" {
		compiled.WasmPolicy, err = apc.wasmGenerator.Generate(optimized)
		if err != nil {
			return nil, fmt.Errorf("Wasm policy generation failed: %w", err)
		}
	}

	// Phase 4: Validate compilation time
	compiled.CompilationTime = time.Since(start)
	if compiled.CompilationTime > apc.config.MaxCompilationTime {
		return nil, fmt.Errorf("compilation too slow: %v (target: <%v)",
			compiled.CompilationTime, apc.config.MaxCompilationTime)
	}

	// Phase 5: Cache the compiled policy
	if err := apc.cacheManager.Store(policyHash, compiled); err != nil {
		// Log warning but don't fail compilation
		fmt.Printf("Warning: failed to cache compiled policy: %v\n", err)
	}

	return compiled, nil
}

// CompilePolicyFromFile compiles a policy from a YAML file
func (apc *AOTPolicyCompiler) CompilePolicyFromFile(filename string) (*CompiledPolicy, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", filename, err)
	}

	return apc.CompilePolicy(string(content))
}

// SaveCompiledPolicy saves a compiled policy to disk for later use
func (apc *AOTPolicyCompiler) SaveCompiledPolicy(compiled *CompiledPolicy, outputDir string) error {
	profileDir := filepath.Join(outputDir, compiled.ProfileName)
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	// Save seccomp BPF
	if len(compiled.SeccompBPF) > 0 {
		seccompPath := filepath.Join(profileDir, "seccomp.bpf")
		if err := os.WriteFile(seccompPath, compiled.SeccompBPF, 0644); err != nil {
			return fmt.Errorf("failed to save seccomp BPF: %w", err)
		}
	}

	// Save landlock rules (as binary format)
	if compiled.LandlockRules != nil {
		landlockPath := filepath.Join(profileDir, "landlock.rules")
		if err := apc.saveLandlockRules(compiled.LandlockRules, landlockPath); err != nil {
			return fmt.Errorf("failed to save landlock rules: %w", err)
		}
	}

	// Save BPF-LSM programs
	if len(compiled.BPFLSMPrograms) > 0 {
		lsmDir := filepath.Join(profileDir, "bpf-lsm")
		if err := os.MkdirAll(lsmDir, 0755); err != nil {
			return fmt.Errorf("failed to create BPF-LSM directory: %w", err)
		}

		for name, program := range compiled.BPFLSMPrograms {
			programPath := filepath.Join(lsmDir, name+".bpf")
			if err := os.WriteFile(programPath, program, 0644); err != nil {
				return fmt.Errorf("failed to save BPF-LSM program %s: %w", name, err)
			}
		}
	}

	// Save cgroup configuration
	if compiled.CgroupConfig != nil {
		cgroupPath := filepath.Join(profileDir, "cgroup.json")
		if err := apc.saveCgroupConfig(compiled.CgroupConfig, cgroupPath); err != nil {
			return fmt.Errorf("failed to save cgroup config: %w", err)
		}
	}

	// Save WebAssembly policy
	if compiled.WasmPolicy != nil {
		wasmPath := filepath.Join(profileDir, "wasm-policy.json")
		if err := apc.saveWasmPolicy(compiled.WasmPolicy, wasmPath); err != nil {
			return fmt.Errorf("failed to save Wasm policy: %w", err)
		}
	}

	return nil
}

// Helper functions
func (apc *AOTPolicyCompiler) calculatePolicyHash(content string) string {
	hasher := sha256.New()
	hasher.Write([]byte(content))
	return hex.EncodeToString(hasher.Sum(nil))[:16] // First 16 chars for brevity
}

func (apc *AOTPolicyCompiler) convertLandlockAccess(access string) landlock.AccessType {
	switch access {
	case "read-only":
		return landlock.AccessReadOnly
	case "read-write":
		return landlock.AccessReadWrite
	case "execute":
		return landlock.AccessExecute
	default:
		return landlock.AccessReadOnly
	}
}

func (apc *AOTPolicyCompiler) saveLandlockRules(_ *landlock.CompiledRules, _ string) error {
	// Serialize landlock rules to binary format
	// Implementation would depend on the landlock.CompiledRules structure
	return nil
}

func (apc *AOTPolicyCompiler) saveCgroupConfig(_ *CgroupConfig, _ string) error {
	// Serialize cgroup config to JSON
	// Implementation would marshal the config to JSON
	return nil
}

func (apc *AOTPolicyCompiler) saveWasmPolicy(_ *WasmPolicy, _ string) error {
	// Serialize Wasm policy to JSON
	// Implementation would marshal the policy to JSON
	return nil
}

// Placeholder types and constructors
type BPFLSMGenerator struct{}
type CgroupConfigGenerator struct{}
type WasmPolicyGenerator struct{}
type PolicyCacheManager struct{}
type CgroupConfig struct{}
type WasmPolicy struct{}
type OptimizerStats struct{}

func NewBPFLSMGenerator() *BPFLSMGenerator                 { return &BPFLSMGenerator{} }
func NewCgroupConfigGenerator() *CgroupConfigGenerator     { return &CgroupConfigGenerator{} }
func NewWasmPolicyGenerator() *WasmPolicyGenerator         { return &WasmPolicyGenerator{} }
func NewPolicyCacheManager(dir string) *PolicyCacheManager { return &PolicyCacheManager{} }

// Placeholder methods
func (bg *BPFLSMGenerator) Generate(policy *BPFLSMPolicyDSL) (map[string][]byte, error) {
	return map[string][]byte{}, nil
}

func (cg *CgroupConfigGenerator) Generate(resources *ResourcePolicyDSL) (*CgroupConfig, error) {
	return &CgroupConfig{}, nil
}

func (wg *WasmPolicyGenerator) Generate(policy *PolicyDSL) (*WasmPolicy, error) {
	return &WasmPolicy{}, nil
}

func (po *PolicyOptimizer) Optimize(policy *PolicyDSL) (*PolicyDSL, *OptimizerStats, error) {
	return policy, &OptimizerStats{}, nil
}

func (pcm *PolicyCacheManager) Get(hash string) (*CompiledPolicy, bool) {
	return nil, false
}

func (pcm *PolicyCacheManager) Store(hash string, policy *CompiledPolicy) error {
	return nil
}

func (pv *PolicyValidator) Validate(policy *PolicyDSL) error {
	return nil
}
