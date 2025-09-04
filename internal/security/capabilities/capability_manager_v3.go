//go:build linux
// +build linux

package capabilities

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Error for capability operations on unsupported platforms
var ErrCapabilityNotSupported = fmt.Errorf("capability operations not supported on this platform")

// Capability constants - fallback values if unix package is missing them
const (
	fallbackCAP_CHOWN            = 0
	fallbackCAP_DAC_OVERRIDE     = 1
	fallbackCAP_DAC_READ_SEARCH  = 2
	fallbackCAP_FOWNER           = 3
	fallbackCAP_FSETID           = 4
	fallbackCAP_KILL             = 5
	fallbackCAP_SETGID           = 6
	fallbackCAP_SETUID           = 7
	fallbackCAP_SETPCAP          = 8
	fallbackCAP_LINUX_IMMUTABLE  = 9
	fallbackCAP_NET_BIND_SERVICE = 10
	fallbackCAP_NET_BROADCAST    = 11
	fallbackCAP_NET_ADMIN        = 12
	fallbackCAP_NET_RAW          = 13
	fallbackCAP_IPC_LOCK         = 14
	fallbackCAP_IPC_OWNER        = 15
	fallbackCAP_SYS_MODULE       = 16
	fallbackCAP_SYS_RAWIO        = 17
	fallbackCAP_SYS_CHROOT       = 18
	fallbackCAP_SYS_PTRACE       = 19
	fallbackCAP_SYS_PACCT        = 20
	fallbackCAP_SYS_ADMIN        = 21
	fallbackCAP_SYS_BOOT         = 22
	fallbackCAP_SYS_NICE         = 23
	fallbackCAP_SYS_RESOURCE     = 24
	fallbackCAP_SYS_TIME         = 25
	fallbackCAP_SYS_TTY_CONFIG   = 26
	fallbackCAP_MKNOD            = 27
	fallbackCAP_LEASE            = 28
	fallbackCAP_AUDIT_WRITE      = 29
	fallbackCAP_AUDIT_CONTROL    = 30
	fallbackCAP_SETFCAP          = 31

	// Prctl constants
	fallbackPR_CAPBSET_DROP      = 24
	fallbackPR_CAP_AMBIENT       = 47
	fallbackPR_CAP_AMBIENT_RAISE = 2
	fallbackPR_SET_NO_NEW_PRIVS  = 38
)

// Helper functions to get capability constants with fallback
func getCapConstant(name string) int {
	switch name {
	case "CAP_CHOWN":
		return fallbackCAP_CHOWN
	case "CAP_DAC_OVERRIDE":
		return fallbackCAP_DAC_OVERRIDE
	case "CAP_DAC_READ_SEARCH":
		return fallbackCAP_DAC_READ_SEARCH
	case "CAP_FOWNER":
		return fallbackCAP_FOWNER
	case "CAP_FSETID":
		return fallbackCAP_FSETID
	case "CAP_KILL":
		return fallbackCAP_KILL
	case "CAP_SETGID":
		return fallbackCAP_SETGID
	case "CAP_SETUID":
		return fallbackCAP_SETUID
	case "CAP_SETPCAP":
		return fallbackCAP_SETPCAP
	case "CAP_LINUX_IMMUTABLE":
		return fallbackCAP_LINUX_IMMUTABLE
	case "CAP_NET_BIND_SERVICE":
		return fallbackCAP_NET_BIND_SERVICE
	case "CAP_NET_BROADCAST":
		return fallbackCAP_NET_BROADCAST
	case "CAP_NET_ADMIN":
		return fallbackCAP_NET_ADMIN
	case "CAP_NET_RAW":
		return fallbackCAP_NET_RAW
	case "CAP_IPC_LOCK":
		return fallbackCAP_IPC_LOCK
	case "CAP_IPC_OWNER":
		return fallbackCAP_IPC_OWNER
	case "CAP_SYS_MODULE":
		return fallbackCAP_SYS_MODULE
	case "CAP_SYS_RAWIO":
		return fallbackCAP_SYS_RAWIO
	case "CAP_SYS_CHROOT":
		return fallbackCAP_SYS_CHROOT
	case "CAP_SYS_PTRACE":
		return fallbackCAP_SYS_PTRACE
	case "CAP_SYS_PACCT":
		return fallbackCAP_SYS_PACCT
	case "CAP_SYS_ADMIN":
		return fallbackCAP_SYS_ADMIN
	case "CAP_SYS_BOOT":
		return fallbackCAP_SYS_BOOT
	case "CAP_SYS_NICE":
		return fallbackCAP_SYS_NICE
	case "CAP_SYS_RESOURCE":
		return fallbackCAP_SYS_RESOURCE
	case "CAP_SYS_TIME":
		return fallbackCAP_SYS_TIME
	case "CAP_SYS_TTY_CONFIG":
		return fallbackCAP_SYS_TTY_CONFIG
	case "CAP_MKNOD":
		return fallbackCAP_MKNOD
	case "CAP_LEASE":
		return fallbackCAP_LEASE
	case "CAP_AUDIT_WRITE":
		return fallbackCAP_AUDIT_WRITE
	case "CAP_AUDIT_CONTROL":
		return fallbackCAP_AUDIT_CONTROL
	case "CAP_SETFCAP":
		return fallbackCAP_SETFCAP
	default:
		return -1
	}
}

// Capability Manager V3 with enhanced fine-grained control
type CapabilityManager struct {
	// Capability definitions
	capabilities    map[string]*Capability
	capabilityNames map[int]*Capability

	// Active restrictions
	activeRestrictions map[string]*CapabilityRestriction

	// Monitoring
	usageTracker    *CapabilityUsageTracker
	violationLogger *ViolationLogger

	// Configuration
	config *CapabilityConfig

	// Synchronization
	mu sync.RWMutex
}

// Enhanced Capability definition
type Capability struct {
	Name           string
	Number         int
	Description    string
	RiskLevel      RiskLevel
	Dependencies   []string
	ConflictsWith  []string
	RequiredKernel string
	DefaultAllowed bool
	Category       CapabilityCategory
}

// Risk levels for capabilities
type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

// Capability categories
type CapabilityCategory int

const (
	CategoryProcess CapabilityCategory = iota
	CategoryFilesystem
	CategoryNetwork
	CategorySystem
	CategorySecurity
	CategoryResource
)

// Capability restriction configuration
type CapabilityRestriction struct {
	ContainerID string
	AllowedCaps map[string]bool
	DeniedCaps  map[string]bool
	AmbientCaps map[string]bool
	BoundingSet map[string]bool
	NoNewPrivs  bool
	AppliedAt   time.Time
	ExpiresAt   *time.Time
}

// Capability configuration
type CapabilityConfig struct {
	DefaultProfile      string
	EnableViolationLog  bool
	EnableUsageTracking bool
	MetricsInterval     time.Duration
	StrictMode          bool
	// Configuration fields for capability restrictions
	Mode        string
	AllowedCaps []string
	DeniedCaps  []string
	AmbientCaps []string
	BoundingSet []string
	NoNewPrivs  bool
}

// Usage tracking
type CapabilityUsageTracker struct {
	usage map[string]*CapabilityUsage
	mu    sync.RWMutex
}

// Usage statistics
type CapabilityUsage struct {
	CapabilityName string
	ContainerID    string
	UsageCount     int64
	LastUsed       time.Time
	FirstUsed      time.Time
	ViolationCount int64
}

// Capability enforcer
type CapabilityEnforcer struct {
	manager        *CapabilityManager
	activeProfiles map[string]*EnforcedProfile
	mu             sync.RWMutex
}

// Enforced profile
type EnforcedProfile struct {
	ContainerID  string
	Restrictions *CapabilityRestriction
	EnforcedAt   time.Time
	Violations   []CapabilityViolation
}

// Capability violation
type CapabilityViolation struct {
	Timestamp      time.Time
	ContainerID    string
	CapabilityName string
	Operation      string
	Denied         bool
	Reason         string
}

// NewCapabilityManager creates enhanced capability manager
func NewCapabilityManager() *CapabilityManager {
	cm := &CapabilityManager{
		capabilities:       make(map[string]*Capability),
		capabilityNames:    make(map[int]*Capability),
		activeRestrictions: make(map[string]*CapabilityRestriction),
		config: &CapabilityConfig{
			DefaultProfile:      "standard",
			EnableViolationLog:  true,
			EnableUsageTracking: true,
			MetricsInterval:     5 * time.Second,
			StrictMode:          false,
		},
	}

	cm.usageTracker = NewCapabilityUsageTracker()
	cm.violationLogger = NewViolationLogger()

	// Initialize built-in capabilities
	cm.initializeCapabilities()

	return cm
}

// NewCapabilityEnforcer creates capability enforcer
func NewCapabilityEnforcer() *CapabilityEnforcer {
	return &CapabilityEnforcer{
		manager:        NewCapabilityManager(),
		activeProfiles: make(map[string]*EnforcedProfile),
	}
}

// initializeCapabilities loads all Linux capabilities
func (cm *CapabilityManager) initializeCapabilities() {
	capabilities := []*Capability{
		{
			Name:           "CAP_CHOWN",
			Number:         getCapConstant("CAP_CHOWN"),
			Description:    "Make arbitrary changes to file UIDs and GIDs",
			RiskLevel:      RiskMedium,
			Category:       CategoryFilesystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_DAC_OVERRIDE",
			Number:         getCapConstant("CAP_DAC_OVERRIDE"),
			Description:    "Bypass file read, write, and execute permission checks",
			RiskLevel:      RiskHigh,
			Category:       CategoryFilesystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_DAC_READ_SEARCH",
			Number:         getCapConstant("CAP_DAC_READ_SEARCH"),
			Description:    "Bypass file read permission checks and directory read and execute permission checks",
			RiskLevel:      RiskHigh,
			Category:       CategoryFilesystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_FOWNER",
			Number:         getCapConstant("CAP_FOWNER"),
			Description:    "Bypass permission checks on operations that normally require the filesystem UID of the process to match the UID of the file",
			RiskLevel:      RiskMedium,
			Category:       CategoryFilesystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_FSETID",
			Number:         getCapConstant("CAP_FSETID"),
			Description:    "Don't clear set-user-ID and set-group-ID mode bits when a file is modified",
			RiskLevel:      RiskMedium,
			Category:       CategoryFilesystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_KILL",
			Number:         getCapConstant("CAP_KILL"),
			Description:    "Bypass permission checks for sending signals",
			RiskLevel:      RiskMedium,
			Category:       CategoryProcess,
			DefaultAllowed: true,
		},
		{
			Name:           "CAP_SETGID",
			Number:         getCapConstant("CAP_SETGID"),
			Description:    "Make arbitrary manipulations of process GIDs and supplementary GID list",
			RiskLevel:      RiskHigh,
			Category:       CategoryProcess,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SETUID",
			Number:         getCapConstant("CAP_SETUID"),
			Description:    "Make arbitrary manipulations of process UIDs",
			RiskLevel:      RiskHigh,
			Category:       CategoryProcess,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SETPCAP",
			Number:         getCapConstant("CAP_SETPCAP"),
			Description:    "Grant or remove any capability in the caller's permitted capability set to or from any other process",
			RiskLevel:      RiskCritical,
			Category:       CategorySecurity,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_LINUX_IMMUTABLE",
			Number:         getCapConstant("CAP_LINUX_IMMUTABLE"),
			Description:    "Set the FS_APPEND_FL and FS_IMMUTABLE_FL i-node flags",
			RiskLevel:      RiskMedium,
			Category:       CategoryFilesystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_NET_BIND_SERVICE",
			Number:         getCapConstant("CAP_NET_BIND_SERVICE"),
			Description:    "Bind a socket to Internet domain privileged ports (port numbers less than 1024)",
			RiskLevel:      RiskLow,
			Category:       CategoryNetwork,
			DefaultAllowed: true,
		},
		{
			Name:           "CAP_NET_BROADCAST",
			Number:         getCapConstant("CAP_NET_BROADCAST"),
			Description:    "Make socket broadcasts, and listen to multicasts",
			RiskLevel:      RiskLow,
			Category:       CategoryNetwork,
			DefaultAllowed: true,
		},
		{
			Name:           "CAP_NET_ADMIN",
			Number:         getCapConstant("CAP_NET_ADMIN"),
			Description:    "Perform various network-related operations",
			RiskLevel:      RiskHigh,
			Category:       CategoryNetwork,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_NET_RAW",
			Number:         getCapConstant("CAP_NET_RAW"),
			Description:    "Use RAW and PACKET sockets; bind to any address for transparent proxying",
			RiskLevel:      RiskHigh,
			Category:       CategoryNetwork,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_IPC_LOCK",
			Number:         getCapConstant("CAP_IPC_LOCK"),
			Description:    "Lock memory (mlock(2), mlockall(2), mmap(2), shmctl(2))",
			RiskLevel:      RiskMedium,
			Category:       CategoryResource,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_IPC_OWNER",
			Number:         getCapConstant("CAP_IPC_OWNER"),
			Description:    "Bypass permission checks for operations on System V IPC objects",
			RiskLevel:      RiskMedium,
			Category:       CategoryProcess,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_MODULE",
			Number:         getCapConstant("CAP_SYS_MODULE"),
			Description:    "Load and unload kernel modules",
			RiskLevel:      RiskCritical,
			Category:       CategorySystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_RAWIO",
			Number:         getCapConstant("CAP_SYS_RAWIO"),
			Description:    "Perform I/O port operations (iopl(2) and ioperm(2))",
			RiskLevel:      RiskCritical,
			Category:       CategorySystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_CHROOT",
			Number:         getCapConstant("CAP_SYS_CHROOT"),
			Description:    "Use chroot(2), change mount namespaces using setns(2)",
			RiskLevel:      RiskHigh,
			Category:       CategoryFilesystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_PTRACE",
			Number:         getCapConstant("CAP_SYS_PTRACE"),
			Description:    "Trace arbitrary processes using ptrace(2)",
			RiskLevel:      RiskHigh,
			Category:       CategoryProcess,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_PACCT",
			Number:         getCapConstant("CAP_SYS_PACCT"),
			Description:    "Use acct(2), switch process accounting on or off",
			RiskLevel:      RiskMedium,
			Category:       CategorySystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_ADMIN",
			Number:         getCapConstant("CAP_SYS_ADMIN"),
			Description:    "Perform a range of system administration operations",
			RiskLevel:      RiskCritical,
			Category:       CategorySystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_BOOT",
			Number:         getCapConstant("CAP_SYS_BOOT"),
			Description:    "Use reboot(2) and kexec_load(2), reboot and load a new kernel for later execution",
			RiskLevel:      RiskCritical,
			Category:       CategorySystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_NICE",
			Number:         getCapConstant("CAP_SYS_NICE"),
			Description:    "Raise process nice value (nice(2), setpriority(2)) and change the nice value for arbitrary processes",
			RiskLevel:      RiskMedium,
			Category:       CategoryResource,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_RESOURCE",
			Number:         getCapConstant("CAP_SYS_RESOURCE"),
			Description:    "Override resource limits",
			RiskLevel:      RiskHigh,
			Category:       CategoryResource,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_TIME",
			Number:         getCapConstant("CAP_SYS_TIME"),
			Description:    "Set system clock (settimeofday(2), stime(2), adjtimex(2)); set real-time (hardware) clock",
			RiskLevel:      RiskHigh,
			Category:       CategorySystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SYS_TTY_CONFIG",
			Number:         getCapConstant("CAP_SYS_TTY_CONFIG"),
			Description:    "Use vhangup(2); employ various privileged ioctl(2) operations on virtual terminals",
			RiskLevel:      RiskMedium,
			Category:       CategorySystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_MKNOD",
			Number:         getCapConstant("CAP_MKNOD"),
			Description:    "Create special files using mknod(2)",
			RiskLevel:      RiskMedium,
			Category:       CategoryFilesystem,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_LEASE",
			Number:         getCapConstant("CAP_LEASE"),
			Description:    "Establish leases on arbitrary files (see fcntl(2))",
			RiskLevel:      RiskLow,
			Category:       CategoryFilesystem,
			DefaultAllowed: true,
		},
		{
			Name:           "CAP_AUDIT_WRITE",
			Number:         getCapConstant("CAP_AUDIT_WRITE"),
			Description:    "Write records to kernel auditing log",
			RiskLevel:      RiskLow,
			Category:       CategorySecurity,
			DefaultAllowed: true,
		},
		{
			Name:           "CAP_AUDIT_CONTROL",
			Number:         getCapConstant("CAP_AUDIT_CONTROL"),
			Description:    "Enable and disable kernel auditing; change auditing filter rules; retrieve auditing status and filtering rules",
			RiskLevel:      RiskMedium,
			Category:       CategorySecurity,
			DefaultAllowed: false,
		},
		{
			Name:           "CAP_SETFCAP",
			Number:         getCapConstant("CAP_SETFCAP"),
			Description:    "Set file capabilities",
			RiskLevel:      RiskMedium,
			Category:       CategorySecurity,
			DefaultAllowed: false,
		},
	}

	// Index capabilities by name and number
	for _, cap := range capabilities {
		cm.capabilities[cap.Name] = cap
		cm.capabilityNames[cap.Number] = cap
	}
}

// ApplyCapabilityRestrictions applies capability restrictions to container
func (ce *CapabilityEnforcer) ApplyCapabilityRestrictions(containerID string, config *CapabilityConfig) error {
	restrictions := &CapabilityRestriction{
		ContainerID: containerID,
		AllowedCaps: make(map[string]bool),
		DeniedCaps:  make(map[string]bool),
		AmbientCaps: make(map[string]bool),
		BoundingSet: make(map[string]bool),
		NoNewPrivs:  config.NoNewPrivs,
		AppliedAt:   time.Now(),
	}

	// Process allowed capabilities
	for _, capName := range config.AllowedCaps {
		if ce.manager.IsValidCapability(capName) {
			restrictions.AllowedCaps[capName] = true
		}
	}

	// Process denied capabilities
	for _, capName := range config.DeniedCaps {
		if ce.manager.IsValidCapability(capName) {
			restrictions.DeniedCaps[capName] = true
		}
	}

	// Process ambient capabilities
	for _, capName := range config.AmbientCaps {
		if ce.manager.IsValidCapability(capName) {
			restrictions.AmbientCaps[capName] = true
		}
	}

	// Process bounding set
	for _, capName := range config.BoundingSet {
		if ce.manager.IsValidCapability(capName) {
			restrictions.BoundingSet[capName] = true
		}
	}

	// Apply restrictions to process
	if err := ce.applyToProcess(restrictions); err != nil {
		return fmt.Errorf("failed to apply capability restrictions: %w", err)
	}

	// Store enforced profile
	profile := &EnforcedProfile{
		ContainerID:  containerID,
		Restrictions: restrictions,
		EnforcedAt:   time.Now(),
		Violations:   []CapabilityViolation{},
	}

	ce.mu.Lock()
	ce.activeProfiles[containerID] = profile
	ce.mu.Unlock()

	// Store in manager
	ce.manager.mu.Lock()
	ce.manager.activeRestrictions[containerID] = restrictions
	ce.manager.mu.Unlock()

	return nil
}

// applyToProcess applies capability restrictions to the actual process
func (ce *CapabilityEnforcer) applyToProcess(restrictions *CapabilityRestriction) error {
	// Apply bounding set restrictions
	for capName, allowed := range restrictions.BoundingSet {
		cap := ce.manager.capabilities[capName]
		if cap == nil {
			continue
		}

		if !allowed {
			if err := ce.dropFromBoundingSet(cap.Number); err != nil {
				return fmt.Errorf("failed to drop %s from bounding set: %w", capName, err)
			}
		}
	}

	// Apply ambient capability restrictions
	for capName, allowed := range restrictions.AmbientCaps {
		cap := ce.manager.capabilities[capName]
		if cap == nil {
			continue
		}

		if allowed {
			if err := ce.addAmbientCapability(cap.Number); err != nil {
				return fmt.Errorf("failed to add ambient capability %s: %w", capName, err)
			}
		}
	}

	// Apply no_new_privs if requested
	if restrictions.NoNewPrivs {
		if err := ce.setNoNewPrivs(); err != nil {
			return fmt.Errorf("failed to set no_new_privs: %w", err)
		}
	}

	return nil
}

// IsValidCapability checks if capability name is valid
func (cm *CapabilityManager) IsValidCapability(name string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	_, exists := cm.capabilities[name]
	return exists
}

// GetCapabilityByName returns capability by name
func (cm *CapabilityManager) GetCapabilityByName(name string) (*Capability, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	cap, exists := cm.capabilities[name]
	if !exists {
		return nil, fmt.Errorf("capability %s not found", name)
	}

	return cap, nil
}

// ListCapabilities returns all available capabilities
func (cm *CapabilityManager) ListCapabilities() []*Capability {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	caps := make([]*Capability, 0, len(cm.capabilities))
	for _, cap := range cm.capabilities {
		caps = append(caps, cap)
	}

	// Sort by name
	sort.Slice(caps, func(i, j int) bool {
		return caps[i].Name < caps[j].Name
	})

	return caps
}

// GetCapabilitiesByRisk returns capabilities filtered by risk level
func (cm *CapabilityManager) GetCapabilitiesByRisk(maxRisk RiskLevel) []*Capability {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var filtered []*Capability
	for _, cap := range cm.capabilities {
		if cap.RiskLevel <= maxRisk {
			filtered = append(filtered, cap)
		}
	}

	return filtered
}

// Helper methods for capability manipulation
func (ce *CapabilityEnforcer) dropFromBoundingSet(capNumber int) error {
	// Drop capability from bounding set
	return unix.Prctl(fallbackPR_CAPBSET_DROP, uintptr(capNumber), 0, 0, 0)
}

func (ce *CapabilityEnforcer) addAmbientCapability(capNumber int) error {
	// Add ambient capability
	return unix.Prctl(fallbackPR_CAP_AMBIENT, fallbackPR_CAP_AMBIENT_RAISE, uintptr(capNumber), 0, 0)
}

func (ce *CapabilityEnforcer) setNoNewPrivs() error {
	// Set no_new_privs bit
	return unix.Prctl(fallbackPR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

// String methods for risk levels
func (rl RiskLevel) String() string {
	switch rl {
	case RiskLow:
		return "Low"
	case RiskMedium:
		return "Medium"
	case RiskHigh:
		return "High"
	case RiskCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// String methods for categories
func (cc CapabilityCategory) String() string {
	switch cc {
	case CategoryProcess:
		return "Process"
	case CategoryFilesystem:
		return "Filesystem"
	case CategoryNetwork:
		return "Network"
	case CategorySystem:
		return "System"
	case CategorySecurity:
		return "Security"
	case CategoryResource:
		return "Resource"
	default:
		return "Unknown"
	}
}

// Placeholder types and constructors
type ViolationLogger struct{}

func NewCapabilityUsageTracker() *CapabilityUsageTracker {
	return &CapabilityUsageTracker{
		usage: make(map[string]*CapabilityUsage),
	}
}

func NewViolationLogger() *ViolationLogger {
	return &ViolationLogger{}
}
