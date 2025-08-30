//go:build linux
// +build linux

package fragments

import (
	"fmt"
	"sync"
	"time"
)

// Capability represents a specific system capability
type Capability string

const (
	// Network capabilities
	TCP_CONNECTIONS Capability = "tcp_connections"
	TCP_LISTEN      Capability = "tcp_listen"
	DNS_LOOKUP      Capability = "dns_lookup"
	DNS_CACHE       Capability = "dns_cache"
	SOCKET_CREATE   Capability = "socket_create"
	SOCKET_BIND     Capability = "socket_bind"
	
	// OS service capabilities
	PROCESS_MANAGEMENT Capability = "process_management"
	SERVICE_START      Capability = "service_start"
	SERVICE_CONTROL    Capability = "service_control"
	SERVICE_STATUS     Capability = "service_status"
	DEVICE_ACCESS      Capability = "device_access"
	DEVICE_CONTROL     Capability = "device_control"
	
	// Process management capabilities
	JOB_CONTROL        Capability = "job_control"
	SIGNAL_HANDLING    Capability = "signal_handling"
	ADVANCED_PROC_MGMT Capability = "advanced_proc_mgmt"
)

// FragmentComponent represents a self-contained, independent fragment
type FragmentComponent struct {
	Name         string
	Size         int64
	Dependencies []string // Empty for standalone components
	Capabilities []Capability
	LoadTime     time.Duration
	Description  string
}

// UnifiedOSLibrary manages all available fragment components
type UnifiedOSLibrary struct {
	components map[string]*FragmentComponent
	mu         sync.RWMutex
}

// NewUnifiedOSLibrary creates a new modular fragment library
func NewUnifiedOSLibrary() *UnifiedOSLibrary {
	library := &UnifiedOSLibrary{
		components: make(map[string]*FragmentComponent),
	}
	
	// Initialize all available components
	library.initializeComponents()
	
	return library
}

// initializeComponents sets up all available fragment components
func (uol *UnifiedOSLibrary) initializeComponents() {
	uol.mu.Lock()
	defer uol.mu.Unlock()
	
	// Network components - completely independent
	uol.components["tcp-stack"] = &FragmentComponent{
		Name:         "TCP Stack",
		Size:         2 * 1024 * 1024, // 2MB
		Dependencies: []string{}, // No dependencies!
		Capabilities: []Capability{TCP_CONNECTIONS, TCP_LISTEN},
		LoadTime:     50 * time.Millisecond,
		Description:  "TCP/IP stack for network connections",
	}
	
	uol.components["dns-resolver"] = &FragmentComponent{
		Name:         "DNS Resolver",
		Size:         1 * 1024 * 1024, // 1MB
		Dependencies: []string{}, // Standalone!
		Capabilities: []Capability{DNS_LOOKUP, DNS_CACHE},
		LoadTime:     30 * time.Millisecond,
		Description:  "DNS resolution and caching",
	}
	
	uol.components["socket-api"] = &FragmentComponent{
		Name:         "Socket API",
		Size:         1 * 1024 * 1024, // 1MB
		Dependencies: []string{}, // Independent!
		Capabilities: []Capability{SOCKET_CREATE, SOCKET_BIND},
		LoadTime:     25 * time.Millisecond,
		Description:  "Socket creation and binding API",
	}
	
	// OS service components - also independent
	uol.components["init-system"] = &FragmentComponent{
		Name:         "Init System",
		Size:         6 * 1024 * 1024, // 6MB
		Dependencies: []string{}, // No dependencies!
		Capabilities: []Capability{PROCESS_MANAGEMENT, SERVICE_START},
		LoadTime:     200 * time.Millisecond,
		Description:  "Process management and service initialization",
	}
	
	uol.components["service-manager"] = &FragmentComponent{
		Name:         "Service Manager",
		Size:         3 * 1024 * 1024, // 3MB
		Dependencies: []string{}, // Standalone!
		Capabilities: []Capability{SERVICE_CONTROL, SERVICE_STATUS},
		LoadTime:     100 * time.Millisecond,
		Description:  "Service control and status management",
	}
	
	uol.components["device-manager"] = &FragmentComponent{
		Name:         "Device Manager",
		Size:         2 * 1024 * 1024, // 2MB
		Dependencies: []string{}, // Independent!
		Capabilities: []Capability{DEVICE_ACCESS, DEVICE_CONTROL},
		LoadTime:     75 * time.Millisecond,
		Description:  "Device access and control",
	}
	
	// Process management components
	uol.components["job-control"] = &FragmentComponent{
		Name:         "Job Control",
		Size:         1 * 1024 * 1024, // 1MB
		Dependencies: []string{}, // Independent!
		Capabilities: []Capability{JOB_CONTROL},
		LoadTime:     40 * time.Millisecond,
		Description:  "Job control and process groups",
	}
	
	uol.components["signal-handling"] = &FragmentComponent{
		Name:         "Signal Handling",
		Size:         1 * 1024 * 1024, // 1MB
		Dependencies: []string{}, // Independent!
		Capabilities: []Capability{SIGNAL_HANDLING},
		LoadTime:     35 * time.Millisecond,
		Description:  "Advanced signal handling",
	}
	
	uol.components["advanced-proc-mgmt"] = &FragmentComponent{
		Name:         "Advanced Process Management",
		Size:         1 * 1024 * 1024, // 1MB
		Dependencies: []string{}, // Independent!
		Capabilities: []Capability{ADVANCED_PROC_MGMT},
		LoadTime:     45 * time.Millisecond,
		Description:  "Advanced process management features",
	}
}

// GetComponent retrieves a component by name
func (uol *UnifiedOSLibrary) GetComponent(name string) (*FragmentComponent, bool) {
	uol.mu.RLock()
	defer uol.mu.RUnlock()
	
	component, exists := uol.components[name]
	return component, exists
}

// ListComponents returns all available components
func (uol *UnifiedOSLibrary) ListComponents() map[string]*FragmentComponent {
	uol.mu.RLock()
	defer uol.mu.RUnlock()
	
	// Return a copy to prevent external modification
	components := make(map[string]*FragmentComponent)
	for name, component := range uol.components {
		components[name] = component
	}
	
	return components
}

// FindComponentsByCapability finds components that provide a specific capability
func (uol *UnifiedOSLibrary) FindComponentsByCapability(capability Capability) []*FragmentComponent {
	uol.mu.RLock()
	defer uol.mu.RUnlock()
	
	var matchingComponents []*FragmentComponent
	for _, component := range uol.components {
		for _, cap := range component.Capabilities {
			if cap == capability {
				matchingComponents = append(matchingComponents, component)
				break
			}
		}
	}
	
	return matchingComponents
}

// GetTotalSize calculates the total size of selected components
func (uol *UnifiedOSLibrary) GetTotalSize(componentNames []string) int64 {
	uol.mu.RLock()
	defer uol.mu.RUnlock()
	
	var totalSize int64
	for _, name := range componentNames {
		if component, exists := uol.components[name]; exists {
			totalSize += component.Size
		}
	}
	
	return totalSize
}

// ValidateComponents checks if all required components exist
func (uol *UnifiedOSLibrary) ValidateComponents(componentNames []string) error {
	uol.mu.RLock()
	defer uol.mu.RUnlock()
	
	for _, name := range componentNames {
		if _, exists := uol.components[name]; !exists {
			return fmt.Errorf("component '%s' not found", name)
		}
	}
	
	return nil
}

// GetComponentInfo returns detailed information about a component
func (uol *UnifiedOSLibrary) GetComponentInfo(name string) (map[string]interface{}, error) {
	uol.mu.RLock()
	defer uol.mu.RUnlock()
	
	component, exists := uol.components[name]
	if !exists {
		return nil, fmt.Errorf("component '%s' not found", name)
	}
	
	info := map[string]interface{}{
		"name":         component.Name,
		"size":         component.Size,
		"size_mb":      float64(component.Size) / (1024 * 1024),
		"dependencies": component.Dependencies,
		"capabilities": component.Capabilities,
		"load_time":    component.LoadTime,
		"description":  component.Description,
	}
	
	return info, nil
}