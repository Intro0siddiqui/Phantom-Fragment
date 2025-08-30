//go:build linux
// +build linux

package fragments

import (
	"regexp"
	"strings"
)

// TaskAnalyzer analyzes tasks to determine required capabilities
type TaskAnalyzer struct {
	// Network detection patterns
	networkPatterns []*regexp.Regexp
	tcpPatterns     []*regexp.Regexp
	dnsPatterns     []*regexp.Regexp
	
	// OS service detection patterns
	initPatterns    []*regexp.Regexp
	servicePatterns []*regexp.Regexp
	devicePatterns  []*regexp.Regexp
	
	// Process management patterns
	jobControlPatterns    []*regexp.Regexp
	signalPatterns        []*regexp.Regexp
	advancedProcPatterns  []*regexp.Regexp
}

// NewTaskAnalyzer creates a new task analyzer with compiled patterns
func NewTaskAnalyzer() *TaskAnalyzer {
	ta := &TaskAnalyzer{}
	ta.initializePatterns()
	return ta
}

// initializePatterns compiles regex patterns for capability detection
func (ta *TaskAnalyzer) initializePatterns() {
	// Network patterns
	ta.networkPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(curl|wget|http|https|ftp|ssh|telnet|netcat|nc)`),
		regexp.MustCompile(`(?i)(socket|bind|listen|connect|accept)`),
		regexp.MustCompile(`(?i)(tcp|udp|ip|network|port)`),
	}
	
	ta.tcpPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(tcp|socket|bind|listen|connect)`),
		regexp.MustCompile(`(?i)(server|client|port|host)`),
	}
	
	ta.dnsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(nslookup|dig|host|dns|resolve)`),
		regexp.MustCompile(`(?i)(domain|hostname|fqdn)`),
	}
	
	// OS service patterns
	ta.initPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(systemd|init|service|daemon)`),
		regexp.MustCompile(`(?i)(start|stop|restart|enable|disable)`),
		regexp.MustCompile(`(?i)(systemctl|service|chkconfig)`),
	}
	
	ta.servicePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(systemctl|service|daemon)`),
		regexp.MustCompile(`(?i)(status|reload|restart|start|stop)`),
	}
	
	ta.devicePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(/dev/|device|mount|umount)`),
		regexp.MustCompile(`(?i)(lsblk|fdisk|parted|mkfs)`),
		regexp.MustCompile(`(?i)(usb|pci|scsi|block)`),
	}
	
	// Process management patterns
	ta.jobControlPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(jobs|fg|bg|nohup|disown)`),
		regexp.MustCompile(`(?i)(job|process.*group|pgid)`),
	}
	
	ta.signalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(kill|signal|trap|sigterm|sigint)`),
		regexp.MustCompile(`(?i)(pkill|killall|signal.*handler)`),
	}
	
	ta.advancedProcPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(ps|top|htop|proc|process.*tree)`),
		regexp.MustCompile(`(?i)(nice|renice|ionice|sched)`),
		regexp.MustCompile(`(?i)(strace|ltrace|gdb|debug)`),
	}
}

// AnalyzeTask analyzes a task and returns required capabilities
func (ta *TaskAnalyzer) AnalyzeTask(task *Task) map[Capability]bool {
	capabilities := make(map[Capability]bool)
	
	// Combine command and arguments for analysis
	fullCommand := ta.buildFullCommand(task)
	
	// Analyze network capabilities
	if ta.needsNetworkCapabilities(fullCommand) {
		if ta.needsTCPConnections(fullCommand) {
			capabilities[TCP_CONNECTIONS] = true
			capabilities[TCP_LISTEN] = true
		}
		
		if ta.needsDNSLookup(fullCommand) {
			capabilities[DNS_LOOKUP] = true
			capabilities[DNS_CACHE] = true
		}
		
		if ta.needsSocketAPI(fullCommand) {
			capabilities[SOCKET_CREATE] = true
			capabilities[SOCKET_BIND] = true
		}
	}
	
	// Analyze OS service capabilities
	if ta.needsInitSystem(fullCommand) {
		capabilities[PROCESS_MANAGEMENT] = true
		capabilities[SERVICE_START] = true
	}
	
	if ta.needsServiceManager(fullCommand) {
		capabilities[SERVICE_CONTROL] = true
		capabilities[SERVICE_STATUS] = true
	}
	
	if ta.needsDeviceAccess(fullCommand) {
		capabilities[DEVICE_ACCESS] = true
		capabilities[DEVICE_CONTROL] = true
	}
	
	// Analyze process management capabilities
	if ta.needsJobControl(fullCommand) {
		capabilities[JOB_CONTROL] = true
	}
	
	if ta.needsSignalHandling(fullCommand) {
		capabilities[SIGNAL_HANDLING] = true
	}
	
	if ta.needsAdvancedProcessManagement(fullCommand) {
		capabilities[ADVANCED_PROC_MGMT] = true
	}
	
	return capabilities
}

// buildFullCommand combines command and arguments into a single string
func (ta *TaskAnalyzer) buildFullCommand(task *Task) string {
	if len(task.Args) == 0 {
		return task.Command
	}
	
	return task.Command + " " + strings.Join(task.Args, " ")
}

// needsNetworkCapabilities checks if task requires any network capabilities
func (ta *TaskAnalyzer) needsNetworkCapabilities(command string) bool {
	for _, pattern := range ta.networkPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// needsTCPConnections checks if task requires TCP capabilities
func (ta *TaskAnalyzer) needsTCPConnections(command string) bool {
	for _, pattern := range ta.tcpPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// needsDNSLookup checks if task requires DNS capabilities
func (ta *TaskAnalyzer) needsDNSLookup(command string) bool {
	for _, pattern := range ta.dnsPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// needsSocketAPI checks if task requires socket API capabilities
func (ta *TaskAnalyzer) needsSocketAPI(command string) bool {
	// If it needs TCP connections, it likely needs socket API
	return ta.needsTCPConnections(command)
}

// needsInitSystem checks if task requires init system capabilities
func (ta *TaskAnalyzer) needsInitSystem(command string) bool {
	for _, pattern := range ta.initPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// needsServiceManager checks if task requires service manager capabilities
func (ta *TaskAnalyzer) needsServiceManager(command string) bool {
	for _, pattern := range ta.servicePatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// needsDeviceAccess checks if task requires device access capabilities
func (ta *TaskAnalyzer) needsDeviceAccess(command string) bool {
	for _, pattern := range ta.devicePatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// needsJobControl checks if task requires job control capabilities
func (ta *TaskAnalyzer) needsJobControl(command string) bool {
	for _, pattern := range ta.jobControlPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// needsSignalHandling checks if task requires signal handling capabilities
func (ta *TaskAnalyzer) needsSignalHandling(command string) bool {
	for _, pattern := range ta.signalPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// needsAdvancedProcessManagement checks if task requires advanced process management
func (ta *TaskAnalyzer) needsAdvancedProcessManagement(command string) bool {
	for _, pattern := range ta.advancedProcPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// GetRequiredComponents returns the component names needed for given capabilities
func (ta *TaskAnalyzer) GetRequiredComponents(capabilities map[Capability]bool, library *UnifiedOSLibrary) []string {
	var requiredComponents []string
	componentMap := make(map[string]bool) // Prevent duplicates
	
	for capability := range capabilities {
		components := library.FindComponentsByCapability(capability)
		for _, component := range components {
			// Find component name by searching through library
			for name, comp := range library.ListComponents() {
				if comp == component && !componentMap[name] {
					requiredComponents = append(requiredComponents, name)
					componentMap[name] = true
					break
				}
			}
		}
	}
	
	return requiredComponents
}

// AnalyzeTaskComplexity returns a complexity score for the task
func (ta *TaskAnalyzer) AnalyzeTaskComplexity(task *Task) TaskComplexity {
	capabilities := ta.AnalyzeTask(task)
	
	complexity := SIMPLE
	
	// Check for network complexity
	if capabilities[TCP_CONNECTIONS] || capabilities[DNS_LOOKUP] {
		complexity = NETWORK
	}
	
	// Check for OS service complexity
	if capabilities[PROCESS_MANAGEMENT] || capabilities[SERVICE_START] {
		complexity = OS_SERVICES
	}
	
	// Check for advanced complexity
	if capabilities[ADVANCED_PROC_MGMT] || capabilities[DEVICE_ACCESS] {
		complexity = ADVANCED
	}
	
	return complexity
}

// TaskComplexity represents the complexity level of a task
type TaskComplexity int

const (
	SIMPLE TaskComplexity = iota
	NETWORK
	OS_SERVICES
	ADVANCED
)

// String returns a string representation of task complexity
func (tc TaskComplexity) String() string {
	switch tc {
	case SIMPLE:
		return "simple"
	case NETWORK:
		return "network"
	case OS_SERVICES:
		return "os_services"
	case ADVANCED:
		return "advanced"
	default:
		return "unknown"
	}
}