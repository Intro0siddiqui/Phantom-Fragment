//go:build linux
// +build linux

package capabilities

import (
	"testing"
	"time"
)

func TestNewCapabilityManager(t *testing.T) {
	cm := NewCapabilityManager()
	
	if cm == nil {
		t.Fatal("NewCapabilityManager returned nil")
	}
	
	if cm.capabilities == nil {
		t.Error("capabilities map not initialized")
	}
	
	if cm.capabilityNames == nil {
		t.Error("capabilityNames map not initialized")
	}
	
	if cm.activeRestrictions == nil {
		t.Error("activeRestrictions map not initialized")
	}
	
	if cm.config == nil {
		t.Error("config not initialized")
	}
	
	// Test default configuration
	if cm.config.DefaultProfile != "standard" {
		t.Errorf("Expected default profile 'standard', got '%s'", cm.config.DefaultProfile)
	}
	
	if !cm.config.EnableViolationLog {
		t.Error("Expected EnableViolationLog to be true")
	}
	
	if !cm.config.EnableUsageTracking {
		t.Error("Expected EnableUsageTracking to be true")
	}
	
	if cm.config.MetricsInterval != 5*time.Second {
		t.Errorf("Expected MetricsInterval 5s, got %v", cm.config.MetricsInterval)
	}
}

func TestCapabilityInitialization(t *testing.T) {
	cm := NewCapabilityManager()
	
	// Test that capabilities were initialized
	if len(cm.capabilities) == 0 {
		t.Error("No capabilities were initialized")
	}
	
	// Test specific capabilities
	testCaps := []string{
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE", 
		"CAP_SETUID",
		"CAP_SETGID",
		"CAP_SYS_ADMIN",
		"CAP_NET_ADMIN",
	}
	
	for _, capName := range testCaps {
		cap, exists := cm.capabilities[capName]
		if !exists {
			t.Errorf("Capability %s not found", capName)
			continue
		}
		
		if cap.Name != capName {
			t.Errorf("Capability name mismatch: expected %s, got %s", capName, cap.Name)
		}
		
		if cap.Number < 0 {
			t.Errorf("Invalid capability number for %s: %d", capName, cap.Number)
		}
		
		if cap.Description == "" {
			t.Errorf("Missing description for capability %s", capName)
		}
	}
}

func TestIsValidCapability(t *testing.T) {
	cm := NewCapabilityManager()
	
	// Test valid capabilities
	validCaps := []string{"CAP_CHOWN", "CAP_SETUID", "CAP_SYS_ADMIN"}
	for _, cap := range validCaps {
		if !cm.IsValidCapability(cap) {
			t.Errorf("Expected %s to be valid capability", cap)
		}
	}
	
	// Test invalid capabilities
	invalidCaps := []string{"INVALID_CAP", "CAP_NONEXISTENT", ""}
	for _, cap := range invalidCaps {
		if cm.IsValidCapability(cap) {
			t.Errorf("Expected %s to be invalid capability", cap)
		}
	}
}

func TestGetCapabilityByName(t *testing.T) {
	cm := NewCapabilityManager()
	
	// Test valid capability
	cap, err := cm.GetCapabilityByName("CAP_CHOWN")
	if err != nil {
		t.Errorf("Unexpected error getting CAP_CHOWN: %v", err)
	}
	if cap.Name != "CAP_CHOWN" {
		t.Errorf("Expected CAP_CHOWN, got %s", cap.Name)
	}
	
	// Test invalid capability
	_, err = cm.GetCapabilityByName("INVALID_CAP")
	if err == nil {
		t.Error("Expected error for invalid capability")
	}
}

func TestListCapabilities(t *testing.T) {
	cm := NewCapabilityManager()
	
	caps := cm.ListCapabilities()
	if len(caps) == 0 {
		t.Error("ListCapabilities returned empty slice")
	}
	
	// Test that capabilities are sorted
	for i := 1; i < len(caps); i++ {
		if caps[i-1].Name >= caps[i].Name {
			t.Errorf("Capabilities not sorted: %s >= %s", caps[i-1].Name, caps[i].Name)
		}
	}
}

func TestGetCapabilitiesByRisk(t *testing.T) {
	cm := NewCapabilityManager()
	
	// Test filtering by risk level
	lowRiskCaps := cm.GetCapabilitiesByRisk(RiskLow)
	mediumRiskCaps := cm.GetCapabilitiesByRisk(RiskMedium)
	allCaps := cm.GetCapabilitiesByRisk(RiskCritical)
	
	// Low risk should be subset of medium risk
	if len(lowRiskCaps) > len(mediumRiskCaps) {
		t.Error("Low risk caps should not exceed medium risk caps")
	}
	
	// Medium risk should be subset of all caps
	if len(mediumRiskCaps) > len(allCaps) {
		t.Error("Medium risk caps should not exceed all caps")
	}
	
	// Verify risk levels
	for _, cap := range lowRiskCaps {
		if cap.RiskLevel > RiskLow {
			t.Errorf("Capability %s has risk level %v, expected <= %v", cap.Name, cap.RiskLevel, RiskLow)
		}
	}
}

func TestNewCapabilityEnforcer(t *testing.T) {
	ce := NewCapabilityEnforcer()
	
	if ce == nil {
		t.Fatal("NewCapabilityEnforcer returned nil")
	}
	
	if ce.manager == nil {
		t.Error("CapabilityEnforcer manager not initialized")
	}
	
	if ce.activeProfiles == nil {
		t.Error("CapabilityEnforcer activeProfiles not initialized")
	}
}

func TestCapabilityConfig(t *testing.T) {
	config := &CapabilityConfig{
		DefaultProfile:      "test",
		EnableViolationLog:  true,
		EnableUsageTracking: false,
		MetricsInterval:     10 * time.Second,
		StrictMode:          true,
		Mode:                "strict",
		AllowedCaps:         []string{"CAP_CHOWN", "CAP_SETUID"},
		DeniedCaps:          []string{"CAP_SYS_ADMIN"},
		AmbientCaps:         []string{"CAP_KILL"},
		BoundingSet:         []string{"CAP_CHOWN", "CAP_SETUID", "CAP_KILL"},
		NoNewPrivs:          true,
	}
	
	if config.DefaultProfile != "test" {
		t.Errorf("Expected DefaultProfile 'test', got '%s'", config.DefaultProfile)
	}
	
	if !config.EnableViolationLog {
		t.Error("Expected EnableViolationLog to be true")
	}
	
	if config.EnableUsageTracking {
		t.Error("Expected EnableUsageTracking to be false")
	}
	
	if len(config.AllowedCaps) != 2 {
		t.Errorf("Expected 2 allowed caps, got %d", len(config.AllowedCaps))
	}
	
	if len(config.DeniedCaps) != 1 {
		t.Errorf("Expected 1 denied cap, got %d", len(config.DeniedCaps))
	}
}

func TestApplyCapabilityRestrictions(t *testing.T) {
	ce := NewCapabilityEnforcer()
	
	config := &CapabilityConfig{
		AllowedCaps: []string{"CAP_CHOWN", "CAP_SETUID"},
		DeniedCaps:  []string{"CAP_SYS_ADMIN"},
		AmbientCaps: []string{"CAP_KILL"},
		BoundingSet: []string{"CAP_CHOWN", "CAP_SETUID", "CAP_KILL"},
		NoNewPrivs:  true,
	}
	
	err := ce.ApplyCapabilityRestrictions("test-container", config)
	if err != nil {
		t.Errorf("Unexpected error applying restrictions: %v", err)
	}
	
	// Check that restrictions were stored
	if len(ce.activeProfiles) != 1 {
		t.Errorf("Expected 1 active profile, got %d", len(ce.activeProfiles))
	}
	
	profile, exists := ce.activeProfiles["test-container"]
	if !exists {
		t.Error("Active profile not found for test-container")
	}
	
	if profile.ContainerID != "test-container" {
		t.Errorf("Expected container ID 'test-container', got '%s'", profile.ContainerID)
	}
	
	if !profile.Restrictions.NoNewPrivs {
		t.Error("Expected NoNewPrivs to be true")
	}
}

func TestRiskLevelString(t *testing.T) {
	tests := []struct {
		level    RiskLevel
		expected string
	}{
		{RiskLow, "Low"},
		{RiskMedium, "Medium"},
		{RiskHigh, "High"},
		{RiskCritical, "Critical"},
		{RiskLevel(999), "Unknown"},
	}
	
	for _, test := range tests {
		if test.level.String() != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, test.level.String())
		}
	}
}

func TestCapabilityCategoryString(t *testing.T) {
	tests := []struct {
		category CapabilityCategory
		expected string
	}{
		{CategoryProcess, "Process"},
		{CategoryFilesystem, "Filesystem"},
		{CategoryNetwork, "Network"},
		{CategorySystem, "System"},
		{CategorySecurity, "Security"},
		{CategoryResource, "Resource"},
		{CapabilityCategory(999), "Unknown"},
	}
	
	for _, test := range tests {
		if test.category.String() != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, test.category.String())
		}
	}
}

func TestGetCapConstant(t *testing.T) {
	tests := []struct {
		name     string
		expected int
	}{
		{"CAP_CHOWN", 0},
		{"CAP_DAC_OVERRIDE", 1},
		{"CAP_SETUID", 7},
		{"CAP_SYS_ADMIN", 21},
		{"INVALID_CAP", -1},
	}
	
	for _, test := range tests {
		result := getCapConstant(test.name)
		if result != test.expected {
			t.Errorf("getCapConstant(%s): expected %d, got %d", test.name, test.expected, result)
		}
	}
}

func TestCapabilityUsageTracker(t *testing.T) {
	tracker := NewCapabilityUsageTracker()
	
	if tracker == nil {
		t.Fatal("NewCapabilityUsageTracker returned nil")
	}
	
	if tracker.usage == nil {
		t.Error("Usage map not initialized")
	}
}

func TestViolationLogger(t *testing.T) {
	logger := NewViolationLogger()
	
	if logger == nil {
		t.Fatal("NewViolationLogger returned nil")
	}
	
	if logger.violations == nil {
		t.Error("Violations slice not initialized")
	}
}

// Benchmark tests
func BenchmarkIsValidCapability(b *testing.B) {
	cm := NewCapabilityManager()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cm.IsValidCapability("CAP_CHOWN")
	}
}

func BenchmarkGetCapabilityByName(b *testing.B) {
	cm := NewCapabilityManager()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cm.GetCapabilityByName("CAP_CHOWN")
	}
}

func BenchmarkListCapabilities(b *testing.B) {
	cm := NewCapabilityManager()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cm.ListCapabilities()
	}
}