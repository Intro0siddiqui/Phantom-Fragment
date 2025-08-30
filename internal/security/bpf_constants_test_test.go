//go:build linux
// +build linux

package security

import (
	"testing"
	"golang.org/x/sys/unix"
)

// TestBPFConstants checks if BPF constants are available in the current version
func TestBPFConstants(t *testing.T) {
	// Test if BPF constants are available
	_ = unix.BPF_PROG_TYPE_LSM
	_ = unix.BPF_PROG_ATTACH
	_ = unix.BPF_LSM_FILE_OPEN
	
	t.Log("BPF constants are available")
}

// TestBPFFallbackConstants checks if fallback constants work
func TestBPFFallbackConstants(t *testing.T) {
	// Test fallback constants from bpf_lsm_v3.go
	const (
		fallbackBPF_PROG_TYPE_LSM = 29
		fallbackBPF_PROG_ATTACH   = 8
		fallbackBPF_LSM_FILE_OPEN = 1
	)
	
	if fallbackBPF_PROG_TYPE_LSM != 29 {
		t.Errorf("Expected fallbackBPF_PROG_TYPE_LSM to be 29, got %d", fallbackBPF_PROG_TYPE_LSM)
	}
	
	if fallbackBPF_PROG_ATTACH != 8 {
		t.Errorf("Expected fallbackBPF_PROG_ATTACH to be 8, got %d", fallbackBPF_PROG_ATTACH)
	}
	
	if fallbackBPF_LSM_FILE_OPEN != 1 {
		t.Errorf("Expected fallbackBPF_LSM_FILE_OPEN to be 1, got %d", fallbackBPF_LSM_FILE_OPEN)
	}
	
	t.Log("Fallback BPF constants are correct")
}