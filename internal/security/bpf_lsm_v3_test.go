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