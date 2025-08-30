package bwrap

import (
	"reflect"
	"testing"
)

func TestBuildArgs(t *testing.T) {
	opts := Options{
		Workdir: "/workspace",
		Binds:   []string{"/home/me/proj:/workspace:rw"},
		Env:     map[string]string{"NODE_ENV": "test"},
		Cmd:     []string{"npm", "test"},
	}

	expected := []string{
		"bwrap",
		"--unshare-all",
		"--share-net",
		"--die-with-parent",
		"--proc", "/proc",
		"--dev", "/dev",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/etc", "/etc",
		"--bind", "/home/me/proj:/workspace:rw",
		"--setenv", "NODE_ENV", "test",
		"--chdir", "/workspace",
		"npm", "test",
	}

	actual := BuildArgs(opts)

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}
