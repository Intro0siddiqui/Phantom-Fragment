package bwrap

import (
	"fmt"
)

// Options for the bubblewrap sandbox.

type Options struct {
	Workdir        string
	Binds          []string
	Env            map[string]string
	Cmd            []string
	MemoryLimitMB  int // Memory limit in MB
	CPULimitCores  int // CPU limit in number of cores
	SeccompProfile string // Seccomp profile name
	ContainerID    string // Container ID for cgroup association
}

// BuildArgs builds the command and arguments for bubblewrap.

func BuildArgs(opts Options) []string {
	args := []string{
		"bwrap",
		"--unshare-all",
		"--share-net",
		"--die-with-parent",
		"--proc", "/proc",
		"--dev", "/dev",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/etc", "/etc",
	}

	if opts.MemoryLimitMB > 0 {
		args = append(args, "--mem-limit", fmt.Sprintf("%dM", opts.MemoryLimitMB))
	}

	// Note: CPU limiting with bwrap is conceptual. Actual CPU limiting will be handled via cgroups.

	for _, bind := range opts.Binds {
		args = append(args, "--bind", bind)
	}

	for key, value := range opts.Env {
		args = append(args, "--setenv", key, value)
	}

	// Add seccomp profile if specified
	if opts.SeccompProfile != "" {
		args = append(args, "--seccomp", opts.SeccompProfile)
	}

	args = append(args, "--chdir", opts.Workdir)
	args = append(args, opts.Cmd...)

	return args
}