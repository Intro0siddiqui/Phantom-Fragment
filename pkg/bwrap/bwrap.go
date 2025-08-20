package bwrap

import (
	"fmt"
)

// Options for the bubblewrap sandbox.

type Options struct {
	Workdir string
	Binds   []string
	Env     map[string]string
	Cmd     []string
	MemoryLimitMB int // Memory limit in MB
	CPULimitCores int // CPU limit in number of cores (conceptual for bwrap)
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

	// bwrap does not have a direct --cpu-limit flag. CPU limiting typically involves cgroups.
	// This is a placeholder for future cgroup integration or a more advanced bwrap feature.
	// if opts.CPULimitCores > 0 {
	// 	args = append(args, "--cpu-limit", fmt.Sprintf("%d", opts.CPULimitCores))
	// }

	for _, bind := range opts.Binds {
		args = append(args, "--bind", bind)
	}

	for key, value := range opts.Env {
		args = append(args, "--setenv", key, value)
	}

	args = append(args, "--chdir", opts.Workdir)
	args = append(args, opts.Cmd...)

	return args
}