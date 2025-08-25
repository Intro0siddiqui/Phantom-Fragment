package driver

import (
	"context"

	"github.com/phantom-fragment/phantom-fragment/pkg/types"
)

// SandboxDriver is the interface for creating, executing, and destroying sandboxed environments.
type SandboxDriver interface {
	// Create creates a new container and returns its ID.
	Create(ctx context.Context, image, workdir string, binds []string, env map[string]string) (string, error)
	// Exec executes a command in a container.
	Exec(ctx context.Context, container types.Container, cmd []string, timeoutMs int, memoryLimitMB int, cpuLimitCores int) (int, string, string, error)
	// Destroy destroys a container.
	Destroy(ctx context.Context, containerID string) error
}
