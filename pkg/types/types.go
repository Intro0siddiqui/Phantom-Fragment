package types

import "time"

// Container represents a sandboxed container instance
type Container struct {
	ID            string
	Workdir       string
	Binds         []string
	Env           map[string]string
	SeccompProfile string

	// Extended fields for zygote spawner v3
	PID        int
	Profile    string
	CreatedAt  time.Time
	Mode       ExecutionMode
	ZygoteID   int
	WasmInstance interface{} // Will be WasmContainer in the fragments package
}

// Destroy performs best-effort cleanup of the container's resources.
// In this minimal implementation, it is a no-op to avoid coupling the types
// package to driver or platform specifics. Higher layers should perform the
// actual teardown and can still call this safely.
func (c *Container) Destroy() error {
    return nil
}

// Execution modes for containers
type ExecutionMode string

const (
	ExecutionModeNamespace ExecutionMode = "namespace"
	ExecutionModeWasm      ExecutionMode = "wasm"
)

// Pool types for different execution modes
type PoolType string

const (
	PoolTypeNamespace PoolType = "namespace"
	PoolTypeWasm      PoolType = "wasm"
)

// SpawnRequest represents a request to spawn a new container
type SpawnRequest struct {
	Profile     string
	Command     []string
	Environment map[string]string
	Workdir     string
	PoolType    PoolType
	Timeout     time.Duration
}
