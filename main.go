package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/sourcegraph/jsonrpc2"

	"github.com/you/ai-sandbox/pkg/driver"
	"github.com/you/ai-sandbox/pkg/types"
)

var rootfs []byte

var containers = make(map[string]types.Container)
var sandboxDriver driver.SandboxDriver

const (
	// ErrorCodeContainerNotFound is a custom error code for when a container is not found.
	ErrorCodeContainerNotFound = -32000

	// Default resource limits
	DefaultMemoryLimitMB = 1024 // 1 GiB
	DefaultCPULimitCores = 2
)

// CreateParams defines the parameters for the "create" method.
type CreateParams struct {
	Image   string            `json:"image"`
	Workdir string            `json:"workdir"`
	Binds   []string          `json:"binds"`
	Env     map[string]string `json:"env"`
}

// CreateResult defines the result for the "create" method.

// CreateResult defines the result for the "create" method.
type CreateResult struct {
	ContainerID string `json:"container_id"`
}

// ExecParams defines the parameters for the "exec" method.

type ExecParams struct {
	ContainerID   string   `json:"container_id"`
	Cmd           []string `json:"cmd"`
	TimeoutMS     int      `json:"timeout_ms"`
	MemoryLimitMB int      `json:"memory_limit_mb,omitempty"`
	CPULimitCores int      `json:"cpu_limit_cores,omitempty"`
}

// ExecResult defines the result for the "exec" method.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// DestroyParams defines the parameters for the "destroy" method.

type DestroyParams struct {
	ContainerID string `json:"container_id"`
}

// handler is an empty struct that implements the JSON-RPC2 handler methods
type handler struct{}

// stdioReadWriteCloser implements io.ReadWriteCloser for stdin/stdout
type stdioReadWriteCloser struct{}

func (s *stdioReadWriteCloser) Read(p []byte) (n int, err error) {
	return os.Stdin.Read(p)
}

func (s *stdioReadWriteCloser) Write(p []byte) (n int, err error) {
	return os.Stdout.Write(p)
}

func (s *stdioReadWriteCloser) Close() error {
	return nil
}

func main() {
	fmt.Fprintf(os.Stderr, "Starting ai-sandbox...\n")
	// Ensure rootfs is extracted on first run
	if err := ensureRootfs(); err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting rootfs: %v\n", err)
		os.Exit(1)
	}

	// Initialize the appropriate sandbox driver based on the OS
	switch runtime.GOOS {
	case "linux", "android":
		sandboxDriver = driver.NewChrootDriver()
	case "darwin", "windows":
		sandboxDriver = driver.NewLimaDriver()
	default:
		fmt.Fprintf(os.Stderr, "Unsupported operating system: %s\n", runtime.GOOS)
		os.Exit(1)
	}

	h := &handler{}
	// Create a ReadWriteCloser from stdin/stdout
	rwc := &stdioReadWriteCloser{}
	stream := jsonrpc2.NewBufferedStream(rwc, jsonrpc2.VSCodeObjectCodec{})
	conn := jsonrpc2.NewConn(context.Background(), stream, jsonrpc2.HandlerWithError(h.Handle))
	<-conn.DisconnectNotify()
}

func (h *handler) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (interface{}, error) {
	fmt.Fprintf(os.Stderr, "Received request: %s\n", req.Method)
	switch req.Method {
	case "create":
		return h.handleCreate(ctx, conn, req)
	case "exec":
		return h.handleExec(ctx, conn, req)
	case "destroy":
		return h.handleDestroy(ctx, conn, req)
	default:
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeMethodNotFound,
			Message: "method not found",
		}
	}
}

func (h *handler) handleCreate(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (interface{}, error) {
	var params CreateParams
	if err := json.Unmarshal(*req.Params, &params); err != nil {
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInvalidParams,
			Message: "invalid params",
		}
	}

	containerID, err := sandboxDriver.Create(ctx, params.Image, params.Workdir, params.Binds, params.Env)
	if err != nil {
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInternalError,
			Message: fmt.Sprintf("failed to create container: %v", err),
		}
	}

	containers[containerID] = types.Container{
		ID:      containerID,
		Workdir: params.Workdir,
		Binds:   params.Binds,
		Env:     params.Env,
	}

	return &CreateResult{ContainerID: containerID}, nil
}

func (h *handler) handleExec(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (interface{}, error) {
	var params ExecParams
	if err := json.Unmarshal(*req.Params, &params); err != nil {
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInvalidParams,
			Message: "invalid params",
		}
	}

	// Apply default resource limits if not provided
	if params.MemoryLimitMB == 0 {
		params.MemoryLimitMB = DefaultMemoryLimitMB
	}
	if params.CPULimitCores == 0 {
		params.CPULimitCores = DefaultCPULimitCores
	}

	container, ok := containers[params.ContainerID]
	if !ok {
		return nil, &jsonrpc2.Error{
			Code:    ErrorCodeContainerNotFound,
			Message: fmt.Sprintf("container_id %s not found", params.ContainerID),
		}
	}

	exitCode, stdout, stderr, err := sandboxDriver.Exec(ctx, container, params.Cmd, params.TimeoutMS, params.MemoryLimitMB, params.CPULimitCores)
	if err != nil {
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInternalError,
			Message: fmt.Sprintf("sandbox execution failed: %v", err),
		}
	}

	return &ExecResult{ExitCode: exitCode, Stdout: stdout, Stderr: stderr}, nil
}

func (h *handler) handleDestroy(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (interface{}, error) {
	var params DestroyParams
	if err := json.Unmarshal(*req.Params, &params); err != nil {
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInvalidParams,
			Message: "invalid params",
		}
	}

	containerID := params.ContainerID
	if _, ok := containers[containerID]; !ok {
		return nil, &jsonrpc2.Error{
			Code:    ErrorCodeContainerNotFound,
			Message: fmt.Sprintf("container_id %s not found", containerID),
		}
	}

	if err := sandboxDriver.Destroy(ctx, containerID); err != nil {
		return nil, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInternalError,
			Message: fmt.Sprintf("failed to destroy container: %v", err),
		}
	}

	delete(containers, containerID)

	return nil, nil
}
