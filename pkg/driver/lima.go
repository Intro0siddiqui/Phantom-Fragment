package driver

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"

	"github.com/phantom-fragment/phantom-fragment/pkg/types"
)

const (
	limaInstanceName = "phantom"
)

// LimaDriver implements the SandboxDriver interface using Lima (Linux virtual machines on macOS and Windows).
type LimaDriver struct{}

// NewLimaDriver creates a new Lima driver instance
func NewLimaDriver() *LimaDriver {
	return &LimaDriver{}
}

func (d *LimaDriver) Create(ctx context.Context, image, workdir string, binds []string, env map[string]string) (string, error) {
	// Check if the Lima instance is already running
	cmd := exec.CommandContext(ctx, "limactl", "list", "--json")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("could not check Lima instances: %w", err)
	}

	if !strings.Contains(out.String(), `"name":"`+limaInstanceName+`"`) {
		// Start a new Lima instance
		cmd = exec.CommandContext(ctx, "limactl", "start", "--name="+limaInstanceName, "docker.io/library/alpine:latest")
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("could not start Lima instance: %w", err)
		}
	}

	containerID := uuid.New().String()
	return containerID, nil
}

func (d *LimaDriver) Exec(ctx context.Context, container types.Container, cmdArgs []string, timeoutMs int, memoryLimitMB int, cpuLimitCores int) (int, string, string, error) {
	// Build the command to execute in the Lima VM
	limaCmd := []string{"shell", limaInstanceName, "--"}

	// Add environment variables
	for key, value := range container.Env {
		limaCmd = append(limaCmd, "export", fmt.Sprintf("%s=%s", key, value), "&&")
	}

	// Set the working directory
	if container.Workdir != "" {
		limaCmd = append(limaCmd, "cd", container.Workdir, "&&")
	}

	// Add the command to execute
	limaCmd = append(limaCmd, cmdArgs...)

	// Execute the command
	cmd := exec.CommandContext(ctx, "limactl", limaCmd...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), stdout.String(), stderr.String(), nil
		} else {
			return -1, "", "", fmt.Errorf("lima execution failed: %w", err)
		}
	}

	return 0, stdout.String(), stderr.String(), nil
}

func (d *LimaDriver) Destroy(ctx context.Context, containerID string) error {
	// Stop the Lima instance
	cmd := exec.CommandContext(ctx, "limactl", "stop", limaInstanceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not stop Lima instance: %w", err)
	}

	return nil
}
