package driver

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/google/uuid"

	"github.com/you/ai-sandbox/pkg/bwrap"
	"github.com/you/ai-sandbox/pkg/types"
)

type ChrootDriver struct {
	// containers map[string]Container // This will be managed by the main package
}

func NewChrootDriver() *ChrootDriver {
	return &ChrootDriver{}
}

func (d *ChrootDriver) Create(ctx context.Context, image, workdir string, binds []string, env map[string]string) (string, error) {
	// In a real scenario, this might involve setting up the rootfs for chroot
	// For now, we just generate a container ID and assume the rootfs is handled externally.
	containerID := uuid.New().String()
	// The actual container state (workdir, binds, env) will be stored in the main package's map.
	return containerID, nil
}

func (d *ChrootDriver) Exec(ctx context.Context, container types.Container, cmdArgs []string, timeoutMs int, memoryLimitMB int, cpuLimitCores int) (int, string, string, error) {
	opts := bwrap.Options{
		Workdir: container.Workdir,
		Binds:   container.Binds,
		Env:     container.Env,
		Cmd:     cmdArgs,
		MemoryLimitMB: memoryLimitMB,
		CPULimitCores: cpuLimitCores,
	}

	args := bwrap.BuildArgs(opts)

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), stdout.String(), stderr.String(), nil
		} else {
			return -1, "", "", fmt.Errorf("bwrap execution failed: %w", err)
		}
	}

	return 0, stdout.String(), stderr.String(), nil
}

func (d *ChrootDriver) Destroy(ctx context.Context, containerID string) error {
	// No specific action needed here for chroot, as it's ephemeral.
	// The main package will remove the container from its map.
	return nil
}