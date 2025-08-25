package driver

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/google/uuid"

	"github.com/phantom-fragment/phantom-fragment/internal/config"
	"github.com/phantom-fragment/phantom-fragment/internal/metrics"
	"github.com/phantom-fragment/phantom-fragment/internal/security/audit"
	"github.com/phantom-fragment/phantom-fragment/internal/security/cgroups"
	"github.com/phantom-fragment/phantom-fragment/internal/security/network"
	"github.com/phantom-fragment/phantom-fragment/internal/security/seccomp"
	"github.com/phantom-fragment/phantom-fragment/pkg/bwrap"
	"github.com/phantom-fragment/phantom-fragment/pkg/types"
)

type ChrootDriver struct {
	logger  *audit.Logger
	metrics *metrics.Collector
	seccomp *seccomp.Monitor
}

func NewChrootDriver() *ChrootDriver {
	cfg := config.DefaultConfig()
	seccompMonitor, err := seccomp.NewMonitor(cfg)
	if err != nil {
		// Fallback to basic logger if seccomp fails
		seccompMonitor = &seccomp.Monitor{}
	}

	driver := &ChrootDriver{
		logger:  audit.NewLogger("/var/log/sandbox-security.log"),
		metrics: metrics.NewCollector(),
		seccomp: seccompMonitor,
	}

	// Set up metrics and logger for seccomp monitoring
	seccompMonitor.SetMetricsCollector(driver.metrics)
	seccompMonitor.SetLogger(driver.logger)

	return driver
}

func (d *ChrootDriver) Create(ctx context.Context, image, workdir string, binds []string, env map[string]string) (string, error) {
	// In a real scenario, this might involve setting up the rootfs for chroot
	// For now, we just generate a container ID and assume the rootfs is handled externally.
	containerID := uuid.New().String()

	// Log container creation
	d.logger.LogContainerCreation(containerID, map[string]interface{}{
		"image":   image,
		"workdir": workdir,
		"binds":   binds,
		"env":     env,
	})

	// The actual container state (workdir, binds, env) will be stored in the main package's map.
	return containerID, nil
}

func (d *ChrootDriver) Exec(ctx context.Context, container types.Container, cmdArgs []string, timeoutMs int, memoryLimitMB int, cpuLimitCores int) (int, string, string, error) {
	startTime := time.Now()

	// Create cgroup for the container
	cgroupManager := cgroups.NewManager(container.ID)
	cgroupManager.SetMetricsCollector(d.metrics)
	if err := cgroupManager.Create(); err != nil {
		return -1, "", "", fmt.Errorf("failed to create cgroup: %w", err)
	}
	defer cgroupManager.Destroy()

	// Set resource limits
	if memoryLimitMB > 0 {
		if err := cgroupManager.SetMemoryLimit(memoryLimitMB); err != nil {
			return -1, "", "", fmt.Errorf("failed to set memory limit: %w", err)
		}
	}

	if cpuLimitCores > 0 {
		if err := cgroupManager.SetCPULimit(cpuLimitCores); err != nil {
			return -1, "", "", fmt.Errorf("failed to set CPU limit: %w", err)
		}
	}

	// Apply network policy
	networkPolicy := network.NoNetworkPolicy()
	if err := networkPolicy.Apply(container.ID); err != nil {
		// Record network violation
		d.metrics.RecordNetworkViolation(container.ID, "policy_application_failed")
		return -1, "", "", fmt.Errorf("failed to apply network policy: %w", err)
	}

	// Log container execution
	d.logger.LogContainerExecution(container.ID, map[string]interface{}{
		"cmd":             cmdArgs,
		"memory_limit_mb": memoryLimitMB,
		"cpu_limit_cores": cpuLimitCores,
		"seccomp_profile": container.SeccompProfile,
	})

	opts := bwrap.Options{
		Workdir:        container.Workdir,
		Binds:          container.Binds,
		Env:            container.Env,
		Cmd:            cmdArgs,
		MemoryLimitMB:  memoryLimitMB,
		CPULimitCores:  cpuLimitCores,
		SeccompProfile: container.SeccompProfile,
		ContainerID:    container.ID,
	}

	args := bwrap.BuildArgs(opts)

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Monitor for seccomp violations if a seccomp profile is being used
	if container.SeccompProfile != "" {
		d.seccomp.MonitorProcess(ctx, cmd, container.ID, container.SeccompProfile)
	}

	// Add process to cgroup
	if err := cgroupManager.AddProcess(cmd.Process.Pid); err != nil {
		return -1, "", "", fmt.Errorf("failed to add process to cgroup: %w", err)
	}

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Record run duration
			d.metrics.RecordRunDuration(container.ID, time.Since(startTime).Seconds())
			return exitErr.ExitCode(), stdout.String(), stderr.String(), nil
		} else {
			return -1, "", "", fmt.Errorf("bwrap execution failed: %w", err)
		}
	}

	// Record run duration
	d.metrics.RecordRunDuration(container.ID, time.Since(startTime).Seconds())

	return 0, stdout.String(), stderr.String(), nil
}

func (d *ChrootDriver) Destroy(ctx context.Context, containerID string) error {
	// Log container destruction
	d.logger.LogContainerDestruction(containerID, map[string]interface{}{})

	// No specific action needed here for chroot, as it's ephemeral.
	// The main package will remove the container from its map.
	return nil
}
