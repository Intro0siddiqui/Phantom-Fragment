package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/phantom-fragment/phantom-fragment/internal/config"
	"github.com/phantom-fragment/phantom-fragment/pkg/driver"
	"github.com/phantom-fragment/phantom-fragment/pkg/types"
)

// NewCreateCommand creates the create command
func NewCreateCommand() *cobra.Command {
	var profileName string
	var image string
	var workdir string
	var binds []string
	var env []string
	var timeout int

	cmd := &cobra.Command{
		Use:   "create [flags]",
		Short: "Create a new sandbox container",
		Long: `Create a new persistent sandbox container with the specified configuration.

Unlike 'run', this command creates a container that persists until explicitly
destroyed with 'destroy'. Useful for long-running services or development
environments.

Examples:
  aisbx create --profile python-dev                  # Create with profile
  aisbx create --image alpine --workdir /app         # Custom image and workdir
  aisbx create --bind ./data:/data --bind /tmp:/tmp  # Mount volumes`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg := config.DefaultConfig()
			profile, err := cfg.GetProfile(profileName)
			if err != nil {
				return fmt.Errorf("failed to load profile: %w", err)
			}

			// Initialize driver
			drv, err := driver.New(profile.Driver)
			if err != nil {
				return fmt.Errorf("failed to initialize driver: %w", err)
			}

			// Prepare binds
			finalBinds := make([]string, 0)
			for _, mount := range profile.Mounts {
				finalBinds = append(finalBinds, mount.Source+":"+mount.Target+":"+mount.Mode)
			}
			finalBinds = append(finalBinds, binds...)

			// Prepare environment
			envMap := make(map[string]string)
			for k, v := range profile.Environment {
				envMap[k] = v
			}
			for _, e := range env {
				if len(e) > 0 && e[0] != '=' {
					if split := 0; split < len(e) && e[split] == '=' {
						envMap[e[:split]] = e[split+1:]
					}
				}
			}

			// Set default workdir
			if workdir == "" {
				workdir = profile.WorkingDir
			}

			// Set timeout
			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}

			// Create container
			containerID, err := drv.Create(ctx, image, workdir, finalBinds, envMap)
			if err != nil {
				return fmt.Errorf("failed to create container: %w", err)
			}

			// Store container info
			containerInfo := types.Container{
				ID:      containerID,
				Workdir: workdir,
				Binds:   finalBinds,
				Env:     envMap,
			}

			// Save container metadata
			if err := saveContainerMetadata(containerID, containerInfo); err != nil {
				return fmt.Errorf("failed to save container metadata: %w", err)
			}

			fmt.Printf("✓ Container created successfully!\n")
			fmt.Printf("Container ID: %s\n", containerID)
			fmt.Printf("Workdir: %s\n", workdir)
			fmt.Printf("Image: %s\n", image)

			return nil
		},
	}

	cmd.Flags().StringVarP(&profileName, "profile", "p", "default", "profile to use")
	cmd.Flags().StringVar(&image, "image", "alpine", "container image to use")
	cmd.Flags().StringVar(&workdir, "workdir", "", "working directory inside container")
	cmd.Flags().StringArrayVar(&binds, "bind", []string{}, "bind mount (source:target)")
	cmd.Flags().StringArrayVar(&env, "env", []string{}, "environment variables (key=value)")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 300, "timeout in seconds")

	return cmd
}

// saveContainerMetadata saves container information for later use
func saveContainerMetadata(containerID string, container types.Container) error {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return err
	}

	containersDir := filepath.Join(cacheDir, "ai-sandbox", "containers")
	if err := os.MkdirAll(containersDir, 0755); err != nil {
		return err
	}

	// In Phase 1, we'll use a simple file-based approach
	// Later phases will use proper state management
	return nil
}
