package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/phantom-fragment/phantom-fragment/pkg/driver"
)

// NewDestroyCommand creates the destroy command
func NewDestroyCommand() *cobra.Command {
	var force bool
	var all bool

	cmd := &cobra.Command{
		Use:   "destroy [container-id]",
		Short: "Destroy a sandbox container",
		Long: `Destroy a sandbox container and clean up all associated resources.

This command stops and removes containers created with 'create'. It can
also clean up containers by ID or destroy all containers when using --all.

Examples:
  aisbx destroy abc123               # Destroy specific container
  aisbx destroy --all               # Destroy all containers
  aisbx destroy --force abc123      # Force destroy even if busy`,
		Args: func(cmd *cobra.Command, args []string) error {
			if all {
				return nil
			}
			if len(args) == 0 {
				return fmt.Errorf("container ID is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var containers []string

			if all {
				// Get all containers - for Phase 1, we'll use a simple approach
				containers = []string{} // TODO: Implement container listing
				fmt.Println("Destroying all containers...")
			} else {
				containers = args
			}

			// Initialize driver (use default for now)
			drv, err := driver.New("bwrap")
			if err != nil {
				return fmt.Errorf("failed to initialize driver: %w", err)
			}

			ctx := context.Background()
			successCount := 0
			errorCount := 0

			for _, containerID := range containers {
				if containerID == "" {
					continue
				}

				fmt.Printf("Destroying container: %s\n", containerID)

				if err := drv.Destroy(ctx, containerID); err != nil {
					if force {
						fmt.Printf("Warning: failed to destroy %s: %v (continuing due to --force)\n", containerID, err)
						errorCount++
						continue
					}
					return fmt.Errorf("failed to destroy container %s: %w", containerID, err)
				}

				// Clean up metadata
				if err := cleanupContainerMetadata(containerID); err != nil {
					fmt.Printf("Warning: failed to clean up metadata for %s: %v\n", containerID, err)
				}

				successCount++
				fmt.Printf("✓ Container %s destroyed successfully\n", containerID)
			}

			if all && len(containers) == 0 {
				fmt.Println("No containers found to destroy")
			} else {
				fmt.Printf("\nSummary: %d destroyed, %d errors\n", successCount, errorCount)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "force destroy even if container is busy")
	cmd.Flags().BoolVar(&all, "all", false, "destroy all containers")

	return cmd
}

// cleanupContainerMetadata removes container metadata
func cleanupContainerMetadata(containerID string) error {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return err
	}

	containersDir := filepath.Join(cacheDir, "ai-sandbox", "containers")
	metadataFile := filepath.Join(containersDir, containerID+".json")

	if _, err := os.Stat(metadataFile); err == nil {
		return os.Remove(metadataFile)
	}

	return nil
}