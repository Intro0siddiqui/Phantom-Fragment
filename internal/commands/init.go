package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/you/ai-sandbox/internal/config"
	"github.com/you/ai-sandbox/internal/rootfs"
)

// NewInitCommand creates the init command
func NewInitCommand() *cobra.Command {
	var rootfsPath string
	var force bool
	var cacheDir string

	cmd := &cobra.Command{
		Use:   "init [flags]",
		Short: "Initialize AI Sandbox with rootfs",
		Long: `Initialize AI Sandbox by setting up the root filesystem and configuration.

This command extracts the Alpine Linux rootfs to your cache directory and creates
initial configuration files. It can also download rootfs tarballs if needed.

Examples:
  aisbx init                          # Use default Alpine rootfs
  aisbx init --rootfs ubuntu.tar.gz  # Use custom rootfs
  aisbx init --force                 # Re-extract even if exists`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize configuration
			cfg := config.DefaultConfig()
			
			// Determine cache directory
			if cacheDir == "" {
				userCacheDir, err := os.UserCacheDir()
				if err != nil {
					return fmt.Errorf("failed to get cache directory: %w", err)
				}
				cacheDir = filepath.Join(userCacheDir, "ai-sandbox")
			}

			// Ensure cache directory exists
			if err := os.MkdirAll(cacheDir, 0755); err != nil {
				return fmt.Errorf("failed to create cache directory: %w", err)
			}

			// Initialize rootfs
			manager := rootfs.NewManager(cacheDir)
			
			if rootfsPath == "" {
				rootfsPath = "alpine-minirootfs.tar.gz"
			}

			fmt.Printf("Initializing AI Sandbox...\n")
			fmt.Printf("Cache directory: %s\n", cacheDir)
			fmt.Printf("Rootfs source: %s\n", rootfsPath)

			if err := manager.Initialize(rootfsPath, force); err != nil {
				return fmt.Errorf("failed to initialize rootfs: %w", err)
			}

			// Create default profile
			profilePath := filepath.Join(cacheDir, "profiles", "default.yaml")
			if err := cfg.SaveProfile(profilePath); err != nil {
				return fmt.Errorf("failed to create default profile: %w", err)
			}

			fmt.Printf("✓ AI Sandbox initialized successfully!\n")
			fmt.Printf("✓ Rootfs extracted to: %s\n", filepath.Join(cacheDir, "images"))
			fmt.Printf("✓ Default profile created: %s\n", profilePath)

			return nil
		},
	}

	cmd.Flags().StringVar(&rootfsPath, "rootfs", "", "path to rootfs tarball")
	cmd.Flags().BoolVar(&force, "force", false, "force re-extraction even if rootfs exists")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "custom cache directory")

	return cmd
}