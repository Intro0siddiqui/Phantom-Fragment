package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/phantom-fragment/phantom-fragment/internal/config"
)

// NewProfileCommand creates the profile command
func NewProfileCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage sandbox profiles",
		Long: `Manage configuration profiles for sandbox environments.

Profiles define resource limits, security settings, network policies,
and mount configurations for sandbox containers.

Examples:
  aisbx profile list          # List available profiles
  aisbx profile show default  # Show profile details
  aisbx profile create myapp  # Create new profile`,
	}

	cmd.AddCommand(newProfileListCommand())
	cmd.AddCommand(newProfileShowCommand())
	cmd.AddCommand(newProfileCreateCommand())

	return cmd
}

func newProfileListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available profiles",
		Long:  "List all available sandbox configuration profiles.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tDRIVER\tCPU\tMEMORY\tNETWORK")

			for _, profile := range cfg.Profiles {
				network := "disabled"
				if profile.Network.Enabled {
					network = "enabled"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					profile.Name, profile.Driver, profile.CPU, profile.Memory, network)
			}

			w.Flush()
			return nil
		},
	}
}

func newProfileShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show [profile-name]",
		Short: "Show profile details",
		Long:  "Display detailed information about a specific profile.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()
			profile, err := cfg.GetProfile(args[0])
			if err != nil {
				return err
			}

			fmt.Printf("Profile: %s\n", profile.Name)
			fmt.Printf("Driver: %s\n", profile.Driver)
			fmt.Printf("CPU: %s\n", profile.CPU)
			fmt.Printf("Memory: %s\n", profile.Memory)
			fmt.Printf("Working Directory: %s\n", profile.WorkingDir)
			fmt.Printf("Timeout: %d seconds\n", profile.Timeout)
			fmt.Printf("Network: %v\n", profile.Network.Enabled)

			if len(profile.Network.Allow) > 0 {
				fmt.Printf("Network Allow: %v\n", profile.Network.Allow)
			}
			if len(profile.Network.Deny) > 0 {
				fmt.Printf("Network Deny: %v\n", profile.Network.Deny)
			}

			if len(profile.Mounts) > 0 {
				fmt.Printf("\nMounts:\n")
				for _, mount := range profile.Mounts {
					fmt.Printf("  %s -> %s (%s)\n", mount.Source, mount.Target, mount.Mode)
				}
			}

			if len(profile.Environment) > 0 {
				fmt.Printf("\nEnvironment:\n")
				for k, v := range profile.Environment {
					fmt.Printf("  %s=%s\n", k, v)
				}
			}

			return nil
		},
	}
}

func newProfileCreateCommand() *cobra.Command {
	var from string

	cmd := &cobra.Command{
		Use:   "create [profile-name]",
		Short: "Create a new profile",
		Long: `Create a new sandbox profile from scratch or based on an existing one.

This command creates a new YAML profile file that can be customized
for specific use cases.

Examples:
  aisbx profile create myapp          # Create from scratch
  aisbx profile create myapp --from default  # Copy from existing`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profileName := args[0]
			cfg := config.DefaultConfig()

			var baseProfile *config.Profile
			if from != "" {
				var err error
				baseProfile, err = cfg.GetProfile(from)
				if err != nil {
					return fmt.Errorf("failed to load base profile: %w", err)
				}
			} else {
				baseProfile = &cfg.Profiles[0] // Use default as base
			}

			// Create new profile
			newProfile := *baseProfile
			newProfile.Name = profileName

			// Save profile to file
			cacheDir, err := os.UserCacheDir()
			if err != nil {
				return fmt.Errorf("failed to get cache directory: %w", err)
			}

			profileDir := filepath.Join(cacheDir, "ai-sandbox", "profiles")
			if err := os.MkdirAll(profileDir, 0755); err != nil {
				return fmt.Errorf("failed to create profile directory: %w", err)
			}

			profilePath := filepath.Join(profileDir, profileName+".yaml")
			if _, err := os.Stat(profilePath); err == nil {
				return fmt.Errorf("profile '%s' already exists", profileName)
			}

			// Create config with just the new profile
			newConfig := &config.Config{
				Profiles: []config.Profile{newProfile},
			}

			if err := newConfig.SaveProfile(profilePath); err != nil {
				return fmt.Errorf("failed to save profile: %w", err)
			}

			fmt.Printf("✓ Profile '%s' created successfully\n", profileName)
			fmt.Printf("Profile file: %s\n", profilePath)
			fmt.Printf("Edit this file to customize the profile\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&from, "from", "", "base profile to copy from")

	return cmd
}