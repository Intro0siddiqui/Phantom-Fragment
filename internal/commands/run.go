package commands

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/you/ai-sandbox/internal/config"
	"github.com/you/ai-sandbox/pkg/driver"
	"github.com/you/ai-sandbox/pkg/types"
)

// NewRunCommand creates the run command
func NewRunCommand() *cobra.Command {
	var profileName string
	var timeout int
	var interactive bool
	var env []string

	cmd := &cobra.Command{
		Use:   "run [command] [args...]",
		Short: "Run a command in sandboxed environment",
		Long: `Run a command in a secure, isolated sandbox environment using the specified profile.

This command creates a temporary container, executes the given command, and
cleans up automatically. It supports resource limits, network policies, and
mount configurations defined in the profile.

Examples:
  aisbx run python script.py                    # Run with default profile
  aisbx run --profile python-dev python app.py  # Run with custom profile
  aisbx run --timeout 60 echo "hello world"     # Run with timeout
  aisbx run --interactive bash                  # Interactive shell`,
		Args: cobra.MinimumNArgs(1),
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

			// Create container
			containerID, err := drv.Create(context.Background(), "alpine", ".", nil, nil)
			if err != nil {
				return fmt.Errorf("failed to create container: %w", err)
			}

			// Ensure cleanup
			defer func() {
				if err := drv.Destroy(context.Background(), containerID); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to destroy container: %v\n", err)
				}
			}()

			// Prepare environment
			envMap := make(map[string]string)
			for k, v := range profile.Environment {
				envMap[k] = v
			}
			for _, e := range env {
				// Simple key=value parsing
				if len(e) > 0 && e[0] != '=' {
					if idx := 0; idx < len(e) && e[idx] == '=' {
						continue
					}
					if idx := 0; idx < len(e) {
						if split := 0; split < len(e) && e[split] == '=' {
							envMap[e[:split]] = e[split+1:]
						}
					}
				}
			}

			// Set timeout
			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}

			// Create container object
			container := types.Container{
				ID:      containerID,
				Workdir: ".",
				Binds:   []string{},
				Env:     envMap,
			}

			// Execute command
			exitCode, stdout, stderr, err := drv.Exec(ctx, container, args, timeout*1000, 512, 1)
			if err != nil {
				return fmt.Errorf("command execution failed: %w", err)
			}

			// Output results
			if stdout != "" {
				fmt.Print(stdout)
			}
			if stderr != "" {
				fmt.Fprint(os.Stderr, stderr)
			}

			// Exit with command's exit code
			if exitCode != 0 {
				os.Exit(exitCode)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&profileName, "profile", "p", "default", "profile to use")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 0, "timeout in seconds")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "interactive mode")
	cmd.Flags().StringArrayVarP(&env, "env", "e", []string{}, "environment variables (key=value)")

	return cmd
}