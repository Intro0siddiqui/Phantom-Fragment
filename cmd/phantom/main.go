package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/phantom-fragment/phantom-fragment/internal/commands"
	"github.com/phantom-fragment/phantom-fragment/internal/config"
)

var (
	cfgFile   string
	verbose   bool
	quiet     bool
	configDir string
)

var rootCmd = &cobra.Command{
	Use:   "phantom",
	Short: "Phantom Fragment - Next-generation container alternative for LLM agents",
	Long: `Phantom Fragment is a revolutionary, performance-by-design sandbox
environment engineered specifically for LLM agents and AI-assisted development.

Unlike Docker's layered complexity, Phantom Fragment delivers unfair-advantage
performance with kernel-native optimization, sub-100ms startup times, and
zero-overhead security using Alpine Linux rootfs with specialized fragments.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize configuration
		if err := config.Initialize(configDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing config: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.phantom/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "quiet output")
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "configuration directory (default is $HOME/.phantom)")

	// Add subcommands
	rootCmd.AddCommand(commands.NewInitCommand())
	rootCmd.AddCommand(commands.NewRunCommand())
	rootCmd.AddCommand(commands.NewCreateCommand())
	rootCmd.AddCommand(commands.NewDestroyCommand())
	rootCmd.AddCommand(commands.NewProfileCommand())
	rootCmd.AddCommand(commands.NewLogsCommand())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}