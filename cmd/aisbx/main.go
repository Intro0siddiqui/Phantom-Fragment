package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/you/ai-sandbox/internal/commands"
	"github.com/you/ai-sandbox/internal/config"
)

var (
	cfgFile   string
	verbose   bool
	quiet     bool
	configDir string
)

var rootCmd = &cobra.Command{
	Use:   "aisbx",
	Short: "AI Sandbox - LLM-native isolated runtime",
	Long: `AI Sandbox is a lightweight, LLM-native sandboxing environment
that provides secure, isolated execution for AI agents and tools.

It uses Alpine Linux rootfs with bubblewrap/chroot/Lima for
maximum security and cross-platform compatibility.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize configuration
		if err := config.Initialize(configDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing config: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.aisbx/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "quiet output")
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "configuration directory (default is $HOME/.aisbx)")

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