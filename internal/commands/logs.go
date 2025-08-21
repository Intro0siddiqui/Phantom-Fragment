package commands

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// NewLogsCommand creates the logs command
func NewLogsCommand() *cobra.Command {
	var follow bool
	var tail int
	var since string

	cmd := &cobra.Command{
		Use:   "logs [container-id]",
		Short: "Show container logs",
		Long: `Show logs from a sandbox container.

This command displays logs from containers created with 'create'.
It supports following logs in real-time and filtering by time.

Examples:
  aisbx logs abc123           # Show all logs
  aisbx logs --follow abc123  # Follow logs in real-time
  aisbx logs --tail 50 abc123 # Show last 50 lines
  aisbx logs --since 1h abc123 # Show logs since 1 hour ago`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			containerID := args[0]
			return showContainerLogs(containerID, follow, tail, since)
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow log output")
	cmd.Flags().IntVar(&tail, "tail", 0, "number of lines to show from end")
	cmd.Flags().StringVar(&since, "since", "", "show logs since timestamp (e.g., 1h, 2024-01-01)")

	return cmd
}

// showContainerLogs displays container logs
func showContainerLogs(containerID string, follow bool, tail int, since string) error {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("failed to get cache directory: %w", err)
	}

	logsDir := filepath.Join(cacheDir, "ai-sandbox", "logs")
	logFile := filepath.Join(logsDir, containerID+".log")

	// Check if log file exists
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		return fmt.Errorf("no logs found for container %s", containerID)
	}

	file, err := os.Open(logFile)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// Handle tail option
	if tail > 0 {
		return tailLogs(file, tail)
	}

	// Handle since option
	if since != "" {
		return filterLogsByTime(file, since)
	}

	// Handle follow option
	if follow {
		return followLogs(file)
	}

	// Default: show all logs
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

	return scanner.Err()
}

// tailLogs shows the last N lines from the log file
func tailLogs(file *os.File, lines int) error {
	// Simple implementation for Phase 1
	// In later phases, we'll use more efficient tailing
	scanner := bufio.NewScanner(file)
	var logLines []string

	for scanner.Scan() {
		logLines = append(logLines, scanner.Text())
		if len(logLines) > lines {
			logLines = logLines[1:]
		}
	}

	for _, line := range logLines {
		fmt.Println(line)
	}

	return scanner.Err()
}

// filterLogsByTime filters logs based on time criteria
func filterLogsByTime(file *os.File, since string) error {
	// Parse since parameter
	var sinceTime time.Time
	if strings.HasSuffix(since, "h") {
		durationStr := strings.TrimSuffix(since, "h")
		duration, err := time.ParseDuration(durationStr + "h")
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		sinceTime = time.Now().Add(-duration)
	} else if strings.HasSuffix(since, "m") {
		durationStr := strings.TrimSuffix(since, "m")
		duration, err := time.ParseDuration(durationStr + "m")
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		sinceTime = time.Now().Add(-duration)
	} else {
		// Try to parse as date
		parsedTime, err := time.Parse("2006-01-02", since)
		if err != nil {
			return fmt.Errorf("invalid time format: %w", err)
		}
		sinceTime = parsedTime
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Simple timestamp parsing - in Phase 1, we'll use basic string matching
		// Later phases will use structured logging with proper timestamps
		if strings.Contains(line, sinceTime.Format("2006-01-02")) {
			fmt.Println(line)
		}
	}

	return scanner.Err()
}

// followLogs follows log output in real-time
func followLogs(file *os.File) error {
	// Simple implementation for Phase 1
	// In later phases, we'll use proper file tailing
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

	// Continue watching for new lines
	// This is a basic implementation - Phase 2 will use proper file watching
	for {
		if _, err := file.Seek(0, 1); err != nil {
			break
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
		time.Sleep(1 * time.Second)
	}

	return nil
}