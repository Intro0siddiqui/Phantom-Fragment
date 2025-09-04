package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/phantom-fragment/phantom-fragment/internal/config"
	"github.com/phantom-fragment/phantom-fragment/internal/mcp/server"
	"github.com/phantom-fragment/phantom-fragment/internal/mcp/types"
	"github.com/phantom-fragment/phantom-fragment/pkg/driver"
	pkgtypes "github.com/phantom-fragment/phantom-fragment/pkg/types"
)

func main() {
	transport := flag.String("transport", "stdio", "Transport mode: stdio or http")
	port := flag.String("port", "8080", "HTTP port (only for http transport)")
	flag.Parse()

	// Create MCP server instance
	srv := server.NewServer()

	// Register built-in tools with full CLI integration
	registerTools(srv)

	// Start appropriate transport
	switch strings.ToLower(*transport) {
	case "stdio":
		startStdioServer(srv)
	case "http":
		startHTTPServer(srv, *port)
	default:
		log.Fatalf("Unsupported transport: %s", *transport)
	}
}

func registerTools(srv *server.Server) {
	// Tool: phantom-run - Execute code in sandbox (COMPLETE IMPLEMENTATION)
	srv.RegisterTool("phantom-run", executeRunCommand)

	// Tool: phantom-build - Build sandbox environment (COMPLETE IMPLEMENTATION)
	srv.RegisterTool("phantom-build", executeBuildCommand)

	// Tool: phantom-profile-list - List available security profiles (COMPLETE IMPLEMENTATION)
	srv.RegisterTool("phantom-profile-list", executeProfileListCommand)
}

// executeRunCommand implements the same security-validated logic as supervisor service
func executeRunCommand(args map[string]interface{}) (*types.ToolResult, error) {
	// Security validation - same as supervisor service
	if err := validateToolArgs("run", args); err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Security validation failed: %v", err)},
			},
			IsError: true,
		}, nil
	}

	command, ok := args["command"].([]interface{})
	if !ok {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: "Error: command argument must be an array"},
			},
			IsError: true,
		}, nil
	}

	// Convert interface{} slice to string slice
	cmdArgs := make([]string, len(command))
	for i, arg := range command {
		if argStr, ok := arg.(string); ok {
			cmdArgs[i] = argStr
		} else {
			return &types.ToolResult{
				Content: []types.ToolResultContent{
					{Type: "text", Text: "Error: all command arguments must be strings"},
				},
				IsError: true,
			}, nil
		}
	}

	// Get profile name (default to "default")
	profileName := "default"
	if profile, ok := args["profile"].(string); ok {
		profileName = profile
	}

	// Load configuration
	cfg := config.DefaultConfig()
	profile, err := cfg.GetProfile(profileName)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error loading profile: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Initialize driver
	drv, err := driver.New(profile.Driver)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error initializing driver: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Create container
	containerID, err := drv.Create(context.Background(), "alpine", ".", nil, nil)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error creating container: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Ensure cleanup
	defer func() {
		if err := drv.Destroy(context.Background(), containerID); err != nil {
			log.Printf("Warning: failed to cleanup container: %v", err)
		}
	}()

	// Create container object
	container := pkgtypes.Container{
		ID:      containerID,
		Workdir: ".",
		Binds:   []string{},
		Env:     profile.Environment,
	}

	// Execute command with timeout
	timeout := 300 // 5 minutes default
	if timeoutVal, ok := args["timeout"].(float64); ok {
		timeout = int(timeoutVal)
	}

	exitCode, stdout, stderr, err := drv.Exec(context.Background(), container, cmdArgs, timeout*1000, 512, 1)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Execution error: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Prepare result content
	result := fmt.Sprintf("Exit code: %d\n", exitCode)
	if stdout != "" {
		result += fmt.Sprintf("Stdout:\n%s\n", stdout)
	}
	if stderr != "" {
		result += fmt.Sprintf("Stderr:\n%s\n", stderr)
	}

	return &types.ToolResult{
		Content: []types.ToolResultContent{
			{Type: "text", Text: result},
		},
		IsError: exitCode != 0,
	}, nil
}

// executeBuildCommand implements container creation functionality
func executeBuildCommand(args map[string]interface{}) (*types.ToolResult, error) {
	// Security validation
	if err := validateToolArgs("build", args); err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Security validation failed: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Get profile name (default to "default")
	profileName := "default"
	if profile, ok := args["profile"].(string); ok {
		profileName = profile
	}

	// Get image (default to "alpine")
	image := "alpine"
	if img, ok := args["image"].(string); ok {
		image = img
	}

	// Get workdir
	workdir := "."
	if wd, ok := args["workdir"].(string); ok {
		workdir = wd
	}

	// Load configuration
	cfg := config.DefaultConfig()
	profile, err := cfg.GetProfile(profileName)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error loading profile: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Initialize driver
	drv, err := driver.New(profile.Driver)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error initializing driver: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Prepare binds
	finalBinds := make([]string, 0)
	for _, mount := range profile.Mounts {
		finalBinds = append(finalBinds, mount.Source+":"+mount.Target+":"+mount.Mode)
	}

	// Create container
	containerID, err := drv.Create(context.Background(), image, workdir, finalBinds, profile.Environment)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error creating container: %v", err)},
			},
			IsError: true,
		}, nil
	}

	result := fmt.Sprintf("✓ Container created successfully!\nContainer ID: %s\nWorkdir: %s\nImage: %s", containerID, workdir, image)

	return &types.ToolResult{
		Content: []types.ToolResultContent{
			{Type: "text", Text: result},
		},
		IsError: false,
	}, nil
}

// executeProfileListCommand implements profile listing functionality
func executeProfileListCommand(args map[string]interface{}) (*types.ToolResult, error) {
	// Security validation
	if err := validateToolArgs("profile-list", args); err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Security validation failed: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Load configuration
	cfg := config.DefaultConfig()

	// Build profile list output
	var result strings.Builder
	result.WriteString("Available Profiles:\n")
	result.WriteString("NAME\tDRIVER\tCPU\tMEMORY\tNETWORK\n")

	for _, profile := range cfg.Profiles {
		network := "disabled"
		if profile.Network.Enabled {
			network = "enabled"
		}
		result.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n",
			profile.Name, profile.Driver, profile.CPU, profile.Memory, network))
	}

	return &types.ToolResult{
		Content: []types.ToolResultContent{
			{Type: "text", Text: result.String()},
		},
		IsError: false,
	}, nil
}

// validateToolArgs implements the same security validation as supervisor service
func validateToolArgs(toolType string, args map[string]interface{}) error {
	// Common validations
	if workdir, ok := args["workdir"]; ok {
		if workdirStr, ok := workdir.(string); ok {
			if !isValidPath(workdirStr) {
				return fmt.Errorf("invalid workdir path: %s", workdirStr)
			}
		}
	}

	if profile, ok := args["profile"]; ok {
		if profileStr, ok := profile.(string); ok {
			if !isValidProfileName(profileStr) {
				return fmt.Errorf("invalid profile name: %s", profileStr)
			}
		}
	}

	// Tool-specific validations
	switch toolType {
	case "run":
		if command, ok := args["command"]; ok {
			if commandSlice, ok := command.([]interface{}); ok {
				for _, cmd := range commandSlice {
					if cmdStr, ok := cmd.(string); ok {
						if isDangerousCommand(cmdStr) {
							return fmt.Errorf("dangerous command blocked: %s", cmdStr)
						}
					}
				}
			}
		}
	}

	return nil
}

// isValidPath validates file paths to prevent directory traversal
func isValidPath(path string) bool {
	if path == "" {
		return false
	}
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return false
	}
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return false
	}
	forbiddenPrefixes := []string{"/etc", "/proc", "/sys", "/dev", "/boot", "/root"}
	for _, forbidden := range forbiddenPrefixes {
		if strings.HasPrefix(cleanPath, forbidden) {
			return false
		}
	}
	return true
}

// isValidProfileName validates profile names with whitelist
func isValidProfileName(profile string) bool {
	if profile == "" {
		return false
	}
	for _, c := range profile {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	if len(profile) > 64 {
		return false
	}
	allowedProfiles := map[string]bool{
		"default": true, "python-dev": true, "node-dev": true, "go-dev": true,
		"rust-dev": true, "java-dev": true, "strict": true, "minimal": true, "secure": true,
	}
	return allowedProfiles[profile]
}

// isDangerousCommand blocks dangerous commands
func isDangerousCommand(cmd string) bool {
	dangerousCommands := []string{
		"rm", "rmdir", "dd", "mkfs", "fdisk", "parted",
		"sudo", "su", "passwd", "chmod", "chown", "chgrp",
		"wget", "curl", "nc", "netcat", "ssh", "scp", "rsync",
		"iptables", "ufw", "systemctl", "service", "systemd",
		"mount", "umount", "losetup", "modprobe", "insmod",
		"kill", "killall", "pkill", "reboot", "shutdown", "halt",
	}
	cmdLower := strings.ToLower(strings.TrimSpace(cmd))
	for _, dangerous := range dangerousCommands {
		if strings.Contains(cmdLower, dangerous) {
			return true
		}
	}
	if strings.ContainsAny(cmd, ";|&`$()<>") {
		return true
	}
	return false
}

// startStdioServer and startHTTPServer remain unchanged
func startStdioServer(srv *server.Server) {
	log.Println("Starting MCP server in stdio mode")

	for {
		var input map[string]interface{}
		decoder := json.NewDecoder(os.Stdin)
		if err := decoder.Decode(&input); err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error decoding input: %v", err)
			continue
		}

		inputBytes, _ := json.Marshal(input)
		response, err := srv.HandleRequest(inputBytes)
		if err != nil {
			log.Printf("Error handling request: %v", err)
			continue
		}

		fmt.Println(string(response))
	}
}

func startHTTPServer(srv *server.Server, port string) {
	log.Printf("Starting MCP server in HTTP mode on port %s", port)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var input map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		inputBytes, _ := json.Marshal(input)
		response, err := srv.HandleRequest(inputBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
