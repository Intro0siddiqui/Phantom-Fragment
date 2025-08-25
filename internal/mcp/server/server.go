package server

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/phantom-fragment/phantom-fragment/internal/mcp/types"
)

// ToolHandler represents a function that handles tool execution
type ToolHandler func(args map[string]interface{}) (*types.ToolResult, error)

// Server represents the MCP server instance
type Server struct {
	Tools map[string]ToolHandler
}

// NewServer creates a new MCP server instance
func NewServer() *Server {
	return &Server{
		Tools: make(map[string]ToolHandler),
	}
}

// RegisterTool registers a new tool with the server
func (s *Server) RegisterTool(name string, handler ToolHandler) {
	s.Tools[name] = handler
}

// HandleRequest processes incoming JSON-RPC requests
func (s *Server) HandleRequest(data []byte) ([]byte, error) {
	var req types.JSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return s.createErrorResponse(nil, types.ErrorCodeInvalidRequest, "Invalid JSON-RPC request")
	}

	// Validate JSON-RPC version
	if req.JSONRPC != "2.0" {
		return s.createErrorResponse(req.ID, types.ErrorCodeInvalidRequest, "Unsupported JSON-RPC version")
	}

	// Route based on method
	switch req.Method {
	case "tools/list":
		return s.handleToolsList(req.ID)
	case "tools/call":
		return s.handleToolsCall(req.ID, req.Params)
	case "initialize":
		return s.handleInitialize(req.ID)
	case "shutdown":
		return s.handleShutdown(req.ID)
	default:
		return s.createErrorResponse(req.ID, types.ErrorCodeMethodNotFound, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

// handleToolsList returns the list of available tools
func (s *Server) handleToolsList(id interface{}) ([]byte, error) {
	tools := make([]types.Tool, 0, len(s.Tools))
	for name := range s.Tools {
		tools = append(tools, types.Tool{
			Name:        name,
			Description: "Tool description", // TODO: Add proper descriptions
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{
					// Schema will be tool-specific
				},
			},
		})
	}

	response := types.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  map[string]interface{}{"tools": tools},
	}

	return json.Marshal(response)
}

// handleToolsCall executes a tool with the given parameters
func (s *Server) handleToolsCall(id interface{}, params interface{}) ([]byte, error) {
	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return s.createErrorResponse(id, types.ErrorCodeInvalidParams, "Invalid tool call parameters")
	}

	toolName, ok := paramsMap["name"].(string)
	if !ok {
		return s.createErrorResponse(id, types.ErrorCodeInvalidParams, "Tool name is required")
	}

	handler, exists := s.Tools[toolName]
	if !exists {
		return s.createErrorResponse(id, types.ErrorCodeUnknownTool, fmt.Sprintf("Unknown tool: %s", toolName))
	}

	// Extract tool arguments
	arguments, ok := paramsMap["arguments"].(map[string]interface{})
	if !ok {
		return s.createErrorResponse(id, types.ErrorCodeInvalidParams, "Tool arguments are required")
	}

	// Execute tool with security validation
	if err := s.validateToolCall(toolName, arguments); err != nil {
		return s.createErrorResponse(id, types.ErrorCodeInvalidParams, err.Error())
	}

	result, err := handler(arguments)
	if err != nil {
		return s.createErrorResponse(id, types.ErrorCodeToolExecutionFailed, fmt.Sprintf("Tool execution failed: %v", err))
	}

	response := types.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  map[string]interface{}{"content": result.Content, "isError": result.IsError},
	}

	return json.Marshal(response)
}

// validateToolCall performs security validation for tool execution
func (s *Server) validateToolCall(toolName string, args map[string]interface{}) error {
	// 1. Validate tool exists
	if _, exists := s.Tools[toolName]; !exists {
		return fmt.Errorf("unknown tool: %s", toolName)
	}

	// 2. Validate workdir path if provided - SECURITY CRITICAL
	if workdir, ok := args["workdir"]; ok {
		workdirStr, ok := workdir.(string)
		if !ok {
			return fmt.Errorf("workdir must be a string")
		}
		if !isValidWorkdir(workdirStr) {
			return fmt.Errorf("invalid workdir path: %s", workdirStr)
		}
	}

	// 3. Validate profile if provided - SECURITY CRITICAL
	if profile, ok := args["profile"]; ok {
		profileStr, ok := profile.(string)
		if !ok {
			return fmt.Errorf("profile must be a string")
		}
		if !isValidProfile(profileStr) {
			return fmt.Errorf("invalid profile: %s", profileStr)
		}
	}

	// 4. Validate command arguments if provided
	if command, ok := args["command"]; ok {
		if err := validateCommand(command); err != nil {
			return fmt.Errorf("invalid command: %w", err)
		}
	}

	// 5. Validate file paths in arguments
	for key, value := range args {
		if strings.Contains(key, "path") || strings.Contains(key, "file") {
			if pathStr, ok := value.(string); ok {
				if !isValidPath(pathStr) {
					return fmt.Errorf("invalid path in %s: %s", key, pathStr)
				}
			}
		}
	}

	return nil
}

// isValidWorkdir validates that workdir is within safe boundaries - SECURITY CRITICAL
func isValidWorkdir(path string) bool {
	// Reject empty paths
	if path == "" {
		return false
	}

	// Reject paths containing directory traversal sequences
	if strings.Contains(path, "..") {
		return false
	}

	// Reject paths with double slashes
	if strings.Contains(path, "//") {
		return false
	}

	// Clean and normalize the path
	cleanPath := filepath.Clean(path)

	// Path must be the same after cleaning (no traversals)
	if cleanPath != path {
		return false
	}

	// Reject absolute paths to sensitive directories
	forbiddenPrefixes := []string{
		"/etc", "/proc", "/sys", "/dev", "/boot", "/root",
		"/var/log", "/var/run", "/tmp", "/usr/bin", "/usr/sbin",
		"/bin", "/sbin", "/lib", "/lib64",
	}

	for _, forbidden := range forbiddenPrefixes {
		if strings.HasPrefix(cleanPath, forbidden) {
			return false
		}
	}

	// Only allow relative paths under current directory or /workspace
	if strings.HasPrefix(cleanPath, "/") {
		// If absolute path, only allow /workspace subdirectories
		return strings.HasPrefix(cleanPath, "/workspace/") || cleanPath == "/workspace"
	}

	// For relative paths, ensure they don't escape current directory
	return !strings.HasPrefix(cleanPath, "/")
}

// isValidProfile validates that profile exists and is allowed - SECURITY CRITICAL
func isValidProfile(profile string) bool {
	// Reject empty profiles
	if profile == "" {
		return false
	}

	// Only allow alphanumeric characters, hyphens, and underscores
	for _, c := range profile {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}

	// Enforce maximum length
	if len(profile) > 64 {
		return false
	}

	// Whitelist of allowed profiles
	allowedProfiles := map[string]bool{
		"default":    true,
		"python-dev": true,
		"node-dev":   true,
		"go-dev":     true,
		"rust-dev":   true,
		"java-dev":   true,
		"strict":     true,
		"minimal":    true,
		"secure":     true,
	}

	return allowedProfiles[profile]
}

// isValidPath validates file paths to prevent directory traversal - SECURITY CRITICAL
func isValidPath(path string) bool {
	// Reject empty paths
	if path == "" {
		return false
	}

	// Reject paths containing directory traversal sequences
	if strings.Contains(path, "..") {
		return false
	}

	// Reject paths with double slashes or other anomalies
	if strings.Contains(path, "//") || strings.Contains(path, "./") {
		return false
	}

	// Clean the path and ensure it hasn't changed
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return false
	}

	// Reject access to sensitive system directories
	forbiddenPrefixes := []string{
		"/etc", "/proc", "/sys", "/dev", "/boot", "/root",
		"/var/log", "/var/run", "/usr/bin", "/usr/sbin",
		"/bin", "/sbin", "/lib", "/lib64",
	}

	for _, forbidden := range forbiddenPrefixes {
		if strings.HasPrefix(cleanPath, forbidden) {
			return false
		}
	}

	return true
}

// validateCommand validates command arguments for security - SECURITY CRITICAL
func validateCommand(command interface{}) error {
	switch cmd := command.(type) {
	case string:
		return validateSingleCommand(cmd)
	case []interface{}:
		for i, c := range cmd {
			if cmdStr, ok := c.(string); ok {
				if err := validateSingleCommand(cmdStr); err != nil {
					return fmt.Errorf("command[%d]: %w", i, err)
				}
			} else {
				return fmt.Errorf("command[%d] must be a string", i)
			}
		}
	default:
		return fmt.Errorf("command must be string or array of strings")
	}
	return nil
}

// validateSingleCommand validates a single command string
func validateSingleCommand(cmd string) error {
	// Block dangerous commands
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
			return fmt.Errorf("dangerous command blocked: %s", dangerous)
		}
	}

	// Block shell operators that could be used for command injection
	if strings.ContainsAny(cmd, ";|&`$()<>") {
		return fmt.Errorf("shell operators not allowed in commands")
	}

	return nil
}

// handleInitialize handles server initialization
func (s *Server) handleInitialize(id interface{}) ([]byte, error) {
	response := types.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  map[string]interface{}{"capabilities": map[string]interface{}{}},
	}

	return json.Marshal(response)
}

// handleShutdown handles server shutdown
func (s *Server) handleShutdown(id interface{}) ([]byte, error) {
	response := types.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  nil,
	}

	return json.Marshal(response)
}

// createErrorResponse creates a JSON-RPC error response
func (s *Server) createErrorResponse(id interface{}, code int, message string) ([]byte, error) {
	response := types.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &types.JSONRPCError{
			Code:    code,
			Message: message,
			Data:    map[string]interface{}{"details": message},
		},
	}

	return json.Marshal(response)
}
