package server

import (
	"encoding/json"
	"fmt"

	"github.com/you/ai-sandbox/internal/mcp/types"
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
				"type": "object",
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

	// 2. Validate workdir path if provided
	if workdir, ok := args["workdir"]; ok {
		if !isValidWorkdir(workdir.(string)) {
			return fmt.Errorf("invalid workdir path")
		}
	}

	// 3. Validate profile if provided
	if profile, ok := args["profile"]; ok {
		if !isValidProfile(profile.(string)) {
			return fmt.Errorf("invalid profile")
		}
	}

	return nil
}

// isValidWorkdir validates that workdir is within safe boundaries
func isValidWorkdir(path string) bool {
	// TODO: Implement proper path validation
	// For now, allow any path - implement sandbox-specific validation
	return true
}

// isValidProfile validates that profile exists and is allowed
func isValidProfile(profile string) bool {
	// TODO: Implement profile validation against available profiles
	return true
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