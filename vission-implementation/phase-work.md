#### **Error Handling Pattern**
Every MCP response MUST follow this exact pattern:
```go
// Success Response
response := &types.JSONRPCResponse{
	JSONRPC: "2.0",
	ID:      req.ID,
	Result:  result,
}

// Error Response  
response := &types.JSONRPCResponse{
	JSONRPC: "2.0",
	ID:      req.ID,
	Error: &types.JSONRPCError{
		Code:    -32603, // Internal error
		Message: "Tool execution failed",
		Data:    map[string]interface{}{"details": err.Error()},
	},
}
```

#### **Security Validation**
Every tool call MUST include these security checks:
```go
func validateToolCall(toolName string, args map[string]interface{}) error {
	// 1. Validate tool exists
	if _, exists := registry.tools[toolName]; !exists {
		return fmt.Errorf("unknown tool: %s", toolName)
	}

	// 2. Validate required arguments
	if err := validateRequiredArgs(toolName, args); err != nil {
		return err
	}

	// 3. Sanitize file paths
	if workdir, ok := args["workdir"]; ok {
		if !isValidWorkdir(workdir.(string)) {
			return fmt.Errorf("invalid workdir path")
		}
	}

	// 4. Check profile permissions
	if profile, ok := args["profile"]; ok {
		if !isValidProfile(profile.(string)) {
			return fmt.Errorf("invalid profile")
		}
	}

	return nil
}
```

### **Build System Integration**

**File**: Update `build.sh`
```bash
#!/bin/bash

# Build main CLI (unchanged)
echo "Building aisbx CLI..."
go build -o bin/aisbx ./cmd/aisbx

# Build MCP server (new)
echo "Building aisbx-mcp server..."
go build -o bin/aisbx-mcp ./cmd/aisbx-mcp

echo "Build complete:"
echo "  - bin/aisbx (CLI)"
echo "  - bin/aisbx-mcp (MCP Server)"
```

### **Usage Examples**

**Direct CLI (unchanged):**
```bash
aisbx run --profile python-dev python test.py
```

**MCP Integration:**
```bash
# Start MCP server for Claude Desktop
./bin/aisbx-mcp --config ~/.aisbx --transport stdio

# Or as HTTP server
./bin/aisbx-mcp --transport http --port 8080
```

**Claude Desktop Configuration:**
```json
{
  "mcpServers": {
    "ai-sandbox": {
      "command": "/path/to/bin/aisbx-mcp",
      "args": ["--config", "/path/to/.aisbx"]
    }
  }
}
```

## 🏁 **Implementation Checklist**

### **Phase 3: MCP Server Implementation**
- [ ] **Binary Setup**: Create `cmd/aisbx-mcp/main.go` with transport selection
- [ ] **Core Server**: Implement `internal/mcp/server/server.go` with JSON-RPC 2.0 
- [ ] **Protocol Types**: Define all MCP message types in `internal/mcp/types/`
- [ ] **Tools Registry**: Implement tool discovery and execution wrapper
- [ ] **Security Layer**: Add validation for all tool calls and arguments
- [ ] **Error Handling**: Implement MCP-compliant error responses
- [ ] **Transport Layer**: Support both STDIO and HTTP transports
- [ ] **Integration Testing**: Test with Claude Desktop and other MCP clients
- [ ] **Documentation**: Create usage examples and configuration guides
- [ ] **Performance Testing**: Benchmark tool execution overhead

### **Critical Success Criteria**
1. **Zero CLI Impact**: Existing `aisbx` commands work unchanged
2. **MCP Compliance**: Full JSON-RPC 2.0 and MCP protocol compliance  
3. **Security**: All existing security policies apply to MCP tools
4. **Performance**: Tool execution overhead < 200ms
5. **Reliability**: 99.9% uptime for MCP server processes

---

## **Removed Phases**

**Note**: Phase 4-6 have been moved to goal-doc.md for strategic planning. This document focuses exclusively on surgical implementation of Phase 3.

**Status: Ready for surgical implementation with exact specifications provided above.**
