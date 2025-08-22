package types

// JSONRPCRequest represents JSON-RPC 2.0 request structure
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// JSONRPCResponse represents JSON-RPC 2.0 response structure
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents JSON-RPC 2.0 error structure
type JSONRPCError struct {
	Code    int                    `json:"code"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// Tool represents an MCP tool definition
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ToolCall represents a tool execution request
type ToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ToolResult represents the result of a tool execution
type ToolResult struct {
	Content []ToolResultContent `json:"content"`
	IsError bool                `json:"isError"`
}

// ToolResultContent represents individual content items in tool results
type ToolResultContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// MCPErrorCode constants for standardized error codes
const (
	ErrorCodeInvalidRequest       = -32600
	ErrorCodeMethodNotFound       = -32601
	ErrorCodeInvalidParams        = -32602
	ErrorCodeInternalError        = -32603
	ErrorCodeServerNotInitialized = -32002
	ErrorCodeUnknownTool          = -32003
	ErrorCodeToolExecutionFailed  = -32004
)
