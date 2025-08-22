package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/you/ai-sandbox/internal/mcp/server"
	"github.com/you/ai-sandbox/internal/mcp/types"
)

func main() {
	transport := flag.String("transport", "stdio", "Transport mode: stdio or http")
	port := flag.String("port", "8080", "HTTP port (only for http transport)")
	flag.Parse()

	// Create MCP server instance
	srv := server.NewServer()

	// Register built-in tools
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
	// Tool: aisbx-run - Execute code in sandbox
	srv.RegisterTool("aisbx-run", func(args map[string]interface{}) (*types.ToolResult, error) {
		workdir, _ := args["workdir"].(string)
		profile, _ := args["profile"].(string)
		command, _ := args["command"].(string)

		// TODO: Implement actual sandbox execution
		result := fmt.Sprintf("Executing in sandbox - Workdir: %s, Profile: %s, Command: %s", workdir, profile, command)

		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: result},
			},
			IsError: false,
		}, nil
	})

	// Tool: aisbx-build - Build sandbox environment
	srv.RegisterTool("aisbx-build", func(args map[string]interface{}) (*types.ToolResult, error) {
		profile, _ := args["profile"].(string)
		platform, _ := args["platform"].(string)

		// TODO: Implement actual build process
		result := fmt.Sprintf("Building sandbox - Profile: %s, Platform: %s", profile, platform)

		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: result},
			},
			IsError: false,
		}, nil
	})

	// Tool: aisbx-profile-list - List available security profiles
	srv.RegisterTool("aisbx-profile-list", func(args map[string]interface{}) (*types.ToolResult, error) {
		// TODO: Implement profile listing from internal/security
		profiles := []string{"default", "python", "nodejs", "go"}

		profilesJSON, _ := json.Marshal(profiles)

		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: string(profilesJSON)},
			},
			IsError: false,
		}, nil
	})
}

func startStdioServer(srv *server.Server) {
	log.Println("Starting MCP server in stdio mode")

	// Read from stdin, write to stdout
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