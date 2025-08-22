#!/bin/bash

# AI Sandbox Build Script
# Phase 1: CLI Foundation

set -e

echo "🔨 Building AI Sandbox Phase 1..."

# Ensure go.mod is tidy
echo "📦 Tidying dependencies..."
go mod tidy

# Build the CLI
echo "🏗️  Building CLI..."
go build -o bin/aisbx ./cmd/aisbx

# Build MCP server binary
echo "🏗️  Building MCP server..."
go build -o bin/aisbx-mcp ./cmd/aisbx-mcp

# Create necessary directories
echo "📁 Setting up directories..."
mkdir -p bin/
mkdir -p dist/

# Build for multiple platforms (Phase 1)
echo "🌍 Building for current platform..."
GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) go build -o bin/aisbx-$(go env GOOS)-$(go env GOARCH) ./cmd/aisbx
GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) go build -o bin/aisbx-mcp-$(go env GOOS)-$(go env GOARCH) ./cmd/aisbx-mcp

# Build for additional platforms
# macOS ARM64
echo "  Building for macOS ARM64..."
GOOS=darwin GOARCH=arm64 go build -o bin/aisbx-mcp-darwin-arm64 ./cmd/aisbx-mcp

# Windows
echo "  Building for Windows..."
GOOS=windows GOARCH=amd64 go build -o bin/aisbx-windows-amd64.exe ./cmd/aisbx

echo "✅ Phase 1 build complete!"
echo ""
echo "📋 Next steps:"
echo "1. Run './bin/aisbx init' to initialize the sandbox"
echo "2. Run './bin/aisbx profile list' to see available profiles"
echo "3. Run './bin/aisbx run --help' for usage instructions"
echo "4. Run './bin/aisbx-mcp' to start the MCP server"