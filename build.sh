#!/bin/bash

# Phantom Fragment Build Script
# Phase 1: CLI Foundation

set -e

echo "🔨 Building Phantom Fragment Phase 1..."

# Ensure go.mod is tidy
echo "📦 Tidying dependencies..."
go mod tidy

# Build the CLI
echo "🏗️  Building CLI..."
go build -o bin/phantom ./cmd/phantom

# Build MCP server binary
echo "🏗️  Building MCP server..."
go build -o bin/phantom-mcp ./cmd/phantom-mcp

# Create necessary directories
echo "📁 Setting up directories..."
mkdir -p bin/
mkdir -p dist/

# Build for multiple platforms (Phase 1)
echo "🌍 Building for current platform..."
GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) go build -o bin/phantom-$(go env GOOS)-$(go env GOARCH) ./cmd/phantom
GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) go build -o bin/phantom-mcp-$(go env GOOS)-$(go env GOARCH) ./cmd/phantom-mcp

# Build for additional platforms
# macOS ARM64
echo "  Building for macOS ARM64..."
GOOS=darwin GOARCH=arm64 go build -o bin/phantom-mcp-darwin-arm64 ./cmd/phantom-mcp

# Windows
echo "  Building for Windows..."
GOOS=windows GOARCH=amd64 go build -o bin/phantom-windows-amd64.exe ./cmd/phantom

echo "✅ Phase 1 build complete!"
echo ""
echo "📋 Next steps:"
echo "1. Run './bin/phantom init' to initialize the sandbox"
echo "2. Run './bin/phantom profile list' to see available profiles"
echo "3. Run './bin/phantom run --help' for usage instructions"
echo "4. Run './bin/phantom-mcp' to start the MCP server"