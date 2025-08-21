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

# Create necessary directories
echo "📁 Setting up directories..."
mkdir -p bin/
mkdir -p dist/

# Build for multiple platforms (Phase 1)
echo "🌍 Building for current platform..."
GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) go build -o bin/aisbx-$(go env GOOS)-$(go env GOARCH) ./cmd/aisbx

echo "✅ Phase 1 build complete!"
echo ""
echo "📋 Next steps:"
echo "1. Run './bin/aisbx init' to initialize the sandbox"
echo "2. Run './bin/aisbx profile list' to see available profiles"
echo "3. Run './bin/aisbx run --help' for usage instructions"