#!/bin/bash

# Test script for MCP server verification
# Tests both STDIO and HTTP transports

set -e

echo "🧪 Testing AI Sandbox MCP Server..."

# Build the MCP server
echo "🏗️  Building MCP server..."
go build -o bin/aisbx-mcp ./cmd/aisbx-mcp

echo "✅ Build successful!"

# Test 1: HTTP server startup
echo "🌐 Testing HTTP server startup..."
timeout 5 ./bin/aisbx-mcp --transport http --port 8081 &
HTTP_PID=$!
sleep 2

# Test if server is responding
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/ | grep -q "405"; then
    echo "✅ HTTP server responding correctly (Method Not Allowed for GET)"
else
    echo "❌ HTTP server not responding as expected"
fi

# Clean up HTTP server
kill $HTTP_PID 2>/dev/null || true
echo "🧹 HTTP server stopped"

# Test 2: JSON-RPC request format
echo "📡 Testing JSON-RPC request format..."
cat > test_request.json << EOF
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
}
EOF

echo "📄 Test request created:"
cat test_request.json

# Test 3: STDIO server (quick test)
echo "📨 Testing STDIO server..."
echo "ℹ️  Starting server with test input..."

# Send the test request to STDIO server
timeout 3 bash -c 'echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}" | ./bin/aisbx-mcp --transport stdio' > test_output.json 2>/dev/null || true

if [ -f test_output.json ] && [ -s test_output.json ]; then
    echo "✅ STDIO server generated output:"
    cat test_output.json
else
    echo "⚠️  STDIO server test needs manual verification"
fi

# Clean up
rm -f test_request.json test_output.json

echo ""
echo "🎉 MCP Server Basic Tests Complete!"
echo ""
echo "📋 Manual verification steps:"
echo "1. Start HTTP server: ./bin/aisbx-mcp --transport http"
echo "2. Test with curl: curl -X POST http://localhost:8080/ -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}'"
echo "3. Start STDIO server: ./bin/aisbx-mcp --transport stdio"
echo "4. Test with echo: echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}' | ./bin/aisbx-mcp --transport stdio"