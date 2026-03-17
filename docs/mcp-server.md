# Phantom MCP Server ✅ IMPLEMENTED

Phantom Fragment includes a built-in Model Context Protocol (MCP) server, allowing AI agents (like Claude Desktop, Cursor, or Windsurf) to securely manage fragments and execute code.

## Status: Active

The MCP server is implemented in Rust using the `rmcp` SDK and is available via the `phantom-mcp` binary.

## Architecture

The MCP server provides a high-level tool interface that delegates core container operations to the `phantom` CLI. This ensures that AI agents interact with the same stable engine used by developers.

### Available Tools

1. **`run_in_fragment`**: Execute ephemeral commands in isolated containers.
2. **`create_fragment`**: Spin up persistent sandboxed environments.
3. **`list_fragments`**: Query system state and active workloads.
4. **`execute_code`**: Language-aware execution (Python, JS, Rust, etc.) with automatic image selection.
5. **`build_image`**: Build new images from Fragmentfiles via MCP.
6. **`get_metrics`**: Retrieve real-time performance and resource usage.

## Configuration

To integrate with your AI agent, add the following to your MCP configuration file:

```json
{
  "mcpServers": {
    "phantom-fragment": {
      "command": "phantom-mcp",
      "args": []
    }
  }
}
```
