# AI-Sandbox - Secure Development Environment for LLM Agents

**AI-Sandbox** is a lightweight, secure sandbox environment designed specifically for LLM agents and developers to safely execute code. It provides stronger isolation than Docker with minimal overhead, making it perfect for AI-assisted development workflows.

## ⚠️ **IMPORTANT: Directory Structure & Setup**

### **Critical Setup Requirements**

**🚨 ALL COMMANDS MUST BE RUN FROM THE PROJECT DIRECTORY:**

This project has a nested directory structure. You must navigate to the correct directory before running any commands:

```powershell
# ❌ WRONG - Running from parent directory will cause errors:
PS C:\path\to\ai-sanbox> .\bin\aisbx-mcp.exe --help
# Error: The term '.\bin\aisbx-mcp.exe' is not recognized...

# ✅ CORRECT - Navigate to project directory first:
PS C:\path\to\ai-sanbox> cd ai-sandbox
PS C:\path\to\ai-sanbox\ai-sandbox> .\bin\aisbx-mcp.exe --help
# Works correctly!
```

### **Directory Structure**
```
ai-sanbox/                    ← Parent directory (❌ Don't run commands here)
└── ai-sandbox/              ← Project directory (✅ Run all commands here)
    ├── bin/                 ← Compiled binaries
    │   ├── aisbx.exe
    │   ├── aisbx-mcp.exe
    │   └── aisbx-supervisor.exe
    ├── cmd/                 ← Source code
    ├── internal/
    ├── go.mod               ← Go module definition
    ├── README.md
    └── test-*.ps1           ← Test scripts
```

### **Setup Steps**

1. **Navigate to correct directory:**
   ```powershell
   cd ai-sandbox  # Enter the project directory
   ```

2. **Verify you're in the right place:**
   ```powershell
   ls  # Should show: bin/, cmd/, internal/, go.mod, README.md
   ```

3. **Now you can run commands successfully:**
   ```powershell
   .\bin\aisbx-mcp.exe --help                    # ✅ Works
   powershell -ExecutionPolicy Bypass -File .\test-mcp-integration.ps1  # ✅ Works
   go build -o bin\aisbx-mcp.exe .\cmd\aisbx-mcp\  # ✅ Works
   ```

## 🚀 **Quick Start Guide**

### **For Human Developers**

Direct CLI usage for fast, secure code execution:

```bash
# Navigate to project directory first
cd ai-sandbox

# Run Python code in isolated environment
.\bin\aisbx.exe run --profile python-dev python script.py

# Create a new sandbox environment
.\bin\aisbx.exe create --name my-project --profile go-dev

# List available security profiles
.\bin\aisbx.exe profile list

# View sandbox logs
.\bin\aisbx.exe logs my-project

# Destroy sandbox when done
.\bin\aisbx.exe destroy my-project
```

### **For LLM Agents (Claude, GPT, etc.)**

Integrate with AI assistants using the Model Context Protocol (MCP):

#### **1. Start MCP Server**
```bash
# Navigate to project directory
cd ai-sandbox

# Start MCP server for Claude Desktop (STDIO mode)
.\bin\aisbx-mcp.exe --transport stdio

# Or start HTTP server for web-based LLMs
.\bin\aisbx-mcp.exe --transport http --port 8080
```

#### **2. Configure Claude Desktop**
Add this to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "ai-sandbox": {
      "command": "C:\\path\\to\\ai-sandbox\\bin\\aisbx-mcp.exe",
      "args": ["--transport", "stdio"]
    }
  }
}
```

#### **3. LLM Usage**
Once configured, LLMs can:
- Execute code safely in isolated environments
- Build and test projects without affecting your system
- List and select appropriate security profiles
- Access sandbox output and error logs

## 🔧 **Building from Source**

### **Prerequisites**
- Go 1.21 or later
- Windows, Linux, or macOS

### **Build Instructions**

```bash
# Navigate to project directory
cd ai-sandbox

# Build all components
go build -o bin/aisbx.exe ./cmd/aisbx
go build -o bin/aisbx-mcp.exe ./cmd/aisbx-mcp
go build -o bin/aisbx-supervisor.exe ./cmd/aisbx-supervisor
go build -o bin/aisbx-security.exe ./cmd/aisbx-security

# Or use the build script
./build.sh  # Linux/macOS
# For Windows, run commands individually as shown above
```

## 🧪 **Testing Your Installation**

### **Basic Functionality Test**

```bash
# Navigate to project directory first
cd ai-sandbox

# Test CLI functionality
.\bin\aisbx.exe --help
.\bin\aisbx.exe profile list

# Test MCP server
.\bin\aisbx-mcp.exe --help
```

### **Integration Tests**

```bash
# Navigate to project directory first
cd ai-sandbox

# Run comprehensive integration tests
powershell -ExecutionPolicy Bypass -File ./test-mcp-integration.ps1    # Windows
./test-mcp-integration.sh                                              # Linux/macOS

# Basic MCP protocol testing
./test-mcp-basic.sh  # Linux/macOS
```

## 🔒 **Security Features**

AI-Sandbox provides enterprise-grade security for safe code execution:

### **Isolation Technologies**
- **User Namespaces**: Unprivileged containers
- **Seccomp Profiles**: System call filtering by language
- **Capabilities Control**: Minimal permission sets
- **Read-only Filesystem**: Immutable base environment
- **Network Isolation**: Optional network access control
- **Resource Limits**: CPU, memory, and disk quotas

### **Security Profiles**
Pre-configured profiles for different programming languages:

| Profile | Language | Network | Filesystem | Use Case |
|---------|----------|---------|------------|-----------|
| `python-dev` | Python | Limited | Restricted | Python development |
| `node-dev` | Node.js | Limited | Restricted | JavaScript/Node development |
| `go-dev` | Go | Limited | Restricted | Go development |
| `rust-dev` | Rust | Limited | Restricted | Rust development |
| `java-dev` | Java | Limited | Restricted | Java development |
| `strict` | Any | Disabled | Read-only | Maximum security |
| `minimal` | Any | Disabled | Minimal | Ultra-lightweight |

### **Authentication & Monitoring**
- **API Key Authentication**: Secure access control
- **Rate Limiting**: Prevent abuse and DoS attacks
- **Audit Logging**: Complete security event tracking
- **Real-time Monitoring**: Prometheus metrics integration
- **Input Validation**: Protection against injection attacks

## 📊 **Production Deployment**

### **Supervisor Service**

For production environments, use the supervisor service:

```bash
# Navigate to project directory
cd ai-sandbox

# Start production supervisor
.\bin\aisbx-supervisor.exe

# The service will be available at:
# - Health check: http://localhost:8080/health
# - Metrics: http://localhost:8080/metrics
# - API endpoints: http://localhost:8080/api/v1/
```

### **Monitoring Endpoints**

```bash
# Health status
curl http://localhost:8080/health

# Prometheus metrics
curl http://localhost:8080/metrics

# Security audit logs
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/security/audit
```

### **Key Metrics**
```
# Request metrics
aisbx_requests_total
aisbx_request_duration_seconds
aisbx_active_connections
aisbx_errors_total

# Sandbox metrics  
aisbx_sandbox_starts_total
aisbx_sandbox_stops_total
aisbx_sandbox_duration_seconds

# Security metrics
aisbx_auth_failures_total
aisbx_rate_limit_hits_total
aisbx_security_violations_total

# Resource metrics
aisbx_cpu_usage_percent
aisbx_memory_usage_bytes
aisbx_disk_usage_bytes
```

## 🛠️ **Configuration**

### **Profile Configuration**

Customize security profiles in `config.yaml`:

```yaml
profiles:
  my-custom-profile:
    name: "my-custom-profile"
    driver: "bwrap"  # or "chroot", "lima"
    cpu: "1"         # CPU limit
    memory: "512m"    # Memory limit
    network:
      enabled: false  # Disable network access
    mounts:
      - source: "./workspace"
        target: "/workspace"
        mode: "rw"     # or "ro" for read-only
    environment:
      TERM: "xterm"
    seccomp: "profiles/custom.json"
```

### **Environment Variables**

```bash
# Configuration file location
AISBX_CONFIG_PATH=/path/to/config.yaml

# Default security profile
AISBX_DEFAULT_PROFILE=python-dev

# Enable debug logging
AISBX_DEBUG=true

# API server settings
AISBX_API_PORT=8080
AISBX_API_KEY=your-secret-key
```

## 🎯 **Use Cases**

### **AI Agent Development**
- **Safe Code Execution**: LLMs can write and test code without system access
- **Iterative Development**: Fast generate-test-fix cycles
- **Multiple Languages**: Support for Python, Node.js, Go, Rust, Java
- **Security by Default**: Isolated environments prevent malicious code

### **Educational Environments**
- **Student Code Execution**: Safe environment for learning
- **Assignment Grading**: Automated testing in isolation
- **Workshop Environments**: Disposable development setups

### **CI/CD Integration**
- **Test Isolation**: Run tests in clean environments
- **Security Testing**: Validate code in restricted environments
- **Multi-language Builds**: Language-specific isolation

### **Research & Experimentation**
- **Malware Analysis**: Study suspicious code safely
- **Tool Testing**: Try new tools without system contamination
- **Performance Benchmarking**: Consistent execution environments

## 🔧 **Troubleshooting**

### **Common Issues**

#### **Command Not Found Errors**
```
Error: The term '.\bin\aisbx-mcp.exe' is not recognized
```
**Solution**: Make sure you're in the `ai-sandbox` directory (not the parent `ai-sanbox` directory).

#### **Go Module Errors**
```
go: go.mod file not found in current directory
```
**Solution**: Navigate to the `ai-sandbox` directory where `go.mod` is located.

#### **Permission Errors**
```
Permission denied or execution policy errors
```
**Solution**: Run PowerShell as administrator or use:
```powershell
powershell -ExecutionPolicy Bypass -File ./script.ps1
```

#### **Binary Not Starting**
**Check dependencies**:
- Ensure Go 1.21+ is installed
- Verify all required system libraries are available
- Check that binaries are executable

### **Debug Mode**

Enable detailed logging:

```bash
# Set debug environment variable
export AISBX_DEBUG=true  # Linux/macOS
set AISBX_DEBUG=true     # Windows

# Run with verbose output
.\bin\aisbx.exe run --profile python-dev --verbose python script.py
```

### **Getting Help**

```bash
# Command help
.\bin\aisbx.exe --help
.\bin\aisbx.exe run --help
.\bin\aisbx-mcp.exe --help

# List available profiles
.\bin\aisbx.exe profile list

# Check system status
.\bin\aisbx-supervisor.exe --health
```

## 🏗️ **Architecture Overview**

```
┌─────────────────────────────────────────┐
│              AI-Sandbox                 │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────────┐ │
│  │        Command Line Interface       │ │
│  │         (aisbx.exe)                 │ │
│  └─────────────────────────────────────┘ │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────────┐ │
│  │       MCP Protocol Server           │ │
│  │        (aisbx-mcp.exe)              │ │
│  │   ┌─────────────┐ ┌─────────────┐  │ │
│  │   │    STDIO    │ │    HTTP     │  │ │
│  │   │  Transport  │ │  Transport  │  │ │
│  │   └─────────────┘ └─────────────┘  │ │
│  └─────────────────────────────────────┘ │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────────┐ │
│  │      Supervisor Service             │ │
│  │     (aisbx-supervisor.exe)          │ │
│  │   ┌─────────────┐ ┌─────────────┐  │ │
│  │   │ REST API    │ │ Prometheus  │  │ │
│  │   │ Endpoints   │ │   Metrics   │  │ │
│  │   └─────────────┘ └─────────────┘  │ │
│  └─────────────────────────────────────┘ │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────────┐ │
│  │        Security Layer               │ │
│  │   ┌─────────────┐ ┌─────────────┐  │ │
│  │   │  Seccomp    │ │  Network    │  │ │
│  │   │  Profiles   │ │  Policies   │  │ │
│  │   └─────────────┘ └─────────────┘  │ │
│  │   ┌─────────────┐ ┌─────────────┐  │ │
│  │   │ Filesystem  │ │ Resource    │  │ │
│  │   │ Isolation   │ │ Limits      │  │ │
│  │   └─────────────┘ └─────────────┘  │ │
│  └─────────────────────────────────────┘ │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────────┐ │
│  │       Execution Drivers             │ │
│  │   ┌─────────────┐ ┌─────────────┐  │ │
│  │   │ Bubblewrap  │ │   Chroot    │  │ │
│  │   │   (Linux)   │ │ (Fallback)  │  │ │
│  │   └─────────────┘ └─────────────┘  │ │
│  │   ┌─────────────┐                  │ │
│  │   │    Lima     │                  │ │
│  │   │ (macOS/Win) │                  │ │
│  │   └─────────────┘                  │ │
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

---

**🏆 Ready to Use**: Production-ready secure development environment for LLM agents and developers

**🔗 Links**: [Documentation](./vission-implementation/) | [Security Profiles](./internal/security/seccomp/profiles/) | [Test Scripts](./test-mcp-basic.sh)

