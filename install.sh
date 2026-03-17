#!/bin/bash
#
# Phantom Fragment - Quick Install Script
# Downloads pre-built binaries from GitHub/Codeberg releases
# Falls back to building from source if needed
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
REPO_GITHUB="Intro0siddiqui/Phantom-Fragment"
REPO_CODEBERG="Intro0siddiqui/Phantom-Fragment"

# Check if running as root or can write to /usr/local/bin
if [ "$EUID" -eq 0 ] || [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
else
    INSTALL_DIR="${INSTALL_DIR:-$HOME/bin}"
fi

BINARY_NAME="${BINARY_NAME:-phantom}"  # Default binary name
VERSION="${VERSION:-1.0.0}"

# Architecture detection
detect_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) echo "$arch" ;;
    esac
}

# OS detection
detect_os() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case $os in
        linux) echo "unknown-linux-gnu" ;;
        darwin) echo "apple-darwin" ;;
        *) echo "$os" ;;
    esac
}

ARCH=$(detect_arch)
OS=$(detect_os)

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Phantom Fragment - Quick Install      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo
echo "Target: $BINARY_NAME v$VERSION ($OS-$ARCH)"
echo "Install: $INSTALL_DIR"
echo

# Show installation mode
if [ "$INSTALL_DIR" = "/usr/local/bin" ]; then
    echo -e "${GREEN}✓ Installing system-wide (global)${NC}"
else
    echo -e "${YELLOW}⚠ Installing to user directory${NC}"
    echo "  To install system-wide, run with sudo:"
    echo "  sudo ./install.sh"
fi
echo

# Check if curl/wget is available
check_tools() {
    if command -v curl &> /dev/null; then
        DOWNLOAD_CMD="curl -fsSL"
    elif command -v wget &> /dev/null; then
        DOWNLOAD_CMD="wget -qO-"
    else
        echo -e "${RED}✗ Neither curl nor wget found${NC}"
        echo "Please install: sudo apt install curl  OR  sudo yum install curl"
        exit 1
    fi
    echo -e "${GREEN}✓ Using $DOWNLOAD_CMD${NC}"
}

# Try to download from GitHub releases
download_from_github() {
    echo -e "${YELLOW}[1/4] Trying GitHub releases...${NC}"
    
    local asset_name="phantom-${VERSION}-${ARCH}-${OS}"
    local download_url="https://github.com/${REPO_GITHUB}/releases/download/v${VERSION}/${asset_name}"
    
    echo "  URL: $download_url"
    
    if $DOWNLOAD_CMD "$download_url" -o "/tmp/phantom-binary" 2>/dev/null; then
        echo -e "${GREEN}✓ Downloaded from GitHub${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ GitHub download failed${NC}"
        return 1
    fi
}

# Try to download from Codeberg releases
download_from_codeberg() {
    echo -e "${YELLOW}[2/4] Trying Codeberg releases...${NC}"
    
    local asset_name="phantom-${VERSION}-${ARCH}-${OS}"
    local download_url="https://codeberg.org/api/v1/repos/${REPO_CODEBERG}/releases/download/v${VERSION}/${asset_name}"
    
    echo "  URL: $download_url"
    
    if $DOWNLOAD_CMD "$download_url" -o "/tmp/phantom-binary" 2>/dev/null; then
        echo -e "${GREEN}✓ Downloaded from Codeberg${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Codeberg download failed${NC}"
        return 1
    fi
}

# Try to download latest release (auto-detect version)
download_latest() {
    echo -e "${YELLOW}[3/4] Trying to get latest release info...${NC}"
    
    # Try GitHub API
    local latest_info
    if latest_info=$($DOWNLOAD_CMD "https://api.github.com/repos/${REPO_GITHUB}/releases/latest" 2>/dev/null); then
        VERSION=$(echo "$latest_info" | grep -o '"tag_name": "v[^"]*"' | cut -d'"' -f4 | sed 's/v//')
        echo "  Latest version: $VERSION"
        
        if download_from_github; then
            return 0
        fi
    fi
    
    # Try Codeberg API
    if latest_info=$($DOWNLOAD_CMD "https://codeberg.org/api/v1/repos/${REPO_CODEBERG}/releases/latest" 2>/dev/null); then
        VERSION=$(echo "$latest_info" | grep -o '"tag_name": "v[^"]*"' | cut -d'"' -f4 | sed 's/v//')
        echo "  Latest version: $VERSION"
        
        if download_from_codeberg; then
            return 0
        fi
    fi
    
    return 1
}

# Fallback: Build from source
build_from_source() {
    echo -e "${YELLOW}[4/4] Falling back to building from source...${NC}"
    
    # Check for git
    if ! command -v git &> /dev/null; then
        echo -e "${RED}✗ Git not found, cannot clone repository${NC}"
        echo "Please install git or download a pre-built binary manually"
        exit 1
    fi
    
    # Check for Rust
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}✗ Rust/Cargo not found${NC}"
        echo "Install Rust: https://rustup.rs/"
        exit 1
    fi
    
    echo "  Cloning repository..."
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Try GitHub first, then Codeberg
    if ! git clone --depth 1 "https://github.com/${REPO_GITHUB}.git" . 2>/dev/null; then
        echo "  GitHub clone failed, trying Codeberg..."
        git clone --depth 1 "https://codeberg.org/${REPO_CODEBERG}.git" . 2>/dev/null || {
            echo -e "${RED}✗ Failed to clone repository${NC}"
            exit 1
        }
    fi
    
    echo "  Building release binary..."
    cargo build --release -p phantom 2>&1 | tail -3
    
    if [ -f "target/release/phantom" ]; then
        cp "target/release/phantom" "/tmp/phantom-binary"
        echo -e "${GREEN}✓ Built from source${NC}"
        cd - > /dev/null
        rm -rf "$temp_dir"
        return 0
    else
        echo -e "${RED}✗ Build failed${NC}"
        cd - > /dev/null
        rm -rf "$temp_dir"
        return 1
    fi
}

# Install the binary
install_binary() {
    echo
    echo -e "${YELLOW}Installing binary...${NC}"
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    
    # Remove old version if exists
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        local old_version=$("$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null || echo "unknown")
        echo "  Removing old version: $old_version"
        rm -f "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    # Copy and make executable
    cp /tmp/phantom-binary "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    
    # Verify
    local new_version=$("$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}✓ Installed: $INSTALL_DIR/$BINARY_NAME${NC}"
    echo "  Version: $new_version"
    
    # Cleanup
    rm -f /tmp/phantom-binary
    
    # Check PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo
        echo -e "${YELLOW}⚠ $INSTALL_DIR is not in your PATH${NC}"
        echo "Add this to your ~/.bashrc or ~/.zshrc:"
        echo "  export PATH=\"\$HOME/bin:\$PATH\""
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --binary-name NAME    Set binary name (default: 1.0.0)"
    echo "  --install-dir DIR     Set installation directory (default: \$HOME/bin)"
    echo "  --version VERSION     Specify version to install (default: latest)"
    echo "  --github              Prefer GitHub over Codeberg"
    echo "  --codeberg            Prefer Codeberg over GitHub"
    echo "  --source              Force build from source"
    echo "  --help                Show this help message"
    echo
    echo "Examples:"
    echo "  $0                              # Install system-wide (requires sudo)"
    echo "  sudo $0                         # Recommended: system-wide install"
    echo "  $0 --binary-name phantom        # Install as 'phantom'"
    echo "  $0 --version 0.9.0              # Install specific version"
    echo "  $0 --install-dir \$HOME/bin     # User-only install"
    echo
}

# Parse arguments
FORCE_SOURCE=false
PREFER_GITHUB=false
PREFER_CODEBERG=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --binary-name)
            BINARY_NAME="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --github)
            PREFER_GITHUB=true
            shift
            ;;
        --codeberg)
            PREFER_CODEBERG=true
            shift
            ;;
        --source)
            FORCE_SOURCE=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main installation flow
check_tools

if [ "$FORCE_SOURCE" = true ]; then
    build_from_source || exit 1
else
    # Try downloads in order of preference
    if [ "$PREFER_GITHUB" = true ]; then
        download_from_github || download_from_codeberg || download_latest || build_from_source
    elif [ "$PREFER_CODEBERG" = true ]; then
        download_from_codeberg || download_from_github || download_latest || build_from_source
    else
        # Default: try GitHub, then Codeberg, then latest, then build
        download_from_github || download_from_codeberg || download_latest || build_from_source
    fi
fi

install_binary

echo
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Installation Complete! ✓          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo
echo "Run: $INSTALL_DIR/$BINARY_NAME --help"
echo
echo "Quick start:"
echo "  $BINARY_NAME run alpine echo 'Hello!'"
echo "  $BINARY_NAME search ubuntu"
echo "  $BINARY_NAME health"
echo
