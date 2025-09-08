#!/bin/bash

# Browser MCP Setup Script for VPS
# This script sets up a lightweight browser with MCP extension support

echo "=== Browser MCP Setup for VPS ==="
echo "VPS IP: 41.216.189.245"
echo "Starting setup..."

# Update system packages
echo "1. Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install virtual display (Xvfb) for headless browser operation
echo "2. Installing virtual display (Xvfb)..."
sudo apt install -y xvfb

# Install Chrome/Chromium browser
echo "3. Installing Chrome browser..."
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt update
sudo apt install -y google-chrome-stable

# Install additional dependencies for browser automation
echo "4. Installing browser automation dependencies..."
sudo apt install -y \
    x11-utils \
    x11-xserver-utils \
    xauth \
    xfonts-100dpi \
    xfonts-75dpi \
    xfonts-scalable \
    xfonts-cyrillic \
    x11-apps

# Install Playwright for browser automation
echo "5. Installing Playwright..."
npm install -g playwright
npx playwright install chromium

# Create a startup script for the browser with virtual display
echo "6. Creating browser startup script..."
cat > /root/start_browser_mcp.sh << 'EOF'
#!/bin/bash

# Start virtual display
export DISPLAY=:99
Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &

# Wait for Xvfb to start
sleep 2

# Start Chrome with MCP extension support
google-chrome-stable \
    --no-sandbox \
    --disable-dev-shm-usage \
    --disable-gpu \
    --remote-debugging-port=9222 \
    --disable-web-security \
    --disable-features=VizDisplayCompositor \
    --user-data-dir=/tmp/chrome-mcp \
    --disable-extensions-except=/path/to/browser-mcp-extension \
    --load-extension=/path/to/browser-mcp-extension \
    --new-window \
    --start-maximized &

echo "Browser started with MCP support on display :99"
echo "Remote debugging available on port 9222"
echo "Browser MCP extension loaded"
EOF

chmod +x /root/start_browser_mcp.sh

# Create a systemd service for auto-starting the browser
echo "7. Creating systemd service..."
cat > /etc/systemd/system/browser-mcp.service << 'EOF'
[Unit]
Description=Browser MCP Service
After=network.target

[Service]
Type=forking
User=root
ExecStart=/root/start_browser_mcp.sh
Restart=always
RestartSec=10
Environment=DISPLAY=:99

[Install]
WantedBy=multi-user.target
EOF

# Enable the service
sudo systemctl daemon-reload
sudo systemctl enable browser-mcp.service

# Configure firewall for MCP communication
echo "8. Configuring firewall..."
sudo ufw allow 9222/tcp  # Chrome remote debugging
sudo ufw allow 3000/tcp  # Common MCP port
sudo ufw allow 8080/tcp  # Alternative MCP port

# Create MCP configuration directory
echo "9. Creating MCP configuration..."
mkdir -p /root/.mcp
cat > /root/.mcp/config.json << 'EOF'
{
  "browser": {
    "host": "localhost",
    "port": 9222,
    "extension_path": "/path/to/browser-mcp-extension"
  },
  "gemini": {
    "api_key": "your-gemini-api-key-here"
  }
}
EOF

echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Download Browser MCP extension to /root/browser-mcp-extension/"
echo "2. Update /root/.mcp/config.json with correct paths and API key"
echo "3. Start the browser service: sudo systemctl start browser-mcp.service"
echo "4. Test connection with Gemini CLI"
echo ""
echo "Useful commands:"
echo "- Start browser: sudo systemctl start browser-mcp.service"
echo "- Stop browser: sudo systemctl stop browser-mcp.service"
echo "- Check status: sudo systemctl status browser-mcp.service"
echo "- View logs: sudo journalctl -u browser-mcp.service -f"
echo "- Manual start: /root/start_browser_mcp.sh"