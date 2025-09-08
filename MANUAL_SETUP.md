# Manual Browser MCP Setup Guide

## VPS Connection Details
- **IP**: 41.216.189.245
- **User**: root
- **Password**: @intro%carbon-006

## Step-by-Step Setup Commands

### 1. Connect to VPS
```bash
ssh root@41.216.189.245
# Enter password: @intro%carbon-006
```

### 2. Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### 3. Install Virtual Display (Xvfb)
```bash
sudo apt install -y xvfb
```

### 4. Install Chrome Browser
```bash
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt update
sudo apt install -y google-chrome-stable
```

### 5. Install Browser Dependencies
```bash
sudo apt install -y x11-utils x11-xserver-utils xauth xfonts-100dpi xfonts-75dpi xfonts-scalable xfonts-cyrillic x11-apps
```

### 6. Install Playwright
```bash
npm install -g playwright
npx playwright install chromium
```

### 7. Create Browser Startup Script
```bash
cat > /root/start_browser_mcp.sh << 'EOF'
#!/bin/bash
export DISPLAY=:99
Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &
sleep 2
google-chrome-stable \
    --no-sandbox \
    --disable-dev-shm-usage \
    --disable-gpu \
    --remote-debugging-port=9222 \
    --disable-web-security \
    --disable-features=VizDisplayCompositor \
    --user-data-dir=/tmp/chrome-mcp \
    --new-window \
    --start-maximized &
echo "Browser started with MCP support on display :99"
echo "Remote debugging available on port 9222"
EOF

chmod +x /root/start_browser_mcp.sh
```

### 8. Configure Firewall
```bash
sudo ufw allow 9222/tcp
sudo ufw allow 3000/tcp
sudo ufw allow 8080/tcp
```

### 9. Create MCP Configuration
```bash
mkdir -p /root/.mcp
cat > /root/.mcp/config.json << 'EOF'
{
  "browser": {
    "host": "localhost",
    "port": 9222,
    "extension_path": "/root/browser-mcp-extension"
  },
  "gemini": {
    "api_key": "your-gemini-api-key-here"
  }
}
EOF
```

## Starting the Browser

### Start Browser with MCP Support
```bash
/root/start_browser_mcp.sh
```

### Check if Browser is Running
```bash
ps aux | grep chrome
netstat -tlnp | grep 9222
```

### View Browser (if needed)
```bash
# Install VNC for remote viewing (optional)
sudo apt install -y tightvncserver
vncserver :1 -geometry 1920x1080 -depth 24
```

## Testing Connection

### Test Chrome Remote Debugging
```bash
curl http://localhost:9222/json
```

### Test with Gemini CLI
```bash
# Make sure Gemini CLI is configured to connect to the MCP server
gemini --help
```

## Troubleshooting

### Check Virtual Display
```bash
ps aux | grep Xvfb
```

### Check Chrome Process
```bash
ps aux | grep chrome
```

### Check Ports
```bash
netstat -tlnp | grep -E "(9222|3000|8080)"
```

### View Logs
```bash
tail -f /var/log/syslog
```

## Next Steps

1. **Download Browser MCP Extension** to `/root/browser-mcp-extension/`
2. **Update config.json** with correct extension path and API key
3. **Test the connection** with Gemini CLI
4. **Start browser automation** tasks

## Useful Commands

```bash
# Start browser
/root/start_browser_mcp.sh

# Stop browser
pkill chrome
pkill Xvfb

# Restart everything
pkill chrome && pkill Xvfb && /root/start_browser_mcp.sh

# Check status
ps aux | grep -E "(chrome|Xvfb)"
```