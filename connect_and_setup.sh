#!/bin/bash

# Connection and Setup Script for Browser MCP
# This script connects to VPS and runs the setup

VPS_IP="41.216.189.245"
VPS_USER="root"
VPS_PASS="@intro%carbon-006"

echo "=== Connecting to VPS and Setting up Browser MCP ==="
echo "VPS: $VPS_USER@$VPS_IP"
echo ""

# Function to run commands on VPS
run_on_vps() {
    local command="$1"
    echo "Running: $command"
    
    # Use sshpass if available, otherwise use expect
    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_IP" "$command"
    else
        expect << EOF
spawn ssh -o StrictHostKeyChecking=no $VPS_USER@$VPS_IP
expect "password:"
send "$VPS_PASS\r"
expect "#"
send "$command\r"
expect "#"
send "exit\r"
expect eof
EOF
    fi
}

# Upload setup script to VPS
echo "1. Uploading setup script to VPS..."
if command -v scp >/dev/null 2>&1; then
    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$VPS_PASS" scp -o StrictHostKeyChecking=no setup_browser_mcp.sh "$VPS_USER@$VPS_IP:/root/"
    else
        echo "Please install sshpass or manually upload setup_browser_mcp.sh to VPS"
        echo "You can copy the contents and paste them into a file on the VPS"
    fi
else
    echo "SCP not available. Please manually upload setup_browser_mcp.sh to VPS"
fi

# Run setup commands step by step
echo "2. Running setup commands on VPS..."

echo "2.1. Updating system packages..."
run_on_vps "sudo apt update && sudo apt upgrade -y"

echo "2.2. Installing virtual display (Xvfb)..."
run_on_vps "sudo apt install -y xvfb"

echo "2.3. Installing Chrome browser..."
run_on_vps "wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -"
run_on_vps "echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' | sudo tee /etc/apt/sources.list.d/google-chrome.list"
run_on_vps "sudo apt update"
run_on_vps "sudo apt install -y google-chrome-stable"

echo "2.4. Installing browser automation dependencies..."
run_on_vps "sudo apt install -y x11-utils x11-xserver-utils xauth xfonts-100dpi xfonts-75dpi xfonts-scalable xfonts-cyrillic x11-apps"

echo "2.5. Installing Playwright..."
run_on_vps "npm install -g playwright"
run_on_vps "npx playwright install chromium"

echo "2.6. Creating browser startup script..."
run_on_vps "cat > /root/start_browser_mcp.sh << 'EOF'
#!/bin/bash
export DISPLAY=:99
Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &
sleep 2
google-chrome-stable --no-sandbox --disable-dev-shm-usage --disable-gpu --remote-debugging-port=9222 --disable-web-security --disable-features=VizDisplayCompositor --user-data-dir=/tmp/chrome-mcp --new-window --start-maximized &
echo 'Browser started with MCP support on display :99'
echo 'Remote debugging available on port 9222'
EOF"

run_on_vps "chmod +x /root/start_browser_mcp.sh"

echo "2.7. Configuring firewall..."
run_on_vps "sudo ufw allow 9222/tcp"
run_on_vps "sudo ufw allow 3000/tcp"
run_on_vps "sudo ufw allow 8080/tcp"

echo "2.8. Creating MCP configuration directory..."
run_on_vps "mkdir -p /root/.mcp"

echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Download Browser MCP extension to VPS"
echo "2. Start the browser: ssh $VPS_USER@$VPS_IP '/root/start_browser_mcp.sh'"
echo "3. Test connection with Gemini CLI"
echo ""
echo "To connect manually:"
echo "ssh $VPS_USER@$VPS_IP"
echo "Password: $VPS_PASS"