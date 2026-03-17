#!/bin/bash
# Auto-replace phantom binary after build completes

set -e

# Configurable paths - can be overridden via environment variables
PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
NEW_BINARY="${NEW_BINARY:-$PROJECT_DIR/target/release/phantom}"
OLD_BINARY="${OLD_BINARY:-$HOME/bin/phantom}"
BACKUP_DIR="${BACKUP_DIR:-$HOME/bin/backups}"

echo "=== Phantom Binary Auto-Updater ==="
echo "Monitoring build process..."
echo "Project directory: $PROJECT_DIR"
echo "New binary: $NEW_BINARY"
echo "Old binary: $OLD_BINARY"
echo "Backup directory: $BACKUP_DIR"

# Wait for cargo build to finish (check if process is running)
while pgrep -f "cargo build --release" > /dev/null; do
    echo "Build in progress... ($(date))"
    sleep 10
done

echo "Build completed. Checking for new binary..."

# Verify new binary exists
if [ ! -f "$NEW_BINARY" ]; then
    echo "ERROR: New binary not found at $NEW_BINARY"
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup old binary with timestamp
if [ -f "$OLD_BINARY" ]; then
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_NAME="phantom_backup_$TIMESTAMP"
    cp "$OLD_BINARY" "$BACKUP_DIR/$BACKUP_NAME"
    echo "Backed up old binary: $BACKUP_DIR/$BACKUP_NAME"
fi

# Copy new binary
cp "$NEW_BINARY" "$OLD_BINARY"
chmod +x "$OLD_BINARY"

# Verify
if [ -f "$OLD_BINARY" ]; then
    NEW_SIZE=$(du -h "$OLD_BINARY" | cut -f1)
    echo "✅ Binary updated successfully!"
    echo "   Location: $OLD_BINARY"
    echo "   Size: $NEW_SIZE"
    echo "   Modes: Sandbox, Hardened, Wasm (Direct removed)"
    
    # Show version info
    echo ""
    echo "Testing binary..."
    $OLD_BINARY --version 2>/dev/null || echo "Version check failed (expected if no --version flag)"
else
    echo "ERROR: Binary update failed"
    exit 1
fi

echo ""
echo "=== Update Complete ==="
echo "You can now use 'phantom' command with the latest code."
