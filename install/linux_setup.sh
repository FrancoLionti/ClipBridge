#!/bin/bash
# ClipBridge Ubuntu/Linux Installation Script

echo "============================================"
echo "ClipBridge - Linux Setup"
echo "============================================"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CLIPBRIDGE_DIR="$(dirname "$SCRIPT_DIR")"
SERVICE_FILE="$SCRIPT_DIR/clipbridge.service"
CURRENT_USER=$(whoami)

# Check dependencies
echo "Checking dependencies..."
python3 -c "import pyperclip" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing Python dependencies..."
    pip3 install -r "$CLIPBRIDGE_DIR/requirements.txt"
fi

# Check for xclip/xsel (needed for pyperclip on X11)
if [ "$XDG_SESSION_TYPE" = "x11" ]; then
    if ! command -v xclip &> /dev/null && ! command -v xsel &> /dev/null; then
        echo "Installing xclip for clipboard access..."
        sudo apt install -y xclip
    fi
fi

# Check for wl-clipboard (needed for Wayland)
if [ "$XDG_SESSION_TYPE" = "wayland" ]; then
    if ! command -v wl-copy &> /dev/null; then
        echo "Installing wl-clipboard for Wayland..."
        sudo apt install -y wl-clipboard
    fi
fi

# Create systemd user service
echo "Setting up systemd service..."
mkdir -p ~/.config/systemd/user/

# Update service file with actual paths and user
sed -e "s|YOUR_USERNAME|$CURRENT_USER|g" \
    -e "s|/home/YOUR_USERNAME/ClipBridge|$CLIPBRIDGE_DIR|g" \
    "$SERVICE_FILE" > ~/.config/systemd/user/clipbridge.service

# Reload and enable
systemctl --user daemon-reload
systemctl --user enable clipbridge.service
systemctl --user start clipbridge.service

echo ""
echo "============================================"
echo "Installation complete!"
echo ""
echo "Service status:"
systemctl --user status clipbridge.service --no-pager
echo ""
echo "Commands:"
echo "  Start:   systemctl --user start clipbridge"
echo "  Stop:    systemctl --user stop clipbridge"
echo "  Status:  systemctl --user status clipbridge"
echo "  Logs:    journalctl --user -u clipbridge -f"
echo "============================================"
