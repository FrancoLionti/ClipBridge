#!/bin/bash
# Install clipnotify for event-based clipboard monitoring
# This eliminates the need for polling and prevents typing interference

echo "============================================"
echo "Installing clipnotify"
echo "============================================"

# Check if already installed
if command -v clipnotify &> /dev/null; then
    echo "✅ clipnotify is already installed"
    exit 0
fi

# Install dependencies
echo "Installing build dependencies..."
sudo apt update
sudo apt install -y git build-essential libxfixes-dev

# Clone and build
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo "Cloning clipnotify..."
git clone https://github.com/cdown/clipnotify.git
cd clipnotify

echo "Building..."
make

echo "Installing..."
sudo make install

# Cleanup
cd /
rm -rf "$TEMP_DIR"

# Verify
if command -v clipnotify &> /dev/null; then
    echo ""
    echo "============================================"
    echo "✅ clipnotify installed successfully!"
    echo "============================================"
else
    echo ""
    echo "============================================"
    echo "❌ Installation failed"
    echo "============================================"
    exit 1
fi
