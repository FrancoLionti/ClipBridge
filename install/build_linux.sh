#!/bin/bash
# Build script for ClipBridge Linux executable
# Run this on Ubuntu/Linux to create the portable binary

echo "============================================"
echo "ClipBridge - Linux Build Script"
echo "============================================"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is required"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
pip3 install -r requirements.txt
pip3 install pyinstaller

# Build executable (excluding Qt packages we don't need)
echo "Building executable..."
python3 -m PyInstaller --onefile --name clipbridge --console \
    --exclude-module PyQt5 \
    --exclude-module PyQt6 \
    --exclude-module PySide2 \
    --exclude-module PySide6 \
    --exclude-module tkinter \
    --exclude-module matplotlib \
    --exclude-module numpy \
    --exclude-module IPython \
    clipbridge.py

# Move to dist folder
if [ -f "dist/clipbridge" ]; then
    echo ""
    echo "============================================"
    echo "SUCCESS! Executable created at:"
    echo "  $(pwd)/dist/clipbridge"
    echo ""
    echo "Usage:"
    echo "  ./dist/clipbridge --server"
    echo "  ./dist/clipbridge --client"
    echo "============================================"
else
    echo "ERROR: Build failed"
    exit 1
fi
