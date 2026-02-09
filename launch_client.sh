#!/bin/bash
# Launcher for ClipBridge Client on Linux

# Get the directory where this script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 could not be found."
    exit 1
fi

echo "🚀 Starting ClipBridge Client..."
python3 clipbridge.py --client
