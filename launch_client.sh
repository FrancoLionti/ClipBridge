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

VENV="$DIR/.venv"
REQ="$DIR/requirements.txt"

if [ ! -d "$VENV" ]; then
    echo "📦 Creating virtual environment in .venv ..."
    if ! python3 -m venv "$VENV"; then
        echo "❌ Failed to create venv. On Debian/Ubuntu try: sudo apt install python3-venv"
        exit 1
    fi
fi

echo "📦 Ensuring dependencies (flask, requests, pyperclip, cryptography)..."
"$VENV/bin/pip" install -q -r "$REQ" || exit 1

echo "🚀 Starting ClipBridge Client..."
# Usage: ./launch_client.sh           → client (foreground sync)
#        ./launch_client.sh on       → client on (sync + clipbridge> shell)
#        ./launch_client.sh off      → client off (stop interactive on this PC)
#        ./launch_client.sh on --ip 192.168.1.5
exec "$VENV/bin/python" "$DIR/clipbridge.py" client "$@"
