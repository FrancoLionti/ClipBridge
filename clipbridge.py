#!/usr/bin/env python3
"""
ClipBridge - Cross-platform clipboard synchronization
https://github.com/YOUR_USERNAME/ClipBridge
"""

import argparse
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import pyperclip
import requests
from flask import Flask, request

# ============================================================
# CONFIGURATION
# ============================================================

SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR / "config.json"

DEFAULT_CONFIG = {
    "server_ip": None,
    "port": 5000,
    "discovery_port": 5001,
    "mode": "auto"
}

def load_config():
    """Load config from file or return defaults."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                user_config = json.load(f)
                return {**DEFAULT_CONFIG, **user_config}
        except Exception:
            pass
    return DEFAULT_CONFIG

CONFIG = load_config()
PORT = CONFIG["port"]
DISCOVERY_PORT = CONFIG["discovery_port"]
DISCOVERY_MAGIC = b"CLIPBRIDGE_DISCOVER"
DISCOVERY_RESPONSE = b"CLIPBRIDGE_SERVER"

# ============================================================
# LOGGING
# ============================================================

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

# ============================================================
# AUTO-DISCOVERY
# ============================================================

def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def discovery_responder():
    """Server: Respond to UDP discovery broadcasts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(("", DISCOVERY_PORT))
        log(f"📡 Discovery responder listening on UDP:{DISCOVERY_PORT}")
        
        while True:
            data, addr = sock.recvfrom(1024)
            if data == DISCOVERY_MAGIC:
                log(f"🔍 Discovery request from {addr[0]}")
                response = DISCOVERY_RESPONSE + b":" + get_local_ip().encode()
                sock.sendto(response, addr)
    except Exception as e:
        log(f"⚠️ Discovery responder error: {e}")
    finally:
        sock.close()

def discover_server(timeout=5):
    """Client: Send UDP broadcast to find server."""
    log("🔍 Searching for ClipBridge server on network...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    
    try:
        # Send broadcast
        sock.sendto(DISCOVERY_MAGIC, ("<broadcast>", DISCOVERY_PORT))
        
        # Wait for response
        data, addr = sock.recvfrom(1024)
        if data.startswith(DISCOVERY_RESPONSE):
            server_ip = data.split(b":")[1].decode()
            log(f"✅ Found server at {server_ip}")
            return server_ip
    except socket.timeout:
        log("⏰ Discovery timeout - no server found")
    except Exception as e:
        log(f"⚠️ Discovery error: {e}")
    finally:
        sock.close()
    
    return None

# ============================================================
# SERVER
# ============================================================

app = Flask(__name__)
clipboard_lock = threading.Lock()
shared_clipboard = ""
last_update_source = "init"

@app.route('/push', methods=['POST'])
def push():
    global shared_clipboard, last_update_source
    incoming = request.data.decode('utf-8')
    
    with clipboard_lock:
        if incoming != shared_clipboard:
            shared_clipboard = incoming
            last_update_source = "remote"
            pyperclip.copy(incoming)
            log(f"📥 RECV from client: {incoming[:40].replace(chr(10), ' ')}...")
    
    return "OK", 200

@app.route('/pull', methods=['GET'])
def pull():
    with clipboard_lock:
        return shared_clipboard

@app.route('/helo', methods=['GET'])
def helo():
    return f"CLIPBRIDGE_SERVER:{get_local_ip()}", 200

def server_clipboard_monitor():
    """Monitor local clipboard and update shared state."""
    global shared_clipboard, last_update_source
    
    last_local = pyperclip.paste()
    log("🔄 Clipboard monitor active")
    
    while True:
        try:
            current = pyperclip.paste()
            
            with clipboard_lock:
                if current != last_local:
                    if last_update_source != "remote" or current != shared_clipboard:
                        shared_clipboard = current
                        last_update_source = "local"
                        log(f"📋 LOCAL copy: {current[:40].replace(chr(10), ' ')}...")
                    last_local = current
                    
        except Exception as e:
            log(f"⚠️ Monitor error: {e}")
        
        time.sleep(0.8)

def start_server():
    global shared_clipboard
    
    local_ip = get_local_ip()
    
    print("\n" + "=" * 50)
    print("   CLIPBRIDGE SERVER")
    print("=" * 50)
    log(f"🚀 Server starting on {local_ip}:{PORT}")
    
    shared_clipboard = pyperclip.paste()
    
    # Start discovery responder
    discovery_thread = threading.Thread(target=discovery_responder, daemon=True)
    discovery_thread.start()
    
    # Start clipboard monitor
    monitor_thread = threading.Thread(target=server_clipboard_monitor, daemon=True)
    monitor_thread.start()
    
    # Silence Flask logs
    import logging
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    
    log("✅ Server ready - waiting for clients...")
    print("=" * 50 + "\n")
    
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)

# ============================================================
# CLIENT
# ============================================================

def client_sync_loop(server_ip):
    """Main client loop: push local changes, pull remote changes.
    
    Uses smart polling to avoid interfering with typing:
    - Longer base interval (2 seconds)
    - Only reads clipboard occasionally for push
    - Prioritizes pull operations (server -> client)
    """
    
    print("\n" + "=" * 50)
    print("   CLIPBRIDGE CLIENT")
    print("=" * 50)
    log(f"🔗 Connecting to server: {server_ip}:{PORT}")
    
    # Verify connection
    connected = False
    for attempt in range(3):
        try:
            resp = requests.get(f"http://{server_ip}:{PORT}/helo", timeout=3)
            if resp.status_code == 200:
                log(f"✅ Connected: {resp.text}")
                connected = True
                break
        except Exception as e:
            log(f"⚠️ Attempt {attempt+1}/3 failed: {type(e).__name__}")
            time.sleep(1)
    
    if not connected:
        log("❌ Could not connect to server")
        log("   Check firewall settings and server status")
        return
    
    log("✅ Sync active - Ctrl+C to stop")
    log("ℹ️  Smart polling enabled (reduced interference with typing)")
    print("=" * 50 + "\n")
    
    last_local = pyperclip.paste()
    last_remote = ""
    last_push_check = 0
    push_check_interval = 2.0  # Only check local clipboard every 2 seconds
    pull_interval = 1.5  # Check server more frequently for incoming changes
    
    while True:
        current_time = time.time()
        
        # PUSH: Check local clipboard less frequently to avoid typing interference
        if current_time - last_push_check >= push_check_interval:
            last_push_check = current_time
            try:
                current_local = pyperclip.paste()
                if current_local != last_local and current_local != last_remote:
                    # Wait a tiny bit to ensure clipboard is stable (user finished copying)
                    time.sleep(0.1)
                    confirm_local = pyperclip.paste()
                    if confirm_local == current_local:  # Clipboard is stable
                        requests.post(
                            f"http://{server_ip}:{PORT}/push",
                            data=current_local.encode('utf-8'),
                            timeout=2
                        )
                        last_local = current_local
                        log(f"📤 SENT to server: {current_local[:40].replace(chr(10), ' ')}...")
            except Exception:
                pass
        
        # PULL: Get remote changes (this doesn't interfere with typing)
        try:
            resp = requests.get(f"http://{server_ip}:{PORT}/pull", timeout=1)
            if resp.status_code == 200:
                remote_clip = resp.text
                if remote_clip and remote_clip != last_local and remote_clip != last_remote:
                    pyperclip.copy(remote_clip)
                    last_remote = remote_clip
                    last_local = remote_clip
                    log(f"📥 RECV from server: {remote_clip[:40].replace(chr(10), ' ')}...")
        except Exception:
            pass
        
        time.sleep(pull_interval)

def start_client():
    # Check for manual IP in config
    server_ip = CONFIG.get("server_ip")
    
    if not server_ip:
        # Try auto-discovery
        server_ip = discover_server(timeout=5)
    
    if not server_ip:
        log("❌ No server found. Options:")
        log("   1. Start a server: python clipbridge.py --server")
        log("   2. Set server_ip in config.json")
        return
    
    client_sync_loop(server_ip)

# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="ClipBridge - Cross-platform clipboard sync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python clipbridge.py --server    # Start as server
  python clipbridge.py --client    # Start as client (auto-discover)
  python clipbridge.py             # Auto-detect mode
        """
    )
    parser.add_argument('--server', '-s', action='store_true', help='Run as server')
    parser.add_argument('--client', '-c', action='store_true', help='Run as client')
    parser.add_argument('--ip', type=str, help='Server IP (client mode)')
    
    args = parser.parse_args()
    
    # Override from config
    config_mode = CONFIG.get("mode", "auto")
    
    if args.server:
        start_server()
    elif args.client:
        if args.ip:
            client_sync_loop(args.ip)
        else:
            start_client()
    elif config_mode == "server":
        start_server()
    elif config_mode == "client":
        start_client()
    else:
        # Auto mode: try to discover, if no server found, become server
        log("🔄 Auto-detecting mode...")
        server_ip = discover_server(timeout=3)
        
        if server_ip:
            log("Found existing server, starting as client...")
            client_sync_loop(server_ip)
        else:
            log("No server found, starting as server...")
            start_server()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        log("👋 ClipBridge stopped")
        sys.exit(0)
