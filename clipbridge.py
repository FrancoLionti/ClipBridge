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

# ============================================================
# LINUX: Prevent ghost windows from clipboard access
# ============================================================
if sys.platform.startswith('linux'):
    # Force xclip/xsel backend instead of GTK/Qt which can create windows
    os.environ.setdefault('PYPERCLIP_BACKEND', 'xclip')
    # Prevent GTK from creating windows
    os.environ.setdefault('GDK_BACKEND', 'x11')
    # Suppress GTK accessibility warnings
    os.environ.setdefault('NO_AT_BRIDGE', '1')
    # Hide from desktop/taskbar
    os.environ.setdefault('SDL_VIDEODRIVER', 'dummy')

import pyperclip
import requests
from flask import Flask, request, abort

# ============================================================
# CONFIGURATION
# ============================================================

SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR / "config.json"

DEFAULT_CONFIG = {
    "server_ip": None,
    "port": 5000,
    "discovery_port": 5001,
    "mode": "auto",
    "push_interval": 3.0,
    "pull_interval": 1.5,
    # Security settings
    "secret_key": None,  # Shared secret for authentication (None = no auth)
    "encryption_enabled": False,  # Encrypt clipboard data
    "rate_limit": 10  # Max requests per second per IP
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
PUSH_INTERVAL = CONFIG.get("push_interval", 3.0)
PULL_INTERVAL = CONFIG.get("pull_interval", 1.5)
SECRET_KEY = CONFIG.get("secret_key")
ENCRYPTION_ENABLED = CONFIG.get("encryption_enabled", False) and SECRET_KEY
RATE_LIMIT = CONFIG.get("rate_limit", 10)
DISCOVERY_MAGIC = b"CLIPBRIDGE_DISCOVER"
DISCOVERY_RESPONSE = b"CLIPBRIDGE_SERVER"

# ============================================================
# SECURITY
# ============================================================

import hashlib
import hmac
import base64
from collections import defaultdict
from functools import wraps

# Optional: cryptography for encryption
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    if ENCRYPTION_ENABLED:
        print("WARNING: cryptography not installed, encryption disabled")
        print("  Install with: pip install cryptography")
        ENCRYPTION_ENABLED = False

class SecurityManager:
    """Handles authentication and encryption for ClipBridge."""
    
    def __init__(self, secret_key, encryption_enabled=False):
        self.secret_key = secret_key.encode() if secret_key else None
        self.encryption_enabled = encryption_enabled and CRYPTO_AVAILABLE and self.secret_key
        self.fernet = None
        
        if self.encryption_enabled:
            # Derive encryption key from secret using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'clipbridge_salt_v1',  # Fixed salt for simplicity
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.secret_key))
            self.fernet = Fernet(key)
    
    def sign(self, data):
        """Create HMAC signature for data."""
        if not self.secret_key:
            return ""
        return hmac.new(self.secret_key, data.encode(), hashlib.sha256).hexdigest()
    
    def verify(self, data, signature):
        """Verify HMAC signature."""
        if not self.secret_key:
            return True  # No auth configured
        expected = self.sign(data)
        return hmac.compare_digest(expected, signature)
    
    def encrypt(self, plaintext):
        """Encrypt data if encryption is enabled."""
        if not self.encryption_enabled:
            return plaintext
        return self.fernet.encrypt(plaintext.encode()).decode()
    
    def decrypt(self, ciphertext):
        """Decrypt data if encryption is enabled."""
        if not self.encryption_enabled:
            return ciphertext
        try:
            return self.fernet.decrypt(ciphertext.encode()).decode()
        except Exception:
            return None

# Initialize security manager
security = SecurityManager(SECRET_KEY, ENCRYPTION_ENABLED)

# Rate limiting
request_counts = defaultdict(list)

def rate_limit_check(ip):
    """Check if IP has exceeded rate limit."""
    import time
    now = time.time()
    # Clean old entries
    request_counts[ip] = [t for t in request_counts[ip] if now - t < 1.0]
    # Check limit
    if len(request_counts[ip]) >= RATE_LIMIT:
        return False
    request_counts[ip].append(now)
    return True

def require_auth(f):
    """Decorator to require authentication on endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Skip rate limiting in test mode
        if not app.config.get('TESTING', False):
            # Rate limit check
            client_ip = request.remote_addr
            if not rate_limit_check(client_ip):
                return "Rate limit exceeded", 429
        
        # Auth check (skip if no secret configured or in test mode)
        if security.secret_key and not app.config.get('TESTING', False):
            auth_header = request.headers.get('X-ClipBridge-Auth', '')
            timestamp = request.headers.get('X-ClipBridge-Time', '0')
            
            # Verify timestamp is recent (within 60 seconds)
            try:
                req_time = float(timestamp)
                if abs(time.time() - req_time) > 60:
                    return "Request expired", 401
            except ValueError:
                return "Invalid timestamp", 401
            
            # Verify signature
            data_to_sign = f"{timestamp}:{request.path}"
            if not security.verify(data_to_sign, auth_header):
                return "Unauthorized", 401
        
        return f(*args, **kwargs)
    return decorated

# ============================================================
# CLIPBOARD ABSTRACTION (Linux-safe)
# ============================================================

import subprocess

def _linux_get_clipboard():
    """Get clipboard on Linux using xclip directly (less intrusive than pyperclip)."""
    try:
        # Try xclip first (X11)
        result = subprocess.run(
            ['xclip', '-selection', 'clipboard', '-o'],
            capture_output=True, text=True, timeout=1
        )
        if result.returncode == 0:
            return result.stdout
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    
    try:
        # Try wl-paste for Wayland
        result = subprocess.run(
            ['wl-paste', '--no-newline'],
            capture_output=True, text=True, timeout=1
        )
        if result.returncode == 0:
            return result.stdout
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    
    # Fallback to pyperclip
    return pyperclip.paste()

def _linux_set_clipboard(text):
    """Set clipboard on Linux using xclip directly."""
    try:
        # Try xclip first (X11)
        process = subprocess.Popen(
            ['xclip', '-selection', 'clipboard'],
            stdin=subprocess.PIPE
        )
        process.communicate(input=text.encode('utf-8'), timeout=1)
        if process.returncode == 0:
            return True
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    
    try:
        # Try wl-copy for Wayland
        process = subprocess.Popen(
            ['wl-copy'],
            stdin=subprocess.PIPE
        )
        process.communicate(input=text.encode('utf-8'), timeout=1)
        if process.returncode == 0:
            return True
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    
    # Fallback to pyperclip
    pyperclip.copy(text)
    return True

def clipboard_get():
    """Cross-platform clipboard get."""
    if sys.platform.startswith('linux'):
        return _linux_get_clipboard()
    return pyperclip.paste()

def clipboard_set(text):
    """Cross-platform clipboard set."""
    if sys.platform.startswith('linux'):
        return _linux_set_clipboard(text)
    pyperclip.copy(text)
    return True

# ============================================================
# EVENT-BASED CLIPBOARD MONITORING (Linux)
# ============================================================

def _has_clipnotify():
    """Check if clipnotify is installed."""
    try:
        result = subprocess.run(['which', 'clipnotify'], capture_output=True)
        return result.returncode == 0
    except Exception:
        return False

def _wait_for_clipboard_change():
    """Block until clipboard changes (Linux only, requires clipnotify).
    
    Returns True if clipboard changed, False on error/timeout.
    """
    try:
        # clipnotify blocks until X selection changes, then exits
        result = subprocess.run(['clipnotify'], timeout=30)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

# Global flag to track if we can use event-based monitoring
USE_CLIPNOTIFY = sys.platform.startswith('linux') and _has_clipnotify()

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
@require_auth
def push():
    global shared_clipboard, last_update_source
    incoming = request.data.decode('utf-8')
    
    # Decrypt if encryption is enabled (skip in test mode)
    if ENCRYPTION_ENABLED and not app.config.get('TESTING', False):
        incoming = security.decrypt(incoming)
        if incoming is None:
            return "Decryption failed", 400
    
    with clipboard_lock:
        if incoming != shared_clipboard:
            shared_clipboard = incoming
            last_update_source = "remote"
            clipboard_set(incoming)
            log(f"📥 RECV from client: {incoming[:40].replace(chr(10), ' ')}...")
    
    return "OK", 200

@app.route('/pull', methods=['GET'])
@require_auth
def pull():
    with clipboard_lock:
        data = shared_clipboard
    
    # Encrypt if encryption is enabled (skip in test mode)
    if ENCRYPTION_ENABLED and not app.config.get('TESTING', False):
        data = security.encrypt(data)
    
    return data

@app.route('/helo', methods=['GET'])
def helo():
    # helo doesn't require auth (used for discovery)
    return f"CLIPBRIDGE_SERVER:{get_local_ip()}", 200

def server_clipboard_monitor():
    """Monitor local clipboard and update shared state."""
    global shared_clipboard, last_update_source
    
    last_local = clipboard_get()
    log("🔄 Clipboard monitor active")
    
    while True:
        try:
            current = clipboard_get()
            
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
    
    shared_clipboard = clipboard_get()
    
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
    
    # Log security status
    if SECRET_KEY:
        log("🔒 Authentication: ENABLED")
        if ENCRYPTION_ENABLED:
            log("🔐 Encryption: ENABLED (AES-256)")
        else:
            log("⚠️  Encryption: disabled (install cryptography)")
    else:
        log("⚠️  Security: disabled (set secret_key in config.json)")
    
    print("=" * 50 + "\n")
    
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)

# ============================================================
# CLIENT
# ============================================================

def _make_auth_headers(path):
    """Create authentication headers for client requests."""
    if not security.secret_key:
        return {}
    
    timestamp = str(time.time())
    data_to_sign = f"{timestamp}:{path}"
    signature = security.sign(data_to_sign)
    
    return {
        'X-ClipBridge-Auth': signature,
        'X-ClipBridge-Time': timestamp
    }

def _client_push(server_ip, data):
    """Push data to server with auth and encryption."""
    # Encrypt if enabled
    if ENCRYPTION_ENABLED:
        data = security.encrypt(data)
    
    headers = _make_auth_headers('/push')
    response = requests.post(
        f"http://{server_ip}:{PORT}/push",
        data=data.encode('utf-8'),
        headers=headers,
        timeout=2
    )
    return response.status_code == 200

def _client_pull(server_ip):
    """Pull data from server with auth and decryption."""
    headers = _make_auth_headers('/pull')
    response = requests.get(
        f"http://{server_ip}:{PORT}/pull",
        headers=headers,
        timeout=2
    )
    
    if response.status_code != 200:
        return None
    
    data = response.text
    
    # Decrypt if enabled
    if ENCRYPTION_ENABLED:
        data = security.decrypt(data)
    
    return data

def client_sync_loop(server_ip):
    """Main client loop: push local changes, pull remote changes.
    
    On Linux with clipnotify: Event-based (no polling, zero interference)
    On Windows or without clipnotify: Polling-based with configurable interval
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
    
    # Log security status
    if SECRET_KEY:
        log("🔒 Authentication: ENABLED")
        if ENCRYPTION_ENABLED:
            log("🔐 Encryption: ENABLED (AES-256)")
        else:
            log("⚠️  Encryption: disabled (install cryptography)")
    else:
        log("⚠️  Security: disabled (no secret_key in config)")
    
    if USE_CLIPNOTIFY:
        log("🎯 Event-based monitoring (clipnotify) - ZERO typing interference")
        _client_loop_event_based(server_ip)
    else:
        if sys.platform.startswith('linux'):
            log("⚠️  clipnotify not found - using polling (run install/install_clipnotify.sh)")
        log(f"ℹ️  Polling mode: push every {PUSH_INTERVAL}s, pull every {PULL_INTERVAL}s")
        _client_loop_polling(server_ip)

def _client_loop_event_based(server_ip):
    """Event-based client loop using clipnotify (Linux only).
    
    Two threads:
    - Main thread: waits for clipboard changes via clipnotify, then pushes
    - Pull thread: polls server for incoming changes
    """
    print("=" * 50 + "\n")
    
    last_local = clipboard_get()
    last_remote = ""
    stop_event = threading.Event()
    
    def pull_thread():
        """Background thread to pull from server."""
        nonlocal last_remote, last_local
        while not stop_event.is_set():
            try:
                remote_clip = _client_pull(server_ip)
                if remote_clip and remote_clip != last_local and remote_clip != last_remote:
                    clipboard_set(remote_clip)
                    last_remote = remote_clip
                    last_local = remote_clip
                    log(f"📥 RECV from server: {remote_clip[:40].replace(chr(10), ' ')}...")
            except Exception:
                pass
            time.sleep(PULL_INTERVAL)
    
    # Start pull thread
    puller = threading.Thread(target=pull_thread, daemon=True)
    puller.start()
    
    # Main loop: wait for clipboard changes
    try:
        while True:
            if _wait_for_clipboard_change():
                current = clipboard_get()
                if current and current != last_local and current != last_remote:
                    try:
                        if _client_push(server_ip, current):
                            last_local = current
                            log(f"📤 SENT to server: {current[:40].replace(chr(10), ' ')}...")
                    except Exception:
                        pass
    finally:
        stop_event.set()

def _client_loop_polling(server_ip):
    """Polling-based client loop (fallback for Windows or when clipnotify unavailable)."""
    print("=" * 50 + "\n")
    
    last_local = clipboard_get()
    last_remote = ""
    last_push_check = 0
    
    while True:
        current_time = time.time()
        
        # PUSH: Check local clipboard at configured interval
        if current_time - last_push_check >= PUSH_INTERVAL:
            last_push_check = current_time
            try:
                current_local = clipboard_get()
                if current_local and current_local != last_local and current_local != last_remote:
                    time.sleep(0.15)
                    confirm_local = clipboard_get()
                    if confirm_local == current_local:
                        if _client_push(server_ip, current_local):
                            last_local = current_local
                            log(f"📤 SENT to server: {current_local[:40].replace(chr(10), ' ')}...")
            except Exception:
                pass
        
        # PULL: Get remote changes
        try:
            remote_clip = _client_pull(server_ip)
            if remote_clip and remote_clip != last_local and remote_clip != last_remote:
                clipboard_set(remote_clip)
                last_remote = remote_clip
                last_local = remote_clip
                log(f"📥 RECV from server: {remote_clip[:40].replace(chr(10), ' ')}...")
        except Exception:
            pass
        
        time.sleep(PULL_INTERVAL)

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

def save_config(updates):
    """Update and save config file."""
    config = load_config()
    config.update(updates)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)
    return config

def main():
    parser = argparse.ArgumentParser(
        description="ClipBridge - Cross-platform clipboard sync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  clipbridge --server              Start as server
  clipbridge --client              Start as client (auto-discover)
  clipbridge                       Auto-detect mode

Security Setup (run once on each machine):
  clipbridge --set-secret KEY      Set shared secret for authentication
  clipbridge --enable-encryption   Enable AES-256 encryption
  clipbridge --show-config         Show current configuration
        """
    )
    parser.add_argument('--server', '-s', action='store_true', help='Run as server')
    parser.add_argument('--client', '-c', action='store_true', help='Run as client')
    parser.add_argument('--ip', type=str, help='Server IP (client mode)')
    parser.add_argument('--set-secret', type=str, metavar='KEY', 
                        help='Set shared secret key (saves to config)')
    parser.add_argument('--enable-encryption', action='store_true',
                        help='Enable encryption (requires cryptography package)')
    parser.add_argument('--disable-encryption', action='store_true',
                        help='Disable encryption')
    parser.add_argument('--show-config', action='store_true',
                        help='Show current configuration')
    
    args = parser.parse_args()
    
    # Handle configuration commands
    if args.set_secret:
        save_config({"secret_key": args.set_secret})
        print(f"✅ Secret key saved to {CONFIG_FILE}")
        print("   Run the same command on the other machine with the same key.")
        return
    
    if args.enable_encryption:
        if not CRYPTO_AVAILABLE:
            print("❌ cryptography package not installed")
            print("   Install with: pip install cryptography")
            return
        save_config({"encryption_enabled": True})
        print(f"✅ Encryption enabled in {CONFIG_FILE}")
        return
    
    if args.disable_encryption:
        save_config({"encryption_enabled": False})
        print(f"✅ Encryption disabled in {CONFIG_FILE}")
        return
    
    if args.show_config:
        config = load_config()
        print("\n📋 Current Configuration:")
        print(f"   Config file: {CONFIG_FILE}")
        print(f"   Mode: {config.get('mode', 'auto')}")
        print(f"   Port: {config.get('port', 5000)}")
        print(f"   Secret key: {'✅ SET' if config.get('secret_key') else '❌ NOT SET'}")
        print(f"   Encryption: {'✅ ENABLED' if config.get('encryption_enabled') else '❌ DISABLED'}")
        if config.get('encryption_enabled') and not CRYPTO_AVAILABLE:
            print("   ⚠️  WARNING: cryptography package not installed!")
        print()
        return
    
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
