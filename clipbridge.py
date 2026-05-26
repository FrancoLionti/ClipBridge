#!/usr/bin/env python3
"""
ClipBridge - Cross-platform clipboard synchronization
https://github.com/FrancoLionti/ClipBridge
"""

__version__ = "2.0.4"

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Optional

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
from flask import Flask, request, abort, Response

# ============================================================
# CONFIGURATION
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent


def _path_looks_installed(package_root: Path) -> bool:
    """True when the package lives under site-packages/dist-packages (pip install)."""
    if getattr(sys, "frozen", False):
        return True  # PyInstaller / frozen: never write beside the exe
    parts = package_root.parts
    return "site-packages" in parts or "dist-packages" in parts


def _user_default_config_file(environ: Mapping[str, str]) -> Path:
    """Per-user config path (used when ClipBridge is installed as a Python package)."""
    if sys.platform.startswith("win"):
        base_raw = environ.get("LOCALAPPDATA", "").strip()
        base = Path(base_raw).expanduser() if base_raw else Path.home() / "AppData" / "Local"
        return base / "clipbridge" / "config.json"
    if sys.platform == "darwin":
        home = Path.home()
        return home / "Library" / "Application Support" / "clipbridge" / "config.json"
    xdg = (environ.get("XDG_CONFIG_HOME") or "").strip()
    root = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return root / "clipbridge" / "config.json"


def resolve_config_file(
    package_root: Path,
    environ: Optional[Mapping[str, str]] = None,
) -> Path:
    """Where to store config.json: env override → repo-local (dev clone) → XDG-ish user dir."""

    envmap = environ if environ is not None else os.environ
    raw = (envmap.get("CLIPBRIDGE_CONFIG") or "").strip()
    if raw:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        if p.is_dir():
            return p / "config.json"
        return p
    if not _path_looks_installed(package_root):
        return package_root / "config.json"
    return _user_default_config_file(envmap)


CONFIG_FILE = resolve_config_file(SCRIPT_DIR)


def _interactive_pid_path() -> Path:
    """File written while ``clipbridge client on`` runs; removed on clean exit."""
    return CONFIG_FILE.parent / "interactive_client.pid"


def _interactive_pid_record() -> None:
    path = _interactive_pid_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()), encoding="utf-8")


def _interactive_pid_clear() -> None:
    try:
        _interactive_pid_path().unlink(missing_ok=True)
    except OSError:
        pass


def _process_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            ).stdout
        except OSError:
            return False
        if not out or "no tasks" in out.lower():
            return False
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _pid_cmdline_for_verify(pid: int) -> str:
    if sys.platform.startswith("linux"):
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
            return raw.replace(b"\0", b" ").decode("utf-8", errors="replace")
        except OSError:
            return ""
    if sys.platform == "win32":
        try:
            out = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(Get-CimInstance Win32_Process -Filter "
                    f"'ProcessId = {pid}' -ErrorAction SilentlyContinue)"
                    ".CommandLine",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            ).stdout.strip()
            return out
        except FileNotFoundError:
            pass
        except OSError:
            pass
    return ""


def _pid_targets_clipbridge(pid: int) -> bool:
    hay = _pid_cmdline_for_verify(pid).lower()
    if not hay:
        return False
    return "clipbridge" in hay or "clipbridge.py" in hay


def stop_remote_interactive_client() -> None:
    """Tell a running ``clipbridge client on`` (same machine, same config dir) to stop.

    Sends SIGINT on Unix (same as Ctrl+C in the REPL). On Windows uses ``taskkill`` without ``/F``.
    """
    path = _interactive_pid_path()
    if not path.is_file():
        log("❌ No interactive client PID file — nothing to stop. Start one with: clipbridge client on")
        return
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except ValueError:
        log("⚠️  Clearing invalid PID file.")
        path.unlink(missing_ok=True)
        return

    if not _process_exists(pid):
        log("⚠️  Process is gone — removing stale PID file.")
        path.unlink(missing_ok=True)
        return

    if not _pid_targets_clipbridge(pid):
        log(
            f"⚠️  Refusing to signal PID {pid} (does not look like ClipBridge). "
            f"Delete {path} manually if it is stuck."
        )
        return

    log(f"🛑 Stopping interactive client (PID {pid})…")
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(pid)],
                capture_output=True,
                timeout=45,
                check=False,
            )
        else:
            os.kill(pid, signal.SIGINT)
    except ProcessLookupError:
        log("👋 Interactive client already exited.")
    except Exception as e:
        log(f"❌ Could not signal process: {e}")
        return
    path.unlink(missing_ok=True)


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
ENCRYPTION_ENABLED = bool(CONFIG.get("encryption_enabled", False) and SECRET_KEY)
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
        self.encryption_enabled = bool(encryption_enabled and CRYPTO_AVAILABLE and self.secret_key)
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
        try:
            result = self.fernet.encrypt(plaintext.encode()).decode()
            return result
        except Exception as e:
            print(f"⚠️ Encryption error: {e}")
            return plaintext
    
    def decrypt(self, ciphertext):
        """Decrypt data if encryption is enabled."""
        if not self.encryption_enabled:
            return ciphertext
        try:
            return self.fernet.decrypt(ciphertext.encode()).decode()
        except Exception as e:
            print(f"⚠️ Decryption error: {e}")
            # Return as-is if decryption fails (might be unencrypted)
            return ciphertext

# Initialize security manager
security = SecurityManager(SECRET_KEY, ENCRYPTION_ENABLED)

# Stable ciphertext for a given (rev, plaintext) so long-poll clients don't see a new token every request.
_enc_wire_lock = threading.Lock()
_enc_wire_cache_key = None  # (rev, plain)
_enc_wire_cache_val = None


def _payload_looks_fernet_token(data: str) -> bool:
    """Heuristic: Fernet wire tokens are long urlsafe-base64 strings (version 0x80 → often 'gAAAA…')."""
    if not data:
        return False
    s = data.strip()
    if len(s) < 32:
        return False
    if not s.startswith("gAAAA"):
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
    return all(c in allowed for c in s)


def _encrypted_payload_for_response(plain_text: str, rev: int) -> str:
    """Return wire payload; encryption is stable until (rev, plaintext) changes."""
    global _enc_wire_cache_key, _enc_wire_cache_val
    if not security.encryption_enabled or app.config.get("TESTING", False):
        return plain_text
    key = (rev, plain_text)
    with _enc_wire_lock:
        if key == _enc_wire_cache_key:
            return _enc_wire_cache_val
        _enc_wire_cache_key = key
        _enc_wire_cache_val = security.encrypt(plain_text)
        return _enc_wire_cache_val


def ensure_crypto_if_encryption_configured():
    """Exit with a clear message if config requests encryption but cryptography is missing."""
    if not bool(CONFIG.get("encryption_enabled", False) and CONFIG.get("secret_key")):
        return
    if CRYPTO_AVAILABLE:
        return
    print(
        "ERROR: config.json has encryption_enabled=true but the 'cryptography' package is not installed.\n"
        "  Fix: pip install cryptography   (use the same venv as ClipBridge)\n"
        "  Or set encryption_enabled to false on this machine.",
        file=sys.stderr,
    )
    sys.exit(1)

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


def _clip_sync_equal(a, b):
    """Whether two clipboard strings are the same for sync (avoids xclip/Wayland newline quirks)."""
    sa = "" if a is None else a
    sb = "" if b is None else b
    if sa == sb:
        return True
    return sa.rstrip("\r\n") == sb.rstrip("\r\n")


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

def _wait_for_clipboard_change(stop_event=None):
    """Block until clipboard changes (Linux only, requires clipnotify).

    If ``stop_event`` is set, the waiting ``clipnotify`` child is terminated and
    this returns False so the client loop can exit promptly (e.g. interactive mode).

    Returns True if clipboard changed, False on error or stop.
    """
    if stop_event and stop_event.is_set():
        return False
    try:
        proc = subprocess.Popen(
            ["clipnotify"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        while True:
            if stop_event and stop_event.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                return False
            code = proc.poll()
            if code is not None:
                return code == 0
            time.sleep(0.2)
    except FileNotFoundError:
        return False
    except Exception:
        return False

# Global flag to track if we can use event-based monitoring
USE_CLIPNOTIFY = sys.platform.startswith('linux') and _has_clipnotify()

# ============================================================
# LOGGING
# ============================================================

_log_lock = threading.Lock()


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    with _log_lock:
        print(line, flush=True)

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
clipboard_condition = threading.Condition()
shared_clipboard = ""
clipboard_rev = 0
last_update_source = "init"

@app.route('/push', methods=['POST'])
@require_auth
def push():
    global shared_clipboard, last_update_source, clipboard_rev
    incoming = request.data.decode('utf-8')
    
    # Decrypt only if body looks like a Fernet token (mixed clients / plaintext push).
    if security.encryption_enabled and not app.config.get('TESTING', False):
        if _payload_looks_fernet_token(incoming):
            decrypted = security.decrypt(incoming)
            if decrypted != incoming:
                incoming = decrypted
                log("🔓 Decrypted incoming data")
    
    with clipboard_condition:
        if incoming != shared_clipboard:
            shared_clipboard = incoming
            clipboard_rev += 1
            last_update_source = "remote"
            clipboard_set(incoming)
            clipboard_condition.notify_all()
            log(f"📥 RECV from client: {incoming[:40].replace(chr(10), ' ')}...")
    
    return "OK", 200

@app.route('/pull', methods=['GET'])
@require_auth
def pull():
    with clipboard_condition:
        data = shared_clipboard
        rev = clipboard_rev
    
    if security.encryption_enabled and not app.config.get('TESTING', False):
        data = _encrypted_payload_for_response(data, rev)
    
    return data


@app.route('/pull_wait', methods=['GET'])
@require_auth
def pull_wait():
    """Long-poll: block until shared clipboard revision advances past ``since`` (or timeout).

    Query params:
      since: last revision seen by client; use -1 for an immediate snapshot (no wait).
      timeout: max seconds to wait (0.5–60, default 30).
    Response header: X-ClipBridge-Rev — current revision after wait.
    """
    try:
        since = int(request.args.get("since", "-1"))
    except ValueError:
        since = -1
    try:
        timeout_s = float(request.args.get("timeout", "30"))
    except ValueError:
        timeout_s = 30.0
    timeout_s = max(0.5, min(timeout_s, 60.0))

    deadline = time.time() + timeout_s

    with clipboard_condition:
        if since < 0:
            payload = shared_clipboard
            rev_out = clipboard_rev
        else:
            while clipboard_rev <= since:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                clipboard_condition.wait(timeout=remaining)
            payload = shared_clipboard
            rev_out = clipboard_rev

    if security.encryption_enabled and not app.config.get("TESTING", False):
        payload = _encrypted_payload_for_response(payload, rev_out)

    body = payload if isinstance(payload, (bytes, bytearray)) else (payload or "")
    return Response(
        body,
        status=200,
        headers={"X-ClipBridge-Rev": str(rev_out)},
        mimetype="text/plain",
    )

@app.route('/helo', methods=['GET'])
def helo():
    # helo doesn't require auth (used for discovery)
    return f"CLIPBRIDGE_SERVER:{get_local_ip()}", 200

def server_clipboard_monitor():
    """Monitor local clipboard and update shared state."""
    global shared_clipboard, last_update_source, clipboard_rev
    
    last_local = clipboard_get()
    log("🔄 Clipboard monitor active")
    
    while True:
        try:
            current = clipboard_get()
            
            with clipboard_condition:
                if current != last_local:
                    if last_update_source != "remote" or current != shared_clipboard:
                        old = shared_clipboard
                        shared_clipboard = current
                        last_update_source = "local"
                        if current != old:
                            clipboard_rev += 1
                            clipboard_condition.notify_all()
                        log(f"📋 LOCAL copy: {current[:40].replace(chr(10), ' ')}...")
                    last_local = current
                    
        except Exception as e:
            log(f"⚠️ Monitor error: {e}")
        
        time.sleep(0.8)

def start_server():
    global shared_clipboard, clipboard_rev
    
    ensure_crypto_if_encryption_configured()
    local_ip = get_local_ip()
    
    print("\n" + "=" * 50)
    print("   CLIPBRIDGE SERVER")
    print("=" * 50)
    log(f"🚀 Server starting on {local_ip}:{PORT}")
    
    # Check if port is already in use
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', PORT))
        sock.close()
    except OSError:
        log(f"❌ Error: Port {PORT} is already in use!")
        log("   Is ClipBridge already running?")
        sys.exit(1)
    
    with clipboard_condition:
        shared_clipboard = clipboard_get()
        clipboard_rev = 1
        clipboard_condition.notify_all()
    
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


def _client_pull_wait(server_ip, since_rev):
    """Block until the server's clipboard revision advances past ``since_rev`` (or timeout).

    Returns ``(text, new_rev)``. ``new_rev`` is None on network/HTTP failure — caller
    should retry with a short backoff. ``since_rev`` of ``-1`` always returns immediately
    with the current snapshot (used for the first request).
    """
    headers = _make_auth_headers('/pull_wait')
    try:
        response = requests.get(
            f"http://{server_ip}:{PORT}/pull_wait",
            params={"since": since_rev, "timeout": 30},
            headers=headers,
            timeout=35,
        )
    except requests.RequestException:
        return None, None

    if response.status_code != 200:
        return None, None

    try:
        new_rev = int(response.headers.get("X-ClipBridge-Rev", ""))
    except ValueError:
        new_rev = None

    data = response.text
    if ENCRYPTION_ENABLED:
        data = security.decrypt(data)

    return data, new_rev

def client_sync_loop(server_ip, stop_event=None):
    """Main client loop: push local changes, pull remote changes.

    Local clipboard:
      Linux + clipnotify: event-based (no polling).
      Otherwise: polling on ``push_interval``.

    Remote clipboard: long-poll ``/pull_wait`` (blocks until the server has something
    new, or a timeout). No periodic GET storm to ``/pull``.

    Pass ``stop_event`` to interrupt the loop (e.g. ``clipbridge client on`` REPL ``exit``).
    """

    ensure_crypto_if_encryption_configured()
    if stop_event is None:
        stop_event = threading.Event()
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
        log("🎯 Local clipboard: clipnotify (event-based, no polling)")
        log("📡 Remote clipboard: long-poll /pull_wait (blocked until server updates)")
        _client_loop_event_based(server_ip, stop_event)
    else:
        if sys.platform.startswith('linux'):
            log("⚠️  clipnotify not found - local clipboard polling (run install/install_clipnotify.sh)")
        log(f"ℹ️  Local clipboard poll every {PUSH_INTERVAL}s · Remote: long-poll (no pull interval)")
        _client_loop_polling(server_ip, stop_event)

def _client_loop_event_based(server_ip, stop_event):
    """Linux + clipnotify: local changes via clipnotify; remote changes via long-poll."""
    print("=" * 50 + "\n")
    
    last_local = clipboard_get()
    last_remote = ""
    backoff = min(5.0, max(0.5, PULL_INTERVAL))
    
    def pull_thread():
        """Background thread: block on /pull_wait until the server revision advances."""
        nonlocal last_remote, last_local
        last_seen_rev = -1
        while not stop_event.is_set():
            try:
                remote_clip, new_rev = _client_pull_wait(server_ip, last_seen_rev)
                if new_rev is not None:
                    last_seen_rev = new_rev
                if remote_clip is None and new_rev is None:
                    time.sleep(backoff)
                    continue
                if (
                    remote_clip
                    and not _clip_sync_equal(remote_clip, last_local)
                    and not _clip_sync_equal(remote_clip, last_remote)
                ):
                    last_remote = remote_clip
                    last_local = remote_clip
                    clipboard_set(remote_clip)
                    read_back = clipboard_get()
                    if read_back is not None:
                        last_local = read_back
                    log(f"📥 RECV from server: {remote_clip[:40].replace(chr(10), ' ')}...")
            except Exception:
                time.sleep(backoff)
    
    # Start pull thread
    puller = threading.Thread(target=pull_thread, daemon=True)
    puller.start()

    # Main loop: wait for clipboard changes
    try:
        while not stop_event.is_set():
            if _wait_for_clipboard_change(stop_event):
                current = clipboard_get()
                if (
                    current
                    and not _clip_sync_equal(current, last_local)
                    and not _clip_sync_equal(current, last_remote)
                ):
                    try:
                        if _client_push(server_ip, current):
                            last_local = current
                            log(f"📤 SENT to server: {current[:40].replace(chr(10), ' ')}...")
                    except Exception:
                        pass
    finally:
        stop_event.set()

def _client_loop_polling(server_ip, stop_event):
    """Fallback: poll local clipboard on ``push_interval``; remote side uses long-poll."""
    print("=" * 50 + "\n")
    
    last_local = clipboard_get()
    last_remote = ""
    last_push_check = 0
    backoff = min(5.0, max(0.5, PULL_INTERVAL))

    def pull_thread():
        nonlocal last_remote, last_local
        last_seen_rev = -1
        while not stop_event.is_set():
            try:
                remote_clip, new_rev = _client_pull_wait(server_ip, last_seen_rev)
                if new_rev is not None:
                    last_seen_rev = new_rev
                if remote_clip is None and new_rev is None:
                    time.sleep(backoff)
                    continue
                if (
                    remote_clip
                    and not _clip_sync_equal(remote_clip, last_local)
                    and not _clip_sync_equal(remote_clip, last_remote)
                ):
                    last_remote = remote_clip
                    last_local = remote_clip
                    clipboard_set(remote_clip)
                    read_back = clipboard_get()
                    if read_back is not None:
                        last_local = read_back
                    log(f"📥 RECV from server: {remote_clip[:40].replace(chr(10), ' ')}...")
            except Exception:
                time.sleep(backoff)

    puller = threading.Thread(target=pull_thread, daemon=True)
    puller.start()

    try:
        while not stop_event.is_set():
            current_time = time.time()

            if current_time - last_push_check >= PUSH_INTERVAL:
                last_push_check = current_time
                try:
                    current_local = clipboard_get()
                    if (
                        current_local
                        and not _clip_sync_equal(current_local, last_local)
                        and not _clip_sync_equal(current_local, last_remote)
                    ):
                        time.sleep(0.15)
                        confirm_local = clipboard_get()
                        if confirm_local == current_local:
                            if _client_push(server_ip, current_local):
                                last_local = current_local
                                log(f"📤 SENT to server: {current_local[:40].replace(chr(10), ' ')}...")
                except Exception:
                    pass

            time.sleep(0.5)
    finally:
        stop_event.set()


def _resolve_client_server_ip(cmdline_ip=None):
    """Return server IP from CLI override, config, or UDP discovery."""
    server_ip = cmdline_ip or CONFIG.get("server_ip")
    if not server_ip:
        server_ip = discover_server(timeout=5)
    return server_ip


def run_interactive_client(server_ip):
    """Run sync in a background thread and accept commands on stdin (``client on``)."""
    stop_event = threading.Event()
    sync_thread = threading.Thread(
        target=client_sync_loop,
        args=(server_ip, stop_event),
        name="ClipBridgeSync",
        daemon=False,
    )
    sync_thread.start()
    time.sleep(0.4)
    if not sync_thread.is_alive():
        log("❌ Client thread stopped (could not connect or config error).")
        return

    _interactive_pid_record()
    try:
        print()
        print("=" * 50)
        print("   CLIPBRIDGE INTERACTIVE CLIENT")
        print("=" * 50)
        print(f"   Server: {server_ip}:{PORT}")
        print("   Sync runs in the background. Type 'help' for commands.")
        print("=" * 50)
        print()

        _interactive_client_repl(stop_event, sync_thread, server_ip)
    finally:
        _interactive_pid_clear()


def _interactive_client_repl(stop_event, sync_thread, server_ip):
    """Simple command loop; sync logs may appear between prompts."""
    while True:
        try:
            line = input("clipbridge> ")
        except EOFError:
            print()
            line = "exit"
        except KeyboardInterrupt:
            print()
            line = "exit"

        parts = line.strip().split()
        cmd = parts[0].lower() if parts else ""

        if cmd in ("",):
            continue
        if cmd in ("exit", "quit", "q", "off"):
            log("🛑 Stopping sync…")
            stop_event.set()
            sync_thread.join(timeout=20)
            if sync_thread.is_alive():
                log("⚠️  Sync thread did not exit in time; exiting anyway.")
            else:
                log("👋 Sync stopped.")
            return
        if cmd in ("help", "?", "h"):
            print(
                "\nCommands:\n"
                "  help     — this text\n"
                "  status   — ping the server (/helo)\n"
                "  off      — stop sync and leave (same as exit / Ctrl+C)\n"
                "  exit     — same as off (also Ctrl+D)\n"
            )
            continue
        if cmd == "status":
            try:
                resp = requests.get(f"http://{server_ip}:{PORT}/helo", timeout=3)
                ok = resp.status_code == 200
                print(f"  Server: {'OK — ' + resp.text if ok else 'HTTP ' + str(resp.status_code)}")
            except Exception as e:
                print(f"  Server: unreachable ({type(e).__name__}: {e})")
            continue

        print(f"  Unknown command: {cmd!r}. Type 'help'.")


def start_client(cmdline_ip=None, interactive_shell=False):
    server_ip = _resolve_client_server_ip(cmdline_ip)

    if not server_ip:
        log("❌ No server found. Options:")
        log("   1. Start a server: python clipbridge.py server")
        log("   2. Set server_ip in config.json")
        return

    if interactive_shell:
        run_interactive_client(server_ip)
    else:
        client_sync_loop(server_ip)

# ============================================================
# MAIN
# ============================================================

def save_config(updates):
    """Update and save config file."""
    config = load_config()
    config.update(updates)
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)
    return config

def main():
    parser = argparse.ArgumentParser(
        description=f"ClipBridge {__version__} - Cross-platform clipboard sync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  clipbridge server              Start as server
  clipbridge client              Start as client (auto-discover)
  clipbridge client on           Client + interactive shell (commands while syncing)
  clipbridge client off          Stop a running interactive client (other terminal)
  clipbridge --server            Same as: clipbridge server
  clipbridge --client            Same as: clipbridge client
  clipbridge                     Auto-detect mode

Security Setup (run once on each machine):
  clipbridge --set-secret KEY      Set shared secret for authentication
  clipbridge --enable-encryption   Enable AES-256 encryption
  clipbridge --show-config         Show current configuration
        """
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ClipBridge {__version__}",
        help="Show version and exit",
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

    subparsers = parser.add_subparsers(dest='subcmd', metavar='COMMAND')
    subparsers.add_parser(
        'server',
        help='Run as server (same as --server)',
    )
    p_client_cmd = subparsers.add_parser(
        'client',
        help='Run as client (same as --client). Use "on" / "off" for interactive control.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Try: clipbridge client on   |   clipbridge client off",
    )
    p_client_cmd.add_argument(
        'interactive',
        nargs='?',
        choices=['on', 'off'],
        default=None,
        metavar='on|off',
        help='"on": REPL + background sync; "off": stop that session (same PC, see PID file)',
    )
    p_client_cmd.add_argument('--ip', type=str, help='Server IP (skip discovery)')
    
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
    subcmd = getattr(args, "subcmd", None)

    if subcmd == 'server':
        start_server()
        return
    if subcmd == 'client':
        if args.interactive == 'on':
            start_client(cmdline_ip=args.ip, interactive_shell=True)
        elif args.interactive == 'off':
            stop_remote_interactive_client()
        elif args.ip:
            client_sync_loop(args.ip)
        else:
            start_client()
        return

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
