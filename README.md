# ClipBridge 📋🔗

Cross-platform clipboard synchronization between Windows and Linux machines on the same network.

Repository: **[github.com/FrancoLionti/ClipBridge](https://github.com/FrancoLionti/ClipBridge)**

**Current release:** **2.0.3** on branch `main` (also shown by `clipbridge --version`). Pre-release (“nightly”) builds on GitHub use tags like **`v2.0.3-nightly`** until you publish **v2.0.3** as stable. To go back to the 1.0 line: `git fetch origin && git checkout v1.0.0` (same client/server version on all machines).

## Features
- 🔄 **Bi-directional sync**: Copy on one PC, paste on another
- 🔍 **Auto-discovery**: No manual IP configuration needed (UDP; configurable port)
- 🚀 **Lightweight**: Pure Python, minimal runtime dependencies ([`pyproject.toml`](pyproject.toml))
- ⚡ **Low latency**: Long-polling + tunable intervals in `config.json`
- 🔐 **Optional security**: Shared-secret HMAC authentication, payload encryption (`cryptography`), and per‑IP rate limiting

## Quick Start

### Installation

**Dependencies only (run from cloned repo — `config.json` lives next to `clipbridge.py`):**
```bash
pip install -r requirements.txt
```

**CLI on your PATH (like other Python tools —works from any directory)**  
Recommended: [**pipx**](https://pypi.org/project/pipx/)
```bash
cd /path/to/ClipBridge
pipx install .

clipbridge server
clipbridge client on
```

Alternative — user-wide `pip`:
```bash
cd /path/to/ClipBridge
python3 -m pip install --user .

# Ensure ~/.local/bin is on PATH (Ubuntu: already for many desktops)
which clipbridge
clipbridge client on
```

PyPI distribution name is `clipbridge-sync`; the executable is **`clipbridge`**.

### Config location

| How you run it | Default `config.json` |
|----------------|------------------------|
| `python clipbridge.py …` from a git checkout | `./config.json` in the repo |
| `pip` / **pipx** install (`clipbridge` command) | Linux: **`~/.config/clipbridge/config.json`** (`$XDG_CONFIG_HOME/clipbridge/config.json` if set). Windows / macOS: per-user application data dirs. |

Override with **`CLIPBRIDGE_CONFIG`**: path to the file **or** a directory (then `<dir>/config.json` is used).

### Usage

**On your main PC (Server):**
```bash
python clipbridge.py server
```
or, if installed system-wide:

```bash
clipbridge server
```

(`python clipbridge.py --server` / `clipbridge --server` are equivalent.)

Show the installed version: `clipbridge --version`.

**On other PCs (Clients):**
```bash
clipbridge client
```

The client will automatically discover the server on your local network.

**Interactive client (terminal stays open — sync runs in background, you keep a `clipbridge>` prompt):**
```bash
clipbridge client on
```
Optional explicit server: `clipbridge client on --ip 192.168.1.10`. Commands: `help`, `status`, `exit`.

From a repo checkout without PATH install:

```bash
python clipbridge.py client on
./launch_client.sh on
```

### Windows (double-click or shortcut)
From the repo folder, use the launchers (they create `.venv`, install `requirements.txt`, then run ClipBridge):

- **Server (desktop / main PC):** `launch_server.bat`
- **Client:** `launch_client.bat` (pass `on` first for interactive mode: `launch_client.bat on`)

Or install via `pip install .` / pipx on Windows — then use **`clipbridge`** from a terminal anywhere.

You can copy a shortcut to `launch_server.bat` onto the desktop; keep the shortcut’s “Start in” directory set to your ClipBridge repo path so local `config.json` and `clipbridge.py` resolve correctly when **not** using a global install.

## Auto-Start on Boot

### Windows
1. Run `install/windows_startup.bat` as Administrator
2. Or manually add to Task Scheduler

### Ubuntu/Linux (`linux_setup.sh` — recommended)

Installs the `clipbridge` CLI with `pip install --user`, optional clipboard packages (see below), and a **systemd user** unit (`~/.config/systemd/user/clipbridge.service`) so ClipBridge starts with your graphical session:

```bash
cd /path/to/ClipBridge/install
chmod +x linux_setup.sh
./linux_setup.sh
```

Manage it with: `systemctl --user enable|stop|status clipbridge.service` · logs: `journalctl --user -u clipbridge -f`

### Linux: manual systemd (**system-wide**)

The [`install/clipbridge.service`](install/clipbridge.service) file shipped in the repo uses the placeholder **`CLIPBRIDGE_EXEC`**. Substitute your real CLI path **before** enabling the unit:

```bash
EXEC="$(command -v clipbridge)"   # e.g. after pip install --user
sudo sed "s|CLIPBRIDGE_EXEC|$EXEC|g" install/clipbridge.service | sudo tee /etc/systemd/system/clipbridge.service >/dev/null
# For a system unit, add User=youruser (and DISPLAY/session details) under [Service] if needed — see comments in the unit file.
sudo systemctl daemon-reload
sudo systemctl enable --now clipbridge.service
```

## Configuration

Edit `config.json` (paths in the table above). **Never commit real `secret_key` values** — use fresh keys via the CLI below or keep overrides in an untracked file and point **`CLIPBRIDGE_CONFIG`** at it.

**Network / mode**
- `server_ip`: Override auto-discovery (client)
- `port`: HTTP API port (**TCP**, default **5000**)
- `discovery_port`: Broadcast / discovery (**UDP**, default **5001**)
- `mode`: `"auto"`, `"server"`, or `"client"`

**Sync tuning**
- `push_interval`: How often the client pushes local clipboard changes (seconds)
- `pull_interval`: Poll / long‑poll pacing toward the server (seconds)

**Optional security**
- `secret_key`: Shared secret (**same on server and clients**). When unset, authentication is disabled.
- `encryption_enabled`: Encrypt payloads over the network (requires `secret_key` and the `cryptography` package).
- `rate_limit`: Max HTTP requests per second **per IP** on the server (abuse mitigation).

CLI helpers (**run once on each machine with the same secret**):

```bash
clipbridge --set-secret YOUR_SHARED_SECRET
clipbridge --enable-encryption       # optional; needs cryptography installed
clipbridge --disable-encryption      # turn encryption off without editing JSON
clipbridge --show-config
```

## Requirements
- Python 3.8+ (see [`pyproject.toml`](pyproject.toml))
- Same local network (LAN)
- Firewall / router: **TCP** `port` (default 5000) and **UDP** `discovery_port` (default 5001) reachable between peers
- **Linux clipboard**: **X11** — `xclip` or `xsel`; **Wayland** — `wl-clipboard` (`wl-copy` / `wl-paste`). The setup script tries to install these on Debian/Ubuntu when missing.

## License
MIT
