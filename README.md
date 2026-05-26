# ClipBridge 📋🔗

Cross-platform clipboard synchronization between Windows and Linux machines on the same network.

**Current release:** 2.0 (`main`). To go back to the 1.0 line: `git fetch origin && git checkout v1.0.0` (same client/server version on all machines).

## Features
- 🔄 **Bi-directional sync**: Copy on one PC, paste on another
- 🔍 **Auto-discovery**: No manual IP configuration needed
- 🚀 **Lightweight**: Pure Python, minimal dependencies
- ⚡ **Fast**: Sub-second sync times

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

### Ubuntu/Linux (system-wide unit or helper script)
Automated installer (installs the `clipbridge` CLI with `pip --user`, then wires systemd **user** service):
```bash
cd /path/to/ClipBridge/install
chmod +x linux_setup.sh
./linux_setup.sh
```
Manual systemd (edit paths and **`ExecStart`** to your `which clipbridge`):
```bash
sudo cp install/clipbridge.service /etc/systemd/system/
sudo systemctl enable clipbridge
sudo systemctl start clipbridge
```

## Configuration
Edit `config.json` (see table above for its path) to manually set:
- `server_ip`: Override auto-discovery
- `port`: Change default port (5000)
- `mode`: Force "server" or "client"

## Requirements
- Python 3.8+
- Same local network (LAN)
- Port 5000 (TCP) and 5001 (UDP) open

## License
MIT
