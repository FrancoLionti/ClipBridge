# ClipBridge 📋🔗

Cross-platform clipboard synchronization between Windows and Linux machines on the same network.

## Features
- 🔄 **Bi-directional sync**: Copy on one PC, paste on another
- 🔍 **Auto-discovery**: No manual IP configuration needed
- 🚀 **Lightweight**: Pure Python, minimal dependencies
- ⚡ **Fast**: Sub-second sync times

## Quick Start

### Installation
```bash
pip install -r requirements.txt
```

### Usage
**On your main PC (Server):**
```bash
python clipbridge.py --server
```

**On other PCs (Clients):**
```bash
python clipbridge.py --client
```

The client will automatically discover the server on your local network.

## Auto-Start on Boot

### Windows
1. Run `install/windows_startup.bat` as Administrator
2. Or manually add to Task Scheduler

### Ubuntu/Linux
```bash
sudo cp install/clipbridge.service /etc/systemd/system/
sudo systemctl enable clipbridge
sudo systemctl start clipbridge
```

## Configuration
Edit `config.json` to manually set:
- `server_ip`: Override auto-discovery
- `port`: Change default port (5000)
- `mode`: Force "server" or "client"

## Requirements
- Python 3.8+
- Same local network (LAN)
- Port 5000 (TCP) and 5001 (UDP) open

## License
MIT
