#!/bin/bash
# ClipBridge Ubuntu/Linux Setup: installs CLI (pip --user), optional deps, systemd user unit.

echo "============================================"
echo "ClipBridge - Linux Setup"
echo "============================================"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CLIPBRIDGE_DIR="$(dirname "$SCRIPT_DIR")"
SERVICE_TEMPLATE="$SCRIPT_DIR/clipbridge.service"
USER_SERVICE_DIR="$HOME/.config/systemd/user"
GENERATED_UNIT="$USER_SERVICE_DIR/clipbridge.service"

die() { echo "❌ $*"; exit 1; }

# --- Install clipbridge CLI into ~/.local/bin (PATH) ---
echo "Installing clipbridge CLI (pip install --user – editable from this checkout) ..."
cd "$CLIPBRIDGE_DIR" || die "Cannot cd to $CLIPBRIDGE_DIR"
python3 -m pip install --upgrade --user . || die "pip install failed"

USER_BASE="$(python3 -c 'import site; print(site.USER_BASE)')"
CLIP_BIN="$USER_BASE/bin/clipbridge"
[[ -x "$CLIP_BIN" ]] || die "clipbridge not executable at $CLIP_BIN (check PATH: export PATH=\$HOME/.local/bin:\$PATH)"

echo "✅ CLI: $CLIP_BIN"
command -v clipbridge >/dev/null 2>&1 || echo "⚠️  ~/.local/bin is not on PATH; add: export PATH=\"\$HOME/.local/bin:\$PATH\""

# Check for xclip/xsel (needed for pyperclip on X11)
echo "Checking clipboard tools..."
if [ "${XDG_SESSION_TYPE:-}" = "x11" ]; then
    if ! command -v xclip &> /dev/null && ! command -v xsel &> /dev/null; then
        echo "Installing xclip for clipboard access..."
        sudo apt install -y xclip || true
    fi
fi

if [ "${XDG_SESSION_TYPE:-}" = "wayland" ]; then
    if ! command -v wl-copy &> /dev/null; then
        echo "Installing wl-clipboard for Wayland..."
        sudo apt install -y wl-clipboard || true
    fi
fi

# --- systemd user service ---
mkdir -p "$USER_SERVICE_DIR"

CLIP_BIN_ESC="${CLIP_BIN//\\/\\\\}"
CLIP_BIN_ESC="${CLIP_BIN_ESC//|/\\|}"

sed \
  -e "s|CLIPBRIDGE_EXEC|$CLIP_BIN_ESC|g" \
  "$SERVICE_TEMPLATE" > "$GENERATED_UNIT" || die "sed failed"

systemctl --user daemon-reload
systemctl --user enable clipbridge.service || true
systemctl --user restart clipbridge.service || systemctl --user start clipbridge.service || true

echo ""
echo "============================================"
echo "Installation complete!"
echo ""
echo "Config (pip install layout): \$XDG_CONFIG_HOME/clipbridge/config.json (.config if unset)."
echo ""
echo "Service status:"
systemctl --user status clipbridge.service --no-pager || true
echo ""
echo "Commands:"
echo "  Hand-run client: clipbridge client   or   clipbridge client on"
echo "  ClipBridge systemd (user session): systemctl --user <start|stop|status> clipbridge"
echo "  Logs: journalctl --user -u clipbridge -f"
echo "============================================"
