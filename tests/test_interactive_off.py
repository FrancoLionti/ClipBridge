"""Tests for interactive client `off` CLI and PID helpers."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_interactive_pid_path_respects_config_parent(monkeypatch, tmp_path):
    import clipbridge

    cfg = tmp_path / "config.json"
    monkeypatch.setattr(clipbridge, "CONFIG_FILE", cfg)
    assert clipbridge._interactive_pid_path() == tmp_path / "interactive_client.pid"


def test_stop_remote_no_pid_file(monkeypatch, tmp_path, capsys):
    import clipbridge

    monkeypatch.setattr(clipbridge, "CONFIG_FILE", tmp_path / "config.json")
    clipbridge.stop_remote_interactive_client()
    out = capsys.readouterr().out
    assert "nothing to stop" in out.lower()


def test_main_client_off_no_pid(monkeypatch, tmp_path, capsys):
    import clipbridge

    monkeypatch.setattr(clipbridge, "CONFIG_FILE", tmp_path / "cfg.json")
    monkeypatch.setattr(sys, "argv", ["clipbridge", "client", "off"])
    clipbridge.main()
    combined = capsys.readouterr().out + capsys.readouterr().err
    assert "nothing to stop" in combined.lower()


def test_pid_targets_clipbridge_linux_self():
    """Current test process cmdline contains python/pytest — not ClipBridge."""
    import os

    import clipbridge

    if not sys.platform.startswith("linux"):
        return
    assert not clipbridge._pid_targets_clipbridge(os.getpid())
