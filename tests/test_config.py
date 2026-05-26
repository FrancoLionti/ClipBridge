"""
Unit tests for configuration loading.
"""
import pytest
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestLoadConfig:
    """Tests for config loading functionality."""
    
    def test_default_config_has_required_keys(self):
        """DEFAULT_CONFIG should have all required keys."""
        import clipbridge
        required_keys = ['server_ip', 'port', 'discovery_port', 'mode']
        for key in required_keys:
            assert key in clipbridge.DEFAULT_CONFIG
    
    def test_default_port_is_5000(self):
        """Default port should be 5000."""
        import clipbridge
        assert clipbridge.DEFAULT_CONFIG['port'] == 5000
    
    def test_default_discovery_port_is_5001(self):
        """Default discovery port should be 5001."""
        import clipbridge
        assert clipbridge.DEFAULT_CONFIG['discovery_port'] == 5001
    
    def test_default_mode_is_auto(self):
        """Default mode should be 'auto'."""
        import clipbridge
        assert clipbridge.DEFAULT_CONFIG['mode'] == 'auto'
    
    def test_load_config_returns_dict(self):
        """load_config should return a dictionary."""
        import clipbridge
        result = clipbridge.load_config()
        assert isinstance(result, dict)
    
    def test_config_has_push_interval(self):
        """Config should have push_interval setting."""
        import clipbridge
        assert 'push_interval' in clipbridge.DEFAULT_CONFIG
        assert isinstance(clipbridge.DEFAULT_CONFIG['push_interval'], (int, float))
    
    def test_config_has_pull_interval(self):
        """Config should have pull_interval setting."""
        import clipbridge
        assert 'pull_interval' in clipbridge.DEFAULT_CONFIG
        assert isinstance(clipbridge.DEFAULT_CONFIG['pull_interval'], (int, float))

    def test_resolve_config_dev_clone_uses_repo_file(self):
        import clipbridge
        from pathlib import Path
        root = Path("/home/user/Projects/ClipBridge")
        assert clipbridge.resolve_config_file(root, {}) == root / "config.json"

    @pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="XDG default path is only used for non-Windows in _user_default_config_file",
    )
    def test_resolve_config_installed_uses_xdg_on_linux(self, monkeypatch):
        import clipbridge
        import os
        monkeypatch.delenv("CLIPBRIDGE_CONFIG", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", "/xdg/conf")
        from pathlib import Path
        root = Path("/usr/lib/python3.12/site-packages")
        fp = clipbridge.resolve_config_file(root, os.environ)
        assert fp == Path("/xdg/conf/clipbridge/config.json")

    def test_resolve_config_env_file_overrides(self, monkeypatch, tmp_path):
        import clipbridge
        import os
        target = tmp_path / "custom.json"
        monkeypatch.setenv("CLIPBRIDGE_CONFIG", str(target))
        from pathlib import Path
        root = Path("/usr/lib/python3.12/site-packages")
        assert clipbridge.resolve_config_file(root, os.environ) == target

    def test_resolve_config_env_dir_overrides(self, monkeypatch, tmp_path):
        import clipbridge
        import os
        d = tmp_path / "clipconf"
        d.mkdir()
        monkeypatch.setenv("CLIPBRIDGE_CONFIG", str(d))
        from pathlib import Path
        root = Path("/usr/lib/python3.12/site-packages")
        assert clipbridge.resolve_config_file(root, os.environ) == d / "config.json"
