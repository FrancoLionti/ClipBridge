"""
Shared fixtures for ClipBridge tests.
"""
import pytest
import sys
import threading
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def mock_clipboard(monkeypatch):
    """Mock clipboard for testing without affecting real clipboard."""
    clipboard_content = [""]
    
    def mock_get():
        return clipboard_content[0]
    
    def mock_set(text):
        clipboard_content[0] = text
        return True
    
    # Import after path is set
    import clipbridge
    monkeypatch.setattr(clipbridge, 'clipboard_get', mock_get)
    monkeypatch.setattr(clipbridge, 'clipboard_set', mock_set)
    
    return clipboard_content


@pytest.fixture
def test_config(tmp_path):
    """Create a temporary config file for testing."""
    import json
    config = {
        "server_ip": "127.0.0.1",
        "port": 15000,  # Use non-standard port for testing
        "discovery_port": 15001,
        "mode": "auto"
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))
    return config_file, config


@pytest.fixture
def server_app():
    """Get the Flask app for testing."""
    import clipbridge
    clipbridge.app.config['TESTING'] = True
    return clipbridge.app


@pytest.fixture
def server_client(server_app):
    """Create a test client for the Flask server."""
    return server_app.test_client()
