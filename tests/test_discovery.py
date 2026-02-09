"""
Unit tests for auto-discovery functionality.
"""
import pytest
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestGetLocalIp:
    """Tests for get_local_ip function."""
    
    def test_returns_string(self):
        """get_local_ip should return a string."""
        import clipbridge
        result = clipbridge.get_local_ip()
        assert isinstance(result, str)
    
    def test_returns_valid_ip_format(self):
        """get_local_ip should return valid IP format."""
        import clipbridge
        result = clipbridge.get_local_ip()
        # Should have 4 parts separated by dots
        parts = result.split('.')
        assert len(parts) == 4
        # Each part should be a number 0-255
        for part in parts:
            assert part.isdigit()
            assert 0 <= int(part) <= 255
    
    def test_not_empty(self):
        """get_local_ip should not return empty string."""
        import clipbridge
        result = clipbridge.get_local_ip()
        assert len(result) > 0


class TestDiscoveryConstants:
    """Tests for discovery protocol constants."""
    
    def test_discovery_magic_is_bytes(self):
        """DISCOVERY_MAGIC should be bytes."""
        import clipbridge
        assert isinstance(clipbridge.DISCOVERY_MAGIC, bytes)
    
    def test_discovery_response_is_bytes(self):
        """DISCOVERY_RESPONSE should be bytes."""
        import clipbridge
        assert isinstance(clipbridge.DISCOVERY_RESPONSE, bytes)
    
    def test_discovery_magic_not_empty(self):
        """DISCOVERY_MAGIC should not be empty."""
        import clipbridge
        assert len(clipbridge.DISCOVERY_MAGIC) > 0
    
    def test_discovery_response_not_empty(self):
        """DISCOVERY_RESPONSE should not be empty."""
        import clipbridge
        assert len(clipbridge.DISCOVERY_RESPONSE) > 0
    
    def test_discovery_port_is_int(self):
        """DISCOVERY_PORT should be an integer."""
        import clipbridge
        assert isinstance(clipbridge.DISCOVERY_PORT, int)
    
    def test_discovery_port_in_valid_range(self):
        """DISCOVERY_PORT should be in valid port range."""
        import clipbridge
        assert 1 <= clipbridge.DISCOVERY_PORT <= 65535
