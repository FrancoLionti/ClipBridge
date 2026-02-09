"""
Tests for security features: authentication, encryption, rate limiting.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestSecurityManager:
    """Tests for SecurityManager class."""
    
    def test_security_manager_exists(self):
        """SecurityManager class should exist."""
        import clipbridge
        assert hasattr(clipbridge, 'SecurityManager')
    
    def test_sign_returns_string(self):
        """sign() should return a string."""
        import clipbridge
        sm = clipbridge.SecurityManager("test_secret")
        result = sm.sign("test data")
        assert isinstance(result, str)
    
    def test_sign_with_no_secret_returns_empty(self):
        """sign() with no secret should return empty string."""
        import clipbridge
        sm = clipbridge.SecurityManager(None)
        result = sm.sign("test data")
        assert result == ""
    
    def test_verify_returns_true_for_valid_signature(self):
        """verify() should return True for valid signature."""
        import clipbridge
        sm = clipbridge.SecurityManager("test_secret")
        signature = sm.sign("test data")
        assert sm.verify("test data", signature) is True
    
    def test_verify_returns_false_for_invalid_signature(self):
        """verify() should return False for invalid signature."""
        import clipbridge
        sm = clipbridge.SecurityManager("test_secret")
        assert sm.verify("test data", "invalid_signature") is False
    
    def test_verify_with_no_secret_returns_true(self):
        """verify() with no secret should always return True."""
        import clipbridge
        sm = clipbridge.SecurityManager(None)
        assert sm.verify("test data", "anything") is True
    
    def test_encrypt_without_encryption_returns_original(self):
        """encrypt() without encryption should return original."""
        import clipbridge
        sm = clipbridge.SecurityManager("test_secret", encryption_enabled=False)
        result = sm.encrypt("test data")
        assert result == "test data"
    
    def test_decrypt_without_encryption_returns_original(self):
        """decrypt() without encryption should return original."""
        import clipbridge
        sm = clipbridge.SecurityManager("test_secret", encryption_enabled=False)
        result = sm.decrypt("test data")
        assert result == "test data"


class TestSecurityConfig:
    """Tests for security configuration."""
    
    def test_default_config_has_secret_key(self):
        """DEFAULT_CONFIG should have secret_key."""
        import clipbridge
        assert 'secret_key' in clipbridge.DEFAULT_CONFIG
    
    def test_default_secret_key_is_none(self):
        """Default secret_key should be None (disabled)."""
        import clipbridge
        assert clipbridge.DEFAULT_CONFIG['secret_key'] is None
    
    def test_default_config_has_encryption_enabled(self):
        """DEFAULT_CONFIG should have encryption_enabled."""
        import clipbridge
        assert 'encryption_enabled' in clipbridge.DEFAULT_CONFIG
    
    def test_default_encryption_is_false(self):
        """Default encryption_enabled should be False."""
        import clipbridge
        assert clipbridge.DEFAULT_CONFIG['encryption_enabled'] is False
    
    def test_default_config_has_rate_limit(self):
        """DEFAULT_CONFIG should have rate_limit."""
        import clipbridge
        assert 'rate_limit' in clipbridge.DEFAULT_CONFIG
    
    def test_default_rate_limit_is_positive(self):
        """Default rate_limit should be positive."""
        import clipbridge
        assert clipbridge.DEFAULT_CONFIG['rate_limit'] > 0


class TestAuthenticatedEndpoints:
    """Tests to verify endpoints work with authentication."""
    
    def test_push_without_auth_works_when_no_secret(self, server_client, mock_clipboard):
        """POST /push should work when no secret is configured."""
        response = server_client.post('/push', data=b'test data')
        assert response.status_code == 200
    
    def test_pull_without_auth_works_when_no_secret(self, server_client, mock_clipboard):
        """GET /pull should work when no secret is configured."""
        response = server_client.get('/pull')
        assert response.status_code == 200
    
    def test_helo_always_works(self, server_client):
        """GET /helo should always work (no auth required)."""
        response = server_client.get('/helo')
        assert response.status_code == 200
