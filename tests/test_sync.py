"""
Integration tests for client-server synchronization.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestServerEndpoints:
    """Integration tests for Flask server endpoints."""
    
    def test_helo_endpoint_returns_200(self, server_client):
        """GET /helo should return 200 OK."""
        response = server_client.get('/helo')
        assert response.status_code == 200
    
    def test_helo_contains_server_identifier(self, server_client):
        """GET /helo should contain CLIPBRIDGE_SERVER."""
        response = server_client.get('/helo')
        assert b'CLIPBRIDGE_SERVER' in response.data
    
    def test_pull_endpoint_returns_200(self, server_client):
        """GET /pull should return 200 OK."""
        response = server_client.get('/pull')
        assert response.status_code == 200
    
    def test_push_endpoint_returns_200(self, server_client):
        """POST /push should return 200 OK."""
        response = server_client.post('/push', data=b'test data')
        assert response.status_code == 200
    
    def test_push_then_pull_returns_same_data(self, server_client, mock_clipboard):
        """Data pushed should be retrievable via pull."""
        import clipbridge
        
        # Reset shared clipboard
        clipbridge.shared_clipboard = ""
        
        # Push data
        test_data = "Hello from test!"
        server_client.post('/push', data=test_data.encode('utf-8'))
        
        # Pull should return same data
        response = server_client.get('/pull')
        assert response.data.decode('utf-8') == test_data
    
    def test_push_updates_shared_clipboard(self, server_client, mock_clipboard):
        """POST /push should update shared_clipboard variable."""
        import clipbridge
        
        clipbridge.shared_clipboard = ""
        test_data = "Updated clipboard"
        
        server_client.post('/push', data=test_data.encode('utf-8'))
        
        assert clipbridge.shared_clipboard == test_data
    
    def test_push_handles_unicode(self, server_client, mock_clipboard):
        """POST /push should handle unicode properly."""
        import clipbridge
        
        clipbridge.shared_clipboard = ""
        test_data = "Emoji: 🚀 Español: ñ"
        
        server_client.post('/push', data=test_data.encode('utf-8'))
        
        response = server_client.get('/pull')
        assert response.data.decode('utf-8') == test_data
    
    def test_push_handles_multiline(self, server_client, mock_clipboard):
        """POST /push should handle multiline text."""
        import clipbridge
        
        clipbridge.shared_clipboard = ""
        test_data = "Line 1\nLine 2\nLine 3"
        
        server_client.post('/push', data=test_data.encode('utf-8'))
        
        response = server_client.get('/pull')
        assert response.data.decode('utf-8') == test_data
    
    def test_push_empty_does_not_crash(self, server_client, mock_clipboard):
        """POST /push with empty data should not crash."""
        response = server_client.post('/push', data=b'')
        assert response.status_code == 200


class TestDataIntegrity:
    """Tests for data integrity during sync."""
    
    def test_large_text_sync(self, server_client, mock_clipboard):
        """Should handle large text content."""
        import clipbridge
        
        clipbridge.shared_clipboard = ""
        # 10KB of text
        test_data = "x" * 10000
        
        server_client.post('/push', data=test_data.encode('utf-8'))
        response = server_client.get('/pull')
        
        assert len(response.data.decode('utf-8')) == 10000
    
    def test_special_characters(self, server_client, mock_clipboard):
        """Should handle special characters."""
        import clipbridge
        
        clipbridge.shared_clipboard = ""
        test_data = "Special: <>&\"'`\\n\\t\\r"
        
        server_client.post('/push', data=test_data.encode('utf-8'))
        response = server_client.get('/pull')
        
        assert response.data.decode('utf-8') == test_data
