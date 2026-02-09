"""
Unit tests for clipboard abstraction functions.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestClipboardGet:
    """Tests for clipboard_get function."""
    
    def test_returns_string(self, mock_clipboard):
        """clipboard_get should return a string."""
        import clipbridge
        result = clipbridge.clipboard_get()
        assert isinstance(result, str)
    
    def test_returns_current_content(self, mock_clipboard):
        """clipboard_get should return current clipboard content."""
        import clipbridge
        mock_clipboard[0] = "test content"
        result = clipbridge.clipboard_get()
        assert result == "test content"


class TestClipboardSet:
    """Tests for clipboard_set function."""
    
    def test_sets_content(self, mock_clipboard):
        """clipboard_set should update clipboard content."""
        import clipbridge
        clipbridge.clipboard_set("new content")
        assert mock_clipboard[0] == "new content"
    
    def test_returns_true_on_success(self, mock_clipboard):
        """clipboard_set should return True on success."""
        import clipbridge
        result = clipbridge.clipboard_set("test")
        assert result is True


class TestClipboardRoundtrip:
    """Integration tests for clipboard get/set."""
    
    def test_set_then_get(self, mock_clipboard):
        """Content set should be retrievable."""
        import clipbridge
        test_text = "Hello, ClipBridge!"
        clipbridge.clipboard_set(test_text)
        result = clipbridge.clipboard_get()
        assert result == test_text
    
    def test_unicode_content(self, mock_clipboard):
        """Should handle unicode characters."""
        import clipbridge
        test_text = "Emojis: 🎉🚀 Español: ñ 日本語"
        clipbridge.clipboard_set(test_text)
        result = clipbridge.clipboard_get()
        assert result == test_text
    
    def test_empty_string(self, mock_clipboard):
        """Should handle empty string."""
        import clipbridge
        clipbridge.clipboard_set("")
        result = clipbridge.clipboard_get()
        assert result == ""
    
    def test_multiline_content(self, mock_clipboard):
        """Should handle multiline text."""
        import clipbridge
        test_text = "Line 1\nLine 2\nLine 3"
        clipbridge.clipboard_set(test_text)
        result = clipbridge.clipboard_get()
        assert result == test_text
