"""
Unit tests for the BHunters base class.
"""

import pytest
import socket
import tempfile
import os
import re
from unittest.mock import Mock, patch, MagicMock
import json


def test_is_string_with_string():
    """Test is_string returns True for string input."""
    from b_hunters.bhunter import BHunters
    
    # Create mock for abstract methods
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        assert hunter.is_string("test") is True
        assert hunter.is_string("hello world") is True


def test_is_string_with_non_string():
    """Test is_string returns False for non-string input."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        assert hunter.is_string(123) is False
        assert hunter.is_string([]) is False
        assert hunter.is_string({}) is False
        assert hunter.is_string(None) is False


def test_is_array_with_list():
    """Test is_array returns True for list input."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        assert hunter.is_array([]) is True
        assert hunter.is_array([1, 2, 3]) is True
        assert hunter.is_array(["a", "b"]) is True


def test_is_array_with_non_list():
    """Test is_array returns False for non-list input."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        assert hunter.is_array("string") is False
        assert hunter.is_array(123) is False
        assert hunter.is_array({"key": "value"}) is False


def test_is_local_ip_with_local_addresses():
    """Test is_local_ip returns True for local IP addresses."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        
        local_ips = [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
        ]
        
        for ip in local_ips:
            assert hunter.is_local_ip(ip) is True, f"{ip} should be local"


def test_is_local_ip_with_public_addresses():
    """Test is_local_ip returns False for public IP addresses."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        
        public_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "13.107.42.14",
            "104.18.23.123",
        ]
        
        for ip in public_ips:
            assert hunter.is_local_ip(ip) is False, f"{ip} should not be local"


def test_generate_random_filename():
    """Test generate_random_filename creates valid temporary files."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        
        # Generate multiple filenames
        filenames = [hunter.generate_random_filename() for _ in range(10)]
        
        # All filenames should be unique
        assert len(set(filenames)) == 10
        
        # All filenames should be in the temp directory
        temp_dir = tempfile.gettempdir()
        for filename in filenames:
            assert filename.startswith(temp_dir)
            # Filenames should have reasonable length (10 random chars + path)
            assert len(os.path.basename(filename)) == 10


def test_get_main_domain():
    """Test get_main_domain extracts registered domain correctly."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        
        test_cases = [
            ("sub.example.com", "example.com"),
            ("deep.sub.example.com", "example.com"),
            ("example.co.uk", "example.co.uk"),
            ("test.example.org", "example.org"),
            ("localhost", ""),  # Edge case
        ]
        
        for input_url, expected in test_cases:
            result = hunter.get_main_domain(input_url)
            assert result == expected, f"Failed for {input_url}: got {result}, expected {expected}"


def test_encode_filename():
    """Test encode_filename sanitizes filenames properly."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        
        test_cases = [
            ("simple.txt", "simple.txt"),
            ("path/to/file.txt", "path_to_file.txt"),
            ('file<with>quotes.txt', "file_with_quotes.txt"),
            ('file:with|invalid?chars*.txt', "file_with_invalid_chars_.txt"),
            ("../path/traversal.txt", ".._path_traversal.txt"),
        ]
        
        for input_path, expected_pattern in test_cases:
            result = hunter.encode_filename(input_path)
            # Check no invalid characters remain
            assert not re.search(r'[<>:"/\\|?*]', result)
            assert len(result) <= 255  # Should not exceed filename limit


def test_encode_filename_very_long_input():
    """Test encode_filename handles very long inputs by hashing."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        
        # Create a very long URL
        long_url = "https://example.com/" + "a" * 500
        result = hunter.encode_filename(long_url)
        
        # Result should be a hash (32 chars for MD5)
        assert len(result) <= 255
        assert len(result) == 32  # MD5 hash length


@pytest.mark.parametrize("url,expected_pattern", [
    ("example.com", "example.com"),
    ("http://example.com", "http://example.com"),
    ("https://example.com", "https://example.com"),
])
def test_check_https_patterns(url, expected_pattern):
    """Test check_https correctly identifies URLs with protocol."""
    from b_hunters.bhunter import BHunters
    
    with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
        hunter = BHunters()
        result = hunter.check_https(url)
        # Simple boolean check - has protocol or not
        if url.startswith("http"):
            assert result is True
        else:
            assert result is False


class TestUpdateTaskStatus:
    """Tests for update_task_status method."""
    
    @pytest.fixture
    def mock_hunter(self):
        """Create a mock BHunters instance."""
        with patch.object(BHunters, '__init__', lambda x, **kwargs: None):
            with patch.object(BHunters, 'monogocon', return_value=Mock()):
                with patch.object(BHunters, 'waitformongo'):
                    hunter = BHunters()
                    hunter.identity = "test-tool"
                    hunter.config = {"Webhook": {"discord_task_status": "http://test.webhook"}}
                    hunter.db = Mock()
                    hunter.db.__getitem__ = Mock(return_value=Mock())
                    return hunter
    
    def test_update_task_status_started(self, mock_hunter):
        """Test update_task_status with Started status."""
        mock_collection = Mock()
        mock_hunter.db.__getitem__.return_value = mock_collection
        
        with patch.object(mock_hunter, 'send_discord_webhook'):
            mock_hunter.update_task_status("example.com", "Started")
            
            mock_collection.update_one.assert_called_once()
            call_args = mock_collection.update_one.call_args
            assert "example.com" in str(call_args)
            assert "processing" in str(call_args)
    
    def test_update_task_status_finished(self, mock_hunter):
        """Test update_task_status with Finished status."""
        mock_collection = Mock()
        mock_hunter.db.__getitem__.return_value = mock_collection
        
        with patch.object(mock_hunter, 'send_discord_webhook'):
            mock_hunter.update_task_status("example.com", "Finished")
            
            mock_collection.update_one.assert_called_once()
    
    def test_update_task_status_failed_raises_exception(self, mock_hunter):
        """Test update_task_status with Failed status raises exception."""
        mock_collection = Mock()
        mock_hunter.db.__getitem__.return_value = mock_collection
        
        with patch.object(mock_hunter, 'send_discord_webhook'):
            with pytest.raises(Exception) as exc_info:
                mock_hunter.update_task_status("example.com", "Failed")
            
            assert "Failed" in str(exc_info.value)
