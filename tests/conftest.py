"""
Global pytest configuration and fixtures for B-Hunters tests.
"""

import pytest
import os
import sys
from unittest.mock import Mock, patch

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture(scope='session')
def test_config():
    """Provide test configuration."""
    return {
        "mongo": {
            "user": "testuser",
            "password": "testpass",
            "db": "testdb",
            "host": "localhost",
            "port": "27017"
        },
        "redis": {
            "host": "localhost",
            "port": 6379
        },
        "s3": {
            "access_key": "testkey",
            "secret_key": "testsecret",
            "address": "localhost:9000",
            "bucket": "testbucket",
            "secure": False
        }
    }


@pytest.fixture(scope='session')
def mock_bhunters_config():
    """Mock B-Hunters config for testing."""
    config = Mock()
    config.__getitem__ = Mock(side_effect=lambda key: {
        "mongo": {
            "user": "testuser",
            "password": "testpass",
            "db": "testdb",
            "host": "localhost",
            "port": 27017
        },
        "Webhook": {
            "discord_report": "http://localhost:8000/webhook",
            "discord_task_status": "http://localhost:8000/status"
        }
    }.get(key, {}))
    return config
