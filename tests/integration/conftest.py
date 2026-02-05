"""
Pytest fixtures for integration tests.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os


@pytest.fixture
def mock_karton_config():
    """Create a mock Karton Config."""
    config = Mock()
    config.__getitem__ = Mock(return_value={
        "user": "test",
        "password": "test",
        "db": "test",
        "host": "localhost",
        "port": "27017"
    })
    return config


@pytest.fixture
def mock_mongo_client():
    """Create a mock MongoDB client."""
    client = Mock()
    client.admin.command.return_value = True
    
    db = Mock()
    collection = Mock()
    
    db.__getitem__ = Mock(return_value=collection)
    client.__getitem__ = Mock(return_value=db)
    
    return client, db, collection


@pytest.fixture
def mock_s3_client():
    """Create a mock S3 client."""
    s3 = Mock()
    
    # Mock list_objects_v2 response
    s3.list_objects_v2.return_value = {
        'Contents': [
            {'Key': 'subdir1_file1.txt'},
            {'Key': 'subdir1_file2.txt'},
            {'Key': 'subdir2_file1.txt'}
        ],
        'IsTruncated': False
    }
    
    # Mock get_object response
    mock_body = Mock()
    mock_body.read.return_value = b"Mock file content"
    s3.get_object.return_value = {'Body': mock_body}
    
    return s3


@pytest.fixture
def sample_scan_document():
    """Create a sample scan document for testing."""
    return {
        "_id": "507f1f77bcf86cd799439011",
        "Domain": "example.com",
        "Scanid": "507f1f77bcf86cd799439011",
        "active": True,
        "status": {
            "processing": [],
            "finished": ["dalfox", "nmap"],
            "failed": []
        },
        "data": {
            "dalfox": {"findings": ["xss1", "xss2"]},
            "nmap": {"ports": "80,443"}
        },
        "Ports": {"80": "http", "443": "https"},
        "Technology": {"example.com": "nginx"},
        "Vulns": {
            "dalfox": [{"url": "http://example.com/xss", "severity": "high"}]
        },
        "Paths": [["GET /api 200 OK http://example.com/api"]],
        "Paths403": [[{"pathurl": "/admin"}]],
        "Subdomains": ["sub1.example.com", "sub2.example.com"]
    }


@pytest.fixture
def sample_domain_documents():
    """Create sample domain documents."""
    return [
        {
            "_id": "507f1f77bcf86cd799439012",
            "Domain": "sub1.example.com",
            "Scanid": "507f1f77bcf86cd799439011",
            "active": True,
            "status": {
                "processing": [],
                "finished": ["dalfox"],
                "failed": []
            }
        },
        {
            "_id": "507f1f77bcf86cd799439013",
            "Domain": "sub2.example.com",
            "Scanid": "507f1f77bcf86cd799439011",
            "active": True,
            "status": {
                "processing": [],
                "finished": ["nmap"],
                "failed": []
            }
        }
    ]


@pytest.fixture
def temp_report_dir():
    """Create a temporary directory for report testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir
