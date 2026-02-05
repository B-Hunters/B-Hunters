"""
Mock fixtures for testing.
"""

import sys
from unittest.mock import Mock, MagicMock, patch
from pathlib import Path
import json
import tempfile


class MockMongoDB:
    """Mock MongoDB connection and collections."""

    def __init__(self):
        self.collections = {}

    def __getitem__(self, name):
        """Get or create a mock collection."""
        if name not in self.collections:
            self.collections[name] = MockCollection(name)
        return self.collections[name]


class MockCollection:
    """Mock MongoDB collection."""

    def __init__(self, name):
        self.name = name
        self.data = []

    def find_one(self, query):
        """Mock find_one operation."""
        if isinstance(query, dict) and "Domain" in query:
            for item in self.data:
                if item.get("Domain") == query["Domain"]:
                    return item
        return None

    def find(self, query=None):
        """Mock find operation."""
        return iter(self.data)

    def insert_one(self, document):
        """Mock insert_one operation."""
        document["_id"] = f"id_{len(self.data)}"
        self.data.append(document)
        return MagicMock(acknowledged=True, inserted_id=document["_id"])

    def update_one(self, query, update):
        """Mock update_one operation."""
        return MagicMock(matched_count=1, modified_count=1)

    def count_documents(self, query=None):
        """Mock count_documents operation."""
        return len(self.data)


class MockS3Client:
    """Mock S3 client for testing."""

    def __init__(self):
        self.objects = {}

    def list_objects_v2(self, **kwargs):
        """Mock list_objects_v2 operation."""
        bucket = kwargs.get('Bucket', 'bhunters')
        keys = list(self.objects.get(bucket, {}).keys())

        if not keys:
            return {'IsTruncated': False}

        chunk_size = 1000
        continuation = kwargs.get('ContinuationToken')

        start_idx = 0
        if continuation:
            start_idx = int(continuation)

        chunk = keys[start_idx:start_idx + chunk_size]
        is_truncated = start_idx + chunk_size < len(keys)

        return {
            'Contents': [{'Key': key} for key in chunk],
            'IsTruncated': is_truncated,
            'NextContinuationToken': str(start_idx + chunk_size) if is_truncated else None
        }

    def get_object(self, **kwargs):
        """Mock get_object operation."""
        bucket = kwargs.get('Bucket', 'bhunters')
        key = kwargs.get('Key')

        if bucket in self.objects and key in self.objects[bucket]:
            return {'Body': MockStringIO(self.objects[bucket][key])}
        raise Exception("Object not found")

    def put_object(self, **kwargs):
        """Mock put_object operation."""
        bucket = kwargs.get('Bucket', 'bhunters')
        key = kwargs.get('Key')
        body = kwargs.get('Body', b'')

        if bucket not in self.objects:
            self.objects[bucket] = {}

        self.objects[bucket][key] = body
        return None


class MockStringIO:
    """Mock S3 Body object."""

    def __init__(self, data):
        self.data = data

    def read(self):
        """Read data."""
        if isinstance(self.data, bytes):
            return self.data
        return self.data.encode('utf-8')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class MockKartonProducer:
    """Mock Karton Producer."""

    def __init__(self):
        self.sent_tasks = []
        self.backend = MockKartonBackend()

    def send_task(self, task):
        """Mock send_task operation."""
        self.sent_tasks.append(task)
        return None


class MockKartonBackend:
    """Mock Karton Backend."""

    def __init__(self):
        self.s3 = MockS3Client()

    def restart_task(self, task):
        """Mock restart_task operation."""
        pass


# Sample data fixtures
class SampleData:
    """Sample data for testing."""

    @staticmethod
    def domain_document(domain="example.com", scan_id="scan_123"):
        """Return sample domain document."""
        return {
            "_id": f"domain_{domain}",
            "Domain": domain,
            "Scanid": scan_id,
            "active": True,
            "status": {
                "processing": [],
                "finished": ["test-tool"],
                "failed": [],
            },
            "Ports": {
                "open_ports": [80, 443, 22]
            },
            "Technology": {
                "technologies": ["nginx", "php", "mysql"]
            },
            "Vulns": {
                "XSS": [
                    {
                        "severity": "High",
                        "type": "XSS",
                        "description": "Cross-site scripting vulnerability",
                        "url": f"https://{domain}/page",
                        "confidence": "High"
                    }
                ]
            },
            "Paths": ["/admin", "/login", "/api"],
            "Paths403": [[{"pathurl": f"https://{domain}/admin"}]],
            "Subdomains": [f"a.{domain}", f"b.{domain}"],
            "ToolsData": {
                "nuclei": {
                    "findings": [
                        {
                            "severity": "Low",
                            "type": "Exposed Version",
                            "description": "Server version exposed",
                            "url": f"https://{domain}"
                        }
                    ]
                }
            },
            "JavaScript": [
                {
                    "url": f"https://{domain}/app.js",
                    "Vulns": ["sensitive_data"]
                }
            ]
        }

    @staticmethod
    def scan_document(domain="example.com", scantype="multi"):
        """Return sample scan document."""
        return {
            "_id": f"scan_{domain}",
            "Domain": domain,
            "Type": scantype,
            "Description": f"Test scan for {domain}",
            "ScanLinks": {}
        }

    @staticmethod
    def vulnerability_list(count=5):
        """Return list of sample vulnerabilities."""
        severities = ["Critical", "High", "Medium", "Low", "Info"]
        types = ["XSS", "SQLi", "RCE", "IDOR", "Info"]

        vulns = []
        for i in range(count):
            severity = severities[i % len(severities)]
            vulns.append({
                "severity": severity,
                "type": types[i % len(types)],
                "description": f"Sample {severity} vulnerability {i}",
                "url": f"https://example.com/vuln-{i}",
                "confidence": "Medium"
            })

        return vulns

    @staticmethod
    def scan_results_for_report(domain="example.com"):
        """Return complete scan results for report generation."""
        return {
            "domain": domain,
            "scantype": "multi",
            "scan_date": "2024-01-15",
            "generated_at": "2024-01-15 12:00:00",
            "metrics": {
                "subdomains": 3,
                "technologies": 4,
                "ports": 5,
                "paths": 10,
                "findings": 3,
                "duration": "2h 30m"
            },
            "subdomains": [
                f"{domain}",
                f"a.{domain}",
                f"b.{domain}"
            ],
            "technologies": ["nginx", "php", "mysql", "redis"],
            "ports": [80, 443, 22, 3306, 6379],
            "paths": ["/admin", "/login", "/api", "/dashboard"],
            "findings": [
                {
                    "severity": "High",
                    "type": "XSS",
                    "description": "Cross-site scripting",
                    "url": f"https://{domain}/search",
                    "confidence": "High"
                },
                {
                    "severity": "Medium",
                    "type": "IDOR",
                    "description": "Insecure direct object reference",
                    "url": f"https://{domain}/api/users/1",
                    "confidence": "Medium"
                },
                {
                    "severity": "Low",
                    "type": "Info",
                    "description": "Server header exposed",
                    "url": f"https://{domain}/",
                    "confidence": "High"
                }
            ],
            "risk_score": {
                "overall_score": 45.0,
                "risk_level": "Medium",
                "critical_count": 0,
                "high_count": 1,
                "medium_count": 1,
                "low_count": 1,
                "info_count": 0
            },
            "executive_summary": {
                "overview": f"Security assessment for {domain}",
                "key_findings": "1 High and 1 Medium severity findings require attention",
                "recommendations": "Address High and Medium findings in the next cycle",
                "risk_assessment": "Overall risk score is 45.0/100 (Medium risk)",
                "metrics": "Assessment covered 3 subdomains and 4 technologies"
            }
        }


# Test configuration fixture
def get_test_config():
    """Return test configuration dictionary."""
    return {
        "mongo": {
            "user": "test_user",
            "password": "test_pass",
            "db": "bhunters_test",
            "host": "localhost",
            "port": 27017
        },
        "redis": {
            "host": "localhost",
            "port": 6379
        },
        "s3": {
            "access_key": "minioadmin",
            "secret_key": "minioadmin",
            "address": "localhost:9000",
            "bucket": "bhunters",
            "secure": "false"
        },
        "Webhook": {
            "discord_report": "http://localhost:8000/webhook/discord",
            "discord_task_status": "http://localhost:8000/webhook/status"
        }
    }


# Pytest fixtures
@pytest.fixture
def mock_mongodb():
    """Pytest fixture for mock MongoDB."""
    return MockMongoDB()


@pytest.fixture
def mock_s3():
    """Pytest fixture for mock S3."""
    return MockS3Client()


@pytest.fixture
def mock_producer():
    """Pytest fixture for mock Karton Producer."""
    return MockKartonProducer()


@pytest.fixture
def sample_domain_doc():
    """Pytest fixture for sample domain document."""
    return SampleData.domain_document()


@pytest.fixture
def sample_scan_doc():
    """Pytest fixture for sample scan document."""
    return SampleData.scan_document()


@pytest.fixture
def test_config():
    """Pytest fixture for test configuration."""
    return get_test_config()


# Export functions for use without pytest
create_mock_mongodb = MockMongoDB
create_mock_s3 = MockS3Client
create_sample_data = SampleData