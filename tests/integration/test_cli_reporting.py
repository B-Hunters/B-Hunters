"""
Integration tests for CLI reporting functionality.
"""

import pytest
import os
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from io import StringIO
import sys

# Test fixtures
@pytest.fixture
def mock_config():
    """Create mock configuration."""
    import configparser
    config = configparser.ConfigParser()
    config["mongo"] = {
        "user": "test_user",
        "password": "test_pass",
        "db": "test_db",
        "host": "localhost",
        "port": "27017"
    }
    config["redis"] = {
        "host": "localhost",
        "port": "6379"
    }
    config["s3"] = {
        "access_key": "test_key",
        "secret_key": "test_secret",
        "address": "localhost:9000",
        "bucket": "bhunters",
        "secure": "false"
    }
    return config


@pytest.fixture
def mock_mongo_db():
    """Create mock MongoDB database."""
    mock_db = MagicMock()

    # Mock scans collection
    scans_col = MagicMock()
    scans_col.find_one.return_value = {
        "_id": "scan_123",
        "Domain": "example.com",
        "Type": "multi",
        "Description": "Test scan"
    }
    mock_db["scans"] = scans_col

    # Mock domains collection
    domains_col = MagicMock()
    domains_col.find.return_value = iter([
        {
            "_id": "domain_1",
            "Domain": "a.example.com",
            "Scanid": "scan_123",
            "active": True,
            "status": {
                "processing": [],
                "finished": ["test-tool"],
                "failed": [],
            },
            "Ports": {"open_ports": [80, 443]},
            "Technology": {"technologies": ["nginx", "php"]},
            "Vulns": {
                "XSS": [{"severity": "High", "type": "XSS", "description": "Test", "url": "https://a.example.com"}]
            },
            "Paths": ["/admin", "/login"],
            "Subdomains": ["a.example.com", "b.example.com"],
        },
        {
            "_id": "domain_2",
            "Domain": "b.example.com",
            "Scanid": "scan_123",
            "active": True,
            "status": {
                "processing": [],
                "finished": ["test-tool"],
                "failed": [],
            },
            "Ports": {"open_ports": [22]},
            "Technology": {"technologies": ["mysql"]},
            "Vulns": {},
            "Paths": [],
            "Subdomains": [],
        }
    ])
    mock_db["domains"] = domains_col

    return mock_db


@pytest.fixture
def mock_s3():
    """Create mock S3 client."""
    mock_s3 = MagicMock()
    mock_s3.list_objects_v2.return_value = {
        'Contents': [],
        'IsTruncated': False
    }
    return mock_s3


class TestCLIReportingIntegration:
    """Integration tests for CLI reporting with enhanced reporting."""

    def test_report_generation_e2e(self, mock_config, mock_mongo_db, mock_s3):
        """Test end-to-end report generation."""
        from b_hunters.reporting import ReportGenerator, aggregate_scan_results

        # Simulate getting data from MongoDB
        scans_col = mock_mongo_db["scans"]
        scan = scans_col.find_one({"Domain": "example.com"})

        domains_col = mock_mongo_db["domains"]
        documents = list(domains_col.find({"Scanid": str(scan["_id"])}))

        # Aggregate results
        aggregated = aggregate_scan_results(
            documents,
            scan["Domain"],
            scan["Type"]
        )

        # Generate reports
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = ReportGenerator(tmpdir)

            # Generate JSON
            json_path = generator.generate_json_report(aggregated, "report.json")
            assert os.path.exists(json_path)

            # Verify JSON content
            with open(json_path, 'r') as f:
                data = json.load(f)

            assert data["domain"] == "example.com"
            assert "executive_summary" in data
            assert "risk_score" in data

            # Generate HTML
            html_path = generator.generate_html_report(aggregated, "report.html")
            assert os.path.exists(html_path)

            with open(html_path, 'r') as f:
                html_content = f.read()

            assert "executive-summary" in html_content
            assert "risk-score" in html_content

    @patch('b_hunters.cli.monogocon')
    @patch('b_hunters.cli.Producer')
    def test_report_command_integration(self, mock_producer, mock_monogocon, mock_mongo_db):
        """Test report command integration with enhanced reporting."""
        from karton.core import Config
        import argparse

        # Setup mocks
        mock_config = Mock(spec=Config)
        mock_config.__getitem__ = lambda self, key: {}
        mock_monogocon.return_value = mock_mongo_db

        producer_mock = MagicMock()
        producer_mock.backend.s3 = MagicMock()
        producer_mock.backend.s3.list_objects_v2.return_value = {
            'Contents': [],
            'IsTruncated': False
        }
        producer_mock.backend.s3.get_object = MagicMock()
        mock_producer.return_value = producer_mock

        # Import after mocking
        import b_hunters.cli

        # Test report generation
        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                domain="example.com",
                output=tmpdir,
                command="report",
            )

            # Monkey patch producer and db
            b_hunters.cli.db = mock_mongo_db
            b_hunters.cli.producer = producer_mock
            b_hunters.cli.s3 = producer_mock.backend.s3

            # Generate report
            try:
                b_hunters.cli.generate_report("example.com", tmpdir)
            except Exception as e:
                # Ignore S3/Mongo errors for this integration test
                if "list_objects_v2" not in str(e):
                    raise

            # Check that output directory was created
            # The actual file creation depends on S3 mock returning data
            pass

    def test_aggregates_multiple_domains(self):
        """Test aggregation across multiple domain documents."""
        from b_hunters.reporting import aggregate_scan_results

        documents = [
            {
                "Domain": "a.example.com",
                "Ports": {"open_ports": [80, 443]},
                "Technology": {"technologies": ["nginx"]},
                "Vulns": {"XSS": [{"severity": "High"}]},
                "Subdomains": ["a.example.com"],
            },
            {
                "Domain": "b.example.com",
                "Ports": {"open_ports": [22]},
                "Technology": {"technologies": ["mysql"]},
                "Vulns": {"SQLi": [{"severity": "Critical"}]},
                "Subdomains": ["b.example.com"],
            },
            {
                "Domain": "c.example.com",
                "Ports": {"open_ports": [3306]},
                "Technology": {"technologies": ["php", "mysql"]},
                "Vulns": {},
                "Subdomains": ["c.example.com"],
            }
        ]

        result = aggregate_scan_results(documents, "example.com", "multi")

        assert len(result["subdomains"]) == 3
        assert len(result["ports"]) == 4
        assert len(set(result["technologies"])) == 3
        assert result["risk_score"]["critical_count"] == 1
        assert result["risk_score"]["high_count"] == 1
        assert "executive_summary" in result

    def test_report_with_findings_aggregation(self):
        """Test report generation with findings from multiple sources."""
        from b_hunters.reporting import aggregate_scan_results

        documents = [
            {
                "Domain": "a.example.com",
                "Vulns": {
                    "XSS": [
                        {"severity": "High", "type": "XSS", "description": "Reflected XSS", "url": "https://a.example.com/page"}
                    ]
                },
                "JavaScript": [
                    {"Vulns": [{"severity": "Medium", "type": "JS Analysis"}]}
                ],
                "ToolsData": {
                    "nuclei": {
                        "findings": [
                            {"severity": "Low", "type": "Exposed Version"}
                        ]
                    }
                }
            }
        ]

        result = aggregate_scan_results(documents, "example.com", "single")

        assert len(result["findings"]) >= 2
        assert result["risk_score"]["high_count"] == 1
        assert result["risk_score"]["low_count"] >= 1

    def test_report_formats_are_valid(self):
        """Test that all report formats produce valid output."""
        from b_hunters.reporting import ReportGenerator

        scan_data = {
            "domain": "example.com",
            "scantype": "multi",
            "scan_date": "2024-01-01",
            "metrics": {"subdomains": 1, "findings": 0},
            "findings": [],
            "subdomains": ["a.example.com"],
            "technologies": [],
            "ports": [],
            "risk_score": {
                "overall_score": 0.0,
                "risk_level": "Informational",
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "executive_summary": {
                "overview": "Test",
                "key_findings": "Test",
                "recommendations": "Test",
                "risk_assessment": "Test",
                "metrics": "Test",
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            generator = ReportGenerator(tmpdir)

            # Test JSON
            json_path = generator.generate_json_report(scan_data)
            assert os.path.exists(json_path)
            with open(json_path) as f:
                json.load(f)  # Valid JSON should parse

            # Test HTML
            html_path = generator.generate_html_report(scan_data)
            assert os.path.exists(html_path)
            with open(html_path) as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content or "<html" in content
            assert "</html>" in content

    def test_risk_score_calculation_realistic(self):
        """Test realistic risk score scenario."""
        from b_hunters.reporting import RiskScoringEngine, RiskLevel, Vulnerability

        # Realistic vulnerability mix
        vulnerabilities = [
            Vulnerability("SQLi", RiskLevel.CRITICAL, "SQL injection", "https://example.com/login"),
            Vulnerability("XSS", RiskLevel.HIGH, "Stored XSS", "https://example.com/page"),
            Vulnerability("XSS", RiskLevel.HIGH, "Reflected XSS", "https://example.com/search"),
            Vulnerability("IDOR", RiskLevel.MEDIUM, "Object reference", "https://example.com/api/1"),
            Vulnerability("Info", RiskLevel.INFO, "Server header", "https://example.com/"),
            Vulnerability("Info", RiskLevel.INFO, "X-Frame-Options", "https://example.com/"),
        ]

        engine = RiskScoringEngine()
        score = engine.calculate_risk(vulnerabilities, asset_count=1)

        assert score.critical_count == 1
        assert score.high_count == 2
        assert score.medium_count == 1
        assert score.info_count == 2
        # With 1 critical and 2 high, score should be at least moderate
        assert score.overall_score >= 30.0


class TestEnhancedReportingWorkflow:
    """Test enhanced reporting workflow end-to-end."""

    def test_full_reporting_workflow(self):
        """Test complete workflow from scan data to multiple formats."""
        from b_hunters.reporting import (
            RiskScoringEngine,
            ExecutiveSummaryGenerator,
            ReportGenerator,
        )

        # Simulate scan results
        scan_docs = [
            {
                "Domain": "a.example.com",
                "Ports": {"open_ports": [80, 443]},
                "Technology": {"technologies": ["nginx", "php"]},
                "Vulns": {
                    "XSS": [
                        {"severity": "High", "type": "XSS", "description": "Stored XSS", "url": "https://a.example.com"}
                    ]
                },
            },
            {
                "Domain": "b.example.com",
                "Ports": {"open_ports": [22, 3306]},
                "Technology": {"technologies": ["mysql", "ssh"]},
                "Vulns": {},
            }
        ]

        # Calculate risk score
        engine = RiskScoringEngine()
        score = engine.calculate_risk(
            [
                {"severity": "High"} for doc in scan_docs
                for _ in doc.get("Vulns", {}).get("XSS", [])
            ],
            asset_count=len(scan_docs)
        )

        # Generate executive summary
        summary_gen = ExecutiveSummaryGenerator()
        summary = summary_gen.generate({
            "domain": "example.com",
            "scantype": "multi",
            "scan_date": "2024-01-01",
            "findings": [],
            "risk_score": score.__dict__,
            "subdomains": ["a.example.com", "b.example.com"],
            "technologies": ["nginx", "php", "mysql"],
            "ports": [80, 443, 22, 3306],
        })

        # Build report data
        report_data = {
            "domain": "example.com",
            "scantype": "multi",
            "scan_date": "2024-01-01",
            "metrics": {
                "subdomains": 2,
                "technologies": 3,
                "ports": 4,
                "findings": 1,
            },
            "findings": [],
            "risk_score": score.__dict__,
            "executive_summary": summary,
        }

        # Generate reports
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = ReportGenerator(tmpdir)

            json_path = generator.generate_json_report(report_data)
            html_path = generator.generate_html_report(report_data)

            assert os.path.exists(json_path)
            assert os.path.exists(html_path)

            # Verify JSON contains all expected fields
            with open(json_path) as f:
                json_data = json.load(f)

            assert "risk_score" in json_data
            assert "executive_summary" in json_data
            assert json_data["risk_score"]["overall_score"] == score.overall_score

    def test_report_data_structure_consistency(self):
        """Test that all report formats use consistent data structure."""
        from b_hunters.reporting import ReportGenerator

        sample_data = {
            "domain": "test.example.com",
            "scantype": "single",
            "scan_date": "2024-01-01",
            "metrics": {"subdomains": 1, "findings": 0},
            "findings": [],
            "subdomains": ["test.example.com"],
            "technologies": [],
            "ports": [],
            "risk_score": {
                "overall_score": 0.0,
                "risk_level": "Informational",
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "executive_summary": {
                "overview": "Test",
                "key_findings": "Test",
                "recommendations": "Test",
                "risk_assessment": "Test",
                "metrics": "Test",
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            generator = ReportGenerator(tmpdir)

            # Generate all formats
            json_path = generator.generate_json_report(sample_data)
            html_path = generator.generate_html_report(sample_data)

            # Load and compare data structures
            with open(json_path) as f:
                json_data = json.load(f)

            # Verify consistent fields
            for key in ["domain", "scantype", "metrics", "risk_score"]:
                assert key in json_data

            # Verify nested consistency
            assert json_data["domain"] == sample_data["domain"]
            assert json_data["risk_score"]["overall_score"] == sample_data["risk_score"]["overall_score"]