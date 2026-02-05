"""
Unit tests for the reporting module.
"""

import pytest
import json
import os
import tempfile
from datetime import datetime
from unittest.mock import Mock, patch
from b_hunters.reporting import (
    RiskLevel,
    Vulnerability,
    RiskScore,
    RiskScoringEngine,
    ExecutiveSummaryGenerator,
    ReportGenerator,
    aggregate_scan_results,
)


class TestRiskLevel:
    """Test RiskLevel enum."""

    def test_risk_levels(self):
        """Test all risk levels are defined."""
        assert RiskLevel.CRITICAL.value == "Critical"
        assert RiskLevel.HIGH.value == "High"
        assert RiskLevel.MEDIUM.value == "Medium"
        assert RiskLevel.LOW.value == "Low"
        assert RiskLevel.INFO.value == "Informational"


class TestVulnerability:
    """Test Vulnerability dataclass."""

    def test_vulnerability_creation(self):
        """Test creating a vulnerability instance."""
        vuln = Vulnerability(
            type="XSS",
            severity=RiskLevel.HIGH,
            description="Cross-site scripting vulnerability",
            url="https://example.com/page",
            evidence="<script>alert(1)</script>",
            confidence="High",
            cwe_id="CWE-79",
        )

        assert vuln.type == "XSS"
        assert vuln.severity == RiskLevel.HIGH
        assert vuln.confidence == "High"
        assert vuln.cwe_id == "CWE-79"

    def test_vulnerability_minimal(self):
        """Test creating vulnerability with minimal fields."""
        vuln = Vulnerability(
            type="SQLi",
            severity=RiskLevel.CRITICAL,
            description="SQL injection",
            url="https://example.com/query",
        )

        assert vuln.evidence == ""
        assert vuln.confidence == "Medium"
        assert vuln.cwe_id is None


class TestRiskScoringEngine:
    """Test risk scoring calculations."""

    @pytest.fixture
    def engine(self):
        """Create a RiskScoringEngine instance."""
        return RiskScoringEngine()

    def test_score_weights(self, engine):
        """Test severity weights are correct."""
        assert engine.SEVERITY_WEIGHTS[RiskLevel.CRITICAL] == 10.0
        assert engine.SEVERITY_WEIGHTS[RiskLevel.HIGH] == 7.0
        assert engine.SEVERITY_WEIGHTS[RiskLevel.MEDIUM] == 4.0
        assert engine.SEVERITY_WEIGHTS[RiskLevel.LOW] == 1.0
        assert engine.SEVERITY_WEIGHTS[RiskLevel.INFO] == 0.1

    def test_calculate_risk_no_vulnerabilities(self, engine):
        """Test risk score with no vulnerabilities."""
        result = engine.calculate_risk([])

        assert result.overall_score == 0.0
        assert result.risk_level == RiskLevel.INFO
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.medium_count == 0
        assert result.low_count == 0
        assert result.info_count == 0

    def test_calculate_risk_critical(self, engine):
        """Test risk score with critical vulnerabilities."""
        vulnerabilities = [
            Vulnerability(
                type="RCE",
                severity=RiskLevel.CRITICAL,
                description="Remote code execution",
                url="https://example.com",
            )
        ]

        result = engine.calculate_risk(vulnerabilities)

        assert result.critical_count == 1
        assert result.overall_score >= 10.0
        assert result.risk_level == RiskLevel.HIGH

    def test_calculate_risk_high(self, engine):
        """Test risk score with high vulnerabilities."""
        vulnerabilities = [
            Vulnerability(
                type="IDOR",
                severity=RiskLevel.HIGH,
                description="Insecure direct object reference",
                url="https://example.com",
            )
        ]

        result = engine.calculate_risk(vulnerabilities)

        assert result.high_count == 1
        assert result.risk_level == RiskLevel.LOW

    def test_calculate_risk_multiple_vulnerabilities(self, engine):
        """Test risk score with mixed severity vulnerabilities."""
        vulnerabilities = [
            Vulnerability(
                type="XSS", severity=RiskLevel.HIGH,
                description="XSS", url="https://example.com"
            ),
            Vulnerability(
                type="SQLi", severity=RiskLevel.CRITICAL,
                description="SQLi", url="https://example.com"
            ),
            Vulnerability(
                type="Info", severity=RiskLevel.INFO,
                description="Header info", url="https://example.com"
            ),
        ]

        result = engine.calculate_risk(vulnerabilities)

        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.info_count == 1
        assert result.overall_score > 0

    def test_calculate_risk_normalized_by_assets(self, engine):
        """Test risk score normalization by asset count."""
        vulnerabilities = [
            Vulnerability(
                type="XSS",
                severity=RiskLevel.HIGH,
                description="XSS",
                url="https://example.com",
            )
        ]

        result_single = engine.calculate_risk(vulnerabilities, asset_count=1)
        result_multiple = engine.calculate_risk(vulnerabilities, asset_count=10)

        assert result_multiple.overall_score < result_single.overall_score

    def test_risk_level_determination(self, engine):
        """Test risk level determination based on score."""
        test_cases = [
            ([], RiskLevel.INFO),
            (
                [Vulnerability("Info", RiskLevel.INFO, "Info", "https://a.com") for _ in range(10)],
                RiskLevel.LOW,
            ),
            (
                [Vulnerability("Medium", RiskLevel.MEDIUM, "Med", "https://a.com") for _ in range(10)],
                RiskLevel.MEDIUM,
            ),
            (
                [Vulnerability("High", RiskLevel.HIGH, "High", "https://a.com") for _ in range(10)],
                RiskLevel.HIGH,
            ),
            (
                [Vulnerability("Critical", RiskLevel.CRITICAL, "Crit", "https://a.com") for _ in range(10)],
                RiskLevel.CRITICAL,
            ),
        ]

        for vulns, expected_level in test_cases:
            result = engine.calculate_risk(vulns)
            assert result.risk_level == expected_level


class TestExecutiveSummaryGenerator:
    """Test executive summary generation."""

    @pytest.fixture
    def generator(self):
        """Create an ExecutiveSummaryGenerator instance."""
        return ExecutiveSummaryGenerator()

    def test_generate_overview(self, generator):
        """Test overview generation."""
        scan_data = {
            "domain": "example.com",
            "scantype": "multi",
            "scan_date": "2024-01-15",
        }

        summary = generator._generate_overview(scan_data)

        assert "example.com" in summary
        assert "multi" in summary
        assert "2024-01-15" in summary
        assert "security assessment" in summary

    def test_generate_key_findings_no_findings(self, generator):
        """Test key findings with no findings."""
        scan_data = {"findings": []}

        findings = generator._generate_key_findings(scan_data)

        assert "No significant security findings" in findings

    def test_generate_key_findings_with_critical(self, generator):
        """Test key findings with critical findings."""
        scan_data = {
            "findings": [
                {"severity": "Critical", "type": "RCE"},
                {"severity": "High", "type": "XSS"},
            ]
        }

        findings = generator._generate_key_findings(scan_data)

        assert "1 Critical" in findings
        assert "1 High" in findings

    def test_generate_recommendations_critical(self, generator):
        """Test recommendations for critical risk."""
        scan_data = {"risk_score": {"risk_level": "Critical"}}

        recommendations = generator._generate_recommendations(scan_data)

        assert "IMMEDIATE ACTION REQUIRED" in recommendations

    def test_generate_recommendations_low(self, generator):
        """Test recommendations for low risk."""
        scan_data = {"risk_score": {"risk_level": "Low"}}

        recommendations = generator._generate_recommendations(scan_data)

        assert "maintenance cycle" in recommendations

    def test_generate_risk_assessment(self, generator):
        """Test risk assessment generation."""
        scan_data = {
            "risk_score": {
                "overall_score": 75.0,
                "risk_level": "Critical"
            }
        }

        assessment = generator._generate_risk_assessment(scan_data)

        assert "75.0/100" in assessment
        assert "Critical" in assessment

    def test_generate_metrics_summary(self, generator):
        """Test metrics summary generation."""
        scan_data = {
            "subdomains": ["a.example.com", "b.example.com"],
            "technologies": ["nginx", "php"],
            "ports": [80, 443],
            "findings": [{"type": "XSS"}, {"type": "SQLi"}],
        }

        metrics = generator._generate_metrics_summary(scan_data)

        assert "2 subdomains" in metrics
        assert "2 technologies" in metrics
        assert "2 open ports" in metrics
        assert "2 security findings" in metrics

    def test_generate_full_summary(self, generator):
        """Test full summary generation."""
        scan_data = {
            "domain": "example.com",
            "scantype": "multi",
            "scan_date": "2024-01-15",
            "findings": [{"severity": "High", "type": "XSS"}],
            "risk_score": {
                "overall_score": 50.0,
                "risk_level": "High"
            },
            "subdomains": ["a.example.com"],
            "technologies": ["nginx"],
            "ports": [443],
        }

        summary = generator.generate(scan_data)

        assert "overview" in summary
        assert "key_findings" in summary
        assert "recommendations" in summary
        assert "risk_assessment" in summary
        assert "metrics" in summary


class TestReportGenerator:
    """Test report generation."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def generator(self, temp_dir):
        """Create ReportGenerator instance."""
        return ReportGenerator(temp_dir)

    @pytest.fixture
    def sample_scan_data(self):
        """Create sample scan data."""
        return {
            "domain": "example.com",
            "scantype": "multi",
            "scan_date": "2024-01-15",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "metrics": {
                "subdomains": 5,
                "technologies": 3,
                "ports": 10,
                "paths": 50,
                "findings": 2,
                "duration": "1h 30m",
            },
            "subdomains": ["a.example.com", "b.example.com"],
            "technologies": ["nginx", "php", "mysql"],
            "ports": [80, 443, 22],
            "findings": [
                {"severity": "High", "type": "XSS", "description": "Test", "url": "https://a.com", "confidence": "High"},
                {"severity": "Medium", "type": "IDOR", "description": "Test", "url": "https://b.com", "confidence": "Medium"},
            ],
            "risk_score": {
                "overall_score": 65.0,
                "risk_level": "High",
                "critical_count": 0,
                "high_count": 1,
                "medium_count": 1,
                "low_count": 0,
                "info_count": 0,
            },
            "executive_summary": {
                "overview": "Test overview",
                "key_findings": "Test findings",
                "recommendations": "Test recommendations",
                "risk_assessment": "Test assessment",
                "metrics": "Test metrics",
            },
        }

    def test_generate_json_report(self, generator, sample_scan_data, temp_dir):
        """Test JSON report generation."""
        output_path = generator.generate_json_report(sample_scan_data, "test_report.json")

        assert os.path.exists(output_path)
        assert output_path.endswith("test_report.json")

        with open(output_path, 'r') as f:
            data = json.load(f)

        assert data["domain"] == "example.com"
        assert data["scantype"] == "multi"

    def test_generate_html_report(self, generator, sample_scan_data, temp_dir):
        """Test HTML report generation."""
        output_path = generator.generate_html_report(sample_scan_data, "test_report.html")

        assert os.path.exists(output_path)
        assert output_path.endswith("test_report.html")

        with open(output_path, 'r') as f:
            content = f.read()

        assert "B-Hunters Security Report" in content
        assert "example.com" in content
        assert "Risk Score" in content
        assert "Vulnerability Findings" in content

    def test_generate_html_report_creates_template(self, generator, sample_scan_data):
        """Test that HTML template is created if it doesn't exist."""
        templates_dir = Path(generator.output_dir).parent / "templates" / "reports"
        template_path = templates_dir / "report_template.html"

        # Remove template if it exists
        if template_path.exists():
            template_path.unlink()

        # Generate report should create template
        output_path = generator.generate_html_report(sample_scan_data)
        assert template_path.exists()
        assert os.path.exists(output_path)

    def test_generate_pdf_report(self, generator, sample_scan_data, temp_dir):
        """Test PDF report generation."""
        # This test requires weasyprint or pdfkit
        try:
            output_path = generator.generate_pdf_report(sample_scan_data, "test_report.pdf")

            assert os.path.exists(output_path)
            assert output_path.endswith("test_report.pdf")

            # Check file size is reasonable > 0
            assert os.path.getsize(output_path) > 0
        except ImportError:
            pytest.skip("weasyprint or pdfkit not installed")

    def test_pdf_fallback_message(self, generator, sample_scan_data):
        """Test PDF fallback when libraries not installed."""
        with patch.dict('sys.modules', {'weasyprint': None, 'pdfkit': None}):
            with pytest.raises(ImportError) as exc_info:
                generator.generate_pdf_report(sample_scan_data)

            assert "weasyprint" in str(exc_info.value) or "pdfkit" in str(exc_info.value)


class TestAggregateScanResults:
    """Test scan result aggregation."""

    def test_aggregate_empty_documents(self):
        """Test aggregation with empty document list."""
        result = aggregate_scan_results([], "example.com", "single")

        assert result["domain"] == "example.com"
        assert result["scantype"] == "single"
        assert result["metrics"]["subdomains"] == 0
        assert result["metrics"]["findings"] == 0

    def test_aggregate_subdomains(self):
        """Test subdomain aggregation."""
        documents = [
            {"Domain": "a.example.com"},
            {"Domain": "b.example.com"},
            {"Domain": "c.example.com"},
        ]

        result = aggregate_scan_results(documents, "example.com", "multi")

        assert len(result["subdomains"]) == 3
        assert "a.example.com" in result["subdomains"]
        assert result["metrics"]["subdomains"] == 3

    def test_aggregate_ports(self):
        """Test port aggregation."""
        documents = [
            {"Ports": {"open_ports": [80, 443]}},
            {"Ports": {"open_ports": [22, 3306]}},
        ]

        result = aggregate_scan_results(documents, "example.com", "single")

        assert 80 in result["ports"]
        assert 443 in result["ports"]
        assert 22 in result["ports"]
        assert 3306 in result["ports"]
        assert result["metrics"]["ports"] == 4

    def test_aggregate_technologies(self):
        """Test technology aggregation."""
        documents = [
            {"Technology": {"technologies": ["nginx", "php"]}},
            {"Technology": {"technologies": ["mysql", "php"]}},
        ]

        result = aggregate_scan_results(documents, "example.com", "single")

        assert "nginx" in result["technologies"]
        assert "php" in result["technologies"]
        assert "mysql" in result["technologies"]
        assert len(result["technologies"]) == 3

    def test_aggregate_findings(self):
        """Test vulnerability findings aggregation."""
        documents = [
            {"Vulns": {"XSS": [{"severity": "High"}]}},
            {"Vulns": {"SQLi": [{"severity": "Critical"}]}},
        ]

        result = aggregate_scan_results(documents, "example.com", "single")

        assert len(result["findings"]) == 2

    def test_aggregate_with_risk_score(self):
        """Test that aggregation includes risk score."""
        documents = [
            {"Domain": "a.example.com"},
            {"Vulns": {"XSS": [{"severity": "High"}]}},
        ]

        result = aggregate_scan_results(documents, "example.com", "single")

        assert "risk_score" in result
        assert "overall_score" in result["risk_score"]
        assert "risk_level" in result["risk_score"]

    def test_aggregate_includes_executive_summary(self):
        """Test that aggregation includes executive summary."""
        documents = [
            {"Domain": "a.example.com"},
            {"Technology": {"technologies": ["nginx"]}},
        ]

        result = aggregate_scan_results(documents, "example.com", "single")

        assert "executive_summary" in result
        assert "overview" in result["executive_summary"]
        assert "key_findings" in result["executive_summary"]
        assert "recommendations" in result["executive_summary"]

    def test_aggregate_paths_limit(self):
        """Test that paths are limited to 100."""
        document = {
            "Domain": "a.example.com",
            "Paths": [f"/path-{i}" for i in range(200)],
        }

        result = aggregate_scan_results([document], "example.com", "single")

        assert len(result["paths"]) == 100
        assert result["paths"][0] == "/path-0"

    def test_aggregate_findings_limit(self):
        """Test that findings are limited to 100."""
        document = {
            "Domain": "a.example.com",
            "Vulns": {
                "XSS": [{"severity": "High"} for _ in range(150)]
            },
        }

        result = aggregate_scan_results([document], "example.com", "single")

        assert len(result["findings"]) == 100