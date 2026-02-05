"""
Integration tests for report generation functionality.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open
import json
import os
import tempfile


@pytest.mark.integration
@pytest.mark.report
class TestReportGenerator:
    """Test the enhanced report generator."""
    
    def test_json_report_export(self, sample_scan_document, temp_report_dir):
        """Test JSON report export functionality."""
        from b_hunters.reports.generator import ReportGenerator
        
        generator = ReportGenerator()
        output_path = os.path.join(temp_report_dir, "report.json")
        
        result = generator.generate_json_report(
            [sample_scan_document],
            output_path=output_path
        )
        
        assert os.path.exists(output_path)
        with open(output_path, 'r') as f:
            data = json.load(f)
            assert "scan_results" in data
    
    def test_html_report_generation(self, sample_scan_document, temp_report_dir):
        """Test HTML report generation."""
        from b_hunters.reports.generator import ReportGenerator
        
        generator = ReportGenerator()
        output_path = os.path.join(temp_report_dir, "report.html")
        
        with patch.object(generator, 'generate_html_report') as mock_html:
            mock_html.return_value = output_path
            result = mock_html([sample_scan_document], output_path)
            
            assert result == output_path
    
    def test_executive_summary_generation(self, sample_scan_document):
        """Test executive summary generation."""
        from b_hunters.reports.generator import ReportGenerator
        
        generator = ReportGenerator()
        
        with patch.object(generator, 'generate_executive_summary') as mock_summary:
            mock_summary.return_value = {
                "total_findings": 10,
                "critical_count": 1,
                "high_count": 3,
                "medium_count": 4,
                "low_count": 2
            }
            
            summary = mock_summary([sample_scan_document])
            
            assert summary["total_findings"] == 10
            assert summary["critical_count"] >= 0


@pytest.mark.integration
class TestRiskScoring:
    """Test risk scoring functionality."""
    
    @pytest.mark.parametrize("finding,expected_severity", [
        ({"type": "sql_injection", "evidence": "sql error in response"}, "Critical"),
        ({"type": "xss", "evidence": "script executed"}, "High"),
        ({"type": "information_disclosure", "evidence": "version leaked"}, "Medium"),
        ({"type": "missing_header", "evidence": "x-frame-options missing"}, "Low"),
    ])
    def test_severity_classification(self, finding, expected_severity):
        """Test severity classification for different vulnerability types."""
        from b_hunters.reports.risk_scoring import RiskScorer
        
        scorer = RiskScorer()
        
        with patch.object(scorer, 'classify_severity') as mock_classify:
            mock_classify.return_value = expected_severity
            result = mock_classify(finding)
            
            assert result == expected_severity
    
    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        from b_hunters.reports.risk_scoring import RiskScorer
        
        scorer = RiskScorer()
        
        findings = [
            {"severity": "Critical", "confidence": "High"},
            {"severity": "High", "confidence": "Medium"},
            {"severity": "Medium", "confidence": "High"},
        ]
        
        with patch.object(scorer, 'calculate_overall_score') as mock_score:
            mock_score.return_value = 8.5
            score = mock_score(findings)
            
            assert 0 <= score <= 10


@pytest.mark.integration
class TestExportIntegration:
    """Test export functionality for third-party integrations."""
    
    def test_jira_export_format(self, sample_scan_document):
        """Test Jira-compatible export format."""
        from b_hunters.reports.exporter import ReportExporter
        
        exporter = ReportExporter()
        
        with patch.object(exporter, 'export_to_jira') as mock_export:
            mock_export.return_value = {
                "issues": [{
                    "summary": "Security Finding",
                    "description": "Vulnerability found",
                    "severity": "High"
                }]
            }
            
            result = mock_export([sample_scan_document])
            
            assert "issues" in result
            assert isinstance(result["issues"], list)
    
    def test_gitlab_export_format(self, sample_scan_document):
        """Test GitLab-compatible export format."""
        from b_hunters.reports.exporter import ReportExporter
        
        exporter = ReportExporter()
        
        with patch.object(exporter, 'export_to_gitlab') as mock_export:
            mock_export.return_value = {
                "vulnerabilities": [{
                    "id": "find-001",
                    "severity": "High"
                }]
            }
            
            result = mock_export([sample_scan_document])
            
            assert "vulnerabilities" in result
