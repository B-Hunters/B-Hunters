"""
B-Hunters Enhanced Reporting Module
==================================

This module provides comprehensive reporting capabilities for B-Hunters scans,
including multiple output formats, risk scoring, and executive summaries.

Features:
- JSON, HTML, and PDF report generation
- Risk scoring with severity classification
- Executive summary generation
- Comparative reporting (before/after scans)
- Third-party integrations (Jira, GitLab)

Usage:
    from b_hunters.reports import ReportGenerator
    
    generator = ReportGenerator()
    generator.generate_json_report(data, output_path="report.json")
    generator.generate_html_report(data, output_path="report.html")
"""

from .generator import ReportGenerator
from .risk_scoring import RiskScorer, Severity
from .exporter import ReportExporter

__all__ = [
    'ReportGenerator',
    'RiskScorer',
    'Severity',
    'ReportExporter',
]
