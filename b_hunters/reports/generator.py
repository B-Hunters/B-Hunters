"""
Report Generator for B-Hunters

Generates comprehensive security reports in multiple formats.

Supported Formats:
- JSON: Machine-readable for integrations
- HTML: Rich visual report with styling
- PDF: Professional printable report

Report Types:
- Standard: Full technical details
- Executive: High-level summary
- Comparative: Before/after scanning

Usage:
    from b_hunters.reports.generator import ReportGenerator
    
    generator = ReportGenerator()
    
    # Generate JSON report
    generator.generate_json_report(data, "report.json")
    
    # Generate HTML report
    generator.generate_html_report(data, "report.html")
    
    # Generate PDF report
    generator.generate_pdf_report(data, "report.pdf")
    
    # Generate executive summary
    generator.generate_executive_summary(data, "executive.html")
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from .risk_scoring import RiskScorer, Severity


class ReportGenerator:
    """
    Main report generation class for B-Hunters.
    
    Provides multiple output formats and report types.
    """
    
    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize the report generator.
        
        Args:
            template_dir: Directory containing report templates (optional)
        """
        self.risk_scorer = RiskScorer()
        self.template_dir = template_dir or os.path.join(
            os.path.dirname(__file__), 'templates'
        )
    
    def generate_json_report(
        self,
        scan_documents: List[Dict[str, Any]],
        output_path: str,
        include_raw_data: bool = True
    ) -> str:
        """
        Generate a comprehensive JSON report.
        
        Args:
            scan_documents: List of scan document dictionaries
            output_path: Path to save the JSON report
            include_raw_data: Whether to include raw tool output
            
        Returns:
            Path to the generated report
        """
        report = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "version": "2.0.0",
                "format": "json",
                "total_scans": len(scan_documents)
            },
            "executive_summary": self._generate_summary_data(scan_documents),
            "scan_results": self._process_scan_results(scan_documents, include_raw_data),
            "risk_analysis": self._generate_risk_analysis(scan_documents),
            "findings_by_severity": self._categorize_findings(scan_documents),
            "recommendations": self._generate_recommendations(scan_documents)
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        return output_path
    
    def generate_html_report(
        self,
        scan_documents: List[Dict[str, Any]],
        output_path: str,
        title: str = "B-Hunters Security Report"
    ) -> str:
        """
        Generate an HTML report with styling.
        
        Args:
            scan_documents: List of scan document dictionaries
            output_path: Path to save the HTML report
            title: Report title
            
        Returns:
            Path to the generated report
        """
        html_content = self._build_html_report(scan_documents, title)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def generate_pdf_report(
        self,
        scan_documents: List[Dict[str, Any]],
        output_path: str,
        title: str = "B-Hunters Security Report"
    ) -> str:
        """
        Generate a PDF report.
        
        This method requires WeasyPrint or pdfkit to be installed.
        Falls back to HTML if PDF generation fails.
        
        Args:
            scan_documents: List of scan document dictionaries
            output_path: Path to save the PDF report
            title: Report title
            
        Returns:
            Path to the generated report
        """
        try:
            import weasyprint
            
            html_content = self._build_html_report(scan_documents, title)
            weasyprint.HTML(string=html_content).write_pdf(output_path)
            return output_path
            
        except ImportError:
            # Fallback to HTML with warning
            html_path = output_path.replace('.pdf', '.html')
            self.generate_html_report(scan_documents, html_path, title)
            
            # Create a text note
            note_path = output_path.replace('.pdf', '_PDF_UNAVAILABLE.txt')
            with open(note_path, 'w') as f:
                f.write(
                    "PDF generation requires WeasyPrint.\n"
                    "Install with: pip install weasyprint\n"
                    f"HTML report generated instead: {html_path}"
                )
            return note_path
    
    def generate_executive_summary(
        self,
        scan_documents: List[Dict[str, Any]],
        output_path: str,
        format: str = "html"
    ) -> str:
        """
        Generate an executive summary report.
        
        Args:
            scan_documents: List of scan document dictionaries
            output_path: Path to save the summary
            format: Output format (html, json, or txt)
            
        Returns:
            Path to the generated report
        """
        summary_data = self._generate_summary_data(scan_documents)
        top_findings = self._get_top_findings(scan_documents, limit=10)
        
        if format.lower() == "json":
            report = {
                "executive_summary": summary_data,
                "top_findings": top_findings,
                "generated_at": datetime.utcnow().isoformat() + "Z"
            }
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
                
        elif format.lower() == "html":
            html = self._build_executive_html(summary_data, top_findings)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
                
        else:  # txt format
            txt = self._build_executive_text(summary_data, top_findings)
            with open(output_path, 'w') as f:
                f.write(txt)
        
        return output_path
    
    def generate_comparative_report(
        self,
        previous_scan: List[Dict[str, Any]],
        current_scan: List[Dict[str, Any]],
        output_path: str,
        format: str = "html"
    ) -> str:
        """
        Generate a comparative report showing changes between scans.
        
        Args:
            previous_scan: Previous scan documents
            current_scan: Current scan documents
            output_path: Path to save the report
            format: Output format
            
        Returns:
            Path to the generated report
        """
        comparison = self._compare_scans(previous_scan, current_scan)
        
        if format.lower() == "json":
            with open(output_path, 'w') as f:
                json.dump(comparison, f, indent=2, default=str)
        else:
            html = self._build_comparison_html(comparison)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
        
        return output_path
    
    def _generate_summary_data(self, scan_documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate executive summary data."""
        all_findings = self._extract_all_findings(scan_documents)
        score, severity_counts = self.risk_scorer.calculate_overall_score(all_findings)
        
        total_domains = len(scan_documents)
        active_domains = sum(1 for doc in scan_documents if doc.get("active", False))
        
        processing_tasks = set()
        finished_tasks = set()
        failed_tasks = set()
        
        for doc in scan_documents:
            status = doc.get("status", {})
            processing_tasks.update(status.get("processing", []))
            finished_tasks.update(status.get("finished", []))
            failed_tasks.update(status.get("failed", []))
        
        return {
            "scan_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "overall_risk_score": score,
            "risk_rating": self.risk_scorer.get_risk_rating(score),
            "total_domains": total_domains,
            "active_domains": active_domains,
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
            "tools_utilized": {
                "processing": list(processing_tasks),
                "completed": list(finished_tasks),
                "failed": list(failed_tasks)
            }
        }
    
    def _extract_all_findings(self, scan_documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract all findings from scan documents."""
        findings = []
        
        for doc in scan_documents:
            vulns = doc.get("Vulns", {})
            for tool, tool_findings in vulns.items():
                if isinstance(tool_findings, list):
                    for finding in tool_findings:
                        finding["tool"] = tool
                        finding["domain"] = doc.get("Domain", "unknown")
                        findings.append(finding)
        
        return findings
    
    def _get_top_findings(
        self,
        scan_documents: List[Dict[str, Any]],
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get top findings ranked by severity."""
        all_findings = self._extract_all_findings(scan_documents)
        
        for finding in all_findings:
            finding["severity_enum"] = self.risk_scorer.classify_severity(finding)
            finding["risk_score"] = self.risk_scorer.calculate_risk_score(finding)
        
        # Sort by severity weight then by risk score
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, 
                         Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        
        sorted_findings = sorted(
            all_findings,
            key=lambda x: (severity_order.get(x["severity_enum"], 5), -x["risk_score"])
        )
        
        return sorted_findings[:limit]
    
    def _process_scan_results(
        self,
        scan_documents: List[Dict[str, Any]],
        include_raw: bool = True
    ) -> List[Dict[str, Any]]:
        """Process scan documents for report."""
        results = []
        
        for doc in scan_documents:
            result = {
                "domain": doc.get("Domain"),
                "active": doc.get("active", False),
                "scan_id": doc.get("Scanid"),
                "status": doc.get("status", {}),
                "technology": doc.get("Technology", {}),
                "ports": doc.get("Ports", {}),
                "subdomains": doc.get("Subdomains", []),
            }
            
            if include_raw:
                result["raw_data"] = doc.get("data", {})
                result["paths"] = doc.get("Paths", [])
                result["vulnerabilities"] = doc.get("Vulns", {})
            
            results.append(result)
        
        return results
    
    def _generate_risk_analysis(self, scan_documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate risk analysis for the report."""
        all_findings = self._extract_all_findings(scan_documents)
        score, severity_counts = self.risk_scorer.calculate_overall_score(all_findings)
        
        # Findings by domain
        domain_risks = {}
        for doc in scan_documents:
            domain = doc.get("Domain", "unknown")
            vulns = doc.get("Vulns", {})
            domain_findings = []
            
            for tool_findings in vulns.values():
                if isinstance(tool_findings, list):
                    domain_findings.extend(tool_findings)
            
            if domain_findings:
                domain_score, _ = self.risk_scorer.calculate_overall_score(domain_findings)
                domain_risks[domain] = {
                    "risk_score": domain_score,
                    "risk_rating": self.risk_scorer.get_risk_rating(domain_score),
                    "finding_count": len(domain_findings)
                }
        
        return {
            "overall_score": score,
            "overall_rating": self.risk_scorer.get_risk_rating(score),
            "severity_distribution": severity_counts,
            "domain_risk_breakdown": domain_risks,
            "total_findings": len(all_findings)
        }
    
    def _categorize_findings(self, scan_documents: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize findings by severity."""
        all_findings = self._extract_all_findings(scan_documents)
        
        categorized = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": [],
            "Info": []
        }
        
        for finding in all_findings:
            severity = self.risk_scorer.classify_severity(finding)
            finding["severity"] = severity.value
            categorized[severity.value].append(finding)
        
        return categorized
    
    def _generate_recommendations(self, scan_documents: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate security recommendations based on findings."""
        all_findings = self._extract_all_findings(scan_documents)
        categorized = self._categorize_findings(scan_documents)
        
        recommendations = []
        
        if categorized["Critical"]:
            recommendations.append({
                "priority": "Immediate",
                "category": "Critical Vulnerabilities",
                "recommendation": "Address all Critical findings immediately. These represent severe security risks.",
                "affected_count": len(categorized["Critical"])
            })
        
        if categorized["High"]:
            recommendations.append({
                "priority": "High",
                "category": "High Risk Issues",
                "recommendation": "Prioritize remediation of High severity findings within 7 days.",
                "affected_count": len(categorized["High"])
            })
        
        # Check for missing security headers
        recommendations.append({
            "priority": "Medium",
            "category": "Security Headers",
            "recommendation": "Implement recommended security headers (CSP, HSTS, X-Frame-Options, etc.).",
            "affected_count": "Review all domains"
        })
        
        # Check for exposed services
        recommendations.append({
            "priority": "Low",
            "category": "Information Disclosure",
            "recommendation": "Review and minimize information disclosure in error messages and headers.",
            "affected_count": "Review all domains"
        })
        
        return recommendations
    
    def _compare_scans(
        self,
        previous: List[Dict[str, Any]],
        current: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Compare two scan results."""
        prev_findings = self._extract_all_findings(previous)
        curr_findings = self._extract_all_findings(current)
        
        prev_score, _ = self.risk_scorer.calculate_overall_score(prev_findings)
        curr_score, curr_severities = self.risk_scorer.calculate_overall_score(curr_findings)
        
        # Create finding signatures for comparison
        prev_signatures = {self._finding_signature(f): f for f in prev_findings}
        curr_signatures = {self._finding_signature(f): f for f in curr_findings}
        
        new_findings = [curr_signatures[sig] for sig in curr_signatures if sig not in prev_signatures]
        resolved_findings = [prev_signatures[sig] for sig in prev_signatures if sig not in curr_signatures]
        persistent_findings = [curr_signatures[sig] for sig in curr_signatures if sig in prev_signatures]
        
        return {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "previous_scan_findings": len(prev_findings),
                "current_scan_findings": len(curr_findings)
            },
            "risk_comparison": {
                "previous_score": prev_score,
                "current_score": curr_score,
                "change": round(curr_score - prev_score, 2),
                "trend": "improved" if curr_score < prev_score else "worsened" if curr_score > prev_score else "unchanged"
            },
            "severity_comparison": {
                "current": curr_severities
            },
            "findings_comparison": {
                "new": new_findings,
                "resolved": resolved_findings,
                "persistent": persistent_findings
            },
            "summary": {
                "new_count": len(new_findings),
                "resolved_count": len(resolved_findings),
                "persistent_count": len(persistent_findings)
            }
        }
    
    def _finding_signature(self, finding: Dict[str, Any]) -> str:
        """Create a unique signature for a finding."""
        return f"{finding.get('type', 'unknown')}:{finding.get('affected_url', finding.get('url', 'unknown'))}"
    
    def _build_html_report(self, scan_documents: List[Dict[str, Any]], title: str) -> str:
        """Build the full HTML report."""
        summary = self._generate_summary_data(scan_documents)
        risk_analysis = self._generate_risk_analysis(scan_documents)
        findings_by_severity = self._categorize_findings(scan_documents)
        recommendations = self._generate_recommendations(scan_documents)
        
        css = self._get_report_css()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>{css}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 {title}</h1>
            <p class="timestamp">Generated: {summary['scan_date']}</p>
        </header>
        
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="risk-score-box {self._get_risk_class(summary['overall_risk_score'])}">
                    <h3>Overall Risk Score</h3>
                    <div class="score">{summary['overall_risk_score']}</div>
                    <div class="rating">{summary['risk_rating']}</div>
                </div>
                <div class="stats-box">
                    <h3>Scan Statistics</h3>
                    <ul>
                        <li><strong>Total Domains:</strong> {summary['total_domains']}</li>
                        <li><strong>Active Domains:</strong> {summary['active_domains']}</li>
                        <li><strong>Total Findings:</strong> {summary['total_findings']}</li>
                    </ul>
                </div>
            </div>
        </section>
        
        <section class="severity-breakdown">
            <h2>Findings by Severity</h2>
            <div class="severity-grid">
                {self._build_severity_boxes(summary['severity_breakdown'])}
            </div>
        </section>
        
        <section class="recommendations">
            <h2>Recommendations</h2>
            {self._build_recommendations_html(recommendations)}
        </section>
        
        <section class="detailed-findings">
            <h2>Detailed Findings</h2>
            {self._build_detailed_findings_html(findings_by_severity)}
        </section>
        
        <footer>
            <p>Report generated by B-Hunters Security Framework</p>
        </footer>
    </div>
</body>
</html>"""
        
        return html
    
    def _build_executive_html(self, summary: Dict, top_findings: List) -> str:
        """Build executive summary HTML."""
        css = self._get_report_css()
        
        findings_html = ""
        for finding in top_findings[:5]:
            severity_class = finding.get("severity_enum", Severity.LOW).value.lower()
            findings_html += f"""
                <tr class="{severity_class}">
                    <td>{finding.get('domain', 'N/A')}</td>
                    <td>{finding.get('type', 'N/A')}</td>
                    <td><span class="badge {severity_class}">{finding.get('severity_enum', Severity.LOW).value}</span></td>
                    <td>{finding.get('evidence', 'N/A')[:100]}...</td>
                </tr>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary - B-Hunters</title>
    <style>{css}</style>
</head>
<body>
    <div class="container executive">
        <header>
            <h1>📊 Executive Summary</h1>
            <p class="timestamp">{summary['scan_date']}</p>
        </header>
        
        <div class="score-banner {self._get_risk_class(summary['overall_risk_score'])}">
            <div class="big-score">{summary['overall_risk_score']}</div>
            <div class="rating-text">{summary['risk_rating']}</div>
        </div>
        
        <div class="key-metrics">
            <div class="metric">
                <span class="number">{summary['total_findings']}</span>
                <span class="label">Total Findings</span>
            </div>
            <div class="metric critical">
                <span class="number">{summary['severity_breakdown']['Critical']}</span>
                <span class="label">Critical</span>
            </div>
            <div class="metric high">
                <span class="number">{summary['severity_breakdown']['High']}</span>
                <span class="label">High</span>
            </div>
        </div>
        
        <h2>Top Priority Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        
        return html
    
    def _build_executive_text(self, summary: Dict, top_findings: List) -> str:
        """Build executive summary text."""
        text = f"""B-HUNTERS SECURITY ASSESSMENT - EXECUTIVE SUMMARY
{'=' * 60}

Scan Date: {summary['scan_date']}
Overall Risk Score: {summary['overall_risk_score']}/10 ({summary['risk_rating']})

KEY METRICS
-----------
Total Findings: {summary['total_findings']}
Critical: {summary['severity_breakdown']['Critical']}
High: {summary['severity_breakdown']['High']}
Medium: {summary['severity_breakdown']['Medium']}
Low: {summary['severity_breakdown']['Low']}
Info: {summary['severity_breakdown']['Info']}

TOP PRIORITY FINDINGS
---------------------
"""
        
        for i, finding in enumerate(top_findings[:5], 1):
            severity = finding.get("severity_enum", Severity.LOW).value
            text += f"""
{i}. {finding.get('type', 'N/A')} ({finding.get('domain', 'N/A')})
   Severity: {severity}
   Evidence: {finding.get('evidence', 'N/A')[:150]}...

"""
        
        text += """
RECOMMENDATIONS
---------------
1. Address all Critical and High severity findings immediately
2. Review security headers across all domains
3. Implement input validation for all forms and API endpoints
4. Schedule regular security assessments

---
Report generated by B-Hunters Security Framework
"""
        return text
    
    def _build_comparison_html(self, comparison: Dict) -> str:
        """Build HTML for comparative report."""
        css = self._get_report_css()
        
        trend_emoji = "📉" if comparison['risk_comparison']['trend'] == 'improved' else "📈" if comparison['risk_comparison']['trend'] == 'worsened' else "➡️"
        
        new_findings_html = ""
        for finding in comparison['findings_comparison']['new'][:10]:
            new_findings_html += f"<li>{finding.get('type', 'N/A')} - {finding.get('url', finding.get('affected_url', 'N/A'))}</li>"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Comparative Report - B-Hunters</title>
    <style>{css}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{trend_emoji} Comparative Security Report</h1>
            <p>Comparison between previous and current scan results</p>
        </header>
        
        <section class="trend-summary">
            <h2>Risk Trend</h2>
            <div class="trend-box {comparison['risk_comparison']['trend']}">
                <p>Overall Risk: <strong>{comparison['risk_comparison']['trend'].upper()}</strong></p>
                <p>Previous Score: {comparison['risk_comparison']['previous_score']}</p>
                <p>Current Score: {comparison['risk_comparison']['current_score']}</p>
                <p>Change: {comparison['risk_comparison']['change']:+.2f}</p>
            </div>
        </section>
        
        <section class="findings-changes">
            <h2>Findings Changes</h2>
            <div class="changes-grid">
                <div class="change-box new">
                    <h3>New Findings</h3>
                    <div class="count">{comparison['summary']['new_count']}</div>
                    <ul>{new_findings_html}</ul>
                </div>
                <div class="change-box resolved">
                    <h3>Resolved Findings</h3>
                    <div class="count">{comparison['summary']['resolved_count']}</div>
                </div>
                <div class="change-box persistent">
                    <h3>Persistent Findings</h3>
                    <div class="count">{comparison['summary']['persistent_count']}</div>
                </div>
            </div>
        </section>
    </div>
</body>
</html>"""
        return html
    
    def _build_severity_boxes(self, severity_breakdown: Dict) -> str:
        """Build HTML for severity boxes."""
        severities = ["Critical", "High", "Medium", "Low", "Info"]
        colors = ["#ff4444", "#ff8800", "#ffcc00", "#00cc66", "#3399ff"]
        
        html = ""
        for sev, color in zip(severities, colors):
            count = severity_breakdown.get(sev, 0)
            html += f"""
                <div class="severity-box" style="border-color: {color}">
                    <h3 style="color: {color}">{sev}</h3>
                    <div class="count" style="color: {color}">{count}</div>
                </div>
            """
        return html
    
    def _build_recommendations_html(self, recommendations: List) -> str:
        """Build HTML for recommendations section."""
        html = ""
        for rec in recommendations:
            priority_class = rec['priority'].lower().replace(' ', '-')
            html += f"""
                <div class="recommendation {priority_class}">
                    <h4>{rec['category']} <span class="priority">[{rec['priority']}]</span></h4>
                    <p>{rec['recommendation']}</p>
                    <p class="affected">Affected: {rec['affected_count']}</p>
                </div>
            """
        return html
    
    def _build_detailed_findings_html(self, findings_by_severity: Dict) -> str:
        """Build HTML for detailed findings."""
        html = ""
        
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            findings = findings_by_severity.get(severity, [])
            if findings:
                html += f"""
                    <div class="severity-section {severity.lower()}">
                        <h3>{severity} Findings ({len(findings)})</h3>
                        <table class="findings-table">
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Type</th>
                                    <th>Tool</th>
                                    <th>Evidence</th>
                                </tr>
                            </thead>
                            <tbody>
                """
                
                for finding in findings[:20]:  # Limit to top 20 per severity
                    html += f"""
                        <tr>
                            <td>{finding.get('domain', 'N/A')}</td>
                            <td>{finding.get('type', 'N/A')}</td>
                            <td>{finding.get('tool', 'N/A')}</td>
                            <td>{finding.get('evidence', 'N/A')[:100]}...</td>
                        </tr>
                    """
                
                if len(findings) > 20:
                    html += f"""
                        <tr><td colspan="4" class="more">... and {len(findings) - 20} more</td></tr>
                    """
                
                html += "</tbody></table></div>"
        
        return html
    
    def _get_risk_class(self, score: float) -> str:
        """Get CSS class for risk score."""
        if score >= 7:
            return "critical"
        elif score >= 4:
            return "high"
        else:
            return "low"
    
    def _get_report_css(self) -> str:
        """Get CSS styles for reports."""
        return '''
            * { box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                   line-height: 1.6; color: #333; margin: 0; padding: 0; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; background: white; }
            header { border-bottom: 3px solid #4a90d9; padding-bottom: 20px; margin-bottom: 30px; }
            h1 { color: #2c3e50; margin: 0; }
            h2 { color: #34495e; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
            .timestamp { color: #7f8c8d; font-size: 0.9em; }
            
            .summary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
            .risk-score-box { background: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; }
            .risk-score-box.critical { background: #ffebee; border: 2px solid #f44336; }
            .risk-score-box.high { background: #fff3e0; border: 2px solid #ff9800; }
            .risk-score-box.low { background: #e8f5e9; border: 2px solid #4caf50; }
            .score { font-size: 4em; font-weight: bold; color: #2c3e50; }
            .rating { font-size: 1.2em; color: #7f8c8d; }
            .stats-box { background: #f8f9fa; border-radius: 8px; padding: 20px; }
            .stats-box ul { list-style: none; padding: 0; }
            .stats-box li { padding: 5px 0; }
            
            .severity-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
            .severity-box { text-align: center; padding: 15px; border-radius: 8px; 
                          background: white; border-width: 3px; border-style: solid; }
            .severity-box h3 { margin: 0 0 10px 0; }
            .severity-box .count { font-size: 2em; font-weight: bold; }
            
            .recommendation { background: #f8f9fa; border-left: 4px solid #4a90d9; 
                           padding: 15px; margin: 10px 0; border-radius: 0 8px 8px 0; }
            .recommendation.immediate { border-left-color: #f44336; }
            .recommendation.high { border-left-color: #ff9800; }
            .recommendation.medium { border-left-color: #ffc107; }
            .recommendation.low { border-left-color: #4caf50; }
            .recommendation h4 { margin: 0 0 10px 0; color: #2c3e50; }
            .priority { font-size: 0.8em; padding: 2px 8px; border-radius: 4px; background: #e0e0e0; }
            .affected { font-size: 0.9em; color: #7f8c8d; margin-top: 10px; }
            
            .findings-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            .findings-table th { background: #34495e; color: white; padding: 12px; text-align: left; }
            .findings-table td { padding: 10px; border-bottom: 1px solid #ecf0f1; }
            .findings-table tr:hover { background: #f8f9fa; }
            .findings-table .critical { color: #f44336; }
            .findings-table .high { color: #ff9800; }
            .findings-table .medium { color: #ffc107; }
            .findings-table .low { color: #4caf50; }
            .badge { padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.85em; }
            .badge.critical { background: #f44336; }
            .badge.high { background: #ff9800; }
            .badge.medium { background: #ffc107; color: #333; }
            .badge.low { background: #4caf50; }
            
            .severity-section { margin: 30px 0; }
            .severity-section h3 { padding: 10px; border-radius: 4px; }
            .severity-section.critical h3 { background: #ffebee; color: #c62828; }
            .severity-section.high h3 { background: #fff3e0; color: #e65100; }
            .severity-section.medium h3 { background: #fffde7; color: #f57f17; }
            .severity-section.low h3 { background: #e8f5e9; color: #2e7d32; }
            
            footer { text-align: center; padding: 20px; color: #7f8c8d; 
                   border-top: 1px solid #ecf0f1; margin-top: 40px; }
            
            /* Executive summary styles */
            .executive .score-banner { text-align: center; padding: 40px; border-radius: 8px; margin: 20px 0; }
            .score-banner.critical { background: linear-gradient(135deg, #ffebee, #ffcdd2); }
            .score-banner.high { background: linear-gradient(135deg, #fff3e0, #ffe0b2); }
            .score-banner.low { background: linear-gradient(135deg, #e8f5e9, #c8e6c9); }
            .big-score { font-size: 6em; font-weight: bold; }
            .rating-text { font-size: 1.5em; color: #7f8c8d; }
            
            .key-metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 30px 0; }
            .metric { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }
            .metric .number { display: block; font-size: 3em; font-weight: bold; color: #2c3e50; }
            .metric .label { color: #7f8c8d; }
            .metric.critical .number { color: #f44336; }
            .metric.high .number { color: #ff9800; }
            
            @media print {
                body { background: white; }
                .container { max-width: 100%; }
            }
        '''
