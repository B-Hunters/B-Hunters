"""
Risk Scoring Module for B-Hunters

Provides severity classification and risk scoring for security findings.

Severity Levels:
- Critical: Immediate threat, exploit available, high impact
- High: Serious vulnerability, likely exploitable
- Medium: Moderate risk, may require additional conditions
- Low: Minor issue, low impact
- Info: Informational, no direct risk

Usage:
    from b_hunters.reports.risk_scoring import RiskScorer
    
    scorer = RiskScorer()
    severity = scorer.classify_severity(finding)
    score = scorer.calculate_overall_score(findings)
"""

from enum import Enum
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass


class Severity(Enum):
    """Severity classification levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0
}


@dataclass
class RiskFinding:
    """Represents a security finding with risk attributes."""
    title: str
    vulnerability_type: str
    severity: Severity
    confidence: str
    description: str
    affected_url: str
    evidence: str
    remediation: str = ""
    references: List[str] = None
    cwe_id: str = ""
    cve_id: str = ""
    
    def __post_init__(self):
        if self.references is None:
            self.references = []


class RiskScorer:
    """
    Risk scoring engine for security findings.
    
    Provides methods for:
    - Severity classification based on vulnerability type
    - Overall risk score calculation
    - Risk trend analysis
    """
    
    # Vulnerability type to severity mapping
    VULN_SEVERITY_MAP = {
        # Critical
        "sql_injection": Severity.CRITICAL,
        "remote_code_execution": Severity.CRITICAL,
        "rce": Severity.CRITICAL,
        "command_injection": Severity.CRITICAL,
        "unauthenticated_access": Severity.CRITICAL,
        "authentication_bypass": Severity.CRITICAL,
        "remote_shell": Severity.CRITICAL,
        "arbitrary_file_upload": Severity.CRITICAL,
        
        # High
        "xss": Severity.HIGH,
        "cross_site_scripting": Severity.HIGH,
        "xxe": Severity.HIGH,
        "xml_external_entity": Severity.HIGH,
        "ssrf": Severity.HIGH,
        "server_side_request_forgery": Severity.HIGH,
        "ssti": Severity.HIGH,
        "server_side_template_injection": Severity.HIGH,
        "path_traversal": Severity.HIGH,
        "lfi": Severity.HIGH,
        "local_file_inclusion": Severity.HIGH,
        "sensitive_data_exposure": Severity.HIGH,
        "private_key_exposure": Severity.HIGH,
        "api_key_exposure": Severity.HIGH,
        
        # Medium
        "csrf": Severity.MEDIUM,
        "cross_site_request_forgery": Severity.MEDIUM,
        "open_redirect": Severity.MEDIUM,
        "information_disclosure": Severity.MEDIUM,
        "version_exposure": Severity.MEDIUM,
        "stack_trace_exposure": Severity.MEDIUM,
        "weak_password_policy": Severity.MEDIUM,
        "insecure_cors": Severity.MEDIUM,
        "missing_csp": Severity.MEDIUM,
        "clickjacking": Severity.MEDIUM,
        
        # Low
        "missing_security_header": Severity.LOW,
        "x_frame_options": Severity.LOW,
        "x_content_type_options": Severity.LOW,
        "strict_transport_security": Severity.LOW,
        "content_security_policy": Severity.LOW,
        "referrer_policy": Severity.LOW,
        "permissions_policy": Severity.LOW,
        "banner_disclosure": Severity.LOW,
        "verbose_error_messages": Severity.LOW,
        
        # Default
        "info": Severity.INFO,
        "informational": Severity.INFO,
        "note": Severity.INFO,
    }
    
    # CWE to severity mapping for common weaknesses
    CWE_SEVERITY_MAP = {
        "CWE-78": Severity.CRITICAL,    # OS Command Injection
        "CWE-89": Severity.CRITICAL,    # SQL Injection
        "CWE-94": Severity.CRITICAL,    # Code Injection
        "CWE-862": Severity.CRITICAL,   # Missing Authorization
        "CWE-798": Severity.CRITICAL,   # Hardcoded Credentials
        "CWE-287": Severity.HIGH,       # Improper Authentication
        "CWE-352": Severity.HIGH,       # CSRF
        "CWE-79": Severity.HIGH,        # XSS
        "CWE-611": Severity.HIGH,       # XXE
        "CWE-918": Severity.HIGH,       # SSRF
        "CWE-22": Severity.HIGH,        # Path Traversal
        "CWE-200": Severity.MEDIUM,     # Information Exposure
        "CWE-209": Severity.MEDIUM,     # Information Exposure Through Error Messages
        "CWE-532": Severity.LOW,        # Insertion of Sensitive Information into Log File
    }
    
    def __init__(self):
        """Initialize the risk scorer."""
        self.severity_weights = SEVERITY_WEIGHTS
    
    def classify_severity(self, finding: Dict[str, Any]) -> Severity:
        """
        Classify the severity of a finding based on its type and evidence.
        
        Args:
            finding: Dictionary containing vulnerability information
            
        Returns:
            Severity enum value
        """
        vuln_type = finding.get("type", "").lower()
        evidence = finding.get("evidence", "").lower()
        cwe_id = finding.get("cwe_id", "")
        
        # Check CWE first if available
        if cwe_id and cwe_id in self.CWE_SEVERITY_MAP:
            return self.CWE_SEVERITY_MAP[cwe_id]
        
        # Check vulnerability type
        for vuln_key, severity in self.VULN_SEVERITY_MAP.items():
            if vuln_key in vuln_type or vuln_key in evidence:
                return severity
        
        # Evidence-based heuristics
        critical_indicators = [
            "root access", "admin shell", "database dumped",
            "arbitrary command", "remote code", "unauthenticated"
        ]
        
        high_indicators = [
            "script executed", "cookie stolen", "session hijacked",
            "file read", "internal access", "sensitive data"
        ]
        
        for indicator in critical_indicators:
            if indicator in evidence:
                return Severity.CRITICAL
        
        for indicator in high_indicators:
            if indicator in evidence:
                return Severity.HIGH
        
        # Default to Low if no match found
        return Severity.LOW
    
    def calculate_risk_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate a numeric risk score (0-10) for a single finding.
        
        Args:
            finding: Dictionary containing vulnerability information
            
        Returns:
            Risk score between 0 and 10
        """
        severity = self.classify_severity(finding)
        base_score = self.severity_weights[severity]
        
        # Confidence adjustment
        confidence = finding.get("confidence", "medium").lower()
        confidence_multiplier = {
            "high": 1.0,
            "medium": 0.8,
            "low": 0.5
        }.get(confidence, 0.8)
        
        # Evidence-based adjustments
        evidence_bonus = 0
        evidence = finding.get("evidence", "").lower()
        
        if "exploit" in evidence or "poc" in evidence or "proof" in evidence:
            evidence_bonus = 0.5
        
        if "authenticated" in evidence or "unauthenticated" in evidence:
            evidence_bonus += 0.5
        
        final_score = (base_score * confidence_multiplier) + evidence_bonus
        return min(final_score, 10.0)
    
    def calculate_overall_score(self, findings: List[Dict[str, Any]]) -> Tuple[float, Dict[str, int]]:
        """
        Calculate overall risk score for a list of findings.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Tuple of (overall_score, severity_counts)
        """
        if not findings:
            return 0.0, {
                "Critical": 0, "High": 0, "Medium": 0, 
                "Low": 0, "Info": 0
            }
        
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        total_score = 0.0
        
        for finding in findings:
            severity = self.classify_severity(finding)
            risk_score = self.calculate_risk_score(finding)
            
            severity_counts[severity.value] += 1
            total_score += risk_score
        
        # Calculate weighted average
        # Critical and High findings have more weight
        weighted_sum = (
            severity_counts["Critical"] * 10 +
            severity_counts["High"] * 7 +
            severity_counts["Medium"] * 4 +
            severity_counts["Low"] * 1
        )
        
        total_findings = sum(severity_counts.values())
        if total_findings == 0:
            return 0.0, severity_counts
        
        overall_score = min(weighted_sum / max(total_findings * 0.5, 1), 10.0)
        
        return round(overall_score, 2), severity_counts
    
    def get_risk_rating(self, score: float) -> str:
        """
        Convert a numeric score to a risk rating.
        
        Args:
            score: Risk score between 0 and 10
            
        Returns:
            Risk rating string
        """
        if score >= 9:
            return "Critical Risk"
        elif score >= 7:
            return "High Risk"
        elif score >= 4:
            return "Medium Risk"
        elif score >= 1:
            return "Low Risk"
        else:
            return "Minimal Risk"
    
    def generate_remediation_priority(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sort findings by remediation priority.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List of findings sorted by priority
        """
        scored_findings = []
        
        for finding in findings:
            score = self.calculate_risk_score(finding)
            scored_findings.append({
                "finding": finding,
                "risk_score": score,
                "severity": self.classify_severity(finding)
            })
        
        # Sort by risk score (descending)
        scored_findings.sort(key=lambda x: x["risk_score"], reverse=True)
        
        return scored_findings
