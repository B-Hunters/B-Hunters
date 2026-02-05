"""
Report Exporter for Third-Party Integrations

Provides export functionality for:
- Jira
- GitLab Security Dashboard
- DefectDojo
- SARIF format
- CSV

Usage:
    from b_hunters.reports.exporter import ReportExporter
    
    exporter = ReportExporter()
    
    # Export to Jira format
    jira_data = exporter.export_to_jira(findings)
    
    # Export to GitLab
    gitlab_data = exporter.export_to_gitlab(findings)
    
    # Export to SARIF
    sarif_data = exporter.export_to_sarif(findings, tool_name="B-Hunters")
"""

import json
import csv
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
import hashlib


class ReportExporter:
    """
    Export findings to various third-party formats.
    """
    
    # Severity mapping to external formats
    JIRA_SEVERITY_MAP = {
        "Critical": "Highest",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Info": "Lowest"
    }
    
    GITLAB_SEVERITY_MAP = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Info": "info"
    }
    
    SARIF_SEVERITY_MAP = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "warning",
        "Info": "note"
    }
    
    CVSS_SCORES = {
        "Critical": 9.0,
        "High": 7.5,
        "Medium": 5.0,
        "Low": 2.0,
        "Info": 0.0
    }
    
    def __init__(self):
        """Initialize the report exporter."""
        pass
    
    def export_to_jira(
        self,
        findings: List[Dict[str, Any]],
        project_key: str = "SECURITY",
        issue_type: str = "Bug"
    ) -> Dict[str, Any]:
        """
        Export findings to Jira-compatible format.
        
        Args:
            findings: List of vulnerability findings
            project_key: Jira project key
            issue_type: Jira issue type
            
        Returns:
            Dictionary containing Jira issues
        """
        issues = []
        
        for finding in findings:
            severity = finding.get("severity", "Low")
            jira_priority = self.JIRA_SEVERITY_MAP.get(severity, "Medium")
            
            issue = {
                "project": {"key": project_key},
                "issuetype": {"name": issue_type},
                "summary": f"[{severity}] {finding.get('type', 'Security Issue')} - {finding.get('domain', 'Unknown')}",
                "description": self._build_jira_description(finding),
                "priority": {"name": jira_priority},
                "labels": ["security", "b-hunters", finding.get("tool", "unknown").lower()],
                "components": [{"name": finding.get("domain", "Unknown")}],
                "customfield_security_severity": finding.get("risk_score", 0),
                "environment": finding.get("affected_url", finding.get("url", "N/A")),
            }
            
            issues.append(issue)
        
        return {
            "issues": issues,
            "metadata": {
                "total": len(issues),
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "tool": "B-Hunters"
            }
        }
    
    def export_to_gitlab(
        self,
        findings: List[Dict[str, Any]],
        schema_version: str = "14.0.0"
    ) -> Dict[str, Any]:
        """
        Export findings to GitLab Security Dashboard format.
        
        Args:
            findings: List of vulnerability findings
            schema_version: GitLab security report schema version
            
        Returns:
            Dictionary matching GitLab security report schema
        """
        vulnerabilities = []
        
        for idx, finding in enumerate(findings, 1):
            severity = finding.get("severity", "Info")
            gitlab_severity = self.GITLAB_SEVERITY_MAP.get(severity, "unknown")
            
            location = self._extract_location(finding)
            
            vuln = {
                "id": finding.get("id", f"b-hunters-{uuid.uuid4().hex[:8]}"),
                "name": finding.get("type", "Security Vulnerability"),
                "description": finding.get("description", finding.get("evidence", "No description available")),
                "severity": gitlab_severity,
                "confidence": finding.get("confidence", "Medium").lower(),
                "solution": finding.get("remediation", "Review and fix the identified vulnerability"),
                "cve": finding.get("cve_id", ""),
                "cwe": self._extract_cwe_id(finding),
                "scanner": {
                    "id": "b-hunters",
                    "name": finding.get("tool", "B-Hunters")
                },
                "location": location,
                "identifiers": self._generate_identifiers(finding),
                "links": finding.get("references", []),
                "raw_metadata": finding
            }
            
            vulnerabilities.append(vuln)
        
        return {
            "version": schema_version,
            "vulnerabilities": vulnerabilities,
            "remediations": [],
            "scan": {
                "start_time": datetime.utcnow().isoformat() + "Z",
                "end_time": datetime.utcnow().isoformat() + "Z",
                "status": "success",
                "type": "dast",
                "scanner": {
                    "id": "b-hunters",
                    "name": "B-Hunters",
                    "version": "2.0.0",
                    "vendor": {
                        "name": "B-Hunters Project"
                    }
                }
            }
        }
    
    def export_to_sarif(
        self,
        findings: List[Dict[str, Any]],
        tool_name: str = "B-Hunters",
        tool_version: str = "2.0.0"
    ) -> Dict[str, Any]:
        """
        Export findings to SARIF format (Static Analysis Results Interchange Format).
        
        SARIF is an OASIS standard used by many security tools and platforms.
        
        Args:
            findings: List of vulnerability findings
            tool_name: Name of the scanning tool
            tool_version: Version of the scanning tool
            
        Returns:
            SARIF-formatted dictionary
        """
        rules = []
        results = []
        rule_indices = {}
        
        for finding in findings:
            vuln_type = finding.get("type", "unknown")
            
            # Create rule if not exists
            if vuln_type not in rule_indices:
                rule_index = len(rules)
                rule_indices[vuln_type] = rule_index
                
                rule = {
                    "id": vuln_type.replace(" ", "-").lower(),
                    "name": vuln_type,
                    "shortDescription": {
                        "text": f"{vuln_type} vulnerability detected"
                    },
                    "fullDescription": {
                        "text": f"A {vuln_type.lower()} vulnerability was identified during the scan."
                    },
                    "defaultConfiguration": {
                        "level": self.SARIF_SEVERITY_MAP.get(
                            finding.get("severity", "Medium"), "warning"
                        )
                    },
                    "properties": {
                        "tags": ["security", finding.get("tool", "b-hunters")],
                        "cwe": self._extract_cwe_id(finding),
                        "cvss": self.CVSS_SCORES.get(finding.get("severity", "Medium"), 5.0)
                    }
                }
                
                rules.append(rule)
            else:
                rule_index = rule_indices[vuln_type]
            
            # Create result
            result = {
                "ruleId": rules[rule_index]["id"],
                "ruleIndex": rule_index,
                "level": self.SARIF_SEVERITY_MAP.get(
                    finding.get("severity", "Medium"), "warning"
                ),
                "message": {
                    "text": finding.get("evidence", finding.get("description", "Issue found"))
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("affected_url", finding.get("url", "unknown"))
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }],
                "properties": {
                    "domain": finding.get("domain", "unknown"),
                    "tool": finding.get("tool", "unknown"),
                    "confidence": finding.get("confidence", "Medium")
                }
            }
            
            results.append(result)
        
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/B-Hunters/B-Hunters",
                        "rules": rules
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": datetime.utcnow().isoformat() + "Z"
                }],
                "properties": {
                    "totalFindings": len(results),
                    "severities": self._count_severities(findings)
                }
            }]
        }
        
        return sarif_report
    
    def export_to_csv(
        self,
        findings: List[Dict[str, Any]],
        output_path: str
    ) -> str:
        """
        Export findings to CSV format.
        
        Args:
            findings: List of vulnerability findings
            output_path: Path to save the CSV file
            
        Returns:
            Path to the generated CSV file
        """
        fieldnames = [
            "id", "severity", "type", "domain", "tool", "affected_url",
            "description", "evidence", "confidence", "remediation", "references"
        ]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for idx, finding in enumerate(findings, 1):
                row = {
                    "id": idx,
                    "severity": finding.get("severity", "Unknown"),
                    "type": finding.get("type", "Unknown"),
                    "domain": finding.get("domain", "Unknown"),
                    "tool": finding.get("tool", "Unknown"),
                    "affected_url": finding.get("affected_url", finding.get("url", "N/A")),
                    "description": finding.get("description", "N/A"),
                    "evidence": finding.get("evidence", "N/A")[:500],  # Limit length
                    "confidence": finding.get("confidence", "Medium"),
                    "remediation": finding.get("remediation", "N/A"),
                    "references": ", ".join(finding.get("references", []))
                }
                writer.writerow(row)
        
        return output_path
    
    def export_to_defectdojo(
        self,
        findings: List[Dict[str, Any]],
        engagement_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Export findings to DefectDojo-compatible format.
        
        DefectDojo is an open-source vulnerability management tool.
        
        Args:
            findings: List of vulnerability findings
            engagement_id: DefectDojo engagement ID
            
        Returns:
            Dictionary compatible with DefectDojo API
        """
        findings_data = []
        
        for finding in findings:
            dd_finding = {
                "title": f"{finding.get('type', 'Vulnerability')} - {finding.get('domain', 'Unknown')}",
                "severity": finding.get("severity", "Info"),
                "cwe": self._extract_cwe_id(finding),
                "cve": finding.get("cve_id", ""),
                "description": finding.get("description", finding.get("evidence", "No description")),
                "mitigation": finding.get("remediation", "No remediation provided"),
                "impact": f"Affected domain: {finding.get('domain', 'Unknown')}",
                "references": "\n".join(finding.get("references", [])),
                "active": True,
                "verified": finding.get("confidence", "").lower() == "high",
                "false_p": False,
                "duplicate": False,
                "thread_id": None,
                "mitigated": None,
                "date": datetime.utcnow().strftime("%Y-%m-%d"),
                "found_by": [finding.get("tool", "B-Hunters")]
            }
            
            if engagement_id:
                dd_finding["engagement"] = engagement_id
            
            findings_data.append(dd_finding)
        
        return {
            "findings": findings_data,
            "test_type": "B-Hunters Scan",
            "scan_date": datetime.utcnow().strftime("%Y-%m-%d"),
            "version": "2.0.0"
        }
    
    def _build_jira_description(self, finding: Dict[str, Any]) -> str:
        """Build Jira-formatted description."""
        description = f"""h2. Security Vulnerability Detected

*Vulnerability Type:* {finding.get('type', 'Unknown')}
*Affected Domain:* {finding.get('domain', 'Unknown')}
*Affected URL:* {finding.get('affected_url', finding.get('url', 'N/A'))}
*Detection Tool:* {finding.get('tool', 'B-Hunters')}
*Severity:* {finding.get('severity', 'Unknown')}
*Confidence:* {finding.get('confidence', 'Medium')}

h3. Evidence

{{code}}
{finding.get('evidence', 'No evidence available')}
{{code}}

h3. Description

{finding.get('description', 'No detailed description available')}

h3. Remediation

{finding.get('remediation', 'Please review and fix this vulnerability')}

h3. References

"""
        
        for ref in finding.get("references", []):
            description += f"* {ref}\n"
        
        return description
    
    def _extract_location(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract location information for GitLab format."""
        url = finding.get("affected_url", finding.get("url", ""))
        
        # Try to parse URL
        if url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                return {
                    "hostname": parsed.hostname or finding.get("domain", "unknown"),
                    "pathname": parsed.path or "/",
                    "full": url
                }
            except:
                pass
        
        return {
            "hostname": finding.get("domain", "unknown"),
            "pathname": "/",
            "full": url or f"https://{finding.get('domain', 'unknown')}"
        }
    
    def _extract_cwe_id(self, finding: Dict[str, Any]) -> str:
        """Extract CWE ID from finding."""
        cwe = finding.get("cwe_id", "")
        if cwe:
            return cwe
        
        # Map vulnerability types to CWEs
        vuln_type = finding.get("type", "").lower()
        
        cwe_mapping = {
            "sql_injection": "CWE-89",
            "xss": "CWE-79",
            "cross_site_scripting": "CWE-79",
            "path_traversal": "CWE-22",
            "lfi": "CWE-98",
            "rfi": "CWE-98",
            "xxe": "CWE-611",
            "ssrf": "CWE-918",
            "csrf": "CWE-352",
            "command_injection": "CWE-78",
            "code_injection": "CWE-94",
        }
        
        for key, cwe in cwe_mapping.items():
            if key in vuln_type:
                return cwe
        
        return ""
    
    def _generate_identifiers(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate identifiers for GitLab format."""
        identifiers = []
        
        cwe = self._extract_cwe_id(finding)
        if cwe:
            identifiers.append({
                "type": "cwe",
                "name": f"CWE-{cwe.replace('CWE-', '')}",
                "value": cwe,
                "url": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"
            })
        
        cve = finding.get("cve_id", "")
        if cve:
            identifiers.append({
                "type": "cve",
                "name": cve,
                "value": cve,
                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
            })
        
        return identifiers
    
    def _count_severities(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in findings:
            sev = finding.get("severity", "Info")
            if sev in counts:
                counts[sev] += 1
        return counts
