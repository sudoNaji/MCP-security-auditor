"""
report.py — Report generation for MCP Security Auditor.

Supports JSON, SARIF (GitHub Code Scanning), and metrics output.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner import ScanResult


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────
# JSON REPORT
# ─────────────────────────────────────────────────────────────

def build_json_report(results: list["ScanResult"], version: str = "1.0.0") -> dict:
    """Build a comprehensive JSON report."""
    total_findings = sum(len(r.findings) for r in results)
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    threat_counts: dict[str, int] = {}
    
    for r in results:
        for f in r.findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
            threat_counts[f.threat_class.value] = threat_counts.get(f.threat_class.value, 0) + 1

    return {
        "schema": "mcp-audit-report",
        "version": version,
        "generated_at": _utcnow(),
        "summary": {
            "total_targets": len(results),
            "total_findings": total_findings,
            "clean_targets": sum(1 for r in results if r.clean),
            "severity_breakdown": severity_counts,
            "threat_breakdown": threat_counts,
        },
        "results": [r.as_dict() for r in results],
    }


def write_json_report(results: list["ScanResult"], output_path: Path | None = None) -> str:
    """Write JSON report to file or return as string."""
    report = build_json_report(results)
    payload = json.dumps(report, indent=2)
    if output_path:
        output_path.write_text(payload, encoding="utf-8")
    return payload


# ─────────────────────────────────────────────────────────────
# SARIF REPORT (GitHub Code Scanning)
# ─────────────────────────────────────────────────────────────

_SARIF_SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def build_sarif_report(results: list["ScanResult"]) -> dict:
    """Build SARIF 2.1.0 report (GitHub Code Scanning compatible)."""
    
    # Aggregate all unique rules from DETECTION_RULES
    from threats import DETECTION_RULES
    rules = []
    for rule_id, rule_data in DETECTION_RULES.items():
        severity = rule_data.get("severity", "MEDIUM")
        severity_str = severity.value if hasattr(severity, 'value') else str(severity)
        
        threat_class = rule_data.get("threat_class", "unknown")
        threat_class_str = threat_class.value if hasattr(threat_class, 'value') else str(threat_class)
        
        rules.append({
            "id": rule_id,
            "name": rule_data.get("title", rule_id),
            "shortDescription": {"text": rule_data.get("description", "")},
            "defaultConfiguration": {
                "level": _SARIF_SEVERITY_MAP.get(severity_str, "warning"),
            },
            "helpUri": "https://github.com/your-org/mcp-security-auditor",
            "properties": {
                "threat_class": threat_class_str,
                "cwe": rule_data.get("cwe", ""),
            },
        })

    sarif_results = []
    for r in results:
        for f in r.findings:
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": _SARIF_SEVERITY_MAP.get(f.severity.value, "warning"),
                "message": {
                    "text": f"{f.title}\n\n{f.description}\n\nRecommendation: {f.recommendation}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": r.target.lstrip("/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": 1},  # Would be parsed from f.location if available
                        }
                    }
                ],
                "properties": {
                    "threat_class": f.threat_class.value,
                    "target_type": r.target_type,
                    "evidence": f.evidence,
                },
            })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP Security Auditor",
                        "informationUri": "https://github.com/your-org/mcp-security-auditor",
                        "version": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_sarif_report(results: list["ScanResult"], output_path: Path | None = None) -> str:
    """Write SARIF report to file or return as string."""
    report = build_sarif_report(results)
    payload = json.dumps(report, indent=2)
    if output_path:
        output_path.write_text(payload, encoding="utf-8")
    return payload


# ─────────────────────────────────────────────────────────────
# METRICS
# ─────────────────────────────────────────────────────────────

def build_metrics(results: list["ScanResult"]) -> dict:
    """Return flat metrics for dashboards/monitoring."""
    total = sum(len(r.findings) for r in results)
    by_severity: dict[str, int] = {}
    by_threat: dict[str, int] = {}

    for r in results:
        for f in r.findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_threat[f.threat_class.value] = by_threat.get(f.threat_class.value, 0) + 1

    return {
        "total_findings": total,
        "by_severity": by_severity,
        "by_threat": by_threat,
        "targets_scanned": len(results),
        "clean_targets": sum(1 for r in results if r.clean),
    }
