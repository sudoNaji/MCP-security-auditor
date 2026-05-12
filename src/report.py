"""
report.py — Report generation for MCP Security Auditor.

Supports JSON, SARIF (GitHub Code Scanning), and metrics output.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanner import ScanResult

_REPO_URL = "https://github.com/sudoNaji/MCP-security-auditor"


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|OPENSSH|EC) PRIVATE KEY-----"),
    re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._\-+/=]+"),
    re.compile(r"\b(?:sk_|pk_|ghp_|xoxb-)[A-Za-z0-9_\-]{10,}\b"),
    re.compile(r"(?i)\b(password|api[_-]?key|secret|token|credential)\b(\s*[:=]\s*)(['\"]?)[^'\"\s]{6,}\3"),
]


def _redact_secrets_in_text(value: str) -> str:
    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact_secrets(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_secrets(v) for v in value]
    if isinstance(value, str):
        return _redact_secrets_in_text(value)
    return value


def _parse_line(location: str) -> int:
    """Extract line number from 'filepath:lineno' strings produced by the scanner."""
    match = re.search(r":(\d+)$", location)
    return int(match.group(1)) if match else 1


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
    sanitized_report = _redact_secrets(report)
    payload = json.dumps(sanitized_report, indent=2)
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

    from threats import DETECTION_RULES
    rules = []
    for rule_id, rule_data in DETECTION_RULES.items():
        severity = rule_data.get("severity", "MEDIUM")
        severity_str = severity.value if hasattr(severity, "value") else str(severity)

        threat_class = rule_data.get("threat_class", "unknown")
        threat_class_str = threat_class.value if hasattr(threat_class, "value") else str(threat_class)

        rules.append({
            "id": rule_id,
            "name": rule_data.get("title", rule_id),
            "shortDescription": {"text": rule_data.get("description", "")},
            "defaultConfiguration": {
                "level": _SARIF_SEVERITY_MAP.get(severity_str, "warning"),
            },
            "helpUri": _REPO_URL,
            "properties": {
                "threat_class": threat_class_str,
                "cwe": rule_data.get("cwe", ""),
            },
        })

    sarif_results = []
    for r in results:
        for f in r.findings:
            # Parse real line number from location string (e.g. "src/foo.py:42")
            line_number = _parse_line(f.location)

            # Build a clean relative URI for the artifact
            uri = r.target.lstrip("/")

            sarif_results.append({
                "ruleId": f.rule_id,
                "level": _SARIF_SEVERITY_MAP.get(f.severity.value, "warning"),
                "message": {
                    "text": (
                        f"{f.title}\n\n"
                        f"{f.description}\n\n"
                        f"Evidence: {f.evidence}\n\n"
                        f"Recommendation: {f.recommendation}"
                    ),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": line_number},
                        }
                    }
                ],
                "properties": {
                    "threat_class": f.threat_class.value,
                    "target_type": r.target_type,
                    "evidence": f.evidence,
                    "cwe": f.cwe,
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
                        "informationUri": _REPO_URL,
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
    sanitized_report = _redact_secrets(report)
    payload = json.dumps(sanitized_report, indent=2)
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
