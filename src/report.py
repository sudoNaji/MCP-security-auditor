"""
report.py — Report generation for MCP Security Auditor.

Supports JSON, SARIF (GitHub Code Scanning), and metrics output.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner import ScanResult

_REPO_URL = "https://github.com/sudoNaji/MCP-security-auditor"

# Patterns that may appear verbatim in evidence strings captured from source lines.
# Matched values are replaced with [REDACTED] before any file is written.
_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(r"(sk_live_|sk_test_|pk_live_|pk_test_)[A-Za-z0-9]{10,}", re.I),  # Stripe
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),                                           # GitHub PAT
    re.compile(r"xoxb-[A-Za-z0-9\-]{40,}"),                                        # Slack bot
    re.compile(r"xoxp-[A-Za-z0-9\-]{40,}"),                                        # Slack user
    re.compile(r"AKIA[A-Z0-9]{16}"),                                                # AWS access key
    re.compile(r"(?i)(password|passwd|api[_-]?key|secret|token|credential)"
               r"[\s:=]+['\"]?([A-Za-z0-9_\-/.+]{16,})['\"]?"),                   # Generic k=v secrets
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}"),                               # Bearer tokens
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),                              # PEM headers
]


def _redact(text: str) -> str:
    """Replace secret values in a string with [REDACTED]."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def _redact_finding(finding_dict: dict) -> dict:
    """Return a copy of a finding dict with sensitive fields redacted."""
    redacted = dict(finding_dict)
    for field in ("evidence", "description", "title"):
        if field in redacted:
            redacted[field] = _redact(str(redacted[field]))
    return redacted


def _redact_results(results_list: list[dict]) -> list[dict]:
    """Redact all findings within a serialised results list."""
    redacted = []
    for r in results_list:
        r2 = dict(r)
        r2["findings"] = [_redact_finding(f) for f in r.get("findings", [])]
        redacted.append(r2)
    return redacted


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


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
    """Write JSON report to file or return as string. Evidence is redacted in file output."""
    report = build_json_report(results)

    if output_path:
        # Redact secrets from evidence fields before writing to disk
        safe_report = dict(report)
        safe_report["results"] = _redact_results(report["results"])
        output_path.write_text(json.dumps(safe_report, indent=2), encoding="utf-8")

    # In-memory / terminal output keeps full evidence for operator review
    return json.dumps(report, indent=2)


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
            line_number = _parse_line(f.location)
            uri = r.target.lstrip("/")

            sarif_results.append({
                "ruleId": f.rule_id,
                "level": _SARIF_SEVERITY_MAP.get(f.severity.value, "warning"),
                "message": {
                    "text": (
                        f"{f.title}\n\n"
                        f"{f.description}\n\n"
                        # Redact evidence in SARIF — uploaded to GitHub servers
                        f"Evidence: {_redact(f.evidence)}\n\n"
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
                    # Redact evidence in properties too — stored in SARIF file
                    "evidence": _redact(f.evidence),
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
    """Write SARIF report to file or return as string. Evidence is always redacted."""
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
