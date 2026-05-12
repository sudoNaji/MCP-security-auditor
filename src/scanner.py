"""
scanner.py — Core MCP security scanner engine.

Scans across 4 target types:
  1. MCP server source code (Python/JS)
  2. MCP tool definitions (JSON/YAML manifests)
  3. Running MCP servers (live inspection via stdio)
  4. npm/PyPI packages (supply chain)
"""

from pathlib import Path
from dataclasses import dataclass, field
import json
import re
from typing import Any

from threats import Finding, ThreatClass, Severity, DETECTION_RULES


# ─────────────────────────────────────────────────────────────
# Scan result model
# ─────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Result of scanning a single target (file, server, package)."""
    target: str
    target_type: str  # "source_code" | "tool_schema" | "live_server" | "package"
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    
    @property
    def clean(self) -> bool:
        return len(self.findings) == 0 and not self.error
    
    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted by severity (CRITICAL first)."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(
            self.findings,
            key=lambda f: severity_order.get(f.severity.value, 99),
        )
    
    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "clean": self.clean,
            "error": self.error,
            "findings": [f.as_dict() for f in self.sorted_findings()],
        }


# ─────────────────────────────────────────────────────────────
# Scanner implementations
# ─────────────────────────────────────────────────────────────

class ToolDefinitionScanner:
    """Scan MCP tool schema (JSON) for security issues."""
    
    def scan(self, schema: dict, tool_name: str = "") -> list[Finding]:
        """Scan a single tool definition schema."""
        findings: list[Finding] = []
        
        # Rule MCP-PI-001: Shell metacharacters in tool name
        if tool_name:
            if re.search(DETECTION_RULES["MCP-PI-001"]["pattern"], tool_name):
                findings.append(Finding(
                    threat_class=ThreatClass.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    rule_id="MCP-PI-001",
                    title=DETECTION_RULES["MCP-PI-001"]["title"],
                    description=DETECTION_RULES["MCP-PI-001"]["description"],
                    evidence=f"tool name '{tool_name}' contains shell metacharacters",
                    location=f"tools.{tool_name}.name",
                    recommendation="Rename tool to use alphanumeric characters only (no $, (), {}, etc.)",
                    cwe="CWE-78",
                ))
        
        # Rule MCP-PI-002: Jailbreak patterns in description
        description = schema.get("description", "") or ""
        for pattern in DETECTION_RULES["MCP-PI-002"]["patterns"]:
            if re.search(pattern, description):
                findings.append(Finding(
                    threat_class=ThreatClass.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    rule_id="MCP-PI-002",
                    title=DETECTION_RULES["MCP-PI-002"]["title"],
                    description=DETECTION_RULES["MCP-PI-002"]["description"],
                    evidence=f"description contains jailbreak pattern: {pattern}",
                    location=f"tools.{tool_name}.description",
                    recommendation="Remove instructions that attempt to override system behavior or bypass restrictions",
                    cwe="CWE-94",
                ))
                break
        
        # Rule MCP-SE-001: Secrets in schema
        for field_name in ["example_inputs", "default_value"]:
            field_value = json.dumps(schema.get(field_name, ""))
            for pattern in DETECTION_RULES["MCP-SE-001"]["patterns"]:
                if re.search(pattern, field_value):
                    findings.append(Finding(
                        threat_class=ThreatClass.SECRETS_EXPOSURE,
                        severity=Severity.CRITICAL,
                        rule_id="MCP-SE-001",
                        title=DETECTION_RULES["MCP-SE-001"]["title"],
                        description=DETECTION_RULES["MCP-SE-001"]["description"],
                        evidence=f"field '{field_name}' contains secret pattern",
                        location=f"tools.{tool_name}.{field_name}",
                        recommendation="Remove hardcoded secrets; use environment variables or secure credential stores instead",
                        cwe="CWE-798",
                    ))
        
        return findings


class SourceCodeScanner:
    """Scan MCP server source code for dangerous patterns."""
    
    def scan(self, filepath: Path) -> list[Finding]:
        """Scan a Python/JS file for security issues."""
        findings: list[Finding] = []
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return [Finding(
                threat_class=ThreatClass.SUPPLY_CHAIN,
                severity=Severity.LOW,
                rule_id="MCP-ERROR-001",
                title="Failed to read file",
                description=str(e),
                evidence=str(filepath),
                location=str(filepath),
                recommendation="Check file permissions",
            )]
        
        lines = content.splitlines()
        
        # Rule MCP-EP-002: Shell execution without restrictions
        for i, line in enumerate(lines, start=1):
            for pattern in DETECTION_RULES["MCP-EP-002"]["patterns"]:
                if re.search(pattern, line):
                    findings.append(Finding(
                        threat_class=ThreatClass.EXCESSIVE_PERMISSIONS,
                        severity=Severity.CRITICAL,
                        rule_id="MCP-EP-002",
                        title=DETECTION_RULES["MCP-EP-002"]["title"],
                        description=DETECTION_RULES["MCP-EP-002"]["description"],
                        evidence=f"Line {i}: {line.strip()}",
                        location=f"{filepath}:{i}",
                        recommendation="Wrap shell execution in strict allowlist; validate all inputs; use subprocess with shell=False",
                        cwe="CWE-78",
                    ))
        
        # Rule MCP-SE-002: Private keys
        for i, line in enumerate(lines, start=1):
            if re.search(DETECTION_RULES["MCP-SE-002"]["pattern"], line):
                findings.append(Finding(
                    threat_class=ThreatClass.SECRETS_EXPOSURE,
                    severity=Severity.CRITICAL,
                    rule_id="MCP-SE-002",
                    title=DETECTION_RULES["MCP-SE-002"]["title"],
                    description=DETECTION_RULES["MCP-SE-002"]["description"],
                    evidence=f"Line {i} contains PEM header",
                    location=f"{filepath}:{i}",
                    recommendation="Remove private key from source code; load from secure environment variables or key management service",
                    cwe="CWE-798",
                ))
        
        return findings


class LiveServerScanner:
    """Scan a running MCP server via stdio transport."""
    
    def scan(self, server_config: dict) -> list[Finding]:
        """
        Introspect a running MCP server.
        
        server_config should contain:
          command: str (e.g., "python -m my_mcp_server")
          args: list[str] (optional)
          env: dict (optional)
        """
        findings: list[Finding] = []
        # Placeholder: actual implementation requires MCP client library + stdio handling
        return findings


class PackageSupplyChainScanner:
    """Scan npm/PyPI packages for supply chain issues."""
    
    def scan(self, package_name: str, version: str = "") -> list[Finding]:
        """
        Scan an MCP package from npm or PyPI.
        
        Checks:
          - Package metadata (homepage, repo, author)
          - Package signatures / SLSA attestations
          - Known CVEs for the version
          - Download history (sudden popularity spike)
        """
        findings: list[Finding] = []
        # Placeholder: actual implementation requires npm registry API + PyPI API
        return findings
