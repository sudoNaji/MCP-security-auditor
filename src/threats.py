"""
threats.py — MCP security threat definitions and detection rules.

Based on OWASP MCP Top 10 (May 2026) + practical attack patterns.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

# ─────────────────────────────────────────────────────────────
# Threat categories
# ─────────────────────────────────────────────────────────────

class ThreatClass(Enum):
    """MCP security threat classifications."""
    TOOL_POISONING = "tool_poisoning"          # Malicious tool descriptions hiding instructions
    PROMPT_INJECTION = "prompt_injection"      # Injection vectors in tool names/descriptions
    EXCESSIVE_PERMISSIONS = "excessive_perms"  # Over-privileged tools (*, shell, filesystem)
    SUPPLY_CHAIN = "supply_chain"              # Untrusted packages, no provenance
    SECRETS_EXPOSURE = "secrets_exposure"      # Credentials in schemas, configs, examples
    INSECURE_TRANSPORT = "insecure_transport"  # Unencrypted MCP connections
    MISSING_VALIDATION = "missing_validation"  # No input sanitization in tool execution
    DANGEROUS_IMPORTS = "dangerous_imports"    # eval(), exec(), or dynamic code loading


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ─────────────────────────────────────────────────────────────
# Finding data model
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Finding:
    """Represents a security finding in an MCP server or tool."""
    threat_class: ThreatClass
    severity: Severity
    rule_id: str
    title: str
    description: str
    evidence: str                           # What triggered the detection (e.g., "tool name contains ${}")
    location: str                           # Where found (file path, line, tool name, etc.)
    recommendation: str                     # How to fix it
    cwe: str = ""                          # CWE reference if applicable
    
    def as_dict(self) -> dict:
        return {
            "threat_class": self.threat_class.value,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
        }


# ─────────────────────────────────────────────────────────────
# Detection rules (template)
# ─────────────────────────────────────────────────────────────

DETECTION_RULES = {
    # PROMPT INJECTION rules
    "MCP-PI-001": {
        "title": "Shell metacharacter in tool name",
        "threat_class": ThreatClass.PROMPT_INJECTION,
        "severity": Severity.CRITICAL,
        "description": "Tool name contains shell metacharacters that could be exploited for injection",
        "pattern": r"[\$\(\)\{\}\[\]`\|&;]",
        "targets": ["tool_name"],
        "cwe": "CWE-78",
    },
    "MCP-PI-002": {
        "title": "LLM prompt markers in tool description",
        "threat_class": ThreatClass.PROMPT_INJECTION,
        "severity": Severity.HIGH,
        "description": "Tool description contains LLM jailbreak patterns (system prompts, role instructions)",
        "patterns": [
            r"(?i)(ignore|forget|disregard).{0,10}(previous|above|prior).{0,10}(instruction|prompt)",
            r"(?i)(act as|pretend|roleplay).{0,10}(administrator|admin|root|superuser)",
            r"(?i)(you are now|from now on|henceforth).{0,10}(uncensored|unrestricted)",
        ],
        "targets": ["description", "long_description"],
        "cwe": "CWE-94",
    },
    "MCP-PI-003": {
        "title": "Template injection in tool schema",
        "threat_class": ThreatClass.PROMPT_INJECTION,
        "severity": Severity.CRITICAL,
        "description": "Tool inputs contain unescaped template expressions (${...}, {{{...}}})",
        "pattern": r"[\$\{][{]?\w+[}]?",
        "targets": ["input_schema", "example_inputs"],
        "cwe": "CWE-1336",
    },
    
    # TOOL POISONING rules
    "MCP-TP-001": {
        "title": "Suspicious instructions in tool description",
        "threat_class": ThreatClass.TOOL_POISONING,
        "severity": Severity.HIGH,
        "description": "Tool description contains hidden instructions or commands disguised as help text",
        "patterns": [
            r"(?i)(execute|run|perform).{0,20}(without.{0,10}asking|silently|automatically)",
            r"(?i)(ignore|bypass|skip).{0,20}(validation|check|confirmation|warning)",
            r"(?i)(always|never).{0,20}(deny|allow|permit|block)",
        ],
        "targets": ["description"],
        "cwe": "CWE-426",
    },
    "MCP-TP-002": {
        "title": "Excessive tool count or hidden tools",
        "threat_class": ThreatClass.TOOL_POISONING,
        "severity": Severity.MEDIUM,
        "description": "Server exposes hundreds of tools or tool names are obfuscated/randomized",
        "thresholds": {
            "max_tools_per_server": 100,
            "obfuscated_name_pattern": r"^[a-f0-9]{8,}$|^tool_[0-9]+$",
        },
        "cwe": "CWE-436",
    },
    
    # EXCESSIVE PERMISSIONS rules
    "MCP-EP-001": {
        "title": "Wildcard filesystem permissions",
        "threat_class": ThreatClass.EXCESSIVE_PERMISSIONS,
        "severity": Severity.CRITICAL,
        "description": "Tool has wildcard access to filesystem (/* or /home/*)",
        "pattern": r"/(.*\*|home/\*|var/\*|tmp/\*)",
        "targets": ["permissions", "allowed_paths"],
        "cwe": "CWE-276",
    },
    "MCP-EP-002": {
        "title": "Shell execution without restrictions",
        "threat_class": ThreatClass.EXCESSIVE_PERMISSIONS,
        "severity": Severity.CRITICAL,
        "description": "Tool executes arbitrary shell commands (exec, shell_out, bash)",
        "patterns": [
            r"(?i)(exec|shell_out|bash|sh|subprocess\.run)",
            r"(?i)(os\.system|popen|os\.popen)",
        ],
        "targets": ["implementation", "function_name"],
        "cwe": "CWE-78",
    },
    "MCP-EP-003": {
        "title": "Network access without restrictions",
        "threat_class": ThreatClass.EXCESSIVE_PERMISSIONS,
        "severity": Severity.HIGH,
        "description": "Tool makes HTTP/network requests to any URL without allowlist",
        "patterns": [
            r"(?i)(request|fetch|http|socket)",
        ],
        "targets": ["implementation"],
        "cwe": "CWE-95",
    },
    
    # SECRETS EXPOSURE rules
    "MCP-SE-001": {
        "title": "API key/token in tool schema",
        "threat_class": ThreatClass.SECRETS_EXPOSURE,
        "severity": Severity.CRITICAL,
        "description": "Tool schema or examples contain hardcoded API keys, tokens, or passwords",
        "patterns": [
            r"(sk_|pk_|ghp_|xoxb-|Bearer\s+)",  # Stripe, GitHub, Slack
            r"(?i)(password|api[_-]?key|secret|token|credential)[\s:=]+['\"]?\S{20,}",
        ],
        "targets": ["example_inputs", "default_value", "description"],
        "cwe": "CWE-798",
    },
    "MCP-SE-002": {
        "title": "Private key in source code",
        "threat_class": ThreatClass.SECRETS_EXPOSURE,
        "severity": Severity.CRITICAL,
        "description": "MCP server source contains PEM-formatted private keys",
        "pattern": r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----",
        "targets": ["source_code"],
        "cwe": "CWE-798",
    },
    
    # SUPPLY CHAIN rules
    "MCP-SC-001": {
        "title": "Package not signed or no provenance",
        "threat_class": ThreatClass.SUPPLY_CHAIN,
        "severity": Severity.HIGH,
        "description": "MCP package (npm/PyPI) has no signature, SLSA attestation, or SBOMattachment",
        "targets": ["package_metadata"],
        "cwe": "CWE-347",
    },
    "MCP-SC-002": {
        "title": "Known vulnerable MCP package version",
        "threat_class": ThreatClass.SUPPLY_CHAIN,
        "severity": Severity.CRITICAL,
        "description": "MCP package version matches a known vulnerable release (CVE database)",
        "targets": ["package_version"],
        "cwe": "CWE-426",
    },
    "MCP-SC-003": {
        "title": "Suspicious package metadata",
        "threat_class": ThreatClass.SUPPLY_CHAIN,
        "severity": Severity.MEDIUM,
        "description": "Package has no homepage, no repository, no author, or recent takeover",
        "targets": ["package_metadata"],
        "cwe": "CWE-426",
    },
}
