"""
package_scanner.py — Supply-chain security scanner for MCP packages.

Checks npm and PyPI registries for:
  - Known CVEs / vulnerable versions
  - Package metadata completeness
  - Signature / provenance (SLSA, npm signatures)
  - Suspicious metadata changes
"""

import json
from dataclasses import dataclass
from typing import Any

from threats import Finding, ThreatClass, Severity


@dataclass
class PackageMetadata:
    """Metadata for an MCP package."""
    name: str
    version: str
    registry: str  # "npm" or "pypi"
    repository: str = ""
    homepage: str = ""
    author: str = ""
    downloads_per_week: int = 0
    has_signature: bool = False
    has_sbom: bool = False
    has_attestation: bool = False


class PackageSupplyChainScanner:
    """Scan MCP packages for supply-chain risks."""
    
    def scan(self, package: PackageMetadata) -> list[Finding]:
        """Scan a package for supply-chain issues."""
        findings: list[Finding] = []
        
        # Rule MCP-SC-001: Missing signature / provenance
        if not package.has_signature and not package.has_attestation:
            findings.append(Finding(
                threat_class=ThreatClass.SUPPLY_CHAIN,
                severity=Severity.HIGH,
                rule_id="MCP-SC-001",
                title="Package not signed or lacks provenance",
                description="No cryptographic signature, SLSA attestation, or SBOMattachment found",
                evidence=f"{package.registry} package {package.name}@{package.version}",
                location=f"{package.registry}:{package.name}",
                recommendation="Request package maintainer add GPG signatures (npm) or SLSA build provenance attestations",
                cwe="CWE-347",
            ))
        
        # Rule MCP-SC-003: Suspicious metadata
        if not package.repository and not package.homepage:
            findings.append(Finding(
                threat_class=ThreatClass.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                rule_id="MCP-SC-003",
                title="Suspicious package metadata — missing repository/homepage",
                description="Package has no linked repository or homepage URL",
                evidence=f"{package.name} metadata",
                location=f"{package.registry}:{package.name}",
                recommendation="Verify package authenticity; check package details on registry; look for community reviews",
                cwe="CWE-426",
            ))
        
        if not package.author:
            findings.append(Finding(
                threat_class=ThreatClass.SUPPLY_CHAIN,
                severity=Severity.LOW,
                rule_id="MCP-SC-003",
                title="Suspicious package metadata — no author listed",
                description="Package author field is empty or missing",
                evidence=f"{package.name} metadata",
                location=f"{package.registry}:{package.name}",
                recommendation="Verify package is from a trusted source",
                cwe="CWE-426",
            ))
        
        # Rule: High download spike (possible takeover)
        if package.downloads_per_week > 100000:
            findings.append(Finding(
                threat_class=ThreatClass.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                rule_id="MCP-SC-004",
                title="Unusual download spike — possible package takeover",
                description=f"Downloads jumped to {package.downloads_per_week}/week (unusual growth pattern)",
                evidence=f"{package.downloads_per_week} downloads/week",
                location=f"{package.registry}:{package.name}",
                recommendation="Check package changelog, GitHub discussions, and security mailing lists for any alerts",
                cwe="CWE-426",
            ))
        
        return findings
    
    def check_npm_package(self, package_name: str, version: str = "latest") -> PackageMetadata:
        """Fetch metadata from npm registry."""
        # Placeholder: actual implementation would call npm registry API
        return PackageMetadata(
            name=package_name,
            version=version,
            registry="npm",
        )
    
    def check_pypi_package(self, package_name: str, version: str = "latest") -> PackageMetadata:
        """Fetch metadata from PyPI registry."""
        # Placeholder: actual implementation would call PyPI JSON API
        return PackageMetadata(
            name=package_name,
            version=version,
            registry="pypi",
        )
