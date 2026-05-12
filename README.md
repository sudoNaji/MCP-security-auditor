# MCP Security Auditor

> **Security scanning for Model Context Protocol (MCP) servers.**
> 
> Detects tool poisoning, prompt injection, supply-chain attacks, and secrets exposure in MCP server implementations.

---

## Why This Matters

MCP servers are being deployed everywhere — integrated into Claude, Cursor, VS Code, and custom AI agents — with **zero standardized security review tooling**. The threats are real:

- **Tool poisoning**: Malicious tool descriptions hiding jailbreak instructions
- **Prompt injection**: Unescaped template expressions in tool names/schemas
- **Excessive permissions**: Tools with wildcard filesystem access, shell execution without restrictions
- **Supply-chain attacks**: Unsigned packages, no SLSA provenance, known vulnerabilities
- **Secrets exposure**: API keys hardcoded in tool examples or server source

This auditor automates detection across all four threat surfaces.

---

## Features

| Scan Target | Detection | Output |
|-------------|-----------|--------|
| **Tool schemas** (JSON) | Prompt injection, secrets, poisoning | SARIF + JSON + rich terminal |
| **Source code** (Python/JS) | Shell execution, private keys, insecure patterns | SARIF + JSON + rich terminal |
| **Live servers** (stdio) | Tool schema introspection + sandbox test execution | SARIF + JSON + rich terminal |
| **npm/PyPI packages** | CVEs, missing signatures, suspicious metadata | SARIF + JSON + rich terminal |

---

## Quick Start

```bash
# Install
pip install click rich

# Scan a tool schema
python src/cli.py scan-schema tools/my_tool.json

# Scan server source code
python src/cli.py scan-source src/my_server.py

# Introspect a running MCP server
python src/cli.py scan-live --command "python -m my_mcp_server"

# Check npm package
python src/cli.py scan-package my-mcp-tool --registry npm

# Output to SARIF (GitHub Code Scanning)
python src/cli.py scan-source src/ --format sarif --output results.sarif

# Show all threat rules
python src/cli.py info
```

---

## Threat Coverage

### Prompt Injection (MCP-PI-*)
- `MCP-PI-001`: Shell metacharacters in tool name (`$()`, `{}`, `[]`)
- `MCP-PI-002`: Jailbreak patterns in tool description
- `MCP-PI-003`: Template injection in tool input schema

### Tool Poisoning (MCP-TP-*)
- `MCP-TP-001`: Hidden instructions in descriptions
- `MCP-TP-002`: Unusual tool counts or obfuscated names

### Excessive Permissions (MCP-EP-*)
- `MCP-EP-001`: Wildcard filesystem access (`/*`, `/home/*`)
- `MCP-EP-002`: Unrestricted shell execution
- `MCP-EP-003`: Unrestricted network access

### Secrets Exposure (MCP-SE-*)
- `MCP-SE-001`: API keys/tokens in tool schemas
- `MCP-SE-002`: Private keys in source code

### Supply Chain (MCP-SC-*)
- `MCP-SC-001`: Missing signatures/provenance
- `MCP-SC-002`: Known vulnerable package versions
- `MCP-SC-003`: Suspicious metadata (no author, no repo, no homepage)

---

## Integration

### GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: "3.11"

- run: pip install click rich
- run: python src/cli.py scan-source src/ --format sarif --output results.sarif

- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
    category: mcp-audit
```

### Pre-commit Hook

```bash
pre-commit install
```

Then configure `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: mcp-audit-source
        name: MCP Security Audit
        entry: python src/cli.py scan-source
        language: python
        types: [python, javascript]
```

---

## Output Formats

### Rich terminal (default)

```
╭─ MCP Security Audit Findings ─╮
│ Severity  Rule       Title
│ CRITICAL  MCP-EP-002 Shell execution without restrictions
│ HIGH      MCP-PI-002 Jailbreak patterns in description
╰────────────────────────────────╯
```

### JSON

```json
{
  "schema": "mcp-audit-report",
  "summary": {
    "total_findings": 5,
    "severity_breakdown": {"CRITICAL": 2, "HIGH": 3}
  },
  "results": [...]
}
```

### SARIF (GitHub Code Scanning)

GitHub Code Scanning automatically parses and displays results.

---

## Architecture

```
src/
  threats.py         — Threat definitions + detection rules
  scanner.py         — Tool schema + source code scanning
  live_server.py     — MCP stdio introspection + testing
  package_scanner.py — Supply-chain checks (npm/PyPI)
  report.py          — JSON, SARIF, metrics output
  cli.py             — Click CLI interface

examples/
  vulnerable_server.py — Synthetic test fixture with intentional vulns

tests/
  test_threats.py — Unit tests
```

---

## Testing

```bash
# Run demo against synthetic vulnerable server
python src/cli.py scan-source examples/vulnerable_server.py

# Run unit tests
python -m pytest tests/ -v

# Generate SARIF
python src/cli.py scan-source examples/vulnerable_server.py --format sarif --output demo.sarif
```

---

## Contributing

Issues and PRs welcome. Priority areas:

- Live server MCP protocol handshake (stdio transport)
- npm/PyPI registry API integration
- SBOM/attestation verification for packages
- More threat rules based on real-world MCP attacks

---

## License

MIT
