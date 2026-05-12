<div align="center">

```
███╗   ███╗ ██████╗██████╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗
████╗ ████║██╔════╝██╔══██╗  ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
██╔████╔██║██║     ██████╔╝  ███████║██║   ██║██║  ██║██║   ██║   
██║╚██╔╝██║██║     ██╔═══╝   ██╔══██║██║   ██║██║  ██║██║   ██║   
██║ ╚═╝ ██║╚██████╗██║       ██║  ██║╚██████╔╝██████╔╝██║   ██║   
╚═╝     ╚═╝ ╚═════╝╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝  
```

# MCP Security Auditor

**The first dedicated security scanner for Model Context Protocol servers.**  
Detects tool poisoning · prompt injection · secrets exposure · supply-chain attacks

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![pip install](https://img.shields.io/badge/pip%20install-mcp--security--auditor-orange?style=flat-square&logo=pypi)](https://pypi.org/project/mcp-security-auditor)
[![SARIF](https://img.shields.io/badge/output-SARIF%20%7C%20JSON%20%7C%20Rich%20CLI-purple?style=flat-square)](https://sarifweb.azurewebsites.net)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

</div>

---

## Why This Exists

MCP servers are being deployed everywhere — baked into Claude, Cursor, VS Code, and custom AI agents — with **zero standardized security review tooling**. Every tool description an LLM reads is an attack surface. The threats are real and largely invisible:

| Threat | What It Looks Like |
|--------|-------------------|
| 🧠 **Tool Poisoning** | A tool description secretly instructs the LLM to exfiltrate data |
| 💉 **Prompt Injection** | `${USER_INPUT}` in a schema triggers template execution |
| 🔑 **Secrets Exposure** | `sk_live_...` hardcoded in an example input |
| 🌐 **Supply Chain** | An npm package with no author, no repo, and a known CVE |
| 🔓 **Excessive Permissions** | A tool with `path: "/*"` and no further restrictions |

**MCP Security Auditor automates detection across all five surfaces.**

---

## ⚡ Quick Install

```bash
# Install from source (recommended)
git clone https://github.com/sudoNaji/mcp-security-auditor.git
cd mcp-security-auditor
pip install .
```

That's it. Dependencies (`click`, `rich`) are installed automatically. The `mcp-audit` command is now available globally.

```bash
# Verify
mcp-audit --version
mcp-audit info
```

> **Virtual environment recommended** — see [Installation Guide](INSTALL.md) for full options including editable installs and dev dependencies.

---

## 🚀 Usage

```bash
# Scan server source code (Python / JS)
mcp-audit scan-source src/my_server.py

# Scan a tool schema (JSON)
mcp-audit scan-schema tools/my_tool.json

# Introspect a running MCP server
mcp-audit scan-live --command "python -m my_mcp_server"

# Check an npm or PyPI package
mcp-audit scan-package my-mcp-tool --registry npm

# Show all 13 threat rules
mcp-audit info

# Export to SARIF for GitHub Code Scanning
mcp-audit scan-source src/ --format sarif --output results.sarif
```

---

## 🛡️ Threat Coverage — 13 Rules

### 💉 Prompt Injection (`MCP-PI-*`)

| Rule | Severity | What It Catches |
|------|----------|----------------|
| `MCP-PI-001` | 🔴 CRITICAL | Shell metacharacters in tool name (`$()`, `{}`, `` ` ``) |
| `MCP-PI-002` | 🟠 HIGH | LLM jailbreak patterns in tool descriptions |
| `MCP-PI-003` | 🔴 CRITICAL | Unescaped template expressions in input schemas (`${...}`) |

### 🧠 Tool Poisoning (`MCP-TP-*`)

| Rule | Severity | What It Catches |
|------|----------|----------------|
| `MCP-TP-001` | 🟠 HIGH | Hidden instructions disguised as help text |
| `MCP-TP-002` | 🟡 MEDIUM | Obfuscated tool names or suspiciously high tool counts |

### 🔓 Excessive Permissions (`MCP-EP-*`)

| Rule | Severity | What It Catches |
|------|----------|----------------|
| `MCP-EP-001` | 🔴 CRITICAL | Wildcard filesystem paths (`/*`, `/home/*`) |
| `MCP-EP-002` | 🔴 CRITICAL | Unrestricted shell execution (`subprocess`, `os.system`) |
| `MCP-EP-003` | 🟠 HIGH | Network requests to any URL without an allowlist |

### 🔑 Secrets Exposure (`MCP-SE-*`)

| Rule | Severity | What It Catches |
|------|----------|----------------|
| `MCP-SE-001` | 🔴 CRITICAL | API keys / tokens in schemas (`sk_live_`, `ghp_`, `xoxb-`) |
| `MCP-SE-002` | 🔴 CRITICAL | PEM private keys embedded in source code |

### 🌐 Supply Chain (`MCP-SC-*`)

| Rule | Severity | What It Catches |
|------|----------|----------------|
| `MCP-SC-001` | 🟠 HIGH | Missing signatures or SLSA provenance |
| `MCP-SC-002` | 🔴 CRITICAL | Known-vulnerable package versions (CVE database) |
| `MCP-SC-003` | 🟡 MEDIUM | Suspicious metadata: no author, no repo, no homepage |

---

## 📊 Output Formats

### Rich Terminal (default)

```
╭──────────┬────────────┬──────────────────┬──────────────────────────────────────╮
│ Severity │ Rule       │ Threat Class     │ Title                                │
├──────────┼────────────┼──────────────────┼──────────────────────────────────────┤
│ CRITICAL │ MCP-EP-002 │ Excessive Perms  │ Shell execution without restrictions  │
│ HIGH     │ MCP-PI-002 │ Prompt Injection │ LLM prompt markers in description     │
│ CRITICAL │ MCP-SE-001 │ Secrets Exposure │ API key/token in tool schema          │
╰──────────┴────────────┴──────────────────┴──────────────────────────────────────╯

  Targets scanned: 1   Clean: 0
  ✗ 3 finding(s) detected  CRITICAL: 2   HIGH: 1
```

### JSON

```bash
mcp-audit scan-source src/ --format json --output report.json
```

```json
{
  "schema": "mcp-audit-report",
  "summary": {
    "total_findings": 3,
    "severity_breakdown": { "CRITICAL": 2, "HIGH": 1 }
  },
  "results": [...]
}
```

### SARIF — GitHub Code Scanning

```bash
mcp-audit scan-source src/ --format sarif --output results.sarif
```

Upload to GitHub and findings appear inline in your PR diff — no extra tooling needed.

---

## 🔁 CI/CD Integration

### GitHub Actions

```yaml
name: MCP Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install mcp-security-auditor
        run: pip install .

      - name: Scan source code
        run: mcp-audit scan-source src/ --format sarif --output results.sarif

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
          category: mcp-audit
```

### Pre-commit Hook

```bash
pip install pre-commit
pre-commit install
```

Already configured in `.pre-commit-config.yaml` — runs automatically on every commit.

---

## 🏗️ Architecture

```
mcp-security-auditor/
├── src/
│   ├── cli.py             — Click CLI — all commands and output rendering
│   ├── threats.py         — 13 threat definitions + detection rule patterns
│   ├── scanner.py         — Tool schema + source code scanning engine
│   ├── live_server.py     — MCP stdio introspection + sandbox test execution
│   ├── package_scanner.py — Supply-chain checks (npm / PyPI registry APIs)
│   └── report.py          — JSON, SARIF, and metrics report writers
│
├── examples/
│   └── vulnerable_server.py  — Synthetic MCP server with all vuln classes
│
├── tests/
│   └── test_threats.py       — Unit tests for detection rules
│
├── policies/              — Extensible rule policy files
├── INSTALL.md             — Full installation guide
├── USAGE.md               — Full command reference
└── setup.py               — pip-installable package config
```

---

## 🧪 Try It Now — Demo Scan

```bash
git clone https://github.com/sudoNaji/mcp-security-auditor.git
cd mcp-security-auditor
pip install .

# Scan the intentionally vulnerable example server
mcp-audit scan-source examples/vulnerable_server.py

# Run the test suite
pip install -e ".[dev]"
pytest tests/ -v
```

Expected output: **8 CRITICAL findings** — every vulnerability class demonstrated.

---

## 📦 Installation Options

```bash
# Standard install (recommended)
pip install .

# Editable / development install
pip install -e .

# With dev tools (pytest, black, flake8)
pip install -e ".[dev]"

# Virtual environment (cleanest)
python3 -m venv mcp-env
source mcp-env/bin/activate
pip install .
```

> See [INSTALL.md](INSTALL.md) for troubleshooting and platform-specific notes.

---

## 🗺️ Roadmap

- [ ] Live server MCP protocol handshake (stdio transport)
- [ ] npm / PyPI registry API integration for real CVE lookups
- [ ] SBOM / attestation verification for packages
- [ ] Additional threat rules based on real-world MCP attacks
- [ ] PyPI publish (`pip install mcp-security-auditor`)
- [ ] VS Code extension for inline findings

---

## 🤝 Contributing

Issues and PRs are very welcome. Priority areas are listed in the roadmap above.

```bash
git clone https://github.com/sudoNaji/mcp-security-auditor.git
pip install -e ".[dev]"
pytest tests/ -v
```

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built to secure the MCP ecosystem.**  
If this helped you, ⭐ star the repo — it helps others find it.

</div>
