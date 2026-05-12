# Installation Guide

## Prerequisites

- Python 3.10 or higher
- pip (comes with Python)

## Installation Methods

### 1. **From source (development mode)**

```bash
git clone https://github.com/sudoNaji/mcp-security-auditor.git
cd mcp-security-auditor
pip install -e .
```

This installs the package in **editable mode**, so changes to the source code are immediately reflected.

### 2. **From source (regular install)**

```bash
git clone https://github.com/sudoNaji/mcp-security-auditor.git
cd mcp-security-auditor
pip install .
```

### 3. **From PyPI (when published)**

```bash
pip install mcp-security-auditor
```

## What Gets Installed

The installation automatically installs all required dependencies:

- **click** (≥8.1.0) — CLI framework
- **rich** (≥13.0.0) — Rich terminal output

## Verify Installation

After installation, the `mcp-audit` command should be available:

```bash
mcp-audit --version
mcp-audit info
```

## Optional: Install development dependencies

For development, testing, and linting:

```bash
pip install -e ".[dev]"
```

This adds:
- pytest (testing)
- black (code formatting)
- flake8 (linting)

## Usage After Installation

Once installed, you can use `mcp-audit` from anywhere:

```bash
# Scan a file
mcp-audit scan-source /path/to/server.py

# Scan a directory
mcp-audit scan-source /path/to/src/

# Scan a tool schema
mcp-audit scan-schema tools/my_tool.json

# Show all threat rules
mcp-audit info

# Output to SARIF
mcp-audit scan-source src/ --format sarif --output results.sarif
```

## Troubleshooting

### "mcp-audit: command not found"

If the `mcp-audit` command isn't found after installation:

1. **Check pip location**: Make sure pip and python are from the same environment
   ```bash
   which pip
   which python
   ```

2. **Reinstall in the current environment**:
   ```bash
   python -m pip install -e .
   ```

3. **Use python module invocation** (fallback):
   ```bash
   python -m cli info
   ```

### "ModuleNotFoundError: No module named 'click'"

The dependencies didn't install. Try:

```bash
pip install --upgrade pip
pip install -e .
```

### Virtual Environment (Recommended)

For a clean installation without affecting system Python:

```bash
# Create virtual environment
python3 -m venv mcp-env
source mcp-env/bin/activate  # On Windows: mcp-env\Scripts\activate

# Install in the virtual environment
pip install .
```

## Next Steps

After installation, try:

```bash
# See all available commands
mcp-audit --help

# Run a demo scan
mcp-audit scan-source examples/vulnerable_server.py

# For more information
mcp-audit info
```
