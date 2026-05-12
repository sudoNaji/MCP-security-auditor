from setuptools import setup, find_packages

setup(
    name="mcp-security-auditor",
    version="1.0.0",
    description="Security auditor for MCP (Model Context Protocol) servers",
    package_dir={"": "src"},
    py_modules=[
        "cli", "threats", "scanner", "report",
        "live_server", "package_scanner"
    ],
    install_requires=["click>=8.1.0", "rich>=13.0.0"],
    entry_points={
        "console_scripts": [
            "mcp-audit=cli:cli",
        ],
    },
    python_requires=">=3.10",
)
