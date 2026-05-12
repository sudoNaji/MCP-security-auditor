from setuptools import setup

setup(
    name="mcp-security-auditor",
    version="1.0.0",
    description="Security auditor for MCP servers",
    author="Naji",
    license="MIT",
    python_requires=">=3.10",
    
    # All modules in src/
    py_modules=["cli", "threats", "scanner", "report", "live_server", "package_scanner"],
    package_dir={"": "src"},
    
    # Auto-install dependencies
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
    ],
    
    # Optional dev dependencies
    extras_require={
        "dev": ["pytest>=8.0.0", "black>=24.0.0", "flake8>=7.0.0"],
    },
    
    # Create 'mcp-audit' command
    entry_points={
        "console_scripts": ["mcp-audit=cli:cli"],
    },
    
    url="https://github.com/sudoNaji/mcp-security-auditor",
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
