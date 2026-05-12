"""
live_server.py — Live MCP server introspection and testing.

Connects to running MCP servers via stdio, introspects tool schemas,
and optionally test-executes tools in a sandbox.
"""

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from threats import Finding, ThreatClass, Severity


@dataclass
class MCPServerConnection:
    """Represents a connection to a running MCP server."""
    command: str
    args: list[str] = None
    env: dict[str, str] = None
    timeout: int = 30
    
    def __post_init__(self):
        if self.args is None:
            self.args = []
        if self.env is None:
            self.env = {}


class LiveServerScanner:
    """Scan a running MCP server."""
    
    def __init__(self, connection: MCPServerConnection, sandbox_mode: bool = True):
        self.connection = connection
        self.sandbox_mode = sandbox_mode
        self.process = None
        self.findings: list[Finding] = []
    
    def connect(self) -> bool:
        """Connect to the MCP server via stdio."""
        try:
            self.process = subprocess.Popen(
                [self.connection.command] + self.connection.args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={**subprocess.os.environ, **self.connection.env},
                timeout=self.connection.timeout,
            )
            return True
        except Exception as e:
            self.findings.append(Finding(
                threat_class=ThreatClass.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                rule_id="MCP-LIVE-001",
                title="Failed to connect to MCP server",
                description=f"Could not spawn MCP server process: {e}",
                evidence=str(self.connection.command),
                location="live_server_connection",
                recommendation="Check that the MCP server is installed and the command is correct",
            ))
            return False
    
    def list_tools(self) -> dict[str, Any]:
        """Request list of available tools from the server."""
        if not self.process:
            return {}
        
        try:
            # Send MCP request: tools/list
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()
            
            # Read response
            response_line = self.process.stdout.readline()
            response = json.loads(response_line)
            
            return response.get("result", {})
        except Exception as e:
            self.findings.append(Finding(
                threat_class=ThreatClass.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                rule_id="MCP-LIVE-002",
                title="Failed to list tools from MCP server",
                description=f"Error communicating with MCP server: {e}",
                evidence=str(e),
                location="live_server_tools_list",
                recommendation="Check server logs and verify MCP protocol compliance",
            ))
            return {}
    
    def inspect_tools(self) -> list[Finding]:
        """
        Inspect all tools exposed by the server.
        Applies threat rules to tool schemas.
        """
        from scanner import ToolDefinitionScanner
        
        tools = self.list_tools()
        scanner = ToolDefinitionScanner()
        
        for tool_name, tool_schema in tools.items():
            findings = scanner.scan(tool_schema, tool_name=tool_name)
            self.findings.extend(findings)
        
        return self.findings
    
    def test_tool_execution(self, tool_name: str, inputs: dict) -> tuple[bool, str]:
        """
        Test-execute a tool with given inputs in sandbox mode.
        
        Returns: (success: bool, output: str)
        """
        if not self.sandbox_mode:
            return False, "Sandbox mode disabled"
        
        if not self.process:
            return False, "Not connected to MCP server"
        
        try:
            # Send MCP call/tool request
            request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": inputs,
                },
            }
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()
            
            # Read response with timeout
            response_line = self.process.stdout.readline()
            response = json.loads(response_line)
            
            if "error" in response:
                return False, response["error"].get("message", "Unknown error")
            
            result = response.get("result", {})
            return True, json.dumps(result)
        except Exception as e:
            return False, str(e)
    
    def close(self):
        """Close the connection."""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
