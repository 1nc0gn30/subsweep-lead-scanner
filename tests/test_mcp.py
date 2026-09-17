"""
Unit Tests for SubSweep Lead Scanner MCP Server & Engine
=========================================================
Tests JSON-RPC 2.0 protocol compliance, tool manifests, tool executions,
client config generation, and error handling.
"""

import json
import pytest
from subsweep_lead_scanner.mcp_server import (
    MCPServer,
    generate_mcp_client_config,
    enumerate_subdomains,
    fingerprint_tech,
    extract_leads,
    probe_ports,
    full_audit,
    get_diagnostics,
    MCP_TOOLS_MANIFEST,
    __version__,
)


SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Acme Global Solutions - Enterprise Cloud</title>
  <meta name="description" content="Leading B2B cloud and infrastructure services provider.">
  <script src="https://cdn.shopify.com/s/files/1/00/theme.js"></script>
  <script src="https://www.googletagmanager.com/gtm.js?id=GTM-TEST"></script>
</head>
<body>
  <h1>Contact Acme Global</h1>
  <p>Reach our sales team at <a href="mailto:sales@acmeglobal.io">sales@acmeglobal.io</a> or support at support@acmeglobal.io</p>
  <p>Call us toll-free: (800) 555-0199 or direct: +1-415-555-2671</p>
  <div class="social-links">
    <a href="https://www.linkedin.com/company/acme-global">LinkedIn Company</a>
    <a href="https://twitter.com/acmeglobal">Twitter / X</a>
    <a href="https://github.com/acme-global">GitHub</a>
  </div>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "LocalBusiness",
    "name": "Acme Global Solutions",
    "telephone": "(800) 555-0199",
    "email": "contact@acmeglobal.io",
    "address": {
      "@type": "PostalAddress",
      "streetAddress": "500 Howard St",
      "addressLocality": "San Francisco",
      "addressRegion": "CA",
      "postalCode": "94105",
      "addressCountry": "US"
    },
    "priceRange": "$$$$"
  }
  </script>
</body>
</html>
"""


class TestMCPServerProtocol:
    """Test suite for MCP Server JSON-RPC 2.0 protocol implementation."""

    @pytest.fixture
    def server(self):
        return MCPServer()

    def test_initialize_handshake(self, server):
        """Test initialize returns protocolVersion, serverInfo, and capabilities."""
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        }
        res = server.handle_message(req)
        assert res is not None
        assert res["jsonrpc"] == "2.0"
        assert res["id"] == 1
        assert "result" in res
        result = res["result"]
        assert result["serverInfo"]["name"] == "subsweep-lead-scanner"
        assert result["serverInfo"]["version"] == __version__
        assert "tools" in result["capabilities"]

    def test_ping(self, server):
        """Test ping response."""
        req = {"jsonrpc": "2.0", "id": 42, "method": "ping", "params": {}}
        res = server.handle_message(req)
        assert res == {"jsonrpc": "2.0", "id": 42, "result": {}}

    def test_initialized_notification(self, server):
        """Test notifications/initialized returns None without error."""
        req = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        res = server.handle_message(req)
        assert res is None

    def test_tools_list(self, server):
        """Test tools/list returns all 6 registered tools with valid schemas."""
        req = {"jsonrpc": "2.0", "id": 100, "method": "tools/list", "params": {}}
        res = server.handle_message(req)
        assert res is not None
        tools = res["result"]["tools"]
        assert len(tools) == 7
        tool_names = [t["name"] for t in tools]
        assert "subsweep_enumerate_subdomains" in tool_names
        assert "subsweep_fingerprint_tech" in tool_names
        assert "subsweep_extract_leads" in tool_names
        assert "subsweep_probe_ports" in tool_names
        assert "subsweep_full_audit" in tool_names
        assert "subsweep_get_diagnostics" in tool_names
        assert "subsweep_audit_policies" in tool_names

        for t in tools:
            assert "name" in t
            assert "description" in t
            assert "inputSchema" in t
            assert t["inputSchema"]["type"] == "object"

    def test_unknown_method(self, server):
        """Test unknown method returns -32601."""
        req = {"jsonrpc": "2.0", "id": 99, "method": "non_existent_method", "params": {}}
        res = server.handle_message(req)
        assert res is not None
        assert "error" in res
        assert res["error"]["code"] == -32601

    def test_parse_error_line(self, server):
        """Test malformed JSON line returns parse error -32700."""
        line = "{invalid json content"
        res_str = server.handle_line(line)
        assert res_str is not None
        data = json.loads(res_str)
        assert data["error"]["code"] == -32700

    def test_empty_line_handling(self, server):
        """Test empty string returns None."""
        assert server.handle_line("") is None
        assert server.handle_line("   \n") is None


class TestMCPToolsExecution:
    """Test individual MCP tool execution handlers."""

    @pytest.fixture
    def server(self):
        return MCPServer()

    def test_tool_call_extract_leads_direct(self, server):
        """Test calling subsweep_extract_leads with direct HTML content."""
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "subsweep_extract_leads",
                "arguments": {
                    "target": "https://acmeglobal.io",
                    "html_content": SAMPLE_HTML
                }
            }
        }
        res = server.handle_message(req)
        assert res is not None
        assert res["result"]["isError"] is False
        content_text = res["result"]["content"][0]["text"]
        payload = json.loads(content_text)

        assert "sales@acmeglobal.io" in payload["emails"]
        assert "support@acmeglobal.io" in payload["emails"]
        assert len(payload["phones"]) >= 2
        assert "linkedin" in payload["social_links"]
        assert "twitter" in payload["social_links"]
        assert payload["business_info"]["name"] == "Acme Global Solutions"
        assert payload["lead_quality_score"] >= 80
        assert payload["lead_score_grade"] in ("A+", "A")

    def test_tool_call_get_diagnostics(self, server):
        """Test calling subsweep_get_diagnostics."""
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "subsweep_get_diagnostics",
                "arguments": {"test_domain": "localhost"}
            }
        }
        res = server.handle_message(req)
        assert res is not None
        assert res["result"]["isError"] is False
        payload = json.loads(res["result"]["content"][0]["text"])
        assert payload["status"] == "healthy"
        assert "system" in payload
        assert "network" in payload

    def test_tool_call_probe_ports_loopback(self, server):
        """Test port probe against localhost."""
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "subsweep_probe_ports",
                "arguments": {
                    "domain": "127.0.0.1",
                    "ports": [65530, 65531],  # Closed ports
                    "timeout": 0.2
                }
            }
        }
        res = server.handle_message(req)
        assert res is not None
        assert res["result"]["isError"] is False
        payload = json.loads(res["result"]["content"][0]["text"])
        assert payload["host"] == "127.0.0.1"
        assert payload["total_scanned"] == 2
        assert payload["total_open"] == 0

    def test_tool_call_unknown_tool(self, server):
        """Test calling unknown tool returns error code -32602."""
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "unknown_tool_xyz",
                "arguments": {}
            }
        }
        res = server.handle_message(req)
        assert res is not None
        assert "error" in res
        assert res["error"]["code"] == -32602


class TestMCPClientConfigGenerator:
    """Test client config generator for various IDEs and AI tools."""

    def test_claude_desktop_config(self):
        cfg = generate_mcp_client_config("claude", python_path="/usr/bin/python3")
        assert "mcpServers" in cfg
        assert "subsweep" in cfg["mcpServers"]
        server_entry = cfg["mcpServers"]["subsweep"]
        assert server_entry["command"] == "/usr/bin/python3"
        assert server_entry["args"] == ["-m", "subsweep_lead_scanner.mcp_server"]

    def test_cursor_config(self):
        cfg = generate_mcp_client_config("cursor")
        assert "mcpServers" in cfg
        assert "subsweep" in cfg["mcpServers"]

    def test_cline_config(self):
        cfg = generate_mcp_client_config("cline")
        assert "mcpServers" in cfg
        assert cfg["mcpServers"]["subsweep"]["disabled"] is False

    def test_zed_config(self):
        cfg = generate_mcp_client_config("zed")
        assert "context_servers" in cfg
        assert "subsweep" in cfg["context_servers"]
        assert cfg["context_servers"]["subsweep"]["command"]["path"] == "python3"

    def test_generic_config(self):
        cfg = generate_mcp_client_config("generic")
        assert cfg["name"] == "subsweep"
        assert cfg["transport"] == "stdio"
        assert cfg["version"] == __version__
