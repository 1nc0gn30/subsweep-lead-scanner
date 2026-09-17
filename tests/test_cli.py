"""
Unit Tests for SubSweep Lead Scanner CLI
========================================
Tests command line parsing, subcommands (scan, subdomains, tech, leads,
ports, mcp, serve, platform, test), exports, and formatting.
"""

import io
import json
import os
import tempfile
import pytest
from unittest.mock import patch

from subsweep_lead_scanner.cli import (
    build_parser,
    main,
    handle_test,
    handle_platform,
    handle_mcp,
    handle_leads,
    handle_subdomains,
    handle_ports,
    _export_csv,
    _export_json,
    _render_score_bar,
)


SAMPLE_HTML_LEADS = """
<!DOCTYPE html>
<html>
<head><title>Stripe Partner Agency</title></head>
<body>
  <h1>Growth Partner</h1>
  <p>Email us: contact@growthagency.com, hello@growthagency.com</p>
  <p>Call: (415) 888-9900</p>
  <a href="https://linkedin.com/company/growth-agency">LinkedIn</a>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "Growth Agency LLC",
    "telephone": "(415) 888-9900",
    "address": "San Francisco, CA"
  }
  </script>
</body>
</html>
"""


class TestCLIParser:
    """Test argument parsing for all subcommands."""

    def test_parser_subcommands(self):
        parser = build_parser()
        
        # Test scan parser
        args_scan = parser.parse_args(["scan", "example.com", "--ports", "80,443", "--json"])
        assert args_scan.command == "scan"
        assert args_scan.domain == "example.com"
        assert args_scan.ports == "80,443"
        assert args_scan.json is True

        # Test subdomains parser
        args_subs = parser.parse_args(["subdomains", "target.org", "-w", "www,api,dev", "--json"])
        assert args_subs.command == "subdomains"
        assert args_subs.domain == "target.org"
        assert args_subs.wordlist == "www,api,dev"

        # Test tech parser
        args_tech = parser.parse_args(["tech", "https://shopify.com", "--timeout", "10", "--json"])
        assert args_tech.command == "tech"
        assert args_tech.target == "https://shopify.com"
        assert args_tech.timeout == 10.0

        # Test leads parser
        args_leads = parser.parse_args(["leads", "example.com", "--export-csv", "out.csv", "--json"])
        assert args_leads.command == "leads"
        assert args_leads.target == "example.com"
        assert args_leads.export_csv == "out.csv"

        # Test ports parser
        args_ports = parser.parse_args(["ports", "127.0.0.1", "--ports", "80,443,22", "--no-banner"])
        assert args_ports.command == "ports"
        assert args_ports.domain == "127.0.0.1"
        assert args_ports.no_banner is True

        # Test mcp parser
        args_mcp = parser.parse_args(["mcp", "--config", "claude"])
        assert args_mcp.command == "mcp"
        assert args_mcp.config == "claude"

        # Test serve parser
        args_serve = parser.parse_args(["serve", "--port", "9000", "--host", "127.0.0.1"])
        assert args_serve.command == "serve"
        assert args_serve.port == 9000
        assert args_serve.host == "127.0.0.1"

        # Test platform parser
        args_plat = parser.parse_args(["platform", "--json"])
        assert args_plat.command == "platform"
        assert args_plat.json is True


class TestCLIExecution:
    """Test execution of CLI handlers."""

    def test_cli_test_command(self, capsys):
        """Test 'subsweep test' / --test runs diagnostic suite."""
        parser = build_parser()
        args = parser.parse_args(["test"])
        code = handle_test(args)
        assert code == 0
        captured = capsys.readouterr().out
        assert "Running Internal Engine Diagnostic Tests" in captured
        assert "Engine Checks Passed" in captured

    def test_cli_platform_json(self, capsys):
        """Test 'subsweep platform --json' returns valid JSON."""
        parser = build_parser()
        args = parser.parse_args(["platform", "--json"])
        code = handle_platform(args)
        assert code == 0
        captured = capsys.readouterr().out
        data = json.loads(captured)
        assert data["status"] == "healthy"
        assert "system" in data
        assert "network" in data

    def test_cli_mcp_tools(self, capsys):
        """Test 'subsweep mcp --tools' returns tools manifest."""
        parser = build_parser()
        args = parser.parse_args(["mcp", "--tools"])
        code = handle_mcp(args)
        assert code == 0
        captured = capsys.readouterr().out
        tools = json.loads(captured)
        assert len(tools) == 7

    def test_cli_mcp_config(self, capsys):
        """Test 'subsweep mcp --config claude'."""
        parser = build_parser()
        args = parser.parse_args(["mcp", "--config", "claude"])
        code = handle_mcp(args)
        assert code == 0
        captured = capsys.readouterr().out
        cfg = json.loads(captured)
        assert "mcpServers" in cfg

    def test_cli_leads_from_file_and_export(self, capsys):
        """Test 'subsweep leads <filepath> --export-csv ... --json'."""
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f_in:
            f_in.write(SAMPLE_HTML_LEADS)
            html_path = f_in.name

        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f_csv:
            csv_path = f_csv.name

        try:
            parser = build_parser()
            args = parser.parse_args(["leads", html_path, "--export-csv", csv_path, "--json"])
            code = handle_leads(args)
            assert code == 0

            captured = capsys.readouterr().out
            data = json.loads(captured)
            assert "contact@growthagency.com" in data["emails"]
            assert data["lead_quality_score"] > 50

            # Verify exported CSV
            assert os.path.exists(csv_path)
            with open(csv_path, "r", encoding="utf-8") as f_out:
                content = f_out.read()
                assert "contact@growthagency.com" in content
                assert "Target" in content
        finally:
            if os.path.exists(html_path): os.remove(html_path)
            if os.path.exists(csv_path): os.remove(csv_path)

    def test_cli_ports_probe_json(self, capsys):
        """Test 'subsweep ports 127.0.0.1 --ports 65530 --json'."""
        parser = build_parser()
        args = parser.parse_args(["ports", "127.0.0.1", "--ports", "65530", "--json"])
        code = handle_ports(args)
        assert code == 0
        captured = capsys.readouterr().out
        data = json.loads(captured)
        assert data["host"] == "127.0.0.1"
        assert data["total_scanned"] == 1

    def test_cli_main_entrypoint_no_args(self, capsys):
        """Test main() with no args prints help and returns 0."""
        code = main([])
        assert code == 0
        captured = capsys.readouterr().out
        assert "usage: subsweep" in captured

    def test_score_meter_rendering(self):
        """Test visual score bar function."""
        high = _render_score_bar(95)
        med = _render_score_bar(65)
        low = _render_score_bar(30)
        assert "95/100" in high
        assert "65/100" in med
        assert "30/100" in low
