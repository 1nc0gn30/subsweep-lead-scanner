"""
Unit Tests for SubSweep Lead Scanner UI Server & REST API
==========================================================
Tests HTTP endpoints, CORS preflight, REST API requests, CSV/JSON exports,
portable ZIP packaging, and embedded Material 3 UI serving.
"""

import io
import json
import socket
import threading
import time
import urllib.request
import zipfile
import pytest

from subsweep_lead_scanner.ui_server import create_ui_server, EMBEDDED_STUDIO_HTML


@pytest.fixture(scope="module")
def live_server():
    """Start an ephemeral ThreadingHTTPServer on port 0 in a background daemon thread."""
    # Find free port
    server = create_ui_server(host="127.0.0.1", port=0)
    assigned_port = server.server_port
    base_url = f"http://127.0.0.1:{assigned_port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield base_url

    server.shutdown()
    server.server_close()


def _http_request(url: str, method: str = "GET", data: dict = None, headers: dict = None):
    """Helper to perform HTTP request using urllib."""
    hdrs = headers or {}
    body_bytes = None
    if data is not None:
        body_bytes = json.dumps(data).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            resp_body = resp.read()
            return resp.status, dict(resp.headers), resp_body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


class TestUIServerEndpoints:
    """Test suite for UI Server and REST API."""

    def test_get_health(self, live_server):
        """Test GET /api/health."""
        status, headers, body = _http_request(f"{live_server}/api/health")
        assert status == 200
        assert "application/json" in headers.get("Content-Type", "")
        data = json.loads(body.decode("utf-8"))
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data
        assert "version" in data
        assert headers.get("Access-Control-Allow-Origin") == "*"

    def test_get_mcp_config(self, live_server):
        """Test GET /api/mcp/config?client=cursor."""
        status, headers, body = _http_request(f"{live_server}/api/mcp/config?client=cursor")
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        assert "mcpServers" in data
        assert "subsweep" in data["mcpServers"]

    def test_embedded_ui_index(self, live_server):
        """Test GET / returns embedded Material 3 Recon Studio HTML."""
        status, headers, body = _http_request(f"{live_server}/")
        assert status == 200
        assert "text/html" in headers.get("Content-Type", "")
        html_str = body.decode("utf-8")
        assert "SubSweep" in html_str
        assert "Recon Studio" in html_str

    def test_post_subdomains(self, live_server):
        """Test POST /api/subdomains."""
        payload = {"domain": "localhost", "wordlist": ["test"], "passive_only": True}
        status, headers, body = _http_request(f"{live_server}/api/subdomains", method="POST", data=payload)
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        assert data["domain"] == "localhost"
        assert "subdomains" in data

    def test_post_tech(self, live_server):
        """Test POST /api/tech."""
        payload = {"target": "https://example.com", "timeout": 1.0}
        status, headers, body = _http_request(f"{live_server}/api/tech", method="POST", data=payload)
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        assert "technologies" in data
        assert "security_headers" in data

    def test_post_leads_with_html(self, live_server):
        """Test POST /api/leads with direct HTML payload."""
        sample_html = """
        <html><body>
          <h1>Acme</h1>
          <p>Email: founder@acme.ai, sales@acme.ai</p>
          <p>Phone: (555) 123-4567</p>
          <a href="https://linkedin.com/company/acme-ai">LinkedIn</a>
        </body></html>
        """
        payload = {"target": "https://acme.ai", "html": sample_html}
        status, headers, body = _http_request(f"{live_server}/api/leads", method="POST", data=payload)
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        assert "founder@acme.ai" in data["emails"]
        assert len(data["phones"]) >= 1
        assert "linkedin" in data["social_links"]
        assert data["lead_quality_score"] > 50

    def test_post_ports(self, live_server):
        """Test POST /api/ports."""
        payload = {"domain": "127.0.0.1", "ports": [65532, 65533], "timeout": 0.2}
        status, headers, body = _http_request(f"{live_server}/api/ports", method="POST", data=payload)
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        assert data["host"] == "127.0.0.1"
        assert data["total_scanned"] == 2

    def test_post_scan(self, live_server):
        """Test POST /api/scan."""
        payload = {"domain": "localhost", "ports": [65534], "timeout": 0.5, "passive_only": True}
        status, headers, body = _http_request(f"{live_server}/api/scan", method="POST", data=payload)
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        assert "lead_summary" in data
        assert "subdomains" in data
        assert "technology" in data
        assert "leads" in data
        assert "ports" in data

    def test_post_email(self, live_server):
        """Test POST /api/email."""
        payload = {"domain": "example.com", "timeout": 0.5}
        status, headers, body = _http_request(f"{live_server}/api/email", method="POST", data=payload)
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        assert "domain" in data
        assert "grade" in data
        assert "security_score" in data

    def test_post_takeovers(self, live_server):
        """Test POST /api/takeovers."""
        payload = {
            "domain": "example.com",
            "subdomains": [{"subdomain": "blog.example.com", "cname": "deadsite.github.io"}],
            "verify_http": False,
        }
        status, headers, body = _http_request(f"{live_server}/api/takeovers", method="POST", data=payload)
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        assert data["domain"] == "example.com"
        assert len(data["findings"]) >= 1

    def test_post_export_csv(self, live_server):
        """Test POST /api/export-csv returns CSV attachment."""
        sample_lead_data = {
            "leads": {
                "target": "acme.com",
                "emails": ["ceo@acme.com", "info@acme.com"],
                "phones": ["555-0199"],
                "social_links": {"linkedin": ["https://linkedin.com/company/acme"]},
                "business_info": {"name": "Acme Inc", "address": "123 Main St"},
                "lead_quality_score": 85,
                "lead_score_grade": "A"
            }
        }
        status, headers, body = _http_request(f"{live_server}/api/export-csv", method="POST", data=sample_lead_data)
        assert status == 200
        assert "text/csv" in headers.get("Content-Type", "")
        assert 'filename="subsweep-leads.csv"' in headers.get("Content-Disposition", "")
        csv_str = body.decode("utf-8")
        assert "ceo@acme.com" in csv_str
        assert "Target" in csv_str

    def test_post_export_json(self, live_server):
        """Test POST /api/export-json returns JSON file attachment."""
        data_payload = {"data": {"domain": "example.com", "score": 90}}
        status, headers, body = _http_request(f"{live_server}/api/export-json", method="POST", data=data_payload)
        assert status == 200
        assert "application/json" in headers.get("Content-Type", "")
        assert 'filename="subsweep-report.json"' in headers.get("Content-Disposition", "")
        parsed = json.loads(body.decode("utf-8"))
        assert parsed["domain"] == "example.com"

    def test_post_export_zip(self, live_server):
        """Test POST /api/export-zip generates valid zip archive in memory."""
        status, headers, body = _http_request(f"{live_server}/api/export-zip", method="POST", data={})
        assert status == 200
        assert "application/zip" in headers.get("Content-Type", "")
        assert 'filename="subsweep-recon-studio.zip"' in headers.get("Content-Disposition", "")

        # Validate ZIP content in memory
        zip_buf = io.BytesIO(body)
        with zipfile.ZipFile(zip_buf, "r") as zf:
            file_names = zf.namelist()
            assert "index.html" in file_names
            assert "README.md" in file_names
            index_html = zf.read("index.html").decode("utf-8")
            assert "SubSweep" in index_html

    def test_options_cors_preflight(self, live_server):
        """Test OPTIONS preflight returns CORS headers."""
        status, headers, _ = _http_request(f"{live_server}/api/scan", method="OPTIONS")
        assert status == 204
        assert headers.get("Access-Control-Allow-Origin") == "*"
        assert "POST" in headers.get("Access-Control-Allow-Methods", "")

    def test_404_not_found(self, live_server):
        """Test requesting invalid endpoint returns 404."""
        status, _, body = _http_request(f"{live_server}/api/invalid-endpoint-xyz", method="POST", data={})
        assert status == 404
        data = json.loads(body.decode("utf-8"))
        assert "error" in data
