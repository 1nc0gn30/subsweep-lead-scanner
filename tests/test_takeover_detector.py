"""Unit tests for Subdomain Takeover & CNAME Dangling Pointer Detector."""

import json
from unittest.mock import MagicMock, patch
import pytest

from subsweep_lead_scanner.takeover_detector import (
    SubdomainTakeoverDetector,
    TakeoverFinding,
    TakeoverScanReport,
    TAKEOVER_FINGERPRINTS,
)
from subsweep_lead_scanner.mcp_server import MCPServer
from subsweep_lead_scanner.cli import main as cli_main


# ============================================================================
# CNAME Pattern Matching Tests
# ============================================================================

def test_cname_pattern_matching():
    detector = SubdomainTakeoverDetector()

    # GitHub Pages
    res_gh = detector.check_cname("docs.example.com", "myrepo.github.io")
    assert res_gh is not None
    assert res_gh.service == "GitHub Pages"
    assert res_gh.severity == "CRITICAL"
    assert res_gh.status == "POTENTIALLY_DANGLING"
    assert res_gh.is_vulnerable is False

    # AWS S3
    res_s3 = detector.check_cname("assets.example.com", "mybucket.s3.amazonaws.com")
    assert res_s3 is not None
    assert res_s3.service == "Amazon S3"
    assert res_s3.severity == "CRITICAL"

    # Heroku
    res_hk = detector.check_cname("app.example.com", "ancient-app.herokuapp.com")
    assert res_hk is not None
    assert res_hk.service == "Heroku"

    # Netlify
    res_net = detector.check_cname("portal.example.com", "cool-site.netlify.app")
    assert res_net is not None
    assert res_net.service == "Netlify"

    # Unmatched / safe CNAME
    res_safe = detector.check_cname("blog.example.com", "cdn.cloudflare.net")
    assert res_safe is None


# ============================================================================
# HTTP Fingerprint Verification Tests
# ============================================================================

def test_http_body_fingerprint_confirmation():
    detector = SubdomainTakeoverDetector()

    # Confirmed GitHub Pages Takeover
    gh_body = "<html><body><h1>404 There isn't a GitHub Pages site here.</h1></body></html>"
    res_gh = detector.check_cname(
        "docs.example.com",
        "abandoned.github.io",
        http_body=gh_body,
        http_status=404,
    )
    assert res_gh is not None
    assert res_gh.is_vulnerable is True
    assert res_gh.status == "CONFIRMED_VULNERABLE"
    assert res_gh.fingerprint_matched == "There isn't a GitHub Pages site here."
    assert "Claim the repository" in res_gh.remediation

    # Confirmed AWS S3 Bucket Takeover
    s3_body = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
    res_s3 = detector.check_cname(
        "static.example.com",
        "orphan.s3.amazonaws.com",
        http_body=s3_body,
        http_status=404,
    )
    assert res_s3 is not None
    assert res_s3.is_vulnerable is True
    assert res_s3.status == "CONFIRMED_VULNERABLE"
    assert res_s3.fingerprint_matched == "NoSuchBucket"


# ============================================================================
# Batch Scan Records Tests
# ============================================================================

def test_scan_records_batch():
    detector = SubdomainTakeoverDetector()

    sample_records = [
        {"subdomain": "api.example.com", "cnames": ["api-prod.internal.net"]},
        {"subdomain": "blog.example.com", "cnames": ["deadblog.github.io"]},
        {"subdomain": "shop.example.com", "cname": "shops.myshopify.com"},
    ]

    report = detector.scan_records("example.com", sample_records, verify_http=False)

    assert report.domain == "example.com"
    assert report.total_checked == 3
    assert report.cnames_analyzed == 3
    assert len(report.findings) == 2  # GitHub Pages and Shopify
    services = [f.service for f in report.findings]
    assert "GitHub Pages" in services
    assert "Shopify" in services

    # Check to_dict()
    d = report.to_dict()
    assert d["domain"] == "example.com"
    assert len(d["findings"]) == 2
    assert d["findings"][0]["subdomain"] == "blog.example.com"


# ============================================================================
# MCP Tool Test
# ============================================================================

def test_mcp_takeover_detection_tool():
    records = [
        {"subdomain": "docs.example.com", "cnames": ["myoldapp.herokuapp.com"]}
    ]

    with patch("subsweep_lead_scanner.mcp_server.SubdomainTakeoverDetector") as MockDetector:
        mock_instance = MagicMock()
        mock_instance.scan_records.return_value = TakeoverScanReport(
            domain="example.com",
            total_checked=1,
            cnames_analyzed=1,
            vulnerabilities_found=0,
            findings=[
                TakeoverFinding(
                    subdomain="docs.example.com",
                    cname="myoldapp.herokuapp.com",
                    service="Heroku",
                    severity="HIGH",
                    is_vulnerable=False,
                    status="POTENTIALLY_DANGLING",
                    remediation="Delete custom domain",
                )
            ],
            duration_seconds=0.05,
        )
        MockDetector.return_value = mock_instance

        server = MCPServer()
        result = server.call_tool("subsweep_detect_takeovers", {
            "domain": "example.com",
            "subdomains": records,
        })

        assert result.get("domain") == "example.com"
        assert len(result.get("findings", [])) == 1
        assert result["findings"][0]["service"] == "Heroku"


# ============================================================================
# CLI Command Test
# ============================================================================

def test_cli_takeovers_command(capsys):
    with patch("subsweep_lead_scanner.cli.SubdomainTakeoverDetector") as MockDetector:
        mock_instance = MagicMock()
        mock_instance.scan_records.return_value = TakeoverScanReport(
            domain="vulntest.org",
            total_checked=2,
            cnames_analyzed=1,
            vulnerabilities_found=1,
            findings=[
                TakeoverFinding(
                    subdomain="staging.vulntest.org",
                    cname="vulntest.surge.sh",
                    service="Surge.sh",
                    severity="HIGH",
                    is_vulnerable=True,
                    status="CONFIRMED_VULNERABLE",
                    fingerprint_matched="project not found",
                    remediation="Claim on surge or delete CNAME",
                )
            ],
            duration_seconds=0.1,
        )
        MockDetector.return_value = mock_instance

        # Provide a mock subdomain enumeration
        with patch("subsweep_lead_scanner.subdomain_finder.SubdomainEnumerator") as MockEnum:
            mock_enum = MagicMock()
            mock_sub = MagicMock()
            mock_sub.to_dict.return_value = {"subdomain": "staging.vulntest.org", "cnames": ["vulntest.surge.sh"]}
            mock_enum.enumerate.return_value = MagicMock(results=[mock_sub])
            MockEnum.return_value = mock_enum

            rc = cli_main(["takeovers", "vulntest.org", "--format", "json"])
            assert rc == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["domain"] == "vulntest.org"
            assert data["vulnerabilities_found"] == 1
            assert len(data["findings"]) == 1
