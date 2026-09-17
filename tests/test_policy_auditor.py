"""Unit tests for Robots.txt & Security.txt Policy Auditor."""

import json
import pytest

from subsweep_lead_scanner.policy_auditor import (
    RobotsAuditor,
    SecurityTxtAuditor,
    audit_policy_endpoints,
)
from subsweep_lead_scanner.mcp_server import MCPServer
from subsweep_lead_scanner.cli import main as cli_main


SAMPLE_ROBOTS_TXT = """
User-agent: Googlebot
Disallow: /admin/
Disallow: /wp-admin/
Disallow: /api/v1/private
Allow: /api/v1/public
Crawl-delay: 2

User-agent: *
Disallow: /internal/dashboard
Disallow: /backup/
Allow: /

Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap-posts.xml
"""

SAMPLE_SECURITY_TXT = """
Contact: mailto:security@example.com
Contact: https://example.com/security-bounty
Expires: 2028-12-31T23:59:59.000Z
Encryption: https://example.com/pgp-key.asc
Policy: https://example.com/disclosure-policy
Hiring: https://example.com/jobs/security
Acknowledgments: https://example.com/hall-of-fame
Preferred-Languages: en, es, fr
Canonical: https://example.com/.well-known/security.txt
"""


# ============================================================================
# Robots.txt Tests
# ============================================================================

def test_parse_robots_txt_complete():
    report = RobotsAuditor.parse_robots_txt(SAMPLE_ROBOTS_TXT, target="https://example.com")
    assert report.exists is True
    assert len(report.sitemaps) == 2
    assert "https://example.com/sitemap.xml" in report.sitemaps
    assert len(report.directives) == 2

    # Sensitive paths check
    assert "/admin/" in report.sensitive_disallowed_paths
    assert "/wp-admin/" in report.sensitive_disallowed_paths
    assert "/backup/" in report.sensitive_disallowed_paths
    assert report.crawl_delay_found is True
    assert report.hygiene_score < 100
    assert len(report.findings) > 0


def test_parse_robots_txt_empty():
    report = RobotsAuditor.parse_robots_txt("", target="https://example.com")
    assert report.exists is False
    assert len(report.sitemaps) == 0
    assert len(report.directives) == 0


# ============================================================================
# Security.txt Tests
# ============================================================================

def test_parse_security_txt_valid_rfc9116():
    report = SecurityTxtAuditor.parse_security_txt(SAMPLE_SECURITY_TXT, target="https://example.com")
    assert report.exists is True
    assert report.rfc9116_compliant is True
    assert len(report.contacts) == 2
    assert "mailto:security@example.com" in report.contacts
    assert report.is_expired is False
    assert report.compliance_score >= 90
    assert "en" in report.preferred_languages
    assert len(report.policy_urls) == 1


def test_parse_security_txt_missing_mandatory():
    # Missing Expires and Contact
    report = SecurityTxtAuditor.parse_security_txt("Preferred-Languages: en\n", target="https://example.com")
    assert report.rfc9116_compliant is False
    assert report.compliance_score == 0
    assert any("Contact" in r for r in report.recommendations)
    assert any("Expires" in r for r in report.recommendations)


def test_parse_security_txt_expired():
    expired_txt = """
    Contact: mailto:sec@old.org
    Expires: 2020-01-01T00:00:00Z
    """
    report = SecurityTxtAuditor.parse_security_txt(expired_txt)
    assert report.is_expired is True
    assert report.rfc9116_compliant is False


# ============================================================================
# Combined Audit Helper & Endpoints
# ============================================================================

def test_audit_policy_endpoints_in_memory():
    res = audit_policy_endpoints(
        domain_or_url="example.com",
        robots_content=SAMPLE_ROBOTS_TXT,
        security_txt_content=SAMPLE_SECURITY_TXT,
    )
    assert res["robots"]["exists"] is True
    assert res["security_txt"]["exists"] is True
    assert len(res["combined_contacts"]) == 2
    assert res["disallowed_endpoints_count"] >= 3


# ============================================================================
# MCP Server Tool Execution
# ============================================================================

def test_mcp_subsweep_audit_policies():
    server = MCPServer()
    res = server.execute_tool(
        "subsweep_audit_policies",
        {
            "domain": "example.com",
            "robots_content": SAMPLE_ROBOTS_TXT,
            "security_txt_content": SAMPLE_SECURITY_TXT,
        },
    )
    assert res["robots"]["exists"] is True
    assert res["security_txt"]["rfc9116_compliant"] is True
    assert len(res["combined_contacts"]) == 2


# ============================================================================
# CLI Command Execution
# ============================================================================

def test_cli_policies_json(tmp_path, capsys):
    rob_file = tmp_path / "robots.txt"
    rob_file.write_text(SAMPLE_ROBOTS_TXT, encoding="utf-8")
    sec_file = tmp_path / "security.txt"
    sec_file.write_text(SAMPLE_SECURITY_TXT, encoding="utf-8")

    code = cli_main([
        "policies",
        "example.com",
        "--robots-file", str(rob_file),
        "--security-file", str(sec_file),
        "--json",
    ])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["robots"]["exists"] is True
    assert data["security_txt"]["compliance_score"] >= 90
