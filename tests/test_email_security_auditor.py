"""Unit tests for Email Security (SPF/DMARC/DKIM/MX) Auditor."""

import json
from unittest.mock import MagicMock, patch
import pytest

from subsweep_lead_scanner.email_security_auditor import (
    EmailSecurityAuditor,
    SPFAudit,
    DMARCAudit,
    DKIMAudit,
    MXRecord,
    EmailSecurityReport,
)
from subsweep_lead_scanner.mcp_server import MCPServer
from subsweep_lead_scanner.cli import main as cli_main


# ============================================================================
# Mock DNS Resolver Helper
# ============================================================================

def make_mock_resolver(dns_map):
    """Create a mock resolver mapping (record_type, query_name) or (query_name, record_type) -> list of strings."""
    def _mock_resolve(arg1, arg2):
        for k in [(arg2.upper(), arg1.lower().rstrip(".")), (arg1.upper(), arg2.lower().rstrip("."))]:
            if k in dns_map:
                return dns_map[k]
        return []
    return _mock_resolve


# ============================================================================
# SPF Parsing Tests
# ============================================================================

def test_spf_parsing_strong_reject():
    auditor = EmailSecurityAuditor()
    spf = auditor.parse_spf("v=spf1 include:_spf.google.com ip4:192.0.2.0/24 -all")
    assert spf.is_present is True
    assert spf.is_valid is True
    assert spf.all_qualifier == "-all"
    assert spf.qualifier_security == "STRONG"
    assert "include:_spf.google.com" in spf.mechanisms
    assert "ip4:192.0.2.0/24" in spf.mechanisms
    assert spf.lookup_count == 1  # 1 include = 1 lookup
    assert len(spf.warnings) == 0


def test_spf_parsing_softfail():
    auditor = EmailSecurityAuditor()
    spf = auditor.parse_spf("v=spf1 mx a include:sendgrid.net ~all")
    assert spf.is_present is True
    assert spf.is_valid is True
    assert spf.all_qualifier == "~all"
    assert spf.qualifier_security == "ACCEPTABLE"
    assert spf.lookup_count == 3  # mx (1) + a (1) + include (1) = 3


def test_spf_parsing_dangerous_all():
    auditor = EmailSecurityAuditor()
    spf = auditor.parse_spf("v=spf1 +all")
    assert spf.is_present is True
    assert spf.all_qualifier == "+all"
    assert spf.qualifier_security == "CRITICAL_VULNERABLE"
    assert any("allows entire internet" in w.lower() or "permitting any server" in w.lower() for w in spf.warnings)


def test_spf_exceeding_10_lookup_limit():
    auditor = EmailSecurityAuditor()
    # 11 includes
    record = "v=spf1 " + " ".join(f"include:inc{i}.com" for i in range(11)) + " -all"
    spf = auditor.parse_spf(record)
    assert spf.lookup_count == 11
    assert spf.lookup_limit_exceeded is True
    assert any("exceeded" in w.lower() for w in spf.warnings)


# ============================================================================
# DMARC Parsing Tests
# ============================================================================

def test_dmarc_parsing_reject():
    auditor = EmailSecurityAuditor()
    dmarc = auditor.parse_dmarc("v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com; aspf=s; adkim=s")
    assert dmarc.is_present is True
    assert dmarc.is_valid is True
    assert dmarc.policy == "reject"
    assert dmarc.enforcement_level == "STRICT_REJECT"
    assert dmarc.subdomain_policy == "reject"
    assert dmarc.percentage == 100
    assert "mailto:dmarc-rua@example.com" in dmarc.rua_addresses
    assert "mailto:dmarc-ruf@example.com" in dmarc.ruf_addresses
    assert dmarc.aspf_mode == "s"
    assert dmarc.adkim_mode == "s"
    assert len(dmarc.warnings) == 0


def test_dmarc_parsing_none_policy_warning():
    auditor = EmailSecurityAuditor()
    dmarc = auditor.parse_dmarc("v=DMARC1; p=none; pct=50")
    assert dmarc.is_present is True
    assert dmarc.policy == "none"
    assert dmarc.enforcement_level == "MONITORING_ONLY"
    assert any("monitoring only" in w.lower() for w in dmarc.warnings)


# ============================================================================
# DKIM Parsing Tests
# ============================================================================

def test_dkim_parsing():
    auditor = EmailSecurityAuditor()
    raw = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3..."
    dkim = auditor.parse_dkim("google", raw)
    assert dkim.has_valid_dkim is True
    assert "google" in dkim.discovered_selectors
    assert dkim.key_types.get("google") == "rsa"


# ============================================================================
# MX Provider Classification Tests
# ============================================================================

def test_mx_provider_classification():
    auditor = EmailSecurityAuditor()
    mx_entries = [
        "10 aspmx.l.google.com",
        "20 alt1.aspmx.l.google.com",
    ]
    mx_records, providers = auditor.parse_mx_records(mx_entries)
    assert len(mx_records) == 2
    assert "Google Workspace" in providers
    assert mx_records[0].priority == 10
    assert mx_records[0].host == "aspmx.l.google.com"


# ============================================================================
# Full End-to-End Domain Audit Tests
# ============================================================================

def test_full_audit_grade_a_plus():
    dns_map = {
        ("TXT", "securecorp.com"): ["v=spf1 include:_spf.google.com -all"],
        ("TXT", "_dmarc.securecorp.com"): ["v=DMARC1; p=reject; rua=mailto:dmarc@securecorp.com"],
        ("TXT", "google._domainkey.securecorp.com"): ["v=DKIM1; k=rsa; p=MIGf..."],
        ("MX", "securecorp.com"): ["5 alt1.aspmx.l.google.com", "1 aspmx.l.google.com"],
    }
    resolver = make_mock_resolver(dns_map)
    auditor = EmailSecurityAuditor(resolver=resolver)
    report = auditor.audit_domain("securecorp.com")

    assert report.domain == "securecorp.com"
    assert report.spf.is_present is True
    assert report.dmarc.is_present is True
    assert report.dmarc.policy == "reject"
    assert len(report.dkim.discovered_selectors) >= 1
    assert report.primary_email_provider == "Google Workspace"
    assert report.grade in ("A+", "A")
    assert report.security_score >= 80

    # Check to_dict()
    d = report.to_dict()
    assert d["domain"] == "securecorp.com"
    assert "spf" in d
    assert "dmarc" in d
    assert "actionable_remediations" in d


def test_full_audit_grade_f_missing_records():
    resolver = make_mock_resolver({})
    auditor = EmailSecurityAuditor(resolver=resolver)
    report = auditor.audit_domain("insecure.org")

    assert report.spf.is_present is False
    assert report.dmarc.is_present is False
    assert len(report.dkim.discovered_selectors) == 0
    assert report.grade == "F"
    assert report.security_score < 40
    assert len(report.actionable_remediations) >= 2


# ============================================================================
# MCP Tool Test
# ============================================================================

def test_mcp_email_security_tool():
    with patch("subsweep_lead_scanner.mcp_server.EmailSecurityAuditor") as MockAuditor:
        mock_instance = MagicMock()
        mock_instance.audit_domain.return_value = EmailSecurityReport(
            domain="testdomain.com",
            grade="B",
            security_score=75,
            primary_email_provider="Custom",
            spoofing_vulnerable=True,
            spf=SPFAudit(is_present=True, is_valid=True, all_qualifier="~all", qualifier_security="ACCEPTABLE"),
            dmarc=DMARCAudit(is_present=True, is_valid=True, policy="none", enforcement_level="MONITORING_ONLY"),
            actionable_remediations=["Upgrade DMARC policy to p=quarantine or p=reject"],
        )
        MockAuditor.return_value = mock_instance

        server = MCPServer()
        result = server.call_tool("subsweep_audit_email_security", {"domain": "testdomain.com"})

        assert result.get("domain") == "testdomain.com"
        assert result.get("grade") == "B"
        assert result.get("security_score") == 75


# ============================================================================
# CLI Command Test
# ============================================================================

def test_cli_email_command(capsys):
    with patch("subsweep_lead_scanner.cli.EmailSecurityAuditor") as MockAuditor:
        mock_instance = MagicMock()
        mock_instance.audit_domain.return_value = EmailSecurityReport(
            domain="clitest.com",
            grade="A",
            security_score=88,
            primary_email_provider="Google Workspace",
            spoofing_vulnerable=False,
            spf=SPFAudit(is_present=True, is_valid=True, all_qualifier="-all", qualifier_security="STRONG"),
            dmarc=DMARCAudit(is_present=True, is_valid=True, policy="reject", enforcement_level="STRICT_REJECT"),
            actionable_remediations=["All controls configured properly."],
        )
        MockAuditor.return_value = mock_instance

        rc = cli_main(["email", "clitest.com", "--format", "json"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["domain"] == "clitest.com"
        assert data["grade"] == "A"
