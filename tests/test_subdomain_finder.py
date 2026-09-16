"""Unit tests for subsweep_lead_scanner.subdomain_finder module."""

import io
import json
import socket
from unittest.mock import MagicMock, patch
import urllib.error

import pytest
from subsweep_lead_scanner.subdomain_finder import (
    DEFAULT_SUBDOMAIN_WORDLIST,
    EnumerationSummary,
    SubdomainEnumerator,
    SubdomainResult,
)


class TestDomainSanitization:
    """Test domain cleaning and normalization."""

    def test_clean_domain_variations(self):
        """Clean various messy domain inputs."""
        finder = SubdomainEnumerator()
        assert finder.clean_domain("https://example.com/test") == "example.com"
        assert finder.clean_domain("http://api.example.com:8080/v1") == "api.example.com"
        assert finder.clean_domain(" .example.com. ") == "example.com"
        assert finder.clean_domain("sub.example.co.uk") == "sub.example.co.uk"


class TestWordlistPermutations:
    """Test subdomain permutation generator."""

    def test_default_permutations(self):
        """Generate permutations using default wordlist."""
        finder = SubdomainEnumerator()
        subs = finder.generate_permutations("example.com")
        assert "example.com" in subs
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "mail.example.com" in subs
        assert len(subs) == len(DEFAULT_SUBDOMAIN_WORDLIST) + 1

    def test_custom_wordlist(self):
        """Generate permutations with custom wordlist."""
        finder = SubdomainEnumerator()
        custom = ["portal", "staging", "v2"]
        subs = finder.generate_permutations("test.org", wordlist=custom)
        assert subs == ["test.org", "portal.test.org", "staging.test.org", "v2.test.org"]


class TestCertificateTransparencyQuery:
    """Test crt.sh query parser and error handling."""

    @patch("urllib.request.urlopen")
    def test_query_crtsh_success(self, mock_urlopen):
        """Parse valid crt.sh JSON response."""
        sample_response = [
            {"name_value": "api.example.com\n*.admin.example.com", "common_name": "example.com"},
            {"name_value": "docs.example.com", "common_name": "docs.example.com"},
            {"name_value": "malformed.otherdomain.com", "common_name": "otherdomain.com"},
        ]
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(sample_response).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        finder = SubdomainEnumerator()
        subs = finder.query_crtsh("example.com")

        assert "api.example.com" in subs
        assert "admin.example.com" in subs
        assert "docs.example.com" in subs
        assert "example.com" in subs
        assert "malformed.otherdomain.com" not in subs

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network down"))
    def test_query_crtsh_error_handling(self, mock_urlopen):
        """Handle network errors gracefully by returning empty list."""
        finder = SubdomainEnumerator()
        subs = finder.query_crtsh("example.com")
        assert subs == []


class TestDnsResolutionAndWildcards:
    """Test DNS resolution, wildcard detection, and latency calculation."""

    def test_wildcard_detection(self):
        """Detect when DNS server returns wildcard IP for random subdomains."""
        finder = SubdomainEnumerator()
        # Mock _raw_resolve_ips to return wildcard IP for wildcard test
        with patch.object(finder, "_raw_resolve_ips", return_value=["93.184.216.34"]):
            wildcards = finder.check_wildcard("example.com")
            assert wildcards == {"93.184.216.34"}

    def test_resolve_subdomain_normal(self):
        """Resolve valid non-wildcard subdomain."""
        finder = SubdomainEnumerator()
        with patch.object(finder, "_raw_resolve_ips", return_value=["192.0.2.1", "2001:db8::1"]):
            res = finder.resolve_subdomain("api.example.com", "example.com")
            assert res.status == "resolved"
            assert res.subdomain == "api.example.com"
            assert "192.0.2.1" in res.ipv4
            assert "2001:db8::1" in res.ipv6
            assert res.latency_ms > 0
            assert res.is_wildcard is False

    def test_resolve_subdomain_wildcard_filtered(self):
        """Mark subdomain as wildcard_filtered when IP matches wildcard set."""
        finder = SubdomainEnumerator()
        with patch.object(finder, "_raw_resolve_ips", return_value=["192.0.2.100"]):
            res = finder.resolve_subdomain(
                "ghost.example.com",
                "example.com",
                wildcard_ips={"192.0.2.100"},
            )
            assert res.status == "wildcard_filtered"
            assert res.is_wildcard is True

    def test_resolve_subdomain_unresolved(self):
        """Handle non-resolving domain."""
        finder = SubdomainEnumerator()
        with patch.object(finder, "_raw_resolve_ips", return_value=[]):
            res = finder.resolve_subdomain("nonexistent.example.com", "example.com")
            assert res.status == "unresolved"
            assert res.ips == []


class TestFullEnumerationPipeline:
    """Test end-to-end enumeration workflow and discovery tree."""

    def test_full_enumeration_run(self):
        """Execute full enumeration with mocked DNS."""
        finder = SubdomainEnumerator()

        def mock_resolver(sub):
            if sub == "example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]
            if sub == "api.example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.35", 0))]
            if sub == "www.example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]
            return []

        finder._custom_resolver = mock_resolver

        with patch.object(finder, "query_crtsh", return_value=["api.example.com"]):
            summary = finder.enumerate(
                domain="example.com",
                use_crtsh=True,
                use_wordlist=True,
                wordlist=["www", "api", "dev"],
                max_workers=4,
            )

            assert isinstance(summary, EnumerationSummary)
            assert summary.domain == "example.com"
            assert summary.resolved_count >= 2
            assert "93.184.216.34" in summary.unique_ips
            assert "93.184.216.35" in summary.unique_ips

            # Check tree structure
            tree = summary.tree()
            assert tree["domain"] == "example.com"
            assert len(tree["subdomains"]) >= 2
            assert "93.184.216.34" in tree["ip_mapping"]
            assert tree["stats"]["resolved"] == summary.resolved_count

            # Check serialization
            summary_dict = summary.to_dict()
            assert summary_dict["domain"] == "example.com"
            assert len(summary_dict["results"]) > 0
