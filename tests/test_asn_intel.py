"""Tests for ASN intelligence and BGP prefix analyzer."""

from subsweep_lead_scanner.asn_intel import (
    ASNIntelligenceReport,
    batch_classify_ips,
    lookup_ip_intelligence,
)


def test_lookup_cloudflare_ip():
    # Cloudflare IP in 104.16.0.0/13
    ip = "104.18.25.10"
    report = lookup_ip_intelligence(ip)
    assert isinstance(report, ASNIntelligenceReport)
    assert report.is_cloud_or_cdn
    assert report.asn == "AS13335"
    assert "Cloudflare" in report.as_name
    assert report.provider_type == "cdn"
    assert report.cidr_block == "104.16.0.0/13"


def test_lookup_aws_ip():
    # AWS IP in 52.0.0.0/11
    ip = "52.12.34.56"
    report = lookup_ip_intelligence(ip)
    assert report.is_cloud_or_cdn
    assert report.asn == "AS16509"
    assert "Amazon" in report.as_name
    assert report.provider_type == "cloud_compute"


def test_lookup_unresolved_host():
    report = lookup_ip_intelligence("this-domain-does-not-exist-at-all-12345.xyz")
    assert not report.is_cloud_or_cdn
    assert report.asn is None
    assert report.provider_type == "unknown"


def test_batch_classify_ips():
    ips = [
        "104.16.1.1",     # Cloudflare
        "52.1.2.3",       # AWS
        "76.76.21.21",    # Vercel
        "192.168.1.1",    # Private
    ]
    summary = batch_classify_ips(ips)
    assert summary["total_targets"] == 4
    assert summary["cloud_cdn_percentage"] == 75.0
    assert "Cloudflare, Inc." in summary["provider_distribution"]
    assert "cdn" in summary["type_distribution"]
    assert len(summary["reports"]) == 4
