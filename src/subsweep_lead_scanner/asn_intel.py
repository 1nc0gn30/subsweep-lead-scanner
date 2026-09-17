"""Autonomous System (ASN) and BGP Prefix Intelligence Analyzer.

Resolves IP addresses and subdomains against an in-memory BGP CIDR prefix registry
to identify cloud infrastructure (AWS, Cloudflare, Google Cloud, Azure, Vercel, Netlify,
DigitalOcean, Fastly) and determine hosting topology.

100% Python Standard Library. Zero external dependencies.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass
class ASNIntelligenceReport:
    """Network attribution and infrastructure classification for an IP address."""

    ip_address: str
    asn: Optional[str]
    as_name: str
    cidr_block: Optional[str]
    is_cloud_or_cdn: bool
    provider_type: str  # 'cdn', 'cloud_compute', 'static_edge', 'dedicated_hosting', 'unknown'
    reverse_hostname: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Canonical BGP IPv4 CIDR blocks for common infrastructure providers
BGP_REGISTRY: List[Tuple[ipaddress.IPv4Network, str, str, str]] = [
    # (Network, ASN, Provider Name, Provider Type)
    # Cloudflare
    (ipaddress.IPv4Network("104.16.0.0/13"), "AS13335", "Cloudflare, Inc.", "cdn"),
    (ipaddress.IPv4Network("104.24.0.0/14"), "AS13335", "Cloudflare, Inc.", "cdn"),
    (ipaddress.IPv4Network("172.64.0.0/13"), "AS13335", "Cloudflare, Inc.", "cdn"),
    (ipaddress.IPv4Network("162.158.0.0/15"), "AS13335", "Cloudflare, Inc.", "cdn"),
    (ipaddress.IPv4Network("198.41.128.0/17"), "AS13335", "Cloudflare, Inc.", "cdn"),
    (ipaddress.IPv4Network("173.245.48.0/20"), "AS13335", "Cloudflare, Inc.", "cdn"),
    # Fastly
    (ipaddress.IPv4Network("151.101.0.0/16"), "AS54113", "Fastly", "cdn"),
    (ipaddress.IPv4Network("199.232.0.0/16"), "AS54113", "Fastly", "cdn"),
    # Vercel
    (ipaddress.IPv4Network("76.76.21.0/24"), "AS16509", "Vercel Inc. (via AWS)", "static_edge"),
    (ipaddress.IPv4Network("76.76.19.0/24"), "AS16509", "Vercel Inc. (via AWS)", "static_edge"),
    # GitHub Pages
    (ipaddress.IPv4Network("185.199.108.0/22"), "AS36459", "GitHub, Inc.", "static_edge"),
    # AWS (Representative ranges)
    (ipaddress.IPv4Network("52.0.0.0/11"), "AS16509", "Amazon.com, Inc.", "cloud_compute"),
    (ipaddress.IPv4Network("54.0.0.0/12"), "AS16509", "Amazon.com, Inc.", "cloud_compute"),
    (ipaddress.IPv4Network("13.32.0.0/15"), "AS16509", "Amazon CloudFront", "cdn"),
    (ipaddress.IPv4Network("18.0.0.0/15"), "AS16509", "Amazon.com, Inc.", "cloud_compute"),
    (ipaddress.IPv4Network("3.0.0.0/9"), "AS16509", "Amazon.com, Inc.", "cloud_compute"),
    # Google Cloud & Services
    (ipaddress.IPv4Network("34.64.0.0/11"), "AS15169", "Google Cloud", "cloud_compute"),
    (ipaddress.IPv4Network("34.96.0.0/11"), "AS15169", "Google Cloud", "cloud_compute"),
    (ipaddress.IPv4Network("35.184.0.0/13"), "AS15169", "Google Cloud", "cloud_compute"),
    (ipaddress.IPv4Network("104.196.0.0/14"), "AS15169", "Google Cloud", "cloud_compute"),
    # Microsoft Azure
    (ipaddress.IPv4Network("20.0.0.0/11"), "AS8075", "Microsoft Azure", "cloud_compute"),
    (ipaddress.IPv4Network("40.74.0.0/15"), "AS8075", "Microsoft Azure", "cloud_compute"),
    # DigitalOcean
    (ipaddress.IPv4Network("104.131.0.0/16"), "AS14061", "DigitalOcean, LLC", "cloud_compute"),
    (ipaddress.IPv4Network("159.203.0.0/16"), "AS14061", "DigitalOcean, LLC", "cloud_compute"),
    (ipaddress.IPv4Network("167.99.0.0/16"), "AS14061", "DigitalOcean, LLC", "cloud_compute"),
    (ipaddress.IPv4Network("138.68.0.0/16"), "AS14061", "DigitalOcean, LLC", "cloud_compute"),
]


def resolve_ip(target: str) -> Optional[str]:
    """Resolve domain or validate IP string into IPv4 address."""
    target = target.strip()
    try:
        ipaddress.IPv4Address(target)
        return target
    except ValueError:
        pass

    try:
        return socket.gethostbyname(target)
    except socket.error:
        return None


def lookup_ip_intelligence(
    ip_or_domain: str,
    resolve_reverse_dns: bool = False,
) -> ASNIntelligenceReport:
    """Lookup ASN, BGP prefix, and cloud hosting classification for an IP or hostname."""
    ip_str = resolve_ip(ip_or_domain)
    if not ip_str:
        return ASNIntelligenceReport(
            ip_address=ip_or_domain,
            asn=None,
            as_name="Unresolved Hostname",
            cidr_block=None,
            is_cloud_or_cdn=False,
            provider_type="unknown",
            reverse_hostname=None,
        )

    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return ASNIntelligenceReport(
            ip_address=ip_str,
            asn=None,
            as_name="Invalid IPv4",
            cidr_block=None,
            is_cloud_or_cdn=False,
            provider_type="unknown",
            reverse_hostname=None,
        )

    # Check against BGP registry
    matched_asn: Optional[str] = None
    matched_name = "Independent / Private Datacenter"
    matched_cidr: Optional[str] = None
    matched_type = "dedicated_hosting"
    is_cloud = False

    for network, asn, name, ptype in BGP_REGISTRY:
        if ip_obj in network:
            matched_asn = asn
            matched_name = name
            matched_cidr = str(network)
            matched_type = ptype
            is_cloud = True
            break

    # Reverse DNS
    reverse_host: Optional[str] = None
    if resolve_reverse_dns:
        try:
            reverse_host, _, _ = socket.gethostbyaddr(ip_str)
        except (socket.error, socket.herror):
            pass

    return ASNIntelligenceReport(
        ip_address=ip_str,
        asn=matched_asn,
        as_name=matched_name,
        cidr_block=matched_cidr,
        is_cloud_or_cdn=is_cloud,
        provider_type=matched_type,
        reverse_hostname=reverse_host,
    )


def batch_classify_ips(ips_or_domains: Sequence[str]) -> Dict[str, Any]:
    """Analyze a batch of hosts and summarize infrastructure distribution."""
    results: List[ASNIntelligenceReport] = []
    provider_counts: Dict[str, int] = {}
    type_counts: Dict[str, int] = {}

    for target in ips_or_domains:
        report = lookup_ip_intelligence(target)
        results.append(report)
        provider_counts[report.as_name] = provider_counts.get(report.as_name, 0) + 1
        type_counts[report.provider_type] = type_counts.get(report.provider_type, 0) + 1

    return {
        "total_targets": len(ips_or_domains),
        "cloud_cdn_percentage": round(
            sum(1 for r in results if r.is_cloud_or_cdn) / len(ips_or_domains) * 100.0, 1
        )
        if ips_or_domains
        else 0.0,
        "provider_distribution": provider_counts,
        "type_distribution": type_counts,
        "reports": [r.to_dict() for r in results],
    }
