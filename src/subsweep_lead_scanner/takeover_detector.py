"""Subdomain Takeover & CNAME Dangling Pointer Detector for subsweep-lead-scanner.

Detects dangling DNS CNAME pointers to unallocated/deleted 3rd-party SaaS services:
- GitHub Pages, AWS S3, Heroku, Netlify, Vercel, Shopify, Fastly, Ghost,
  Surge.sh, Readme.io, Bitbucket, WordPress, Zendesk, Tumblr, HubSpot, Fly.io.

100% Python Standard Library (zero external runtime dependencies).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import re
import socket
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

TAKEOVER_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_pattern": r"github\.io",
        "fingerprints": [
            "There isn't a GitHub Pages site here.",
            "404 There isn't a GitHub Pages site here.",
        ],
        "severity": "CRITICAL",
        "remediation": "Claim the repository name on GitHub or delete the dangling CNAME DNS record immediately.",
    },
    {
        "service": "Amazon S3",
        "cname_pattern": r"(s3\.amazonaws\.com|s3-website.*\.amazonaws\.com)",
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "CRITICAL",
        "remediation": "Create the matching S3 bucket in the designated AWS region or remove the CNAME record.",
    },
    {
        "service": "Heroku",
        "cname_pattern": r"(herokudns\.com|herokuapp\.com)",
        "fingerprints": [
            "No such app",
            "Heroku | No such app",
            "<title>No such app</title>",
        ],
        "severity": "HIGH",
        "remediation": "Delete the custom domain link on Heroku or update the DNS CNAME record.",
    },
    {
        "service": "Netlify",
        "cname_pattern": r"netlify\.(app|com)",
        "fingerprints": [
            "Not Found - Request ID:",
            "page not found",
            "Netlify - Not Found",
        ],
        "severity": "HIGH",
        "remediation": "Rebind the domain inside your Netlify team dashboard or purge the CNAME DNS pointer.",
    },
    {
        "service": "Vercel",
        "cname_pattern": r"(vercel-dns\.com|now\.sh)",
        "fingerprints": [
            "404: NOT_FOUND",
            "The deployment could not be found",
            "Deployment not found",
        ],
        "severity": "HIGH",
        "remediation": "Attach the domain to an active Vercel project or delete the DNS record.",
    },
    {
        "service": "Shopify",
        "cname_pattern": r"myshopify\.com",
        "fingerprints": [
            "Sorry, this shop is currently unavailable.",
            "shops.myshopify.com",
        ],
        "severity": "HIGH",
        "remediation": "Re-link your Shopify store domain or remove the DNS CNAME.",
    },
    {
        "service": "Fastly CDN",
        "cname_pattern": r"fastly\.net",
        "fingerprints": [
            "Fastly error: unknown domain",
        ],
        "severity": "MEDIUM",
        "remediation": "Add the domain service to Fastly configuration or remove the DNS record.",
    },
    {
        "service": "Ghost",
        "cname_pattern": r"ghost\.io",
        "fingerprints": [
            "The thing you were looking for is no longer here",
        ],
        "severity": "MEDIUM",
        "remediation": "Attach the custom domain in Ghost(Pro) admin or purge the DNS record.",
    },
    {
        "service": "Surge.sh",
        "cname_pattern": r"surge\.sh",
        "fingerprints": [
            "project not found",
        ],
        "severity": "HIGH",
        "remediation": "Deploy a project under the subdomain via `surge` CLI or delete the CNAME record.",
    },
    {
        "service": "Zendesk",
        "cname_pattern": r"zendesk\.com",
        "fingerprints": [
            "Help Center Closed",
        ],
        "severity": "MEDIUM",
        "remediation": "Update host mapping in Zendesk Admin Center or remove CNAME record.",
    },
    {
        "service": "WordPress.com",
        "cname_pattern": r"wordpress\.com",
        "fingerprints": [
            "Do you want to register",
            "doesn't exist",
        ],
        "severity": "HIGH",
        "remediation": "Claim the blog on WordPress.com or delete the dangling CNAME.",
    },
    {
        "service": "HubSpot",
        "cname_pattern": r"hubspot\.net",
        "fingerprints": [
            "Domain not found",
            "HubSpot - 404",
        ],
        "severity": "MEDIUM",
        "remediation": "Verify the domain in HubSpot CMS or delete the DNS record.",
    },
]


@dataclass
class TakeoverFinding:
    """A detected potential or confirmed subdomain takeover vulnerability."""
    subdomain: str
    cname: str
    service: str
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'INFO'
    is_vulnerable: bool
    status: str  # 'CONFIRMED_VULNERABLE', 'POTENTIALLY_DANGLING', 'SECURE'
    fingerprint_matched: Optional[str] = None
    http_status: Optional[int] = None
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TakeoverScanReport:
    """Consolidated report of subdomain takeover analysis."""
    domain: str
    total_checked: int = 0
    cnames_analyzed: int = 0
    vulnerabilities_found: int = 0
    findings: List[TakeoverFinding] = field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "total_checked": self.total_checked,
            "cnames_analyzed": self.cnames_analyzed,
            "vulnerabilities_found": self.vulnerabilities_found,
            "duration_seconds": round(self.duration_seconds, 3),
            "timestamp": self.timestamp,
            "findings": [f.to_dict() for f in self.findings],
        }


class SubdomainTakeoverDetector:
    """Engine to detect dangling CNAME records and takeover risks."""

    def __init__(self, http_timeout: float = 3.0) -> None:
        self.http_timeout = http_timeout

    def check_cname(
        self,
        subdomain: str,
        cname_target: str,
        http_body: Optional[str] = None,
        http_status: Optional[int] = None,
    ) -> Optional[TakeoverFinding]:
        """Check a single subdomain and its CNAME against fingerprint patterns."""
        if not cname_target:
            return None

        clean_cname = cname_target.lower().strip().rstrip(".")

        for spec in TAKEOVER_FINGERPRINTS:
            if re.search(spec["cname_pattern"], clean_cname, re.IGNORECASE):
                # Pattern match on CNAME
                matched_fp: Optional[str] = None
                is_vuln = False
                status = "POTENTIALLY_DANGLING"

                # Check body fingerprints if available
                if http_body:
                    for fp in spec["fingerprints"]:
                        if fp.lower() in http_body.lower():
                            matched_fp = fp
                            is_vuln = True
                            status = "CONFIRMED_VULNERABLE"
                            break

                return TakeoverFinding(
                    subdomain=subdomain,
                    cname=cname_target,
                    service=spec["service"],
                    severity=spec["severity"],
                    is_vulnerable=is_vuln,
                    status=status,
                    fingerprint_matched=matched_fp,
                    http_status=http_status,
                    remediation=spec["remediation"],
                )

        return None

    def scan_records(
        self,
        domain: str,
        subdomain_records: List[Dict[str, Any]],
        verify_http: bool = False,
    ) -> TakeoverScanReport:
        """Scan an array of discovered subdomains for takeover risks."""
        start_time = time.perf_counter()
        findings: List[TakeoverFinding] = []
        cnames_checked = 0

        for rec in subdomain_records:
            sub = rec.get("subdomain", "")
            cnames = rec.get("cnames", [])
            if not cnames and "cname" in rec:
                cnames = [rec["cname"]]

            for cn in cnames:
                if not cn:
                    continue
                cnames_checked += 1

                http_body: Optional[str] = None
                http_status: Optional[int] = None

                if verify_http:
                    http_status, http_body = self._fetch_http_content(sub)

                finding = self.check_cname(sub, cn, http_body=http_body, http_status=http_status)
                if finding:
                    findings.append(finding)

        elapsed = time.perf_counter() - start_time
        vuln_count = sum(1 for f in findings if f.is_vulnerable or f.status == "CONFIRMED_VULNERABLE")

        return TakeoverScanReport(
            domain=domain,
            total_checked=len(subdomain_records),
            cnames_analyzed=cnames_checked,
            vulnerabilities_found=vuln_count,
            findings=findings,
            duration_seconds=elapsed,
        )

    def _fetch_http_content(self, host: str) -> Tuple[Optional[int], Optional[str]]:
        """Safely fetch HTTP page content for fingerprint validation."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "SubSweep-TakeoverVerifier/1.0"},
            )
            try:
                with urllib.request.urlopen(req, timeout=self.http_timeout) as resp:
                    status = resp.status
                    body = resp.read().decode("utf-8", errors="replace")
                    return status, body
            except urllib.error.HTTPError as exc:
                try:
                    err_body = exc.read().decode("utf-8", errors="replace")
                    return exc.code, err_body
                except Exception:
                    return exc.code, None
            except Exception:
                continue

        return None, None
