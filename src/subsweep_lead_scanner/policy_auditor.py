"""Robots.txt & Security.txt Policy Auditor, Contact Harvesting & Crawler Matrix Engine.

Deeply analyzes security and administrative endpoints for business and infrastructure intelligence:
1. `robots.txt` Parser:
   - Sitemaps extraction
   - Disallowed paths & sensitive endpoint discovery (/admin, /api, /wp-admin, /internal, /backend, /backup, /dev)
   - Crawl-delay rules per user-agent
   - Cleanliness and policy hygiene score (0-100)

2. RFC 9116 `security.txt` Auditor:
   - Evaluates standard location (`/.well-known/security.txt` and `/security.txt`)
   - Directives parsed: Contact, Expires, Encryption, Preferred-Languages, Canonical, Policy, Hiring, Acknowledgments
   - Security team contacts & bug bounty endpoints extraction
   - RFC 9116 compliance scoring and expiration check (UTC ISO format)

100% Python Standard Library. Zero external dependencies.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request


@dataclass
class RobotsDirective:
    """A user-agent block in robots.txt."""

    user_agent: str
    allow: List[str] = field(default_factory=list)
    disallow: List[str] = field(default_factory=list)
    crawl_delay: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RobotsReport:
    """Comprehensive robots.txt analysis report."""

    target: str
    exists: bool
    sitemaps: List[str] = field(default_factory=list)
    directives: List[RobotsDirective] = field(default_factory=list)
    sensitive_disallowed_paths: List[str] = field(default_factory=list)
    crawl_delay_found: bool = False
    hygiene_score: int = 100
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "exists": self.exists,
            "sitemaps": self.sitemaps,
            "directives": [d.to_dict() for d in self.directives],
            "sensitive_disallowed_paths": self.sensitive_disallowed_paths,
            "crawl_delay_found": self.crawl_delay_found,
            "hygiene_score": self.hygiene_score,
            "findings": self.findings,
        }


@dataclass
class SecurityTxtReport:
    """RFC 9116 security.txt audit and contact intelligence report."""

    target: str
    exists: bool
    url_found: Optional[str] = None
    contacts: List[str] = field(default_factory=list)
    expires: Optional[str] = None
    is_expired: bool = False
    encryption_keys: List[str] = field(default_factory=list)
    policy_urls: List[str] = field(default_factory=list)
    hiring_urls: List[str] = field(default_factory=list)
    acknowledgments_urls: List[str] = field(default_factory=list)
    canonical_urls: List[str] = field(default_factory=list)
    preferred_languages: List[str] = field(default_factory=list)
    rfc9116_compliant: bool = False
    compliance_score: int = 0  # 0 to 100
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


SENSITIVE_PATH_PATTERNS = [
    r"/admin\b",
    r"/wp-admin\b",
    r"/api\b",
    r"/backend\b",
    r"/internal\b",
    r"/staging\b",
    r"/backup\b",
    r"/private\b",
    r"/dev\b",
    r"/test\b",
    r"/secret\b",
    r"/config\b",
    r"/database\b",
    r"/v1\b",
]


class RobotsAuditor:
    """Parses and audits robots.txt content."""

    @staticmethod
    def parse_robots_txt(content: str, target: str = "") -> RobotsReport:
        """Parse raw robots.txt text."""
        lines = content.splitlines()
        sitemaps: List[str] = []
        directives_map: Dict[str, RobotsDirective] = {}
        current_agents: List[str] = []
        sensitive_paths: List[str] = []
        findings: List[str] = []

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            key, _, val = line.partition(":")
            field_name = key.strip().lower()
            field_val = val.strip()

            if field_name == "sitemap":
                if field_val and field_val not in sitemaps:
                    sitemaps.append(field_val)

            elif field_name == "user-agent":
                agent = field_val
                current_agents = [agent]
                if agent not in directives_map:
                    directives_map[agent] = RobotsDirective(user_agent=agent)

            elif field_name == "disallow":
                for agent in current_agents:
                    if agent in directives_map and field_val:
                        directives_map[agent].disallow.append(field_val)
                # Check for sensitive path revelation
                for pat in SENSITIVE_PATH_PATTERNS:
                    if re.search(pat, field_val, re.IGNORECASE):
                        if field_val not in sensitive_paths:
                            sensitive_paths.append(field_val)

            elif field_name == "allow":
                for agent in current_agents:
                    if agent in directives_map and field_val:
                        directives_map[agent].allow.append(field_val)

            elif field_name == "crawl-delay":
                try:
                    delay_num = float(field_val)
                    for agent in current_agents:
                        if agent in directives_map:
                            directives_map[agent].crawl_delay = delay_num
                except ValueError:
                    pass

        has_crawl_delay = any(d.crawl_delay is not None for d in directives_map.values())
        hygiene = 100

        if sensitive_paths:
            hygiene -= min(40, len(sensitive_paths) * 10)
            findings.append(f"Disallowed rules expose {len(sensitive_paths)} internal/admin paths to crawlers.")

        if not sitemaps:
            hygiene -= 15
            findings.append("No Sitemap directive declared in robots.txt.")

        directives_list = list(directives_map.values())
        if not directives_list:
            findings.append("No User-agent blocks identified.")

        return RobotsReport(
            target=target,
            exists=bool(content.strip()),
            sitemaps=sitemaps,
            directives=directives_list,
            sensitive_disallowed_paths=sensitive_paths,
            crawl_delay_found=has_crawl_delay,
            hygiene_score=max(0, hygiene),
            findings=findings,
        )


class SecurityTxtAuditor:
    """Parses and audits RFC 9116 security.txt."""

    @staticmethod
    def parse_security_txt(content: str, target: str = "") -> SecurityTxtReport:
        """Parse RFC 9116 security.txt format."""
        lines = content.splitlines()
        contacts: List[str] = []
        expires: Optional[str] = None
        encryption: List[str] = []
        policy: List[str] = []
        hiring: List[str] = []
        acknowledgments: List[str] = []
        canonical: List[str] = []
        preferred_langs: List[str] = []
        recommendations: List[str] = []

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue

            k, _, v = line.partition(":")
            key = k.strip().lower()
            val = v.strip()

            if key == "contact":
                if val and val not in contacts:
                    contacts.append(val)
            elif key == "expires":
                expires = val
            elif key == "encryption":
                encryption.append(val)
            elif key == "policy":
                policy.append(val)
            elif key == "hiring":
                hiring.append(val)
            elif key == "acknowledgments":
                acknowledgments.append(val)
            elif key == "canonical":
                canonical.append(val)
            elif key == "preferred-languages":
                langs = [l.strip() for l in val.split(",") if l.strip()]
                preferred_langs.extend(langs)

        # RFC 9116 Validation:
        # Mandatory fields: Contact, Expires
        score = 0
        is_expired = False

        if contacts:
            score += 40
        else:
            recommendations.append("Missing mandatory 'Contact' directive with security email or URL.")

        if expires:
            score += 30
            # Parse ISO 8601 / RFC 3339 date
            try:
                # Normalization for trailing Z or offsets
                exp_clean = expires.replace("Z", "+00:00")
                exp_dt = datetime.fromisoformat(exp_clean)
                now_utc = datetime.now(timezone.utc)
                if exp_dt < now_utc:
                    is_expired = True
                    score -= 20
                    recommendations.append(f"Security.txt has expired on {expires}.")
            except Exception:
                recommendations.append(f"Invalid 'Expires' date format: '{expires}'. Use RFC 3339 / ISO 8601.")
        else:
            recommendations.append("Missing mandatory 'Expires' directive in security.txt.")

        if encryption:
            score += 10
        if policy:
            score += 10
        if canonical:
            score += 10

        compliant = (bool(contacts) and bool(expires) and not is_expired)

        return SecurityTxtReport(
            target=target,
            exists=bool(content.strip()),
            url_found=target,
            contacts=contacts,
            expires=expires,
            is_expired=is_expired,
            encryption_keys=encryption,
            policy_urls=policy,
            hiring_urls=hiring,
            acknowledgments_urls=acknowledgments,
            canonical_urls=canonical,
            preferred_languages=preferred_langs,
            rfc9116_compliant=compliant,
            compliance_score=max(0, min(100, score)),
            recommendations=recommendations,
        )


def audit_policy_endpoints(
    domain_or_url: str,
    timeout: float = 4.0,
    robots_content: Optional[str] = None,
    security_txt_content: Optional[str] = None,
) -> Dict[str, Any]:
    """Audit both robots.txt and security.txt endpoints for a target."""
    raw = domain_or_url.strip()
    if "://" not in raw:
        base_url = f"https://{raw.rstrip('/')}"
    else:
        parsed = urllib.parse.urlparse(raw)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

    # 1. robots.txt
    if robots_content is None:
        robots_url = f"{base_url}/robots.txt"
        try:
            req = urllib.request.Request(robots_url, headers={"User-Agent": "SubSweep-Audit/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                robots_content = resp.read().decode("utf-8", errors="replace")
        except Exception:
            robots_content = ""

    robots_report = RobotsAuditor.parse_robots_txt(robots_content, target=base_url)

    # 2. security.txt
    if security_txt_content is None:
        sec_url_1 = f"{base_url}/.well-known/security.txt"
        sec_url_2 = f"{base_url}/security.txt"
        sec_found_url = None

        for s_url in [sec_url_1, sec_url_2]:
            try:
                req = urllib.request.Request(s_url, headers={"User-Agent": "SubSweep-Audit/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        body = resp.read().decode("utf-8", errors="replace")
                        if "Contact:" in body or "Expires:" in body:
                            security_txt_content = body
                            sec_found_url = s_url
                            break
            except Exception:
                continue

        if security_txt_content is None:
            security_txt_content = ""
    else:
        sec_found_url = base_url

    sec_report = SecurityTxtAuditor.parse_security_txt(security_txt_content, target=sec_found_url or base_url)

    return {
        "target": base_url,
        "robots": robots_report.to_dict(),
        "security_txt": sec_report.to_dict(),
        "combined_contacts": sec_report.contacts,
        "disallowed_endpoints_count": len(robots_report.sensitive_disallowed_paths),
    }
