"""Email Deliverability & Mail Exchange (MX) Security Auditor for subsweep-lead-scanner.

Audits:
- SPF (Sender Policy Framework, RFC 7208) mechanism parsing, DNS lookup ceiling (10 max), qualifier strength.
- DMARC (Domain-based Message Authentication, Reporting, and Conformance, RFC 7489) enforcement policy & reporting.
- DKIM (DomainKeys Identified Mail, RFC 6376) common selector discovery & public key validation.
- MX Exchange provider identification (Google Workspace, Microsoft 365, Proton, Fastmail, Postmark, etc.).
- Deliverability & anti-spoofing security score (0-100) with grade and copy-paste DNS TXT recommendations.

100% Python Standard Library (zero external runtime dependencies).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

COMMON_DKIM_SELECTORS = [
    "default",
    "google",
    "k1",
    "s1",
    "mail",
    "selector1",
    "mandrill",
    "sendgrid",
    "20230601",
    "20240101",
    "cm",
    "mx",
]

MAIL_PROVIDER_FINGERPRINTS = [
    ("Google Workspace", [r"aspmx\.l\.google\.com", r"googlemail\.com", r"\.google\.com"]),
    ("Microsoft 365 / Exchange", [r"outlook\.com", r"microsoft\.com", r"protection\.outlook\.com"]),
    ("ProtonMail", [r"protonmail\.ch", r"mailroute\.proton\.me"]),
    ("Fastmail", [r"messagingengine\.com", r"fastmail\.com"]),
    ("Zoho Mail", [r"zoho\.(com|eu|in)"]),
    ("Postmark", [r"postmarkapp\.com", r"inbound\.postmarkapp\.com"]),
    ("SendGrid", [r"sendgrid\.net"]),
    ("Amazon SES", [r"email-smtp\..*\.amazonaws\.com", r"inbound-smtp\..*\.amazonaws\.com"]),
    ("Mailgun", [r"mailgun\.org"]),
    ("Mimecast", [r"mimecast\.(com|net)"]),
    ("Proofpoint", [r"pphosted\.com", r"proofpoint\.com"]),
]


@dataclass
class MXRecord:
    """Mail exchange server entry."""
    host: str
    priority: int
    provider: str = "Unknown / Custom"
    ips: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SPFAudit:
    """Evaluation of Sender Policy Framework (RFC 7208)."""
    raw_record: Optional[str] = None
    is_present: bool = False
    is_valid: bool = False
    all_qualifier: str = "missing"  # '-all', '~all', '?all', '+all', 'missing'
    qualifier_security: str = "INSECURE"  # 'STRONG', 'ACCEPTABLE', 'WEAK', 'CRITICAL_VULNERABLE'
    mechanisms: List[str] = field(default_factory=list)
    lookup_count: int = 0
    lookup_limit_exceeded: bool = False
    has_deprecated_ptr: bool = False
    multiple_records_detected: bool = False
    warnings: List[str] = field(default_factory=list)
    recommended_record: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DMARCAudit:
    """Evaluation of DMARC authentication policy (RFC 7489)."""
    raw_record: Optional[str] = None
    is_present: bool = False
    is_valid: bool = False
    policy: str = "missing"  # 'none', 'quarantine', 'reject', 'missing'
    subdomain_policy: Optional[str] = None
    percentage: int = 100
    rua_addresses: List[str] = field(default_factory=list)
    ruf_addresses: List[str] = field(default_factory=list)
    adkim_mode: str = "r"  # 'r' (relaxed) or 's' (strict)
    aspf_mode: str = "r"
    enforcement_level: str = "NONE"  # 'STRICT_REJECT', 'MODERATE_QUARANTINE', 'MONITORING_ONLY', 'VULNERABLE'
    warnings: List[str] = field(default_factory=list)
    recommended_record: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DKIMAudit:
    """Evaluation of DKIM selector presence."""
    discovered_selectors: List[str] = field(default_factory=list)
    selector_records: Dict[str, str] = field(default_factory=dict)
    key_types: Dict[str, str] = field(default_factory=dict)
    has_valid_dkim: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EmailSecurityReport:
    """Consolidated email security and deliverability audit report."""
    domain: str
    security_score: int  # 0 - 100
    grade: str  # 'A+', 'A', 'B', 'C', 'D', 'F'
    mx_records: List[MXRecord] = field(default_factory=list)
    spf: SPFAudit = field(default_factory=SPFAudit)
    dmarc: DMARCAudit = field(default_factory=DMARCAudit)
    dkim: DKIMAudit = field(default_factory=DKIMAudit)
    primary_email_provider: str = "None / Unknown"
    spoofing_vulnerable: bool = False
    key_findings: List[str] = field(default_factory=list)
    actionable_remediations: List[str] = field(default_factory=list)
    audited_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "security_score": self.security_score,
            "grade": self.grade,
            "primary_email_provider": self.primary_email_provider,
            "spoofing_vulnerable": self.spoofing_vulnerable,
            "mx_records": [r.to_dict() for r in self.mx_records],
            "spf": self.spf.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "dkim": self.dkim.to_dict(),
            "key_findings": self.key_findings,
            "actionable_remediations": self.actionable_remediations,
            "audited_at": self.audited_at,
        }


class EmailSecurityAuditor:
    """DNS-based email security posture and deliverability auditor."""

    def __init__(
        self,
        custom_dns_resolver: Optional[Callable[[str, str], List[str]]] = None,
        resolver: Optional[Callable[[str, str], List[str]]] = None,
        doh_timeout: float = 3.0,
        timeout: Optional[float] = None,
    ) -> None:
        self._custom_dns_resolver = custom_dns_resolver or resolver
        self._doh_timeout = timeout if timeout is not None else doh_timeout

    def parse_spf(self, raw_record: str) -> SPFAudit:
        """Parse and audit a single SPF record string."""
        return self.audit_spf("dummy.com", preloaded_txt=[raw_record])

    def parse_dmarc(self, raw_record: str) -> DMARCAudit:
        """Parse and audit a single DMARC record string."""
        return self.audit_dmarc("dummy.com", preloaded_txt=[raw_record])

    def parse_dkim(self, selector: str, raw_record: str) -> DKIMAudit:
        """Parse and audit a single DKIM record string."""
        audit = DKIMAudit()
        if "v=DKIM1" in raw_record or "p=" in raw_record:
            audit.discovered_selectors.append(selector)
            audit.selector_records[selector] = raw_record
            audit.has_valid_dkim = True
            k_match = re.search(r"k=([a-zA-Z0-9]+)", raw_record)
            audit.key_types[selector] = k_match.group(1) if k_match else "rsa"
        return audit

    def parse_mx_records(self, mx_entries: List[str]) -> Tuple[List[MXRecord], List[str]]:
        """Parse a list of raw MX entry strings into MXRecord models and distinct providers."""
        records: List[MXRecord] = []
        providers: List[str] = []
        for item in mx_entries:
            parts = item.split()
            if len(parts) >= 2:
                try:
                    prio = int(parts[0])
                    host = parts[1].rstrip(".")
                except ValueError:
                    prio = 10
                    host = parts[0].rstrip(".")
            else:
                prio = 10
                host = item.rstrip(".")

            provider = "Unknown / Custom"
            for prov_name, regexes in MAIL_PROVIDER_FINGERPRINTS:
                if any(re.search(pattern, host, re.IGNORECASE) for pattern in regexes):
                    provider = prov_name
                    break

            records.append(MXRecord(host=host, priority=prio, provider=provider))
            if provider not in providers and provider != "Unknown / Custom":
                providers.append(provider)

        records.sort(key=lambda x: x.priority)
        return records, providers

    def _query_dns(self, name: str, record_type: str) -> List[str]:
        """Query DNS via custom resolver or Cloudflare DNS-over-HTTPS (DoH)."""
        if self._custom_dns_resolver:
            try:
                try:
                    return self._custom_dns_resolver(name, record_type)
                except Exception:
                    return self._custom_dns_resolver(record_type, name)
            except Exception as exc:
                logger.debug("Custom resolver error for %s %s: %s", name, record_type, exc)
                return []

        # Cloudflare DoH query (pure Python stdlib urllib)
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={record_type}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "SubSweep-EmailAuditor/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=self._doh_timeout) as resp:
                if resp.status != 200:
                    return []
                body = json.loads(resp.read().decode("utf-8"))
                answers = body.get("Answer", [])
                results: List[str] = []
                for ans in answers:
                    data = ans.get("data", "")
                    if data:
                        # Clean quotes around TXT records
                        clean_data = data.strip('"').replace('" "', '')
                        results.append(clean_data)
                return results
        except Exception as exc:
            logger.debug("DoH query failed for %s %s: %s", name, record_type, exc)
            return []

    def audit_spf(self, domain: str, preloaded_txt: Optional[List[str]] = None) -> SPFAudit:
        """Audit SPF record for RFC 7208 compliance and security strength."""
        txt_records = preloaded_txt if preloaded_txt is not None else self._query_dns(domain, "TXT")
        spf_records = [r for r in txt_records if r.startswith("v=spf1") or "v=spf1" in r]

        audit = SPFAudit(
            recommended_record=f"v=spf1 mx ~all"
        )

        if not spf_records:
            audit.warnings.append("No SPF (v=spf1) record found. Domain is vulnerable to unauthorized email spoofing.")
            return audit

        audit.is_present = True
        if len(spf_records) > 1:
            audit.multiple_records_detected = True
            audit.warnings.append("Multiple SPF records found. RFC 7208 dictates this results in a PermError.")

        raw_spf = spf_records[0].strip()
        audit.raw_record = raw_spf
        tokens = raw_spf.split()

        if tokens[0] != "v=spf1":
            audit.warnings.append("SPF record does not strictly start with 'v=spf1'.")

        lookups = 0
        mechanisms: List[str] = []
        qualifier = "missing"

        for token in tokens[1:]:
            token_lower = token.lower()
            mechanisms.append(token)

            # Check lookup count mechanisms
            if any(token_lower.startswith(p) for p in ("include:", "a:", "mx:", "ptr:", "exists:", "redirect=")):
                lookups += 1
            elif token_lower in ("a", "mx", "ptr"):
                lookups += 1

            if "ptr" in token_lower:
                audit.has_deprecated_ptr = True
                audit.warnings.append("Deprecated 'ptr' mechanism detected. RFC 7208 discourages PTR lookups.")

            # Check all terminator
            if token_lower.endswith("all"):
                qualifier = token_lower

        audit.mechanisms = mechanisms
        audit.lookup_count = lookups
        audit.all_qualifier = qualifier
        audit.lookup_limit_exceeded = (lookups > 10)

        if audit.lookup_limit_exceeded:
            audit.warnings.append(f"SPF DNS lookup limit exceeded: {lookups}/10 maximum. Causes SPF PermError.")

        if qualifier in ("-all",):
            audit.qualifier_security = "STRONG"
            audit.is_valid = not audit.lookup_limit_exceeded and not audit.multiple_records_detected
        elif qualifier in ("~all",):
            audit.qualifier_security = "ACCEPTABLE"
            audit.is_valid = not audit.lookup_limit_exceeded and not audit.multiple_records_detected
        elif qualifier in ("?all",):
            audit.qualifier_security = "WEAK"
            audit.warnings.append("SPF uses '?all' (Neutral), which offers zero enforcement against spoofing.")
        elif qualifier in ("+all",):
            audit.qualifier_security = "CRITICAL_VULNERABLE"
            audit.warnings.append("SPF uses '+all' (Pass), explicitly permitting ANY server on the internet to send mail.")
        else:
            audit.qualifier_security = "WEAK"
            audit.warnings.append("SPF is missing a terminal 'all' qualifier mechanism.")

        return audit

    def audit_dmarc(self, domain: str, preloaded_txt: Optional[List[str]] = None) -> DMARCAudit:
        """Audit DMARC policy at _dmarc.<domain> for RFC 7489 enforcement."""
        dmarc_name = f"_dmarc.{domain}"
        txt_records = preloaded_txt if preloaded_txt is not None else self._query_dns(dmarc_name, "TXT")
        dmarc_records = [r for r in txt_records if "v=DMARC1" in r]

        audit = DMARCAudit(
            recommended_record=f"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@{domain}; sp=reject; aspf=r; adkim=r;"
        )

        if not dmarc_records:
            audit.warnings.append("No DMARC record found at _dmarc." + domain + ". Domain lacks spoofing protection.")
            audit.enforcement_level = "VULNERABLE"
            return audit

        audit.is_present = True
        raw = dmarc_records[0].strip()
        audit.raw_record = raw

        # Parse semicolon separated tag-value pairs
        tags: Dict[str, str] = {}
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        if tags.get("v") != "DMARC1":
            audit.warnings.append("DMARC record does not start with valid 'v=DMARC1'.")
            audit.enforcement_level = "VULNERABLE"
            return audit

        audit.is_valid = True
        p_val = tags.get("p", "").lower()
        audit.policy = p_val if p_val else "missing"

        if "sp" in tags:
            audit.subdomain_policy = tags["sp"].lower()

        if "pct" in tags:
            try:
                audit.percentage = int(tags["pct"])
            except ValueError:
                audit.percentage = 100

        if "rua" in tags:
            audit.rua_addresses = [a.strip() for a in tags["rua"].split(",") if a.strip()]

        if "ruf" in tags:
            audit.ruf_addresses = [a.strip() for a in tags["ruf"].split(",") if a.strip()]

        audit.adkim_mode = tags.get("adkim", "r").lower()
        audit.aspf_mode = tags.get("aspf", "r").lower()

        if p_val == "reject":
            audit.enforcement_level = "STRICT_REJECT"
        elif p_val == "quarantine":
            audit.enforcement_level = "MODERATE_QUARANTINE"
        elif p_val == "none":
            audit.enforcement_level = "MONITORING_ONLY"
            audit.warnings.append("DMARC policy is set to 'p=none' (monitoring only). Spoofed emails will still be delivered.")
        else:
            audit.enforcement_level = "VULNERABLE"
            audit.warnings.append("Missing or unrecognized DMARC policy tag 'p='.")

        if not audit.rua_addresses:
            audit.warnings.append("DMARC has no aggregate reporting address (rua=). Mail flow feedback is disabled.")

        return audit

    def audit_dkim(self, domain: str, selectors: Optional[List[str]] = None) -> DKIMAudit:
        """Probe common DKIM selectors for public key records."""
        audit = DKIMAudit()
        probe_selectors = selectors or COMMON_DKIM_SELECTORS

        for sel in probe_selectors:
            target_name = f"{sel}._domainkey.{domain}"
            records = self._query_dns(target_name, "TXT")
            for r in records:
                if "v=DKIM1" in r or "p=" in r:
                    audit.discovered_selectors.append(sel)
                    audit.selector_records[sel] = r
                    audit.has_valid_dkim = True
                    # Check key type (k=rsa or k=ed25519)
                    k_match = re.search(r"k=([a-zA-Z0-9]+)", r)
                    audit.key_types[sel] = k_match.group(1) if k_match else "rsa"
                    break

        return audit

    def audit_mx(self, domain: str) -> List[MXRecord]:
        """Query and evaluate MX records."""
        mx_strings = self._query_dns(domain, "MX")
        records: List[MXRecord] = []

        for item in mx_strings:
            parts = item.split()
            if len(parts) >= 2:
                try:
                    prio = int(parts[0])
                    host = parts[1].rstrip(".")
                except ValueError:
                    prio = 10
                    host = parts[0].rstrip(".")
            else:
                prio = 10
                host = item.rstrip(".")

            # Identify provider
            provider = "Unknown / Custom"
            for prov_name, regexes in MAIL_PROVIDER_FINGERPRINTS:
                if any(re.search(pattern, host, re.IGNORECASE) for pattern in regexes):
                    provider = prov_name
                    break

            records.append(MXRecord(host=host, priority=prio, provider=provider))

        # Sort by priority ascending
        records.sort(key=lambda x: x.priority)
        return records

    def audit_domain(self, domain: str) -> EmailSecurityReport:
        """Run full comprehensive email security & deliverability audit."""
        clean_d = re.sub(r"^https?://", "", domain.lower().strip()).split("/")[0]

        mx_records = self.audit_mx(clean_d)
        spf_audit = self.audit_spf(clean_d)
        dmarc_audit = self.audit_dmarc(clean_d)
        dkim_audit = self.audit_dkim(clean_d)

        # Primary provider
        primary_provider = mx_records[0].provider if mx_records else "None / Unknown"

        # Calculate composite score (0-100)
        score = 0

        # DMARC points (max 35)
        if dmarc_audit.enforcement_level == "STRICT_REJECT":
            score += 35
        elif dmarc_audit.enforcement_level == "MODERATE_QUARANTINE":
            score += 25
        elif dmarc_audit.enforcement_level == "MONITORING_ONLY":
            score += 12

        # SPF points (max 30)
        if spf_audit.qualifier_security == "STRONG":
            score += 30
        elif spf_audit.qualifier_security == "ACCEPTABLE":
            score += 24
        elif spf_audit.qualifier_security == "WEAK":
            score += 8

        # MX present & valid (max 15)
        if mx_records:
            score += 15

        # DKIM detected (max 15)
        if dkim_audit.has_valid_dkim:
            score += 15

        # Lookup ceiling intact (max 5)
        if spf_audit.is_present and not spf_audit.lookup_limit_exceeded:
            score += 5

        # Clamp score 0 to 100
        score = max(0, min(100, score))

        # Grade calculation
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 55:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        spoofing_vulnerable = (dmarc_audit.enforcement_level in ("MONITORING_ONLY", "VULNERABLE")) or (spf_audit.qualifier_security in ("CRITICAL_VULNERABLE", "WEAK"))

        findings: List[str] = []
        if dmarc_audit.enforcement_level == "STRICT_REJECT":
            findings.append("DMARC is actively enforcing 'reject', preventing spoofed inbound messages.")
        elif dmarc_audit.enforcement_level == "MONITORING_ONLY":
            findings.append("DMARC is in 'p=none' monitoring mode; spoofed messages are still delivered to recipients.")
        elif not dmarc_audit.is_present:
            findings.append("DMARC record is missing. Attackers can forge emails appearing from this domain.")

        if spf_audit.qualifier_security == "CRITICAL_VULNERABLE":
            findings.append("CRITICAL: SPF '+all' allows ANY host on the internet to send mail authorized by domain.")
        elif spf_audit.lookup_limit_exceeded:
            findings.append(f"SPF configuration exceeded 10 DNS lookup limit ({spf_audit.lookup_count}/10). Mail servers will treat this as a PermError.")

        remediations: List[str] = []
        if not dmarc_audit.is_present or dmarc_audit.policy == "none":
            remediations.append(f"Publish a hardened DMARC record at _dmarc.{clean_d}: {dmarc_audit.recommended_record}")
        if not spf_audit.is_present:
            remediations.append(f"Publish an SPF TXT record for {clean_d}: {spf_audit.recommended_record}")
        elif spf_audit.qualifier_security in ("WEAK", "CRITICAL_VULNERABLE"):
            remediations.append(f"Change SPF terminator from '{spf_audit.all_qualifier}' to '-all' or '~all'.")

        return EmailSecurityReport(
            domain=clean_d,
            security_score=score,
            grade=grade,
            mx_records=mx_records,
            spf=spf_audit,
            dmarc=dmarc_audit,
            dkim=dkim_audit,
            primary_email_provider=primary_provider,
            spoofing_vulnerable=spoofing_vulnerable,
            key_findings=findings,
            actionable_remediations=remediations,
        )
