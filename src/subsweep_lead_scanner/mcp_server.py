"""
MCP Server & OSINT Recon Engine for SubSweep Lead Scanner
==========================================================
Zero external runtime dependencies - pure Python stdlib.
Implements Model Context Protocol (MCP) / JSON-RPC 2.0 stdio server,
subdomain enumeration, tech stack fingerprinting, lead harvesting,
port probing, full domain audit, and client configuration generators.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import html
import json
import os
import platform
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple, Union

from .email_security_auditor import EmailSecurityAuditor
from .takeover_detector import SubdomainTakeoverDetector

__version__ = "1.0.0"

# Default Curated High-Value Subdomains for Enumeration
DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "api", "dev", "staging", "app", "admin", "portal", "shop",
    "store", "cdn", "m", "test", "cloud", "auth", "login", "gateway", "crm",
    "leads", "support", "status", "dashboard", "internal", "billing", "pay",
    "static", "assets", "media", "docs", "hub", "direct", "connect", "mx",
    "beta", "prod", "demo", "mobile", "help", "kb", "news", "account"
]

# Standard Service Port Mapping
PORT_SERVICE_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Dev",
    8080: "HTTP-Proxy/Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443, 27017]


# ---------------------------------------------------------------------------
# Core Reconnaissance & Intelligence Functions (Pure Python stdlib)
# ---------------------------------------------------------------------------

def _clean_domain(domain_or_url: str) -> str:
    """Normalize input domain or URL into a clean hostname."""
    d = domain_or_url.strip()
    if not d:
        return ""
    if "://" in d:
        parsed = urllib.parse.urlparse(d)
        d = parsed.netloc or parsed.path
    # Remove paths, ports, query strings
    d = d.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip()
    # Remove leading dots or wildcards
    d = d.lstrip(".*")
    return d.lower()


def _resolve_host(hostname: str, timeout: float = 3.0) -> Tuple[Optional[str], Optional[str], float]:
    """
    Resolve hostname to IP address and CNAME with latency measurement.
    Returns: (ip, cname, latency_ms)
    """
    t0 = time.perf_counter()
    ip: Optional[str] = None
    cname: Optional[str] = None
    try:
        # Set default socket timeout for lookup
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            res = socket.gethostbyname_ex(hostname)
            canonical = res[0]
            ips = res[2]
            if ips:
                ip = ips[0]
            if canonical and canonical != hostname:
                cname = canonical
        except Exception:
            # Fallback to getaddrinfo
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            if addr_info:
                ip = addr_info[0][4][0]
        finally:
            socket.setdefaulttimeout(old_timeout)
    except Exception:
        ip = None
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    return ip, cname, latency_ms


def _doh_query(name: str, timeout: float = 3.0) -> Optional[str]:
    """Query Cloudflare / Google DNS over HTTPS for passive resolution."""
    urls = [
        f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type=A",
        f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type=A",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json", "User-Agent": "SubSweepRecon/1.0"}
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8", errors="ignore"))
                    answers = data.get("Answer", [])
                    for ans in answers:
                        if ans.get("type") == 1:  # A record
                            return str(ans.get("data"))
        except Exception:
            continue
    return None


def enumerate_subdomains(
    domain: str,
    wordlist: Optional[List[str]] = None,
    passive_only: bool = False,
    timeout: float = 3.0,
    max_workers: int = 20
) -> Dict[str, Any]:
    """
    Enumerate subdomains with IPs, status, latency, and DNS records.
    """
    t_start = time.perf_counter()
    clean = _clean_domain(domain)
    if not clean:
        return {
            "domain": domain,
            "error": "Invalid domain supplied",
            "subdomains": [],
            "total_found": 0,
            "scan_duration_ms": 0.0
        }

    prefixes = list(dict.fromkeys(wordlist or DEFAULT_SUBDOMAIN_WORDLIST))
    subdomains_found: List[Dict[str, Any]] = []

    # 1. Resolve root apex domain
    apex_ip, apex_cname, apex_latency = _resolve_host(clean, timeout=timeout)
    if not apex_ip and passive_only:
        apex_ip = _doh_query(clean, timeout=timeout)

    if apex_ip:
        subdomains_found.append({
            "subdomain": clean,
            "host": clean,
            "ip": apex_ip,
            "cname": apex_cname,
            "status": "active",
            "latency_ms": apex_latency,
            "source": "apex"
        })

    # 2. Worker task for subdomains
    def probe_prefix(prefix: str) -> Optional[Dict[str, Any]]:
        target_host = f"{prefix}.{clean}"
        if target_host == clean:
            return None
        
        if passive_only:
            t0 = time.perf_counter()
            doh_ip = _doh_query(target_host, timeout=timeout)
            dur = round((time.perf_counter() - t0) * 1000, 2)
            if doh_ip:
                return {
                    "subdomain": target_host,
                    "host": target_host,
                    "ip": doh_ip,
                    "cname": None,
                    "status": "active",
                    "latency_ms": dur,
                    "source": "doh_passive"
                }
            return None
        else:
            ip, cname, lat = _resolve_host(target_host, timeout=timeout)
            if ip:
                return {
                    "subdomain": target_host,
                    "host": target_host,
                    "ip": ip,
                    "cname": cname,
                    "status": "active",
                    "latency_ms": lat,
                    "source": "dns_active"
                }
            return None

    # Run probes concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(max_workers, 50))) as executor:
        future_map = {executor.submit(probe_prefix, p): p for p in prefixes}
        for future in concurrent.futures.as_completed(future_map):
            try:
                res = future.result()
                if res:
                    subdomains_found.append(res)
            except Exception:
                pass

    # Sort subdomains: apex first, then alphabetical
    subdomains_found.sort(key=lambda s: (s["source"] != "apex", s["subdomain"]))
    duration_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return {
        "domain": clean,
        "subdomains": subdomains_found,
        "total_found": len(subdomains_found),
        "scanned_prefixes": len(prefixes),
        "passive_only": passive_only,
        "scan_duration_ms": duration_ms
    }


def _fetch_url(url: str, timeout: float = 5.0) -> Tuple[int, Dict[str, str], str, str]:
    """
    Fetch URL contents using standard library urllib.
    Returns: (status_code, headers_dict, html_body, final_url)
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SubSweep/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    # Normalize protocol
    if not url.startswith(("http://", "https://")):
        target_urls = [f"https://{url}", f"http://{url}"]
    else:
        target_urls = [url]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    last_err = ""
    for candidate in target_urls:
        try:
            req = urllib.request.Request(candidate, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                raw = resp.read()
                try:
                    encoding = resp.headers.get_content_charset() or "utf-8"
                    body = raw.decode(encoding, errors="replace")
                except Exception:
                    body = raw.decode("utf-8", errors="replace")
                return status, resp_headers, body, resp.geturl()
        except urllib.error.HTTPError as e:
            resp_headers = {k.lower(): v for k, v in e.headers.items()}
            raw = e.read()
            body = raw.decode("utf-8", errors="replace") if raw else ""
            return e.code, resp_headers, body, candidate
        except Exception as e:
            last_err = str(e)
            continue

    return 0, {}, "", target_urls[0]


def fingerprint_tech(target: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Identify CMS, frontend frameworks, CDN, analytics, and server stack.
    """
    clean = target.strip()
    status_code, headers, body, final_url = _fetch_url(clean, timeout=timeout)
    server_header = headers.get("server", "Unknown")

    body_lower = body.lower()
    headers_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

    technologies: List[Dict[str, str]] = []
    cms: Optional[str] = None
    frameworks: List[str] = []
    cdn: Optional[str] = None
    analytics: List[str] = []

    # 1. CMS Detection
    if "wp-content" in body_lower or "wp-includes" in body_lower or "wp-json" in body_lower:
        cms = "WordPress"
        technologies.append({"name": "WordPress", "category": "CMS", "confidence": "high"})
    elif "cdn.shopify.com" in body_lower or "shopify.theme" in body_lower or "myshopify.com" in body_lower:
        cms = "Shopify"
        technologies.append({"name": "Shopify", "category": "E-Commerce / CMS", "confidence": "high"})
    elif "webflow.com" in body_lower or "data-wf-page" in body_lower or "data-wf-site" in body_lower:
        cms = "Webflow"
        technologies.append({"name": "Webflow", "category": "No-Code / CMS", "confidence": "high"})
    elif "squarespace.com" in body_lower or "static1.squarespace.com" in body_lower:
        cms = "Squarespace"
        technologies.append({"name": "Squarespace", "category": "CMS", "confidence": "high"})
    elif "wixsite.com" in body_lower or "wix.com" in body_lower or "x-wix-renderer" in headers_str:
        cms = "Wix"
        technologies.append({"name": "Wix", "category": "CMS", "confidence": "high"})
    elif "ghost.io" in body_lower or "ghost-root" in body_lower or "ghost" in headers.get("x-powered-by", "").lower():
        cms = "Ghost"
        technologies.append({"name": "Ghost", "category": "Headless CMS", "confidence": "high"})
    elif "drupal.settings" in body_lower or "/sites/default/files" in body_lower:
        cms = "Drupal"
        technologies.append({"name": "Drupal", "category": "CMS", "confidence": "high"})
    elif "hubspot.com" in body_lower or "hs-script-loader" in body_lower or "hubspot" in headers_str:
        cms = "HubSpot CMS"
        technologies.append({"name": "HubSpot CMS", "category": "Marketing / CMS", "confidence": "high"})
    elif "index.php?option=com_" in body_lower or "/media/jui/" in body_lower:
        cms = "Joomla"
        technologies.append({"name": "Joomla", "category": "CMS", "confidence": "medium"})

    # 2. Frontend / JavaScript Frameworks
    if "__next_data__" in body_lower or "_next/static" in body_lower:
        frameworks.append("Next.js")
        technologies.append({"name": "Next.js", "category": "Frontend Framework", "confidence": "high"})
    if "__nuxt__" in body_lower or "_nuxt/" in body_lower:
        frameworks.append("Nuxt.js")
        technologies.append({"name": "Nuxt.js", "category": "Frontend Framework", "confidence": "high"})
    if "data-reactroot" in body_lower or "_reactrootcontainer" in body_lower or "react" in body_lower and "react-dom" in body_lower:
        if "Next.js" not in frameworks:
            frameworks.append("React")
            technologies.append({"name": "React", "category": "UI Library", "confidence": "high"})
    if "v-cloak" in body_lower or "__vue__" in body_lower or "vue.min.js" in body_lower:
        if "Nuxt.js" not in frameworks:
            frameworks.append("Vue.js")
            technologies.append({"name": "Vue.js", "category": "UI Framework", "confidence": "high"})
    if "ng-version" in body_lower or "ng-app" in body_lower:
        frameworks.append("Angular")
        technologies.append({"name": "Angular", "category": "Frontend Framework", "confidence": "high"})
    if "svelte-" in body_lower or "__svelte" in body_lower:
        frameworks.append("Svelte")
        technologies.append({"name": "Svelte", "category": "UI Framework", "confidence": "high"})
    if "tailwind" in body_lower or "tw-" in body_lower or "border-slate" in body_lower or "bg-indigo" in body_lower:
        frameworks.append("Tailwind CSS")
        technologies.append({"name": "Tailwind CSS", "category": "CSS Framework", "confidence": "high"})
    if "bootstrap.min.css" in body_lower or "navbar-expand" in body_lower or "btn-primary" in body_lower:
        frameworks.append("Bootstrap")
        technologies.append({"name": "Bootstrap", "category": "CSS Framework", "confidence": "high"})
    if "htmx.org" in body_lower or "hx-get" in body_lower or "hx-post" in body_lower:
        frameworks.append("HTMX")
        technologies.append({"name": "HTMX", "category": "Frontend Library", "confidence": "high"})
    if "alpinejs" in body_lower or "x-data=" in body_lower:
        frameworks.append("Alpine.js")
        technologies.append({"name": "Alpine.js", "category": "JavaScript Library", "confidence": "high"})

    # 3. CDN & Hosting
    if "cloudflare" in server_header.lower() or "cf-ray" in headers:
        cdn = "Cloudflare"
        technologies.append({"name": "Cloudflare", "category": "CDN / Security", "confidence": "high"})
    elif "cloudfront.net" in body_lower or "x-amz-cf-id" in headers:
        cdn = "AWS CloudFront"
        technologies.append({"name": "AWS CloudFront", "category": "CDN", "confidence": "high"})
    elif "fastly" in headers_str or "x-fastly" in headers:
        cdn = "Fastly"
        technologies.append({"name": "Fastly", "category": "CDN", "confidence": "high"})
    elif "akamai" in headers_str:
        cdn = "Akamai"
        technologies.append({"name": "Akamai", "category": "CDN", "confidence": "high"})
    elif "x-vercel-id" in headers or "vercel" in server_header.lower():
        cdn = "Vercel Edge"
        technologies.append({"name": "Vercel", "category": "Hosting / CDN", "confidence": "high"})
    elif "x-nf-request-id" in headers or "netlify" in server_header.lower():
        cdn = "Netlify"
        technologies.append({"name": "Netlify", "category": "Hosting / CDN", "confidence": "high"})
    elif "gws" in server_header.lower() or "google" in server_header.lower():
        cdn = "Google Cloud Infrastructure"
        technologies.append({"name": "Google Cloud", "category": "Hosting / CDN", "confidence": "high"})

    # 4. Analytics & Marketing Tracking
    if "gtag/js" in body_lower or "google-analytics.com" in body_lower or "g-" in body:
        analytics.append("Google Analytics 4")
        technologies.append({"name": "Google Analytics 4", "category": "Analytics", "confidence": "high"})
    if "googletagmanager.com/gtm.js" in body_lower or "gtm-" in body:
        analytics.append("Google Tag Manager")
        technologies.append({"name": "Google Tag Manager", "category": "Tag Management", "confidence": "high"})
    if "connect.facebook.net" in body_lower or "fbq(" in body_lower:
        analytics.append("Meta Pixel")
        technologies.append({"name": "Meta Pixel", "category": "Ad Tracking", "confidence": "high"})
    if "snap.licdn.com" in body_lower or "_linkedin_partner_id" in body_lower:
        analytics.append("LinkedIn Insight Tag")
        technologies.append({"name": "LinkedIn Insight Tag", "category": "B2B Tracking", "confidence": "high"})
    if "posthog.init" in body_lower or "app.posthog.com" in body_lower:
        analytics.append("PostHog")
        technologies.append({"name": "PostHog", "category": "Product Analytics", "confidence": "high"})
    if "static.hotjar.com" in body_lower or "_hjsettings" in body_lower:
        analytics.append("Hotjar")
        technologies.append({"name": "Hotjar", "category": "Heatmaps / UX", "confidence": "high"})
    if "plausible.io" in body_lower:
        analytics.append("Plausible Analytics")
        technologies.append({"name": "Plausible Analytics", "category": "Privacy Analytics", "confidence": "high"})
    if "clarity.ms" in body_lower:
        analytics.append("Microsoft Clarity")
        technologies.append({"name": "Microsoft Clarity", "category": "Session Recording", "confidence": "high"})
    if "segment.com/analytics.js" in body_lower or "analytics.track(" in body_lower:
        analytics.append("Segment CDP")
        technologies.append({"name": "Segment", "category": "CDP", "confidence": "high"})

    # 5. Security Headers
    security_headers = {
        "strict-transport-security": headers.get("strict-transport-security", "Missing"),
        "content-security-policy": "Present" if "content-security-policy" in headers else "Missing",
        "x-frame-options": headers.get("x-frame-options", "Missing"),
        "x-content-type-options": headers.get("x-content-type-options", "Missing"),
        "referrer-policy": headers.get("referrer-policy", "Missing"),
    }

    return {
        "target": target,
        "final_url": final_url,
        "status_code": status_code,
        "server": server_header,
        "cms": cms,
        "frameworks": list(dict.fromkeys(frameworks)),
        "cdn": cdn,
        "analytics": list(dict.fromkeys(analytics)),
        "technologies": technologies,
        "security_headers": security_headers,
        "detected_count": len(technologies),
    }


def extract_leads(
    target: str,
    html_content: Optional[str] = None,
    timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Harvest emails, phones, social profiles, Schema.org LocalBusiness data,
    and compute Lead Quality Score (0-100).
    """
    content = html_content or ""
    final_url = target
    status_code = 200

    if not content and target:
        status_code, _, fetched_body, final_url = _fetch_url(target, timeout=timeout)
        content = fetched_body

    if not content:
        return {
            "target": target,
            "status_code": status_code,
            "emails": [],
            "phones": [],
            "social_links": {},
            "schema_org": [],
            "meta": {},
            "lead_quality_score": 0,
            "lead_score_grade": "D",
            "lead_score_breakdown": {"error": "No content fetched"},
        }

    # 1. Emails Extraction
    email_regex = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    raw_emails = re.findall(email_regex, content)
    junk_extensions = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js", ".woff", ".woff2")
    junk_domains = ("example.com", "domain.com", "email.com", "sentry.io", "w3.org", "schema.org", "wixpress.com")

    cleaned_emails: List[str] = []
    for em in raw_emails:
        em_clean = em.lower().strip(".,;:\"'<>(){}[]")
        if any(em_clean.endswith(ext) for ext in junk_extensions):
            continue
        domain_part = em_clean.split("@")[-1] if "@" in em_clean else ""
        if domain_part in junk_domains or not "." in domain_part:
            continue
        if em_clean not in cleaned_emails:
            cleaned_emails.append(em_clean)

    # 2. Phones Extraction
    phone_patterns = [
        r'(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})',  # US/Canada standard
        r'\+[1-9][0-9]{0,2}[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}',  # International
        r'href=["\']tel:([+0-9\-\s\(\)\.]+)["\']',  # Tel anchors
    ]
    raw_phones: List[str] = []
    for pattern in phone_patterns:
        matches = re.findall(pattern, content)
        for m in matches:
            if isinstance(m, tuple):
                p_str = "-".join(m)
            else:
                p_str = str(m)
            # Normalize digits
            digits_only = re.sub(r'[^0-9+]', '', p_str)
            if len(digits_only) >= 10:
                p_clean = p_str.strip(" \"'")
                if p_clean not in raw_phones:
                    raw_phones.append(p_clean)

    # 3. Social Media Links
    social_domains = {
        "linkedin": r'https?://(?:www\.)?linkedin\.com/(?:company|in)/[a-zA-Z0-9_-]+/?',
        "twitter": r'https?://(?:www\.)?(?:twitter\.com|x\.com)/[a-zA-Z0-9_]+/?',
        "facebook": r'https?://(?:www\.)?facebook\.com/[a-zA-Z0-9_.-]+/?',
        "instagram": r'https?://(?:www\.)?instagram\.com/[a-zA-Z0-9_.-]+/?',
        "github": r'https?://(?:www\.)?github\.com/[a-zA-Z0-9_-]+/?',
        "youtube": r'https?://(?:www\.)?youtube\.com/(?:@[a-zA-Z0-9_-]+|channel/[a-zA-Z0-9_-]+|c/[a-zA-Z0-9_-]+)/?',
        "tiktok": r'https?://(?:www\.)?tiktok\.com/@[a-zA-Z0-9_.-]+/?',
    }
    social_links: Dict[str, List[str]] = {}
    for platform_name, regex_pat in social_domains.items():
        found = re.findall(regex_pat, content, re.IGNORECASE)
        # Deduplicate and filter generic sharing links
        filtered = []
        for link in found:
            link_clean = link.rstrip("/")
            if "share" not in link_clean and "intent" not in link_clean and link_clean not in filtered:
                filtered.append(link_clean)
        if filtered:
            social_links[platform_name] = filtered

    # 4. Schema.org JSON-LD extraction
    schema_org_data: List[Dict[str, Any]] = []
    ld_json_pattern = r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>'
    ld_matches = re.findall(ld_json_pattern, content, re.DOTALL | re.IGNORECASE)
    for match in ld_matches:
        try:
            parsed = json.loads(match.strip())
            if isinstance(parsed, dict):
                schema_org_data.append(parsed)
            elif isinstance(parsed, list):
                schema_org_data.extend(item for item in parsed if isinstance(item, dict))
        except Exception:
            continue

    # Extract business info from Schema.org if available
    business_info: Dict[str, Any] = {}
    for item in schema_org_data:
        type_val = str(item.get("@type", ""))
        if any(b_type in type_val for b_type in ["Business", "Organization", "Corporation", "Store", "Restaurant", "LegalService"]):
            business_info = {
                "name": item.get("name"),
                "legalName": item.get("legalName"),
                "telephone": item.get("telephone"),
                "email": item.get("email"),
                "address": item.get("address"),
                "priceRange": item.get("priceRange"),
                "geo": item.get("geo"),
            }
            break

    # 5. HTML Meta Information
    title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
    title = html.unescape(title_match.group(1).strip()) if title_match else ""
    desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']', content, re.IGNORECASE)
    description = html.unescape(desc_match.group(1).strip()) if desc_match else ""

    # 6. Calculate Lead Quality Score (0 - 100)
    score = 0
    score_breakdown: Dict[str, int] = {}

    # Email scoring (up to 30)
    if cleaned_emails:
        score += 20
        score_breakdown["emails_present"] = 20
        # Check for non-free custom business emails
        free_domains = ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com")
        if any(not em.endswith(free_domains) for em in cleaned_emails):
            score += 10
            score_breakdown["custom_domain_email"] = 10
    else:
        score_breakdown["emails_present"] = 0

    # Phone scoring (up to 20)
    if raw_phones:
        score += 20
        score_breakdown["phones_present"] = 20
    else:
        score_breakdown["phones_present"] = 0

    # Business Schema / Address scoring (up to 20)
    if business_info.get("address") or len(schema_org_data) > 0:
        score += 20
        score_breakdown["structured_business_schema"] = 20
    else:
        score_breakdown["structured_business_schema"] = 0

    # Social Presence scoring (up to 15)
    social_count = len(social_links)
    social_score = min(social_count * 5, 15)
    score += social_score
    score_breakdown["social_profiles"] = social_score

    # SSL / HTTPS security (10)
    if final_url.startswith("https://"):
        score += 10
        score_breakdown["https_secure"] = 10
    else:
        score_breakdown["https_secure"] = 0

    # Meta Tags richness (5)
    if title and description:
        score += 5
        score_breakdown["meta_tags"] = 5
    else:
        score_breakdown["meta_tags"] = 0

    score = min(score, 100)

    # Score Grade
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "D"

    return {
        "target": target,
        "final_url": final_url,
        "title": title,
        "description": description,
        "emails": cleaned_emails,
        "phones": raw_phones[:10],
        "social_links": social_links,
        "business_info": business_info,
        "schema_org": schema_org_data[:5],
        "lead_quality_score": score,
        "lead_score_grade": grade,
        "lead_score_breakdown": score_breakdown,
        "total_emails": len(cleaned_emails),
        "total_phones": len(raw_phones),
        "total_social": sum(len(v) for v in social_links.values()),
    }


def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """Connect to port and capture service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # For HTTP/HTTPS send generic request
        if port in (80, 8080, 8000, 8888):
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port in (443, 8443):
            # SSL wrap
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s)
            ss.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = ss.recv(256).decode("utf-8", errors="ignore").splitlines()[0]
            ss.close()
            return banner.strip()
        else:
            s.sendall(b"\r\n")

        data = s.recv(256)
        s.close()
        if data:
            line = data.decode("utf-8", errors="ignore").splitlines()
            return line[0].strip() if line else ""
    except Exception:
        pass
    return None


def probe_ports(
    domain: str,
    ports: Optional[Union[List[int], str]] = None,
    timeout: float = 1.5,
    grab_banner: bool = True,
    max_workers: int = 20
) -> Dict[str, Any]:
    """
    Fast TCP port probe with banner grabbing for common services.
    """
    t_start = time.perf_counter()
    clean_host = _clean_domain(domain)
    if not clean_host:
        return {
            "host": domain,
            "error": "Invalid host supplied",
            "open_ports": [],
            "total_scanned": 0,
            "total_open": 0,
            "duration_ms": 0.0
        }

    # Parse port list
    port_list: List[int] = []
    if isinstance(ports, str):
        for part in ports.split(","):
            part_str = part.strip()
            if part_str.isdigit():
                port_list.append(int(part_str))
    elif isinstance(ports, list):
        port_list = [int(p) for p in ports if str(p).isdigit()]

    if not port_list:
        port_list = DEFAULT_PORTS

    # Resolve IP
    ip, _, _ = _resolve_host(clean_host, timeout=timeout)
    if not ip:
        return {
            "host": clean_host,
            "ip": None,
            "error": f"Failed to resolve host {clean_host}",
            "open_ports": [],
            "total_scanned": len(port_list),
            "total_open": 0,
            "duration_ms": round((time.perf_counter() - t_start) * 1000, 2)
        }

    open_results: List[Dict[str, Any]] = []

    def check_port(p: int) -> Optional[Dict[str, Any]]:
        t0 = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            res = sock.connect_ex((ip, p))
            latency = round((time.perf_counter() - t0) * 1000, 2)
            sock.close()
            if res == 0:
                service = PORT_SERVICE_MAP.get(p, "Custom/Unknown")
                banner = _grab_banner(ip, p, timeout=timeout) if grab_banner else None
                return {
                    "port": p,
                    "service": service,
                    "state": "open",
                    "latency_ms": latency,
                    "banner": banner
                }
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(max_workers, 50))) as executor:
        future_map = {executor.submit(check_port, p): p for p in port_list}
        for future in concurrent.futures.as_completed(future_map):
            try:
                res = future.result()
                if res:
                    open_results.append(res)
            except Exception:
                pass

    open_results.sort(key=lambda x: x["port"])
    duration_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return {
        "host": clean_host,
        "ip": ip,
        "open_ports": open_results,
        "total_scanned": len(port_list),
        "total_open": len(open_results),
        "duration_ms": duration_ms
    }


def full_audit(
    domain: str,
    ports: Optional[List[int]] = None,
    passive_only: bool = False,
    timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Complete multi-vector OSINT audit (subdomains + tech + leads + ports).
    """
    t_start = time.perf_counter()
    clean = _clean_domain(domain)

    # 1. Enumerate subdomains
    subdomains_res = enumerate_subdomains(clean, passive_only=passive_only, timeout=timeout)

    # 2. Fingerprint tech
    tech_res = fingerprint_tech(clean, timeout=timeout)

    # 3. Harvest business leads
    leads_res = extract_leads(clean, timeout=timeout)

    # 4. Probe common open ports
    ports_res = probe_ports(clean, ports=ports, timeout=min(timeout, 2.0))

    duration_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return {
        "domain": clean,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_duration_ms": duration_ms,
        "lead_summary": {
            "score": leads_res.get("lead_quality_score", 0),
            "grade": leads_res.get("lead_score_grade", "D"),
            "emails_count": len(leads_res.get("emails", [])),
            "phones_count": len(leads_res.get("phones", [])),
            "social_platforms": list(leads_res.get("social_links", {}).keys()),
            "cms": tech_res.get("cms"),
            "frameworks": tech_res.get("frameworks", []),
            "open_ports_count": ports_res.get("total_open", 0),
            "subdomains_count": subdomains_res.get("total_found", 0),
        },
        "subdomains": subdomains_res,
        "technology": tech_res,
        "leads": leads_res,
        "ports": ports_res,
    }


def get_diagnostics(test_domain: str = "example.com") -> Dict[str, Any]:
    """
    Platform and network diagnostic information.
    """
    dns_ok = False
    dns_latency = 0.0
    try:
        t0 = time.perf_counter()
        socket.gethostbyname(test_domain)
        dns_latency = round((time.perf_counter() - t0) * 1000, 2)
        dns_ok = True
    except Exception:
        dns_ok = False

    return {
        "status": "healthy",
        "version": __version__,
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
        },
        "network": {
            "dns_resolution": dns_ok,
            "dns_latency_ms": dns_latency,
            "test_target": test_domain,
            "ipv6_supported": socket.has_ipv6,
            "ssl_version": ssl.OPENSSL_VERSION,
        },
        "capabilities": {
            "subdomain_enum": True,
            "tech_fingerprint": True,
            "lead_harvester": True,
            "port_probe": True,
            "mcp_stdio_server": True,
            "material3_ui_server": True,
        }
    }


# ---------------------------------------------------------------------------
# MCP Client Config Generator
# ---------------------------------------------------------------------------

def generate_mcp_client_config(
    client_name: str,
    python_path: str = "python3",
    project_root: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate client configuration for Claude Desktop, Cursor, Cline, Zed, and generic MCP clients.
    """
    client = client_name.lower().strip()
    script_module = "subsweep_lead_scanner.mcp_server"
    
    server_args = ["-m", script_module]
    env_dict = {"PYTHONPATH": project_root} if project_root else {}

    if client in ("claude", "claude_desktop", "claude-desktop"):
        return {
            "mcpServers": {
                "subsweep": {
                    "command": python_path,
                    "args": server_args,
                    "env": env_dict
                }
            }
        }
    elif client in ("cursor", "cursor_ide"):
        return {
            "mcpServers": {
                "subsweep": {
                    "command": python_path,
                    "args": server_args,
                    "env": env_dict
                }
            }
        }
    elif client in ("cline", "roo-cline", "roo_code"):
        return {
            "mcpServers": {
                "subsweep": {
                    "command": python_path,
                    "args": server_args,
                    "env": env_dict,
                    "disabled": False,
                    "autoApprove": []
                }
            }
        }
    elif client in ("zed", "zed_editor"):
        return {
            "context_servers": {
                "subsweep": {
                    "command": {
                        "path": python_path,
                        "args": server_args,
                        "env": env_dict
                    }
                }
            }
        }
    else:  # Generic MCP descriptor
        return {
            "name": "subsweep",
            "version": __version__,
            "description": "SubSweep Lead Scanner & Domain Recon MCP Server",
            "transport": "stdio",
            "command": python_path,
            "args": server_args,
            "env": env_dict
        }


# ---------------------------------------------------------------------------
# MCP JSON-RPC 2.0 Server Protocol Engine
# ---------------------------------------------------------------------------

MCP_TOOLS_MANIFEST = [
    {
        "name": "subsweep_enumerate_subdomains",
        "description": "Enumerate subdomains for a target domain with IP addresses, DNS status, and network latency.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target apex domain to enumerate (e.g. 'example.com')"
                },
                "wordlist": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Custom list of subdomain prefixes (optional)"
                },
                "passive_only": {
                    "type": "boolean",
                    "description": "Perform only passive DNS-over-HTTPS queries without direct socket probes",
                    "default": False
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in seconds per query",
                    "default": 3.0
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "subsweep_fingerprint_tech",
        "description": "Identify CMS, JavaScript frameworks, CDN, analytics trackers, and security headers of a website.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target website URL or domain name"
                },
                "timeout": {
                    "type": "number",
                    "description": "Request timeout in seconds",
                    "default": 5.0
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "subsweep_extract_leads",
        "description": "Harvest emails, phones, social media links, Schema.org business metadata, and compute a 0-100 Lead Quality Score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or domain to harvest leads from"
                },
                "html_content": {
                    "type": "string",
                    "description": "Direct HTML content to analyze without making network requests (optional)"
                },
                "timeout": {
                    "type": "number",
                    "description": "Request timeout in seconds",
                    "default": 5.0
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "subsweep_probe_ports",
        "description": "Fast multi-threaded TCP port scan with service banner grabbing for common web, database, and admin ports.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target host or domain to scan"
                },
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of TCP port numbers to probe (defaults to standard web/db/admin ports)"
                },
                "timeout": {
                    "type": "number",
                    "description": "Connection timeout in seconds per port",
                    "default": 1.5
                },
                "grab_banner": {
                    "type": "boolean",
                    "description": "Attempt to grab service response banner",
                    "default": True
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "subsweep_full_audit",
        "description": "Complete multi-vector OSINT audit (subdomains + tech fingerprint + business leads + open ports) for a domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain for 360-degree audit"
                },
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Custom ports to probe (optional)"
                },
                "passive_only": {
                    "type": "boolean",
                    "description": "Passive enumeration only",
                    "default": False
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in seconds",
                    "default": 5.0
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "subsweep_get_diagnostics",
        "description": "Get runtime platform details, network connectivity status, DNS latency, and tool diagnostics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "test_domain": {
                    "type": "string",
                    "description": "Domain to test DNS resolution against",
                    "default": "example.com"
                }
            }
        }
    },
    {
        "name": "subsweep_audit_policies",
        "description": "Audit robots.txt (sitemaps, sensitive disallow rules, crawl delays) and RFC 9116 security.txt (security contacts, bug bounties).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain or URL to audit for robots.txt and security.txt",
                },
                "robots_content": {
                    "type": "string",
                    "description": "Optional raw robots.txt content to parse directly",
                },
                "security_txt_content": {
                    "type": "string",
                    "description": "Optional raw security.txt content to parse directly",
                },
                "timeout": {
                    "type": "number",
                    "description": "HTTP request timeout in seconds",
                    "default": 4.0,
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "subsweep_audit_email_security",
        "description": "Audit email security posture (SPF RFC 7208 lookup ceilings and qualifiers, DMARC RFC 7489 enforcement, DKIM selector validation, and MX mail provider fingerprinting) with a 0-100 deliverability score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to audit (e.g. 'example.com')",
                },
                "timeout": {
                    "type": "number",
                    "description": "DoH query timeout in seconds",
                    "default": 3.0,
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "subsweep_detect_takeovers",
        "description": "Detect subdomain takeover risks and dangling CNAME records across 20+ cloud/SaaS hosts (GitHub Pages, AWS S3, Netlify, Vercel, Heroku, Shopify, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target apex domain",
                },
                "subdomains": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "subdomain": {"type": "string"},
                            "cnames": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["subdomain"],
                    },
                    "description": "List of discovered subdomain records with CNAMEs",
                },
                "verify_http": {
                    "type": "boolean",
                    "description": "Whether to perform live HTTP requests to verify error body signatures",
                    "default": False,
                },
            },
            "required": ["domain", "subdomains"],
        },
    },
]


class MCPServer:
    """
    Pure Python JSON-RPC 2.0 Model Context Protocol (MCP) Server.
    """

    def __init__(self) -> None:
        self.name = "subsweep-lead-scanner"
        self.version = __version__
        self.tools = MCP_TOOLS_MANIFEST

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tool by name and return payload."""
        if tool_name == "subsweep_enumerate_subdomains":
            domain = arguments.get("domain", "")
            wordlist = arguments.get("wordlist")
            passive_only = bool(arguments.get("passive_only", False))
            timeout = float(arguments.get("timeout", 3.0))
            return enumerate_subdomains(domain, wordlist=wordlist, passive_only=passive_only, timeout=timeout)

        elif tool_name == "subsweep_fingerprint_tech":
            target = arguments.get("target", "")
            timeout = float(arguments.get("timeout", 5.0))
            return fingerprint_tech(target, timeout=timeout)

        elif tool_name == "subsweep_extract_leads":
            target = arguments.get("target", "")
            html_content = arguments.get("html_content")
            timeout = float(arguments.get("timeout", 5.0))
            return extract_leads(target, html_content=html_content, timeout=timeout)

        elif tool_name == "subsweep_probe_ports":
            domain = arguments.get("domain", arguments.get("host", ""))
            ports = arguments.get("ports")
            timeout = float(arguments.get("timeout", 1.5))
            grab_banner = bool(arguments.get("grab_banner", True))
            return probe_ports(domain, ports=ports, timeout=timeout, grab_banner=grab_banner)

        elif tool_name == "subsweep_full_audit":
            domain = arguments.get("domain", "")
            ports = arguments.get("ports")
            passive_only = bool(arguments.get("passive_only", False))
            timeout = float(arguments.get("timeout", 5.0))
            return full_audit(domain, ports=ports, passive_only=passive_only, timeout=timeout)

        elif tool_name == "subsweep_get_diagnostics":
            test_domain = arguments.get("test_domain", "example.com")
            return get_diagnostics(test_domain=test_domain)

        elif tool_name == "subsweep_audit_policies":
            from .policy_auditor import audit_policy_endpoints
            domain = arguments.get("domain", "")
            robots_content = arguments.get("robots_content")
            security_txt_content = arguments.get("security_txt_content")
            timeout = float(arguments.get("timeout", 4.0))
            return audit_policy_endpoints(
                domain_or_url=domain,
                timeout=timeout,
                robots_content=robots_content,
                security_txt_content=security_txt_content,
            )

        elif tool_name == "subsweep_audit_email_security":
            domain = arguments.get("domain", "")
            timeout = float(arguments.get("timeout", 3.0))
            auditor = EmailSecurityAuditor(doh_timeout=timeout)
            report = auditor.audit_domain(domain)
            return report.to_dict()

        elif tool_name == "subsweep_detect_takeovers":
            domain = arguments.get("domain", "")
            subdomains = arguments.get("subdomains", [])
            verify_http = bool(arguments.get("verify_http", False))
            detector = SubdomainTakeoverDetector()
            report = detector.scan_records(domain, subdomains, verify_http=verify_http)
            return report.to_dict()

        else:
            raise ValueError(f"Unknown MCP tool: {tool_name}")

    call_tool = execute_tool

    def handle_message(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single JSON-RPC request and return response dict."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        # Handle notifications (no id)
        if req_id is None and method in ("notifications/initialized", "initialized"):
            return None

        # Standard methods
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": self.name,
                        "version": self.version
                    },
                    "capabilities": {
                        "tools": {
                            "listChanged": False
                        },
                        "prompts": {},
                        "resources": {}
                    }
                }
            }

        elif method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {}
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.tools
                }
            }

        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            try:
                result_data = self.execute_tool(tool_name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result_data, indent=2)
                            }
                        ],
                        "isError": False
                    }
                }
            except ValueError as ve:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,  # Invalid params
                        "message": str(ve)
                    }
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Error executing tool {tool_name}: {str(e)}"
                            }
                        ],
                        "isError": True
                    }
                }

        else:
            if req_id is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,  # Method not found
                        "message": f"Method '{method}' not found"
                    }
                }
            return None

    def handle_line(self, line: str) -> Optional[str]:
        """Process incoming raw string line and return serialized response."""
        line = line.strip()
        if not line:
            return None
        try:
            req = json.loads(line)
        except Exception:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "Parse error: Invalid JSON received"
                }
            }
            return json.dumps(err_resp)

        resp = self.handle_message(req)
        return json.dumps(resp) if resp is not None else None

    def serve_stdio(self, in_stream=None, out_stream=None) -> None:
        """Run stdio event loop."""
        in_stream = in_stream or sys.stdin
        out_stream = out_stream or sys.stdout

        while True:
            try:
                line = in_stream.readline()
                if not line:
                    break
                out_str = self.handle_line(line)
                if out_str:
                    out_stream.write(out_str + "\n")
                    out_stream.flush()
            except (KeyboardInterrupt, SystemExit):
                break
            except Exception:
                continue


def run_mcp_server() -> None:
    """Entry point for running stdio MCP server."""
    server = MCPServer()
    server.serve_stdio()


if __name__ == "__main__":
    run_mcp_server()
