"""Web technology profiling and fingerprint detection engine for subsweep-lead-scanner.

Detects 40+ frameworks, CMSs, hosting/CDNs, analytics, security headers, and backend stacks
from HTTP response headers, HTML DOM structures, script assets, and meta tags.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

CATEGORY_FRONTEND = "Frontend"
CATEGORY_BACKEND = "Backend"
CATEGORY_CMS = "CMS"
CATEGORY_HOSTING = "Hosting & CDN"
CATEGORY_ANALYTICS = "Analytics & Marketing"
CATEGORY_SECURITY = "Security & Protection"


@dataclass
class TechnologyMatch:
    """Individual detected technology match."""

    name: str
    category: str
    confidence: int  # 0 to 100
    matched_by: List[str] = field(default_factory=list)
    version: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize technology match to dictionary."""
        return asdict(self)


@dataclass
class TechProfileResult:
    """Consolidated technology profile result for a web target."""

    url: str
    status_code: int = 200
    server: Optional[str] = None
    technologies: List[TechnologyMatch] = field(default_factory=list)
    categories: Dict[str, List[str]] = field(default_factory=dict)
    overall_confidence: int = 0
    security_headers: Dict[str, bool] = field(default_factory=dict)
    security_score: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize profile result to dictionary."""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "server": self.server,
            "technologies": [t.to_dict() for t in self.technologies],
            "categories": self.categories,
            "overall_confidence": self.overall_confidence,
            "security_headers": self.security_headers,
            "security_score": self.security_score,
            "headers": self.headers,
            "scanned_at": self.scanned_at,
        }


# Fingerprint Definitions: 40+ technologies across 6 categories
TECH_FINGERPRINTS: List[Dict[str, Any]] = [
    # --- Frameworks & Frontend ---
    {
        "name": "Next.js",
        "category": CATEGORY_FRONTEND,
        "description": "React-based full-stack web application framework",
        "headers": {"x-powered-by": r"next\.?js"},
        "html": [r"/_next/static/", r'<div id="__next"', r"__NEXT_DATA__"],
        "scripts": [r"/_next/static/chunks/"],
        "meta": {},
    },
    {
        "name": "Nuxt.js",
        "category": CATEGORY_FRONTEND,
        "description": "Vue.js-based intuitive web framework",
        "headers": {"x-powered-by": r"nuxt"},
        "html": [r"/_nuxt/", r'<div id="__nuxt"', r"__NUXT__", r"window\.__NUXT__"],
        "scripts": [r"/_nuxt/"],
        "meta": {},
    },
    {
        "name": "React",
        "category": CATEGORY_FRONTEND,
        "description": "Component-based declarative JavaScript UI library",
        "headers": {},
        "html": [r'data-reactroot=""', r"data-reactid", r"_reactListening", r"react-dom"],
        "scripts": [r"react(?:\.production|\.development)?\.js", r"react-dom"],
        "meta": {},
    },
    {
        "name": "Vue.js",
        "category": CATEGORY_FRONTEND,
        "description": "Progressive approachable JavaScript framework",
        "headers": {},
        "html": [r"data-v-[a-f0-9]+", r"__vue__", r"__VUE__"],
        "scripts": [r"vue(?:\.runtime)?(?:\.min|\.global)?\.js"],
        "meta": {},
    },
    {
        "name": "Svelte",
        "category": CATEGORY_FRONTEND,
        "description": "Cybernetically enhanced reactive web UI compiler",
        "headers": {},
        "html": [r"svelte-[a-z0-9]+", r"__svelte__"],
        "scripts": [r"svelte[.-]"],
        "meta": {},
    },
    {
        "name": "Angular",
        "category": CATEGORY_FRONTEND,
        "description": "TypeScript-based enterprise web application framework",
        "headers": {},
        "html": [r'ng-version="([^"]+)"', r"ng-app", r"ng-binding", r"_ngcontent-"],
        "scripts": [r"angular(?:\.min)?\.js", r"@angular/core"],
        "meta": {},
    },
    {
        "name": "Astro",
        "category": CATEGORY_FRONTEND,
        "description": "Content-focused web framework with zero-JS by default",
        "headers": {},
        "html": [r'astro-island(?:\s|>)', r"astro-[a-z0-9]+"],
        "scripts": [r"/_astro/"],
        "meta": {"generator": r"Astro(?:\s+v?([\d\.]+))?"},
    },
    {
        "name": "Gatsby",
        "category": CATEGORY_FRONTEND,
        "description": "React-based static site generator with GraphQL data layer",
        "headers": {},
        "html": [r'<div id="___gatsby"', r"___gatsby"],
        "scripts": [r"/gatsby-"],
        "meta": {"generator": r"Gatsby(?:\s+v?([\d\.]+))?"},
    },
    {
        "name": "Remix",
        "category": CATEGORY_FRONTEND,
        "description": "Full-stack React framework focused on web standards",
        "headers": {},
        "html": [r"window\.__remixContext", r"__remixContext"],
        "scripts": [r"/build/_shared/"],
        "meta": {},
    },
    {
        "name": "Tailwind CSS",
        "category": CATEGORY_FRONTEND,
        "description": "Utility-first CSS framework for rapid UI development",
        "headers": {},
        "html": [r'class="[^"]*(?:flex|grid|items-center|justify-between|text-gray-|bg-slate-|rounded-lg)[^"]*"'],
        "scripts": [r"tailwindcss"],
        "meta": {},
    },
    {
        "name": "Bootstrap",
        "category": CATEGORY_FRONTEND,
        "description": "Popular responsive CSS and JavaScript UI toolkit",
        "headers": {},
        "html": [r'class="[^"]*(?:container-fluid|col-md-\d+|navbar-expand)[^"]*"', r"bootstrap(?:\.min)?\.css"],
        "scripts": [r"bootstrap(?:\.bundle)?(?:\.min)?\.js"],
        "meta": {},
    },
    {
        "name": "jQuery",
        "category": CATEGORY_FRONTEND,
        "description": "Fast, small, feature-rich legacy JavaScript library",
        "headers": {},
        "html": [],
        "scripts": [r"jquery(?:\-([\d\.]+))?(?:\.min)?\.js"],
        "meta": {},
    },

    # --- CMS & Site Builders ---
    {
        "name": "WordPress",
        "category": CATEGORY_CMS,
        "description": "World's leading open-source content management system",
        "headers": {"x-powered-by": r"wp", "link": r"wp-json"},
        "html": [r"/wp-content/", r"/wp-includes/", r"wp-block-"],
        "scripts": [r"/wp-content/", r"/wp-includes/"],
        "meta": {"generator": r"WordPress(?:\s+([\d\.]+))?"},
    },
    {
        "name": "Shopify",
        "category": CATEGORY_CMS,
        "description": "Leading multi-channel commerce platform",
        "headers": {"x-shopify-stage": r".+", "x-shopid": r".+"},
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"Shopify\.shop"],
        "scripts": [r"cdn\.shopify\.com"],
        "meta": {},
    },
    {
        "name": "Webflow",
        "category": CATEGORY_CMS,
        "description": "Visual web design and CMS publishing platform",
        "headers": {},
        "html": [r'data-wf-page="[^"]+"', r'data-wf-site="[^"]+"', r"assets\.website-files\.com"],
        "scripts": [r"webflow(?:\.[a-z0-9]+)?\.js"],
        "meta": {"generator": r"Webflow"},
    },
    {
        "name": "Squarespace",
        "category": CATEGORY_CMS,
        "description": "All-in-one website building and hosting platform",
        "headers": {"x-squarespace-hosted": r".+"},
        "html": [r"static1\.squarespace\.com", r"squarespace-site", r"Squarespace\.Constants"],
        "scripts": [r"static1\.squarespace\.com"],
        "meta": {"generator": r"Squarespace"},
    },
    {
        "name": "Wix",
        "category": CATEGORY_CMS,
        "description": "Cloud-based website creation and management platform",
        "headers": {"x-wix-request-id": r".+"},
        "html": [r"static\.wixstatic\.com", r"wix-warmup-data", r"_wix_browser_sess"],
        "scripts": [r"static\.wixstatic\.com"],
        "meta": {"generator": r"Wix\.com"},
    },
    {
        "name": "Ghost",
        "category": CATEGORY_CMS,
        "description": "Open-source professional publishing platform for creators",
        "headers": {"x-ghost-cache-status": r".+"},
        "html": [r"ghost-portal", r"ghost-search"],
        "scripts": [r"public/ghost\.js"],
        "meta": {"generator": r"Ghost(?:\s+([\d\.]+))?"},
    },
    {
        "name": "Drupal",
        "category": CATEGORY_CMS,
        "description": "Open source enterprise digital experience and CMS framework",
        "headers": {"x-drupal-cache": r".+", "x-generator": r"Drupal"},
        "html": [r"Drupal\.settings", r"/sites/default/files/"],
        "scripts": [r"drupal\.js"],
        "meta": {"generator": r"Drupal(?:\s+([\d\.]+))?"},
    },
    {
        "name": "Joomla",
        "category": CATEGORY_CMS,
        "description": "Popular open-source content management system",
        "headers": {},
        "html": [r"/media/jui/", r"/media/system/js/"],
        "scripts": [r"/media/system/js/core\.js"],
        "meta": {"generator": r"Joomla!(?:\s+([\d\.]+))?"},
    },
    {
        "name": "HubSpot CMS",
        "category": CATEGORY_CMS,
        "description": "Marketing, sales, and content management platform",
        "headers": {"x-hs-cache-config": r".+"},
        "html": [r"js\.hs-scripts\.com", r"hs-content-id"],
        "scripts": [r"js\.hs-scripts\.com", r"js\.hs-analytics\.net"],
        "meta": {"generator": r"HubSpot"},
    },

    # --- Hosting & CDNs ---
    {
        "name": "Vercel",
        "category": CATEGORY_HOSTING,
        "description": "Frontend cloud platform for serverless and edge hosting",
        "headers": {"x-vercel-id": r".+", "x-vercel-cache": r".+", "server": r"Vercel"},
        "html": [],
        "scripts": [],
        "meta": {},
    },
    {
        "name": "Netlify",
        "category": CATEGORY_HOSTING,
        "description": "Cloud hosting platform for modern web architectures",
        "headers": {"x-nf-request-id": r".+", "server": r"Netlify"},
        "html": [],
        "scripts": [],
        "meta": {},
    },
    {
        "name": "Cloudflare",
        "category": CATEGORY_HOSTING,
        "description": "Global edge network, CDN, and DNS infrastructure",
        "headers": {"cf-ray": r".+", "server": r"cloudflare", "cf-cache-status": r".+"},
        "html": [r"cdn-cgi/challenge-platform"],
        "scripts": [r"challenges\.cloudflare\.com"],
        "meta": {},
    },
    {
        "name": "Fastly",
        "category": CATEGORY_HOSTING,
        "description": "Programmable edge cloud and high-performance CDN",
        "headers": {"x-fastly-request-id": r".+", "fastly-debug-digest": r".+"},
        "html": [],
        "scripts": [],
        "meta": {},
    },
    {
        "name": "AWS CloudFront",
        "category": CATEGORY_HOSTING,
        "description": "Amazon Web Services low-latency Content Delivery Network",
        "headers": {"x-amz-cf-id": r".+", "x-amz-cf-pop": r".+", "via": r"CloudFront"},
        "html": [],
        "scripts": [],
        "meta": {},
    },
    {
        "name": "Akamai",
        "category": CATEGORY_HOSTING,
        "description": "Global distributed cloud and enterprise content delivery network",
        "headers": {"x-akamai-transformed": r".+", "x-check-cacheable": r".+"},
        "html": [],
        "scripts": [r"akamai[a-z0-9\.\-]+\.js"],
        "meta": {},
    },
    {
        "name": "GitHub Pages",
        "category": CATEGORY_HOSTING,
        "description": "Static site hosting service directly from GitHub repositories",
        "headers": {"x-github-request-id": r".+", "server": r"GitHub\.com"},
        "html": [],
        "scripts": [],
        "meta": {},
    },
    {
        "name": "Firebase Hosting",
        "category": CATEGORY_HOSTING,
        "description": "Google Firebase production-grade web app hosting",
        "headers": {"x-firebase-hosting": r".+"},
        "html": [r"__/firebase/init\.js"],
        "scripts": [r"www\.gstatic\.com/firebasejs/"],
        "meta": {},
    },
    {
        "name": "Render",
        "category": CATEGORY_HOSTING,
        "description": "Unified cloud platform to build and run apps and sites",
        "headers": {"x-render-origin-server": r".+", "server": r"Render"},
        "html": [],
        "scripts": [],
        "meta": {},
    },

    # --- Analytics & Marketing ---
    {
        "name": "Google Analytics / GTM",
        "category": CATEGORY_ANALYTICS,
        "description": "Google Analytics (GA4/Universal) and Google Tag Manager",
        "headers": {},
        "html": [r"googletagmanager\.com/gtm\.js", r"google-analytics\.com/analytics\.js", r"gtag\s*\(\s*['\"]config['\"]\s*,\s*['\"](G-[A-Z0-9]+|UA-[0-9\-]+)"],
        "scripts": [r"googletagmanager\.com/(?:gtm|gtag)", r"google-analytics\.com/analytics\.js"],
        "meta": {},
    },
    {
        "name": "Meta Pixel",
        "category": CATEGORY_ANALYTICS,
        "description": "Meta (Facebook) advertising and conversion tracking pixel",
        "headers": {},
        "html": [r"connect\.facebook\.net/[a-zA-Z_]+/fbevents\.js", r"fbq\s*\(\s*['\"]init['\"]"],
        "scripts": [r"connect\.facebook\.net/[a-zA-Z_]+/fbevents\.js"],
        "meta": {},
    },
    {
        "name": "PostHog",
        "category": CATEGORY_ANALYTICS,
        "description": "Open-source product analytics and session recording suite",
        "headers": {},
        "html": [r"posthog\.init", r"app\.posthog\.com", r"us\.i\.posthog\.com"],
        "scripts": [r"posthog[a-z0-9\.\-]*\.js"],
        "meta": {},
    },
    {
        "name": "Hotjar",
        "category": CATEGORY_ANALYTICS,
        "description": "Behavior analytics and heatmaps tracking platform",
        "headers": {},
        "html": [r"static\.hotjar\.com/c/hotjar-", r"hjid\s*:"],
        "scripts": [r"static\.hotjar\.com/c/hotjar-"],
        "meta": {},
    },
    {
        "name": "Segment",
        "category": CATEGORY_ANALYTICS,
        "description": "Customer Data Platform (CDP) for telemetry and tracking",
        "headers": {},
        "html": [r"cdn\.segment\.com/analytics\.js", r"analytics\.load\s*\("],
        "scripts": [r"cdn\.segment\.com/analytics\.js"],
        "meta": {},
    },
    {
        "name": "Microsoft Clarity",
        "category": CATEGORY_ANALYTICS,
        "description": "User behavior insights, session replays, and heatmaps tool",
        "headers": {},
        "html": [r"www\.clarity\.ms/tag/", r"clarity\s*\(\s*['\"]init['\"]"],
        "scripts": [r"www\.clarity\.ms/tag/"],
        "meta": {},
    },

    # --- Security & Web Protection ---
    {
        "name": "Cloudflare WAF / Turnstile",
        "category": CATEGORY_SECURITY,
        "description": "Cloudflare Web Application Firewall and smart CAPTCHA challenge",
        "headers": {"cf-chl-bypass": r".+", "cf-mitigated": r".+"},
        "html": [r"challenges\.cloudflare\.com/turnstile", r"cf-turnstile"],
        "scripts": [r"challenges\.cloudflare\.com/turnstile/v0/api\.js"],
        "meta": {},
    },
    {
        "name": "Google reCAPTCHA",
        "category": CATEGORY_SECURITY,
        "description": "Google bot detection and fraud prevention CAPTCHA service",
        "headers": {},
        "html": [r"www\.google\.com/recaptcha/api\.js", r"grecaptcha\.execute", r"g-recaptcha"],
        "scripts": [r"www\.google\.com/recaptcha/api\.js"],
        "meta": {},
    },
    {
        "name": "HSTS Security",
        "category": CATEGORY_SECURITY,
        "description": "HTTP Strict Transport Security enforcement header",
        "headers": {"strict-transport-security": r"max-age=\d+"},
        "html": [],
        "scripts": [],
        "meta": {},
    },
    {
        "name": "Content Security Policy (CSP)",
        "category": CATEGORY_SECURITY,
        "description": "W3C Content Security Policy mitigating XSS and data injections",
        "headers": {"content-security-policy": r".+"},
        "html": [r'<meta[^>]+http-equiv=[\'"]Content-Security-Policy[\'"]'],
        "scripts": [],
        "meta": {"content-security-policy": r".+"},
    },

    # --- Backend & Server Stacks ---
    {
        "name": "Laravel",
        "category": CATEGORY_BACKEND,
        "description": "PHP web application framework with elegant syntax",
        "headers": {"set-cookie": r"laravel_session", "x-powered-by": r"laravel"},
        "html": [r'name="csrf-token"\s+content="[^"]+"', r"laravel_session"],
        "scripts": [],
        "meta": {},
    },
    {
        "name": "Django",
        "category": CATEGORY_BACKEND,
        "description": "High-level Python web framework encouraging clean design",
        "headers": {"set-cookie": r"csrftoken"},
        "html": [r'name="csrfmiddlewaretoken"'],
        "scripts": [],
        "meta": {},
    },
    {
        "name": "Express.js",
        "category": CATEGORY_BACKEND,
        "description": "Fast, unopinionated, minimalist web framework for Node.js",
        "headers": {"x-powered-by": r"Express"},
        "html": [],
        "scripts": [],
        "meta": {},
    },
    {
        "name": "Ruby on Rails",
        "category": CATEGORY_BACKEND,
        "description": "Model-view-controller framework in Ruby",
        "headers": {"x-powered-by": r"Phusion Passenger", "set-cookie": r"_session_id"},
        "html": [r'name="csrf-param"\s+content="authenticity_token"'],
        "scripts": [],
        "meta": {},
    },
]


class TechnologyProfiler:
    """Enterprise technology stack profiler and fingerprint analyzer."""

    def __init__(self, fingerprints: Optional[List[Dict[str, Any]]] = None) -> None:
        """Initialize profiler with default or custom fingerprint definitions.

        Args:
            fingerprints: Optional custom fingerprint list.
        """
        self.fingerprints = (
            fingerprints if fingerprints is not None else TECH_FINGERPRINTS
        )

    def extract_meta_tags(self, html: str) -> Dict[str, str]:
        """Extract name/property and content pairs from HTML meta elements.

        Args:
            html: Raw HTML document string.

        Returns:
            Dict[str, str]: Normalized lowercase meta key-value pairs.
        """
        meta_dict: Dict[str, str] = {}
        # Match <meta ...>
        meta_tags = re.findall(r"<meta\b[^>]*>", html, re.IGNORECASE)
        for tag in meta_tags:
            name_match = re.search(r'(?:name|property|http-equiv)=(?:"([^"]+)"|\'([^\']+)\')', tag, re.IGNORECASE)
            content_match = re.search(r'content=(?:"([^"]*)"|\'([^\']*)\')', tag, re.IGNORECASE)
            if name_match and content_match:
                key = (name_match.group(1) if name_match.group(1) is not None else name_match.group(2)).strip().lower()
                val = (content_match.group(1) if content_match.group(1) is not None else content_match.group(2)).strip()
                meta_dict[key] = val
        return meta_dict

    def extract_scripts(self, html: str) -> List[str]:
        """Extract script src attributes and inline script contents.

        Args:
            html: Raw HTML document string.

        Returns:
            List[str]: Combined list of script URLs and inline blocks.
        """
        scripts: List[str] = []
        # Extract src attributes
        src_matches = re.findall(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\']', html, re.IGNORECASE)
        scripts.extend(src_matches)

        # Extract inline script content chunks
        inline_matches = re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL)
        for inline in inline_matches:
            s = inline.strip()
            if s:
                # Add snippet of inline script
                scripts.append(s[:2000])
        return scripts

    def check_security_headers(self, headers: Dict[str, str]) -> Tuple[Dict[str, bool], int]:
        """Audit HTTP response headers against standard web security benchmarks.

        Args:
            headers: Normalized lowercase header dictionary.

        Returns:
            Tuple[Dict[str, bool], int]: (Header presence map, 0-100 security score).
        """
        checks = {
            "hsts": "strict-transport-security" in headers,
            "csp": "content-security-policy" in headers or "content-security-policy-report-only" in headers,
            "x_frame_options": "x-frame-options" in headers,
            "x_content_type_options": "x-content-type-options" in headers,
            "referrer_policy": "referrer-policy" in headers,
            "permissions_policy": "permissions-policy" in headers or "feature-policy" in headers,
        }

        # Weighting
        weights = {
            "hsts": 25,
            "csp": 25,
            "x_frame_options": 15,
            "x_content_type_options": 15,
            "referrer_policy": 10,
            "permissions_policy": 10,
        }

        score = sum(weights[k] for k, present in checks.items() if present)
        return checks, score

    def profile_html(
        self,
        html: str,
        headers: Optional[Dict[str, str]] = None,
        url: str = "",
        status_code: int = 200,
    ) -> TechProfileResult:
        """Analyze HTML content and HTTP headers to detect technology fingerprints.

        Args:
            html: Raw HTML response body.
            headers: Raw or normalized HTTP response headers.
            url: Target URL string.
            status_code: HTTP response status code.

        Returns:
            TechProfileResult: Complete technology profile and category breakdown.
        """
        norm_headers: Dict[str, str] = {}
        if headers:
            for k, v in headers.items():
                norm_headers[str(k).strip().lower()] = str(v).strip()

        server = norm_headers.get("server")
        meta_tags = self.extract_meta_tags(html)
        scripts = self.extract_scripts(html)

        matched_technologies: List[TechnologyMatch] = []
        categories_map: Dict[str, List[str]] = {}

        for fp in self.fingerprints:
            name = fp["name"]
            category = fp["category"]
            matched_by: List[str] = []
            confidence_points = 0
            version: Optional[str] = None

            # 1. Header Checks
            header_rules: Dict[str, str] = fp.get("headers", {})
            for h_key, h_pattern in header_rules.items():
                val = norm_headers.get(h_key.lower())
                if val:
                    m = re.search(h_pattern, val, re.IGNORECASE)
                    if m:
                        matched_by.append(f"header: {h_key}={val}")
                        confidence_points += 45
                        if m.groups() and m.group(1):
                            version = m.group(1)

            # 2. Meta Tag Checks
            meta_rules: Dict[str, str] = fp.get("meta", {})
            for m_key, m_pattern in meta_rules.items():
                m_val = meta_tags.get(m_key.lower())
                if m_val:
                    m = re.search(m_pattern, m_val, re.IGNORECASE)
                    if m:
                        matched_by.append(f"meta: {m_key}={m_val}")
                        confidence_points += 40
                        if m.groups() and m.group(1):
                            version = m.group(1)

            # 3. HTML Pattern Checks
            html_rules: List[str] = fp.get("html", [])
            for pattern in html_rules:
                m = re.search(pattern, html, re.IGNORECASE)
                if m:
                    snippet = m.group(0)[:50]
                    matched_by.append(f"html: {snippet}")
                    confidence_points += 30
                    if m.groups() and m.group(1):
                        version = version or m.group(1)

            # 4. Script Checks
            script_rules: List[str] = fp.get("scripts", [])
            for script_pattern in script_rules:
                for s in scripts:
                    m = re.search(script_pattern, s, re.IGNORECASE)
                    if m:
                        matched_by.append(f"script: {s[:50]}")
                        confidence_points += 35
                        if m.groups() and m.group(1):
                            version = version or m.group(1)
                        break

            if matched_by:
                confidence = min(100, max(20, confidence_points))
                match = TechnologyMatch(
                    name=name,
                    category=category,
                    confidence=confidence,
                    matched_by=matched_by,
                    version=version,
                    description=fp.get("description", ""),
                )
                matched_technologies.append(match)
                categories_map.setdefault(category, []).append(name)

        # Sort technologies by confidence descending
        matched_technologies.sort(key=lambda t: t.confidence, reverse=True)

        # Compute overall confidence
        if matched_technologies:
            overall_conf = int(
                sum(t.confidence for t in matched_technologies)
                / len(matched_technologies)
            )
        else:
            overall_conf = 0

        # Audit security headers
        sec_checks, sec_score = self.check_security_headers(norm_headers)

        return TechProfileResult(
            url=url,
            status_code=status_code,
            server=server,
            technologies=matched_technologies,
            categories=categories_map,
            overall_confidence=overall_conf,
            security_headers=sec_checks,
            security_score=sec_score,
            headers=norm_headers,
        )

    def profile_url(
        self,
        url: str,
        timeout: float = 6.0,
        user_agent: str = "Mozilla/5.0 (compatible; SubSweepLeadScanner/1.0)",
    ) -> TechProfileResult:
        """Fetch remote URL and execute full technology profiling scan.

        Args:
            url: Target web address.
            timeout: Network request timeout in seconds.
            user_agent: HTTP User-Agent string.

        Returns:
            TechProfileResult: Technology stack profile findings.
        """
        target_url = url
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status_code = response.status
                headers_dict = dict(response.headers)
                raw_bytes = response.read(1024 * 512)  # Read up to 512KB
                html_text = raw_bytes.decode("utf-8", errors="replace")
                return self.profile_html(
                    html=html_text,
                    headers=headers_dict,
                    url=target_url,
                    status_code=status_code,
                )
        except urllib.error.HTTPError as exc:
            headers_dict = dict(exc.headers) if hasattr(exc, "headers") else {}
            return self.profile_html(
                html="",
                headers=headers_dict,
                url=target_url,
                status_code=exc.code,
            )
        except Exception as exc:
            logger.debug("Failed to profile URL %s: %s", target_url, exc)
            return TechProfileResult(
                url=target_url,
                status_code=0,
                headers={},
            )
