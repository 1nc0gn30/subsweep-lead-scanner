"""Lead intelligence and business data extraction engine for subsweep-lead-scanner.

Extracts emails, international phone numbers, social media profiles, and Schema.org
JSON-LD LocalBusiness / Organization structured metadata from HTML content,
calculating an accurate Lead Quality Score (0-100).
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import html as html_parser
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Union
import urllib.parse

logger = logging.getLogger(__name__)

# File extensions to ignore when matching email patterns
IGNORE_EMAIL_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico",
    "css", "js", "ts", "jsx", "tsx", "map", "json",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "mp3", "webm", "wav", "avi", "mov",
    "pdf", "zip", "tar", "gz", "rar",
}

# Domain exclusions for dummy/sample emails
IGNORE_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net",
    "domain.com", "email.com", "test.com", "sample.com",
    "yoursite.com", "yourdomain.com", "mysite.com",
    "sentry.io", "w3.org", "schema.org", "github.com",
    "sentry-cdn.com", "gravatar.com",
}


@dataclass
class AddressData:
    """Structured postal address representation."""

    street_address: str = ""
    locality: str = ""  # City / Town
    region: str = ""  # State / Province / County
    postal_code: str = ""  # ZIP / Postal code
    country: str = ""
    formatted: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize address to dictionary."""
        return asdict(self)


@dataclass
class GeoCoordinates:
    """Latitude and longitude coordinates."""

    latitude: Optional[float] = None
    longitude: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize coordinates to dictionary."""
        return asdict(self)


@dataclass
class RatingData:
    """Customer review ratings and counts."""

    rating_value: Optional[float] = None
    review_count: Optional[int] = None
    best_rating: Optional[float] = None
    worst_rating: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize rating to dictionary."""
        return asdict(self)


@dataclass
class BusinessEntity:
    """Schema.org LocalBusiness or Organization entity."""

    name: str = ""
    entity_type: str = "Organization"
    description: str = ""
    url: str = ""
    email: Optional[str] = None
    telephone: Optional[str] = None
    address: Optional[AddressData] = None
    geo: Optional[GeoCoordinates] = None
    rating: Optional[RatingData] = None
    opening_hours: List[str] = field(default_factory=list)
    price_range: str = ""
    same_as: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize business entity to dictionary."""
        return {
            "name": self.name,
            "entity_type": self.entity_type,
            "description": self.description,
            "url": self.url,
            "email": self.email,
            "telephone": self.telephone,
            "address": self.address.to_dict() if self.address else None,
            "geo": self.geo.to_dict() if self.geo else None,
            "rating": self.rating.to_dict() if self.rating else None,
            "opening_hours": self.opening_hours,
            "price_range": self.price_range,
            "same_as": self.same_as,
        }


@dataclass
class LeadData:
    """Consolidated business lead record."""

    url: str = ""
    domain: str = ""
    company_name: Optional[str] = None
    emails: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)
    socials: Dict[str, List[str]] = field(default_factory=dict)
    entities: List[BusinessEntity] = field(default_factory=list)
    address: Optional[AddressData] = None
    geo: Optional[GeoCoordinates] = None
    rating: Optional[RatingData] = None
    has_ssl: bool = False
    lead_quality_score: int = 0
    extracted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete lead to dictionary."""
        return {
            "url": self.url,
            "domain": self.domain,
            "company_name": self.company_name,
            "emails": self.emails,
            "phones": self.phones,
            "socials": self.socials,
            "entities": [e.to_dict() for e in self.entities],
            "address": self.address.to_dict() if self.address else None,
            "geo": self.geo.to_dict() if self.geo else None,
            "rating": self.rating.to_dict() if self.rating else None,
            "has_ssl": self.has_ssl,
            "lead_quality_score": self.lead_quality_score,
            "extracted_at": self.extracted_at,
        }


class LeadExtractor:
    """High-accuracy OSINT lead harvester and Schema.org business analyzer."""

    # RFC 5322 compliant regex for matching emails in text and links
    EMAIL_REGEX = re.compile(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        re.IGNORECASE,
    )

    # Social platform domain mapping
    SOCIAL_PLATFORMS: Dict[str, re.Pattern] = {
        "twitter": re.compile(r"https?://(?:www\.)?(?:twitter\.com|x\.com)/([a-zA-Z0-9_]{1,30})/?", re.IGNORECASE),
        "linkedin": re.compile(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:company|in|school)/([a-zA-Z0-9_\-\.%]+)/?", re.IGNORECASE),
        "github": re.compile(r"https?://(?:www\.)?github\.com/([a-zA-Z0-9_\-]+)/?", re.IGNORECASE),
        "facebook": re.compile(r"https?://(?:www\.)?facebook\.com/([a-zA-Z0-9_\-\.]+)/?", re.IGNORECASE),
        "instagram": re.compile(r"https?://(?:www\.)?instagram\.com/([a-zA-Z0-9_\-\.]+)/?", re.IGNORECASE),
        "youtube": re.compile(r"https?://(?:www\.)?youtube\.com/(?:@[a-zA-Z0-9_\-]+|channel/[a-zA-Z0-9_\-]+|c/[a-zA-Z0-9_\-]+)/?", re.IGNORECASE),
        "discord": re.compile(r"https?://(?:www\.)?(?:discord\.gg|discord\.com/invite)/([a-zA-Z0-9_\-]+)/?", re.IGNORECASE),
        "tiktok": re.compile(r"https?://(?:www\.)?tiktok\.com/@([a-zA-Z0-9_\-\.]+)/?", re.IGNORECASE),
    }

    # Social profile path blocklist (ignore generic share/intent URLs)
    SOCIAL_BLOCKLIST = {
        "share", "sharer", "sharearticle", "intent", "home", "search",
        "login", "signup", "terms", "privacy", "help", "about", "status",
        "hashtag", "explore", "messages", "notifications", "settings",
    }

    def clean_text(self, text: str) -> str:
        """Unescape HTML entities and normalize whitespace."""
        unescaped = html_parser.unescape(text)
        return unescaped

    def extract_emails(self, html: str) -> List[str]:
        """Harvest, validate, and deduplicate business email addresses.

        Handles mailto links, raw text occurrences, and obfuscated formats.

        Args:
            html: HTML page content.

        Returns:
            List[str]: List of unique, normalized email addresses.
        """
        raw_text = self.clean_text(html)

        # 1. De-obfuscate common patterns: user [at] domain.com, user(at)domain[dot]com
        deobf_text = re.sub(r"\s*\[at\]\s*|\s*\(at\)\s*|\s*\{\s*at\s*\}\s*", "@", raw_text, flags=re.IGNORECASE)
        deobf_text = re.sub(r"\s*\[dot\]\s*|\s*\(dot\)\s*|\s*\{\s*dot\s*\}\s*", ".", deobf_text, flags=re.IGNORECASE)

        # 2. Extract mailto: links specifically
        mailto_matches = re.findall(r'mailto:\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', raw_text, re.IGNORECASE)

        # 3. Extract all email pattern matches from document
        all_matches = self.EMAIL_REGEX.findall(deobf_text)
        combined = set(mailto_matches + all_matches)

        valid_emails: Set[str] = set()
        for candidate in combined:
            email = candidate.strip().lower().rstrip(".,;:)'\"")

            # Check basic structure
            if "@" not in email:
                continue
            parts = email.split("@")
            if len(parts) != 2:
                continue
            local_part, domain_part = parts

            if not local_part or not domain_part:
                continue

            # Check domain part structure
            domain_split = domain_part.split(".")
            if len(domain_split) < 2:
                continue

            tld = domain_split[-1]

            # Filter asset extensions (e.g., photo@2x.png, font.woff2)
            if tld in IGNORE_EMAIL_EXTENSIONS:
                continue

            # Filter dummy / blocked domains
            if domain_part in IGNORE_EMAIL_DOMAINS:
                continue

            # Filter dummy local parts
            if local_part in {"yourname", "username", "user", "name", "email"}:
                continue

            # Disallow trailing or leading invalid characters
            if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
                valid_emails.add(email)

        return sorted(valid_emails)

    def extract_phones(self, html: str) -> List[str]:
        """Harvest international and local business phone numbers.

        Extracts from tel: href attributes and text phone patterns.

        Args:
            html: HTML document string.

        Returns:
            List[str]: List of unique normalized phone numbers.
        """
        raw_text = self.clean_text(html)
        discovered: Set[str] = set()

        # 1. Extract tel: links
        tel_matches = re.findall(r'href=["\']tel:([^"\']+)["\']', raw_text, re.IGNORECASE)
        for tm in tel_matches:
            cleaned = re.sub(r"[^\d+]", "", tm)
            if 7 <= len(re.sub(r"\D", "", cleaned)) <= 15:
                discovered.add(tm.strip())

        # 2. Extract structured telephone meta/text patterns
        phone_patterns = [
            # +1 (XXX) XXX-XXXX or +1-XXX-XXX-XXXX or +44 XX XXXX XXXX
            r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
            # International with plus: +44 20 7123 4567 / +49 30 1234567
            r"\+\d{1,3}[-.\s]\d{1,4}[-.\s]\d{3,4}[-.\s]\d{3,4}",
            # Standard US: (XXX) XXX-XXXX
            r"\(\d{3}\)\s*\d{3}-\d{4}",
        ]

        # Strip scripts, styles, SVG paths, and numbers inside HTML tags to prevent false positives
        no_scripts = re.sub(r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", "", raw_text, flags=re.IGNORECASE)
        no_styles = re.sub(r"<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>", "", no_scripts, flags=re.IGNORECASE)
        no_tags = re.sub(r"<[^>]+>", " ", no_styles)

        for pattern in phone_patterns:
            matches = re.findall(pattern, no_tags)
            for m in matches:
                phone_str = m.strip()
                digits_only = re.sub(r"\D", "", phone_str)
                # Ensure digit count fits standard phone numbers (7 to 15 digits)
                if 10 <= len(digits_only) <= 15:
                    # Filter out dates like 2024-01-01 or IP-like numbers
                    if not re.match(r"^(?:19|20)\d\d[-/]\d\d[-/]\d\d", phone_str):
                        discovered.add(phone_str)

        # Normalize and deduplicate
        normalized: List[str] = []
        seen_digits: Set[str] = set()
        for p in sorted(discovered):
            digits = re.sub(r"\D", "", p)
            if digits not in seen_digits:
                seen_digits.add(digits)
                normalized.append(p)

        return normalized

    def extract_socials(self, html: str) -> Dict[str, List[str]]:
        """Extract links to social media business accounts.

        Args:
            html: HTML document string.

        Returns:
            Dict[str, List[str]]: Map of social platform to list of profile URLs.
        """
        socials_map: Dict[str, List[str]] = {}
        # Find all href attributes
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)

        for href in hrefs:
            url_clean = href.strip()
            if not url_clean.startswith("http"):
                continue

            for platform, pattern in self.SOCIAL_PLATFORMS.items():
                match = pattern.search(url_clean)
                if match:
                    # Verify handle is not in blocklist
                    handle = match.group(1).lower().strip("/?")
                    if handle not in self.SOCIAL_BLOCKLIST and len(handle) > 1:
                        # Normalize URL
                        clean_url = match.group(0).rstrip("/")
                        social_list = socials_map.setdefault(platform, [])
                        if clean_url not in social_list:
                            social_list.append(clean_url)

        return socials_map

    def parse_json_ld(self, html: str) -> List[BusinessEntity]:
        """Extract and parse Schema.org LocalBusiness and Organization entities.

        Args:
            html: HTML document string.

        Returns:
            List[BusinessEntity]: Discovered structured business entities.
        """
        entities: List[BusinessEntity] = []
        # Find all <script type="application/ld+json"> blocks
        blocks = re.findall(
            r'<script\b[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
            html,
            re.IGNORECASE | re.DOTALL,
        )

        for block in blocks:
            raw_json = block.strip()
            if not raw_json:
                continue
            try:
                data = json.loads(raw_json)
                self._extract_entities_from_json_node(data, entities)
            except Exception:
                continue

        return entities

    def _extract_entities_from_json_node(
        self,
        node: Any,
        out_list: List[BusinessEntity],
    ) -> None:
        """Recursively search a JSON-LD data node for business entities."""
        if isinstance(node, list):
            for item in node:
                self._extract_entities_from_json_node(item, out_list)
            return

        if not isinstance(node, dict):
            return

        # Check @graph container
        if "@graph" in node and isinstance(node["@graph"], list):
            for item in node["@graph"]:
                self._extract_entities_from_json_node(item, out_list)
            return

        node_type = node.get("@type")
        types_to_check: List[str] = []
        if isinstance(node_type, list):
            types_to_check = [str(t) for t in node_type]
        elif isinstance(node_type, str):
            types_to_check = [node_type]

        # Target business / organization schemas
        target_keywords = (
            "organization", "localbusiness", "corporation", "store", "restaurant",
            "medicalbusiness", "legalservice", "financialservice", "professionalservice",
            "generalcontractor", "dentist", "physician", "accountingservice",
            "automotivebusiness", "childcare", "emergencyservice", "entertainmentbusiness",
            "foodestablishment", "governmentoffice", "healthandbeautybusiness", "homegoodsstore",
            "insuranceagency", "lodgingbusiness", "shoppingcenter", "sportsactivitylocation",
            "travelagency", "realestateagent",
        )

        is_match = any(
            any(kw in t.lower() for kw in target_keywords)
            for t in types_to_check
        )

        if is_match:
            entity = self._parse_single_business_entity(node, types_to_check[0] if types_to_check else "Organization")
            if entity.name or entity.telephone or entity.address or entity.email:
                out_list.append(entity)

        # Recursively search child objects
        for val in node.values():
            if isinstance(val, (dict, list)):
                self._extract_entities_from_json_node(val, out_list)

    def _parse_single_business_entity(self, data: Dict[str, Any], entity_type: str) -> BusinessEntity:
        """Parse dictionary fields into a structured BusinessEntity."""
        name = str(data.get("name") or data.get("legalName") or "").strip()
        desc = str(data.get("description") or "").strip()
        url = str(data.get("url") or "").strip()
        tel = str(data.get("telephone") or "").strip() or None
        email = str(data.get("email") or "").strip() or None
        price_range = str(data.get("priceRange") or "").strip()

        # Opening Hours
        opening_hours: List[str] = []
        raw_hours = data.get("openingHours") or data.get("openingHoursSpecification")
        if isinstance(raw_hours, list):
            for h in raw_hours:
                if isinstance(h, str):
                    opening_hours.append(h)
                elif isinstance(h, dict):
                    days = h.get("dayOfWeek", "")
                    opens = h.get("opens", "")
                    closes = h.get("closes", "")
                    opening_hours.append(f"{days}: {opens}-{closes}".strip())
        elif isinstance(raw_hours, str):
            opening_hours.append(raw_hours)

        # SameAs
        same_as: List[str] = []
        raw_same_as = data.get("sameAs")
        if isinstance(raw_same_as, list):
            same_as = [str(s) for s in raw_same_as if isinstance(s, str)]
        elif isinstance(raw_same_as, str):
            same_as = [raw_same_as]

        # Address
        address_obj: Optional[AddressData] = None
        raw_addr = data.get("address")
        if isinstance(raw_addr, dict):
            street = str(raw_addr.get("streetAddress") or "").strip()
            locality = str(raw_addr.get("addressLocality") or "").strip()
            region = str(raw_addr.get("addressRegion") or "").strip()
            postal = str(raw_addr.get("postalCode") or "").strip()
            country = str(raw_addr.get("addressCountry") or "").strip()

            formatted_parts = [p for p in (street, locality, region, postal, country) if p]
            formatted = ", ".join(formatted_parts)

            address_obj = AddressData(
                street_address=street,
                locality=locality,
                region=region,
                postal_code=postal,
                country=country,
                formatted=formatted,
            )
        elif isinstance(raw_addr, str) and raw_addr.strip():
            address_obj = AddressData(formatted=raw_addr.strip())

        # Geo Coordinates
        geo_obj: Optional[GeoCoordinates] = None
        raw_geo = data.get("geo")
        if isinstance(raw_geo, dict):
            try:
                lat = float(raw_geo.get("latitude")) if raw_geo.get("latitude") is not None else None
                lon = float(raw_geo.get("longitude")) if raw_geo.get("longitude") is not None else None
                if lat is not None and lon is not None:
                    geo_obj = GeoCoordinates(latitude=lat, longitude=lon)
            except (ValueError, TypeError):
                pass

        # Aggregate Rating
        rating_obj: Optional[RatingData] = None
        raw_rating = data.get("aggregateRating")
        if isinstance(raw_rating, dict):
            try:
                val = float(raw_rating.get("ratingValue")) if raw_rating.get("ratingValue") is not None else None
                count = int(raw_rating.get("reviewCount") or raw_rating.get("ratingCount") or 0)
                best = float(raw_rating.get("bestRating")) if raw_rating.get("bestRating") is not None else 5.0
                worst = float(raw_rating.get("worstRating")) if raw_rating.get("worstRating") is not None else 1.0
                rating_obj = RatingData(
                    rating_value=val,
                    review_count=count,
                    best_rating=best,
                    worst_rating=worst,
                )
            except (ValueError, TypeError):
                pass

        return BusinessEntity(
            name=name,
            entity_type=entity_type,
            description=desc,
            url=url,
            email=email,
            telephone=tel,
            address=address_obj,
            geo=geo_obj,
            rating=rating_obj,
            opening_hours=opening_hours,
            price_range=price_range,
            same_as=same_as,
        )

    def calculate_lead_score(
        self,
        emails: List[str],
        phones: List[str],
        address: Optional[AddressData],
        socials: Dict[str, List[str]],
        has_ssl: bool,
    ) -> int:
        """Calculate Lead Quality Score (0-100) based on data completeness.

        Weighting breakdown:
        - Verified Email(s): +25
        - Verified Phone(s): +25
        - Physical Address / Geo: +20
        - Social Profiles: +15
        - Valid SSL / HTTPS: +15

        Args:
            emails: List of extracted emails.
            phones: List of extracted phone numbers.
            address: Extracted physical address object.
            socials: Extracted social media links.
            has_ssl: Flag indicating SSL/TLS is active.

        Returns:
            int: Quality score clamped to [0, 100].
        """
        score = 0
        if emails and len(emails) > 0:
            score += 25
        if phones and len(phones) > 0:
            score += 25
        if address and (address.formatted or address.street_address or address.locality):
            score += 20
        if socials and sum(len(v) for v in socials.values()) > 0:
            score += 15
        if has_ssl:
            score += 15

        return min(100, max(0, score))

    def extract_from_html(
        self,
        html: str,
        url: str = "",
        has_ssl: bool = False,
    ) -> LeadData:
        """Execute full lead harvesting pipeline on HTML document.

        Args:
            html: HTML document string.
            url: Origin URL of the target.
            has_ssl: Whether the source connection has valid SSL.

        Returns:
            LeadData: Structured business intelligence and quality score.
        """
        domain = ""
        is_https = has_ssl
        if url:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc or parsed.path
            if parsed.scheme == "https":
                is_https = True

        emails = self.extract_emails(html)
        phones = self.extract_phones(html)
        socials = self.extract_socials(html)
        entities = self.parse_json_ld(html)

        primary_address: Optional[AddressData] = None
        primary_geo: Optional[GeoCoordinates] = None
        primary_rating: Optional[RatingData] = None
        company_name: Optional[str] = None

        if entities:
            # Pick first rich entity
            e = entities[0]
            if e.name:
                company_name = e.name
            if e.address:
                primary_address = e.address
            if e.geo:
                primary_geo = e.geo
            if e.rating:
                primary_rating = e.rating
            if e.email and e.email not in emails:
                emails.append(e.email)
            if e.telephone and e.telephone not in phones:
                phones.append(e.telephone)

        # Fallback company name from title / meta
        if not company_name:
            title_match = re.search(r"<title\b[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            if title_match:
                t = self.clean_text(title_match.group(1)).strip()
                # Split at | or -
                company_name = re.split(r"[-|–—]", t)[0].strip() or t

        score = self.calculate_lead_score(
            emails=emails,
            phones=phones,
            address=primary_address,
            socials=socials,
            has_ssl=is_https,
        )

        return LeadData(
            url=url,
            domain=domain,
            company_name=company_name,
            emails=emails,
            phones=phones,
            socials=socials,
            entities=entities,
            address=primary_address,
            geo=primary_geo,
            rating=primary_rating,
            has_ssl=is_https,
            lead_quality_score=score,
        )
