"""Subdomain enumeration and DNS reconnaissance engine for subsweep-lead-scanner.

Features:
- Passive Certificate Transparency (crt.sh) discovery
- Wordlist permutation generation
- Concurrency-driven DNS resolution with socket.getaddrinfo
- Wildcard DNS detection and duplicate IP filtering
- Structured subdomain discovery tree with latency metrics
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import re
import socket
import time
from typing import Any, Callable, Dict, List, Optional, Set
import urllib.error
import urllib.parse
import urllib.request
import uuid

logger = logging.getLogger(__name__)

DEFAULT_SUBDOMAIN_WORDLIST: List[str] = [
    "www",
    "api",
    "app",
    "dev",
    "stage",
    "mail",
    "admin",
    "cdn",
    "auth",
    "portal",
    "docs",
    "status",
    "test",
    "blog",
    "vpn",
    "shop",
    "beta",
    "m",
    "secure",
    "hub",
]


@dataclass
class SubdomainResult:
    """Individual subdomain resolution record."""

    subdomain: str
    domain: str
    ips: List[str] = field(default_factory=list)
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    status: str = "unresolved"  # 'resolved', 'wildcard_filtered', 'unresolved', 'timeout', 'error'
    latency_ms: float = 0.0
    is_wildcard: bool = False
    source: str = "unknown"  # 'crtsh', 'wordlist', 'manual'
    resolved_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize record to dictionary."""
        return asdict(self)


@dataclass
class EnumerationSummary:
    """Consolidated summary of subdomain enumeration scan."""

    domain: str
    total_candidates: int = 0
    resolved_count: int = 0
    wildcard_detected: bool = False
    wildcard_ips: List[str] = field(default_factory=list)
    unique_ips: List[str] = field(default_factory=list)
    results: List[SubdomainResult] = field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize summary to dictionary."""
        return {
            "domain": self.domain,
            "total_candidates": self.total_candidates,
            "resolved_count": self.resolved_count,
            "wildcard_detected": self.wildcard_detected,
            "wildcard_ips": self.wildcard_ips,
            "unique_ips": self.unique_ips,
            "duration_seconds": round(self.duration_seconds, 3),
            "timestamp": self.timestamp,
            "results": [r.to_dict() for r in self.results],
        }

    def tree(self) -> Dict[str, Any]:
        """Generate a hierarchical discovery tree grouped by status and IPs."""
        resolved_tree: Dict[str, List[Dict[str, Any]]] = {}
        by_ip: Dict[str, List[str]] = {}

        for res in self.results:
            if res.status == "resolved":
                for ip in res.ips:
                    by_ip.setdefault(ip, []).append(res.subdomain)

        return {
            "domain": self.domain,
            "wildcard_detected": self.wildcard_detected,
            "stats": {
                "total_tested": self.total_candidates,
                "resolved": self.resolved_count,
                "unique_ips_count": len(self.unique_ips),
            },
            "ip_mapping": by_ip,
            "subdomains": [
                {
                    "subdomain": r.subdomain,
                    "ips": r.ips,
                    "status": r.status,
                    "latency_ms": round(r.latency_ms, 2),
                    "source": r.source,
                }
                for r in self.results
                if r.status == "resolved"
            ],
        }


class SubdomainEnumerator:
    """High-performance passive & active subdomain enumeration engine."""

    def __init__(
        self,
        user_agent: str = "Mozilla/5.0 (compatible; SubSweepLeadScanner/1.0)",
        dns_resolver: Optional[
            Callable[[str], List[tuple]]
        ] = None,
    ) -> None:
        """Initialize the subdomain enumerator.

        Args:
            user_agent: Custom HTTP user-agent header for passive queries.
            dns_resolver: Optional custom DNS resolution function for testing/dependency injection.
        """
        self.user_agent = user_agent
        self._custom_resolver = dns_resolver

    def clean_domain(self, domain: str) -> str:
        """Sanitize and normalize a root domain name."""
        d = domain.strip().lower()
        if d.startswith("http://") or d.startswith("https://"):
            parsed = urllib.parse.urlparse(d)
            d = parsed.netloc or parsed.path
        # Strip port or trailing slashes/dots
        d = d.split(":")[0].strip("./")
        return d

    def query_crtsh(self, domain: str, timeout: float = 6.0) -> List[str]:
        """Query Certificate Transparency logs via crt.sh for passive subdomain discovery.

        Args:
            domain: Target root domain.
            timeout: Network request timeout in seconds.

        Returns:
            List[str]: Cleaned, deduplicated discovered subdomains.
        """
        clean_d = self.clean_domain(domain)
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(clean_d)}&output=json"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "application/json",
            },
        )

        discovered: Set[str] = set()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status != 200:
                    return []
                raw_data = response.read().decode("utf-8", errors="replace")
                entries = json.loads(raw_data)
                for entry in entries:
                    for key in ("name_value", "common_name"):
                        val = entry.get(key)
                        if isinstance(val, str):
                            # May contain multi-line values or wildcard strings
                            for line in val.split("\n"):
                                item = line.strip().lower()
                                if item.startswith("*."):
                                    item = item[2:]
                                if item.endswith(f".{clean_d}") or item == clean_d:
                                    # Validate domain characters
                                    if re.match(
                                        r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$",
                                        item,
                                    ):
                                        discovered.add(item)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            logger.debug("crt.sh query for %s encountered: %s", clean_d, exc)
            return sorted(discovered)
        except Exception as exc:
            logger.debug("Unexpected error during crt.sh query for %s: %s", clean_d, exc)
            return sorted(discovered)

        return sorted(discovered)

    def generate_permutations(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
    ) -> List[str]:
        """Generate candidate subdomain hostnames from wordlist.

        Args:
            domain: Target root domain.
            wordlist: List of subdomain prefixes (defaults to DEFAULT_SUBDOMAIN_WORDLIST).

        Returns:
            List[str]: List of fully-qualified candidate subdomains.
        """
        clean_d = self.clean_domain(domain)
        words = wordlist if wordlist is not None else DEFAULT_SUBDOMAIN_WORDLIST
        candidates: List[str] = [clean_d]
        for word in words:
            w = word.strip().lower().strip(".")
            if w:
                candidates.append(f"{w}.{clean_d}")
        # Return deduplicated preserving order
        seen: Set[str] = set()
        deduped: List[str] = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                deduped.append(c)
        return deduped

    def check_wildcard(self, domain: str) -> Set[str]:
        """Detect wildcard DNS resolution by querying a non-existent randomized subdomain.

        Args:
            domain: Target root domain.

        Returns:
            Set[str]: Set of resolved IP addresses if wildcard DNS is active, empty set otherwise.
        """
        clean_d = self.clean_domain(domain)
        test_host = f"subsweep-wildcard-{uuid.uuid4().hex[:12]}.{clean_d}"
        ips = self._raw_resolve_ips(test_host)
        return set(ips)

    def _raw_resolve_ips(self, host: str) -> List[str]:
        """Resolve a host to unique IP strings."""
        if self._custom_resolver:
            try:
                results = self._custom_resolver(host)
                ips = [res[4][0] for res in results if len(res) >= 5 and res[4]]
                return sorted(set(ips))
            except Exception:
                return []

        try:
            addr_info = socket.getaddrinfo(
                host, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            ips = [item[4][0] for item in addr_info if len(item) >= 5 and item[4]]
            return sorted(set(ips))
        except (socket.gaierror, socket.herror, OSError):
            return []

    def resolve_subdomain(
        self,
        subdomain: str,
        domain: str,
        wildcard_ips: Optional[Set[str]] = None,
        source: str = "wordlist",
        timeout: float = 2.0,
    ) -> SubdomainResult:
        """Resolve an individual subdomain candidate with latency calculation.

        Args:
            subdomain: Subdomain to resolve.
            domain: Root domain.
            wildcard_ips: Set of wildcard IPs to filter.
            source: Discovery source identifier.
            timeout: Resolution timeout hint.

        Returns:
            SubdomainResult: Detailed resolution result.
        """
        result = SubdomainResult(
            subdomain=subdomain,
            domain=domain,
            source=source,
        )

        start_time = time.perf_counter()
        raw_ips = self._raw_resolve_ips(subdomain)
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        result.latency_ms = max(0.01, latency_ms)

        if not raw_ips:
            result.status = "unresolved"
            return result

        result.ips = raw_ips
        for ip in raw_ips:
            if ":" in ip:
                result.ipv6.append(ip)
            else:
                result.ipv4.append(ip)

        # Check against wildcard DNS
        wildcard_set = wildcard_ips or set()
        if wildcard_set and set(raw_ips) == wildcard_set and subdomain != domain:
            result.is_wildcard = True
            result.status = "wildcard_filtered"
        else:
            result.status = "resolved"

        return result

    def enumerate(
        self,
        domain: str,
        use_crtsh: bool = True,
        use_wordlist: bool = True,
        wordlist: Optional[List[str]] = None,
        max_workers: int = 20,
        timeout: float = 2.0,
    ) -> EnumerationSummary:
        """Execute full subdomain enumeration pipeline.

        Args:
            domain: Target root domain.
            use_crtsh: Enable passive Certificate Transparency query.
            use_wordlist: Enable active wordlist permutation generation.
            wordlist: Custom wordlist prefixes.
            max_workers: Thread pool concurrency limit.
            timeout: DNS query timeout in seconds.

        Returns:
            EnumerationSummary: Scan statistics and list of SubdomainResults.
        """
        start_time = time.perf_counter()
        clean_d = self.clean_domain(domain)

        # 1. Check for wildcard DNS
        wildcard_ips = self.check_wildcard(clean_d)
        wildcard_detected = len(wildcard_ips) > 0

        # 2. Gather candidates
        candidates_dict: Dict[str, str] = {}  # subdomain -> source

        if use_crtsh:
            crt_subs = self.query_crtsh(clean_d)
            for sub in crt_subs:
                candidates_dict[sub] = "crtsh"

        if use_wordlist:
            wordlist_subs = self.generate_permutations(clean_d, wordlist=wordlist)
            for sub in wordlist_subs:
                if sub not in candidates_dict:
                    candidates_dict[sub] = "wordlist"

        # Ensure root domain is present
        if clean_d not in candidates_dict:
            candidates_dict[clean_d] = "root"

        total_candidates = len(candidates_dict)
        results: List[SubdomainResult] = []
        unique_ips: Set[str] = set()

        # 3. Concurrent DNS resolution
        workers = min(max_workers, max(1, total_candidates))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_sub = {
                executor.submit(
                    self.resolve_subdomain,
                    sub,
                    clean_d,
                    wildcard_ips,
                    source,
                    timeout,
                ): sub
                for sub, source in candidates_dict.items()
            }

            for future in as_completed(future_to_sub):
                try:
                    res = future.result()
                    results.append(res)
                    if res.status == "resolved":
                        unique_ips.update(res.ips)
                except Exception as exc:
                    sub = future_to_sub[future]
                    results.append(
                        SubdomainResult(
                            subdomain=sub,
                            domain=clean_d,
                            status="error",
                            source=candidates_dict.get(sub, "unknown"),
                        )
                    )

        # Sort results: root domain first, then resolved alphabetically, then others
        def sort_key(r: SubdomainResult):
            if r.subdomain == clean_d:
                return (0, r.subdomain)
            if r.status == "resolved":
                return (1, r.subdomain)
            return (2, r.subdomain)

        results.sort(key=sort_key)
        resolved_count = sum(1 for r in results if r.status == "resolved")
        duration = time.perf_counter() - start_time

        return EnumerationSummary(
            domain=clean_d,
            total_candidates=total_candidates,
            resolved_count=resolved_count,
            wildcard_detected=wildcard_detected,
            wildcard_ips=sorted(wildcard_ips),
            unique_ips=sorted(unique_ips),
            results=results,
            duration_seconds=duration,
        )
