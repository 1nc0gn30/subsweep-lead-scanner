"""
SubSweep Lead Scanner & Recon Studio
====================================
Pure Python stdlib high-velocity OSINT subdomain reconnaissance,
technology stack fingerprinting, business lead harvester, port prober,
and JSON-RPC 2.0 Model Context Protocol (MCP) server.

Zero external runtime dependencies.
"""

from .compat import (
    atomic_write,
    get_platform_name,
    get_runtime_diagnostics,
    is_linux,
    is_macos,
    is_termux,
    is_windows,
    open_in_browser,
    setup_utf8_output,
    to_posix_path,
)
from .subdomain_finder import (
    DEFAULT_SUBDOMAIN_WORDLIST,
    EnumerationSummary,
    SubdomainEnumerator,
    SubdomainResult,
)
from .tech_profiler import (
    CATEGORY_ANALYTICS,
    CATEGORY_BACKEND,
    CATEGORY_CMS,
    CATEGORY_FRONTEND,
    CATEGORY_HOSTING,
    CATEGORY_SECURITY,
    TechnologyMatch,
    TechnologyProfiler,
    TechProfileResult,
)
from .lead_extractor import (
    AddressData,
    BusinessEntity,
    GeoCoordinates,
    LeadData,
    LeadExtractor,
    RatingData,
)
from .port_prober import (
    DATABASE_PORTS,
    DEFAULT_PORTS,
    INFRASTRUCTURE_PORTS,
    WEB_PORTS,
    HostProbeSummary,
    PortProber,
    PortResult,
)
from .asn_intel import (
    ASNIntelligenceReport,
    lookup_ip_intelligence,
    batch_classify_ips,
)
from .policy_auditor import (
    RobotsDirective,
    RobotsReport,
    SecurityTxtReport,
    RobotsAuditor,
    SecurityTxtAuditor,
    audit_policy_endpoints,
)
from .mcp_server import (
    MCPServer,
    run_mcp_server,
    generate_mcp_client_config,
    enumerate_subdomains,
    fingerprint_tech,
    extract_leads,
    probe_ports,
    full_audit,
    get_diagnostics,
)
from .ui_server import (
    create_ui_server,
    run_ui_server,
)
from .cli import (
    main,
)

__version__ = "1.0.0"
__author__ = "SubSweep Recon Team"
__license__ = "MIT"

__all__ = [
    "__version__",
    "atomic_write",
    "get_platform_name",
    "get_runtime_diagnostics",
    "is_linux",
    "is_macos",
    "is_termux",
    "is_windows",
    "open_in_browser",
    "setup_utf8_output",
    "to_posix_path",
    "DEFAULT_SUBDOMAIN_WORDLIST",
    "EnumerationSummary",
    "SubdomainEnumerator",
    "SubdomainResult",
    "CATEGORY_ANALYTICS",
    "CATEGORY_BACKEND",
    "CATEGORY_CMS",
    "CATEGORY_FRONTEND",
    "CATEGORY_HOSTING",
    "CATEGORY_SECURITY",
    "TechnologyMatch",
    "TechnologyProfiler",
    "TechProfileResult",
    "AddressData",
    "BusinessEntity",
    "GeoCoordinates",
    "LeadData",
    "LeadExtractor",
    "RatingData",
    "DATABASE_PORTS",
    "DEFAULT_PORTS",
    "INFRASTRUCTURE_PORTS",
    "WEB_PORTS",
    "HostProbeSummary",
    "PortProber",
    "PortResult",
    "MCPServer",
    "run_mcp_server",
    "generate_mcp_client_config",
    "enumerate_subdomains",
    "fingerprint_tech",
    "extract_leads",
    "probe_ports",
    "full_audit",
    "get_diagnostics",
    "create_ui_server",
    "run_ui_server",
    "main",
    "ASNIntelligenceReport",
    "lookup_ip_intelligence",
    "batch_classify_ips",
    "RobotsDirective",
    "RobotsReport",
    "SecurityTxtReport",
    "RobotsAuditor",
    "SecurityTxtAuditor",
    "audit_policy_endpoints",
]
