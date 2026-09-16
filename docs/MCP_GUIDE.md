# SubSweep Model Context Protocol (MCP) Server Architecture & Integration Guide

The Model Context Protocol (MCP) is an open standard that allows large language models (LLMs) and autonomous AI coding agents to securely invoke local tools, read databases, and run reconnaissance operations.

`subsweep-lead-scanner` provides a production-grade, stdio-compliant MCP server that exposes domain enumeration, lead harvesting, and security auditing tools to AI environments like **Anthropic Claude Desktop**, **Cursor IDE**, **Cline (VS Code)**, and **Zed Editor**.

---

## 1. Protocol Architecture & Transports

```
┌─────────────────────────────────────────────────────────┐
│               AI Host (Claude / Cursor / Zed)           │
└────────────────────────────┬────────────────────────────┘
                             │ stdio (JSON-RPC 2.0)
                             ▼
┌─────────────────────────────────────────────────────────┐
│             SubSweep MCP Server Subprocess              │
│       (`python -m subsweep_lead_scanner.mcp_server`)    │
├────────────────────────────┬────────────────────────────┤
│ 1. Tool Registry & Schema  │ 2. Security Sandbox & Rate │
│    Validation              │    Limiter                 │
├────────────────────────────┴────────────────────────────┤
│ 3. Core Recon Engines (DNS, Ports, Leads, Scorer)       │
└─────────────────────────────────────────────────────────┘
```

The MCP server communicates using **JSON-RPC 2.0** messages transmitted over standard input and standard output (`stdio`), guaranteeing zero open local network ports and strict OS-level process encapsulation.

---

## 2. Tool Definitions & JSON Schemas

### 2.1 `subsweep.recon_subdomains`
Enumerates subdomains for a target apex domain using Certificate Transparency and passive DNS.

```json
{
  "name": "subsweep.recon_subdomains",
  "description": "Performs passive Certificate Transparency and DNS reconnaissance on a domain.",
  "parameters": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Target apex domain (e.g. acme-cloud.io, stripe.com)"
      },
      "passive_only": {
        "type": "boolean",
        "description": "If true, skips active DNS probing and uses only public logs",
        "default": true
      },
      "timeout": {
        "type": "integer",
        "description": "HTTP and query timeout in seconds",
        "default": 10
      }
    },
    "required": ["domain"]
  }
}
```

---

### 2.2 `subsweep.harvest_leads`
Scrapes, validates, and ranks B2B decision maker leads and verified executive contact details.

```json
{
  "name": "subsweep.harvest_leads",
  "description": "Harvests verified business contacts, computes 0-100 lead quality scores, and formats CRM-ready prospects.",
  "parameters": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Target company domain"
      },
      "max_leads": {
        "type": "integer",
        "description": "Maximum number of leads to return",
        "default": 20
      },
      "min_score": {
        "type": "integer",
        "description": "Minimum lead score filter (0-100)",
        "default": 0
      },
      "verify_mx": {
        "type": "boolean",
        "description": "Verify MX record deliverability",
        "default": true
      }
    },
    "required": ["domain"]
  }
}
```

---

### 2.3 `subsweep.fingerprint_tech`
Identifies frontend frameworks, cloud hosting providers, CDNs, CMS systems, and security headers.

```json
{
  "name": "subsweep.fingerprint_tech",
  "description": "Analyzes HTTP headers, DOM structure, and scripts to fingerprint web technologies.",
  "parameters": {
    "type": "object",
    "properties": {
      "url": {
        "type": "string",
        "description": "Target web URL or hostname (e.g. https://acme-cloud.io)"
      },
      "deep_scan": {
        "type": "boolean",
        "description": "Inspect script bundles and meta tags in addition to response headers",
        "default": true
      }
    },
    "required": ["url"]
  }
}
```

---

### 2.4 `subsweep.scan_ports`
Probes perimeter TCP service ports and returns service banners and exposure risk classifications.

```json
{
  "name": "subsweep.scan_ports",
  "description": "Scans common network perimeter TCP ports and inspects service banners.",
  "parameters": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Target domain or IP address"
      },
      "ports": {
        "type": "array",
        "items": { "type": "integer" },
        "description": "List of TCP port numbers to probe",
        "default": [22, 80, 443, 3306, 5432, 8443]
      }
    },
    "required": ["target"]
  }
}
```

---

### 2.5 `subsweep.generate_recon_report`
Generates an executive intelligence brief with composite score and vulnerability posture.

```json
{
  "name": "subsweep.generate_recon_report",
  "description": "Compiles comprehensive domain reconnaissance and lead data into Markdown or JSON.",
  "parameters": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "Target company domain"
      },
      "format": {
        "type": "string",
        "enum": ["markdown", "json", "html"],
        "default": "markdown"
      }
    },
    "required": ["domain"]
  }
}
```

---

## 3. Autonomous AI Agent Recipes & Prompts

When connected via MCP, an AI agent can execute end-to-end multi-step intelligence operations autonomously:

### Recipe 1: Competitive Security Audit
> **Prompt:** *"Perform a reconnaissance audit on target.io. Find all public endpoints, check if database ports like 3306 or 5432 are exposed, and generate a 1-page executive markdown risk report."*

### Recipe 2: Targeted Account-Based Selling (ABM)
> **Prompt:** *"Use SubSweep to find the VP of Engineering, CISO, and Head of DevOps at cloud-target.com. Filter for contacts with lead scores above 85, and generate a tailored cold outreach email citing their current technology stack."*

---

## 4. Troubleshooting & Verification

1. **Verify stdio Launch Manually:**
   ```bash
   python -m subsweep_lead_scanner.mcp_server
   ```
   Type `{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}` and press Enter.

2. **Environment Variables:**
   - `SUBSWEEP_RATE_LIMIT`: Maximum concurrent requests per second (default: `50`).
   - `SUBSWEEP_TIMEOUT`: Network timeout in seconds (default: `10`).
   - `SUBSWEEP_CACHE_TTL`: Results cache time-to-live in seconds (default: `3600`).
