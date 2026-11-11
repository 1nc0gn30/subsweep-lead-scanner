<p align="center">
  <img src="assets/hero-banner.svg" alt="SubSweep Lead Scanner — OSINT Subdomain Reconnaissance, Tech Fingerprinting & Lead Harvester" width="100%" />
</p>

# SubSweep Lead Scanner

**Zero-dependency Python 3.8+ OSINT subdomain enumerator, dangling CNAME takeover detector, TCP service banner prober, HTTP technology fingerprinter, SPF/DMARC/DKIM email security auditor, business contact harvester, and MCP server.**

- **Zoth Studio v2 Dossier**: [https://zoth.nullai.tech/tools/subsweep-lead-scanner](https://zoth.nullai.tech/tools/subsweep-lead-scanner)
- **Default Loopback Endpoint**: `http://127.0.0.1:8090`
- **Runtime Dependencies**: Zero external Python runtime packages (100% Python `stdlib`)
- **License**: MIT (100% free and open-source)

---

## Overview

`subsweep-lead-scanner` combines passive Certificate Transparency (`crt.sh`) / DNS resolution, HTTP header and DOM technology stack fingerprinting, non-intrusive TCP port and banner probing, `robots.txt` + RFC 9116 `security.txt` policy inspection, SPF/DMARC/DKIM DNS record validation, dangling CNAME subdomain takeover detection, and public B2B contact extraction into a single stdlib Python CLI, Google Material 3 dark loopback workstation, and MCP server.

---

## Architecture

```text
src/subsweep_lead_scanner/
├── recon_engine.py        # Subdomain enumerator, TCP port prober, HTTP tech fingerprinter & lead scorer
├── policy_auditor.py      # robots.txt & RFC 9116 /.well-known/security.txt parser and scorer
├── email_auditor.py       # SPF lookup-depth validator, DMARC policy parser & DKIM selector check
├── takeover_detector.py   # Dangling CNAME & unclaimed cloud provider subdomain takeover scanner
├── exporter.py            # CSV, JSON, and deterministic ZIP report bundlers
├── mcp_server.py          # JSON-RPC 2.0 stdio MCP server exposing 9 OSINT & security audit tools
├── ui_server.py           # Loopback HTTP API + browser workstation server (127.0.0.1:8090)
└── cli.py                 # Unified CLI entrypoint (`subsweep` / `lead-scanner`)
```

---

## Quickstart

```bash
git clone https://github.com/1nc0gn30/subsweep-lead-scanner.git
cd subsweep-lead-scanner
python3 -m pip install -e ".[dev]"

# Launch the loopback web workstation on http://127.0.0.1:8090
subsweep serve --host 127.0.0.1 --port 8090
```

Run directly from a source checkout without installing:

```bash
PYTHONPATH=src python3 -m subsweep_lead_scanner.cli serve --port 8090
```

---

## CLI & MCP Usage

### CLI Usage & Subcommands

Installed entrypoints: `subsweep`, `lead-scanner`, and `subsweep-recon`.

```bash
# View CLI help
subsweep --help

# Run a multi-vector OSINT audit (subdomains + tech + leads + ports)
subsweep scan example.com --json

# Enumerate subdomains with resolved IPv4/IPv6 addresses and latency
subsweep subdomains example.com --json

# Fingerprint CMS, web frameworks, CDN, and analytics tags
subsweep tech https://example.com --json

# Extract public business contacts, social profiles, and lead quality score
subsweep leads https://example.com --json

# Probe common TCP ports with socket banner grabbing
subsweep ports example.com --ports 80,443,8080 --json

# Audit robots.txt and RFC 9116 security.txt policies
subsweep policies example.com --json

# Audit SPF lookup limits, DMARC enforcement, and DKIM selectors
subsweep email example.com --json

# Detect dangling CNAME records vulnerable to subdomain takeover
subsweep takeovers example.com --json

# Display runtime diagnostics or run internal self-tests
subsweep platform
subsweep test

# Launch the stdio MCP server
subsweep mcp
```

### ZothOS v3.4.0 CLI Integration

On ZothOS v3.4.0 workstations, `subsweep` is installed in `/usr/local/bin/subsweep`:

```bash
subsweep platform
subsweep web                 # Starts http://127.0.0.1:8090
subsweep desktop             # Launches the Electron workstation shell
```

### Model Context Protocol (MCP) Tools

```json
{
  "mcpServers": {
    "subsweep-lead-scanner": {
      "command": "subsweep",
      "args": ["mcp"]
    }
  }
}
```

| MCP Tool | Description |
| :--- | :--- |
| `subsweep_full_audit` | Run combined subdomain enumeration, tech fingerprinting, lead extraction, and port scan |
| `subsweep_enumerate_subdomains` | Discover subdomains, resolved IPs, and HTTP status/latency |
| `subsweep_fingerprint_tech` | Detect server headers, CDN, frontend frameworks, CMS, and analytics |
| `subsweep_extract_leads` | Harvest public business emails, phone numbers, social links, and lead score |
| `subsweep_probe_ports` | Probe specified TCP ports with timeout-bounded banner capture |
| `subsweep_audit_policies` | Inspect `robots.txt` directives and `/.well-known/security.txt` compliance |
| `subsweep_audit_email_security` | Evaluate SPF record syntax/lookup count, DMARC policy, and DKIM selectors |
| `subsweep_detect_takeovers` | Check CNAME targets against known unclaimed cloud-service takeover fingerprints |
| `subsweep_get_diagnostics` | Return host OS, Python version, DNS resolver status, and tool telemetry |

---

## HTTP API Reference

When running on `http://127.0.0.1:8090`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health`, `/api/health` | Service health status, uptime, and runtime diagnostics |
| `GET` | `/api/mcp/config?client=claude` | Ready-to-paste MCP client JSON configuration |
| `POST` | `/api/scan` | Full OSINT domain reconnaissance report |
| `POST` | `/api/subdomains` | Subdomain discovery and DNS resolution |
| `POST` | `/api/tech` | HTTP technology stack fingerprinting |
| `POST` | `/api/leads` | Public business contact harvesting and scoring |
| `POST` | `/api/ports` | TCP port and service banner probe |
| `POST` | `/api/policies` | `robots.txt` and `security.txt` security policy audit |
| `POST` | `/api/email` | SPF, DMARC, and DKIM email security audit |
| `POST` | `/api/takeovers` | Dangling CNAME subdomain takeover check |
| `POST` | `/api/export-csv`, `/api/export-json`, `/api/export-zip` | Export structured audit artifacts |

---

## Testing & Verification

```bash
# Run the pytest suite
python3 -m pytest -q

# Run internal CLI self-test
subsweep test

# Scan repository with gitleaks
gitleaks detect --source . --no-banner --redact
```

---

## Support

SubSweep Lead Scanner is 100% free and open-source software. Optional community support is available via [Buy Us a Coffee (Stripe)](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X).

## License

MIT License — Copyright (c) 2026 [1nc0gn30](https://1nc0gn30.si) (`@1nc0gn30`) & [NullAI](https://nullai.tech). See [LICENSE](LICENSE) for full text.
