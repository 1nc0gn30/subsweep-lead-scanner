# SubSweep Reference Examples & Integrations

This directory contains production-ready scripts, reference datasets, and configuration files illustrating real-world use cases for SubSweep.

## Example Index

### 1. 🌐 [Domain Reconnaissance & Attack Surface Audit](./domain-recon-audit/)
- Complete reconnaissance on an enterprise domain (`acme-cloud.io`).
- Includes `audit_report.json` with 18+ subdomains, DNS records, open ports, and tech stack profiling.
- Standalone CLI runner `run_audit.py` with multi-format output (ANSI tables, Markdown, JSON).

### 2. 🏢 [B2B Lead Generation & Decision Maker Pipeline](./lead-generation-pipeline/)
- Multi-factor lead qualification scoring (`0-100` scale).
- Evaluates deliverable MX email verification, executive seniority (CISO, CTO, VP), direct phone reachability, and tech stack fit.
- Includes `sample_leads.csv` and `export_leads.py` with 1-click filtering and CSV/JSON export.

### 3. 🤖 [Model Context Protocol (MCP) AI Client Configurations](./mcp-clients/)
- Zero-config setup files for Anthropic Claude Desktop, Cursor IDE, Cline VS Code Extension, and Zed Editor.
- Exposes SubSweep tools (`recon_subdomains`, `harvest_leads`, `fingerprint_tech`, `scan_ports`, `generate_recon_report`) to autonomous AI agents.

---

## Quick Command Matrix

| Task | Command |
|---|---|
| Run Terminal Recon Audit | `python examples/domain-recon-audit/run_audit.py --domain acme-cloud.io` |
| Export Markdown Audit | `python examples/domain-recon-audit/run_audit.py --format markdown --output audit.md` |
| Filter Platinum Leads (≥80) | `python examples/lead-generation-pipeline/export_leads.py --min-score 80` |
| Export Executive Leads CSV | `python examples/lead-generation-pipeline/export_leads.py --exec-only --format csv --output execs.csv` |
| Connect Claude Desktop | Copy `examples/mcp-clients/claude_desktop_config.json` |
