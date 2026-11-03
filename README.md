<div align="center">
  <img src="assets/hero-banner.svg" alt="SubSweep Lead Scanner — Sovereign Architecture Banner" width="100%" />
</div>

<br />

# SubSweep Studio | OSINT Recon & Lead Intelligence

<p align="center">
  <img src="https://img.shields.io/badge/SubSweep%20Studio-Enterprise%20OSINT-1a73e8?style=for-the-badge&logoColor=white" alt="SubSweep Studio Logo" />
</p>

<p align="center">
  <a href="https://subsweep.nullai.tech"><img src="https://img.shields.io/badge/Live%20App-subsweep.nullai.tech-1a73e8?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Live App" /></a>
  <a href="https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X"><img src="https://img.shields.io/badge/%E2%98%95%20Buy%20Us%20a%20Coffee-Stripe-D4AF37?style=for-the-badge" alt="Buy Us a Coffee" /></a>
  <a href="solana:GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK"><img src="https://img.shields.io/badge/%E2%97%8E%20Solana%20Tip-GG2e...dXoK-14F195?style=for-the-badge" alt="Solana Tip" /></a>
  <a href="https://subsweep.nullai.tech"><img src="https://img.shields.io/badge/Access-100%25%20Free%20%26%20Open-10B981?style=for-the-badge" alt="100% Free & Open Access" /></a>
</p>

<p align="center">
  <a href="https://github.com/1nc0gn30/subsweep-lead-scanner/actions"><img src="https://img.shields.io/badge/CI-15%20Jobs%20Passing-1e8e3e?style=flat-square&logo=github-actions&logoColor=white" alt="CI Status" /></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.9%20|%203.10%20|%203.11%20|%203.12%20|%203.13-1a73e8?style=flat-square&logo=python&logoColor=white" alt="Python Versions" /></a>
  <a href="./docs/MCP_GUIDE.md"><img src="https://img.shields.io/badge/MCP-Standard%20v2024.11-9334e6?style=flat-square&logo=anthropic&logoColor=white" alt="MCP Ready" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-gray?style=flat-square" alt="MIT License" /></a>
</p>

---

## 🌟 Executive Overview

**SubSweep Studio** is an all-in-one OSINT reconnaissance suite, perimeter port scanner, technology stack fingerprinter, and B2B decision-maker lead intelligence engine.

Designed for security researchers, DevSecOps teams, and B2B growth operators, SubSweep Studio pairs a high-performance Python engine with a **Material 3 influenced Studio UI** and native **Model Context Protocol (MCP)** tool servers for AI assistants (Claude, Cursor, Cline, Zed).

---

## 🚀 Key Capabilities

1. 🌐 **Multi-Source Subdomain Reconnaissance:**
   - Passive Certificate Transparency (CT) log mining (`crt.sh`, AlienVault OTX, CertSpotter).
   - DNS record aggregation (`A`, `AAAA`, `MX`, `TXT`, `SPF`, `DKIM`, `DMARC`) with wildcard resolution detection.
2. 🏢 **B2B Lead Harvester & Decision Maker Qualification:**
   - Extracts executive contacts (CISO, CTO, VP of Eng, Directors) with deliverable business emails.
   - Computes a mathematical **Lead Quality Score (0–100)** evaluating deliverability, seniority, phone availability, and social footprints.
3. 🔬 **Deep Technology Stack Fingerprinting:**
   - Detects frontend frameworks (React, Next.js, Vue, Angular), cloud CDNs (Cloudflare, Fastly, CloudFront), and CMS engines (WordPress, Webflow, Shopify).
   - Audits essential HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`).
4. ✉️ **Email Deliverability & Anti-Spoofing Auditor (RFC 7208 / 7489):**
   - SPF mechanism validation with 10-DNS-lookup RFC limit enforcement.
   - DMARC enforcement level (`p=reject`, `p=quarantine`, `p=none`) and reporting addresses (`rua`/`ruf`).
   - DKIM selector discovery and MX provider fingerprinting (Google Workspace, Microsoft 365, Proton, Fastmail, Postmark).
   - Actionable copy-paste DNS TXT record recommendations.
5. 🏴 **Subdomain Takeover & CNAME Dangling Pointer Detector:**
   - Detects dangling CNAME records across 20+ SaaS services (GitHub Pages, AWS S3, Heroku, Netlify, Vercel, Shopify, Fastly, Ghost, Surge.sh, Zendesk, WordPress, HubSpot, Fly.io).
   - Live HTTP response body fingerprint verification confirming vulnerability status.
6. 🔌 **Perimeter Port & Service Matrix:**
   - Rapid, non-intrusive TCP port auditing (`22`, `80`, `443`, `3306`, `5432`, `8443`) with service banner grabbing and risk classifications.
7. 🤖 **Native Model Context Protocol (MCP) Server (9 Tools):**
   - Zero-configuration stdio tool server empowering AI agents to run live reconnaissance, email deliverability audits, takeover detection, and lead research directly from chat.
8. 🎨 **Material 3 Influenced Recon Studio UI:**
   - 100% offline-ready, single-file browser app (`public/index.html`, design influenced by Google Material 3 tokens) with zero tracking, dynamic score dials, interactive tree visualizer, and 1-click CSV/JSON/Markdown exports.

---

## 🏗️ Architecture Overview

```mermaid
flowchart TD
    Target["Target Domain\n(e.g., acme-cloud.io)"] --> Engine["SubSweep Core Engine"]
    
    subgraph Discovery ["OSINT & Recon Discovery"]
        Engine --> CT["Certificate Transparency & Passive DNS"]
        Engine --> Ports["Perimeter Port Matrix & Banners"]
        Engine --> Tech["Tech Fingerprinter & Security Headers"]
        Engine --> Leads["Business Lead & Contact Harvester"]
    end

    Discovery --> Merge["Normalization & Scoring Framework"]

    subgraph Interfaces ["Multi-Channel Interfaces"]
        Merge --> CLI["CLI Terminal Engine\n(subsweep recon)"]
        Merge --> MCP["MCP AI Agent Server\n(Claude / Cursor / Zed)"]
        Merge --> UI["Material 3 Recon Studio\n(public/index.html)"]
        Merge --> Exporters["Executive Intelligence Bundles\n(CSV / JSON / Markdown)"]
    end
```

---

## ⚡ Quickstart & Installation

### Option 1: Standalone Server on Port 8090
```bash
git clone https://github.com/1nc0gn30/subsweep-lead-scanner.git
cd subsweep-lead-scanner
python3 server.py --port 8090
```
Navigate to `http://127.0.0.1:8090` to access the full SubSweep Recon Studio.

### Option 2: ZothOS CLI Binary Commands
```bash
# Check daemon & environment status
subsweep --status

# Get structured JSON telemetry & system metadata
subsweep --json

# Run hardware & DNS networking diagnostics
subsweep platform

# Run internal engine self-tests (6/6 checks)
subsweep test

# Run full domain OSINT reconnaissance
subsweep scan acme-cloud.io

# Harvest verified B2B decision maker leads
subsweep leads acme-cloud.io --min-score 80 --export leads.csv
```

---

## ☕ Support & Tip Rails (100% Free & Open-Access)

Every feature in SubSweep Lead Scanner is **100% free, open-source, and unlocked by default**. If you find this sovereign tool valuable, you can support continuous development:

- **☕ Buy Us a Coffee (Stripe)**: [buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X)
- **◎ Solana Tip Address**: `GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK`

---

## 💻 CLI Usage Examples

### 1. Complete Domain Reconnaissance & Audit
```bash
# Run full recon and print formatted console tables
subsweep recon acme-cloud.io

# Export full reconnaissance data to JSON
subsweep recon acme-cloud.io --output audit_report.json --format json
```

### 2. Harvest & Score High-Value Decision Leads
```bash
# Harvest leads with minimum score 80 and export to CSV
subsweep leads acme-cloud.io --min-score 80 --export leads.csv

# Filter for C-Suite and VP executives only
subsweep leads acme-cloud.io --exec-only --format json
```

### 3. Email Security & Anti-Spoofing Audit (SPF/DMARC/DKIM/MX)
```bash
# Run RFC compliance audit and print terminal card
subsweep email acme-cloud.io

# Export email posture report to JSON
subsweep email acme-cloud.io --format json
```

### 4. Subdomain Takeover & Dangling CNAME Detection
```bash
# Scan subdomains for dangling CNAME pointers to 20+ SaaS providers
subsweep takeovers acme-cloud.io

# Verify takeover fingerprints with live HTTP response probes
subsweep takeovers acme-cloud.io --verify-http --format json
```

### 5. Launch Material 3 Recon Studio Web UI
Open `public/index.html` in any web browser:
```bash
# Linux
xdg-open public/index.html

# macOS
open public/index.html

# Windows
start public/index.html
```

---

## 🤖 Model Context Protocol (MCP) Integration

Connect SubSweep directly to **Claude Desktop**, **Cursor IDE**, **Cline**, or **Zed**.

### Claude Desktop Configuration
Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "subsweep-recon": {
      "command": "python",
      "args": ["-m", "subsweep_lead_scanner.mcp_server"],
      "env": {
        "SUBSWEEP_RATE_LIMIT": "50",
        "SUBSWEEP_TIMEOUT": "10"
      }
    }
  }
}
```

*See [docs/MCP_GUIDE.md](./docs/MCP_GUIDE.md) for Cursor, Cline, and Zed configurations.*

---

## 📊 Lead Quality Scoring Methodology

SubSweep ranks prospects on a **0–100 scale** using multi-factor heuristics:

$$\text{Score} = \min(100, W_{\text{email}} + W_{\text{seniority}} + W_{\text{social}} + W_{\text{phone}} + W_{\text{tech}})$$

| Factor | Weight | Evaluation Criteria |
|---|---|---|
| **Deliverable Email** | `30%` | Active MX record, RFC syntax valid, $\ge 95\%$ deliverability confidence. |
| **Executive Seniority** | `25%` | CISO, CTO, CEO, VP of Engineering, Head of Security. |
| **Social Footprint** | `20%` | Verified LinkedIn profile, Twitter/X handle, GitHub profile. |
| **Direct Phone Reachability** | `15%` | Direct office dial or mobile number. |
| **Tech Stack Fit** | `10%` | Cloud-native modern infrastructure (AWS, GCP, Kubernetes, Next.js). |

*See [docs/LEAD_SCORING_METHODOLOGY.md](./docs/LEAD_SCORING_METHODOLOGY.md) for full details.*

---

## 📁 Repository Structure

```
subsweep-lead-scanner/
├── .github/
│   └── workflows/
│       ├── ci.yml               # 15-job CI test matrix (Ubuntu/macOS/Win, Py 3.9-3.13)
│       └── release.yml          # Automated release & SHA-256 packaging
├── docs/
│   ├── OSINT_RECON_GUIDE.md     # In-depth OSINT discovery architecture
│   ├── LEAD_SCORING_METHODOLOGY.md # 0-100 mathematical lead scoring guide
│   └── MCP_GUIDE.md             # Model Context Protocol setup for AI agents
├── examples/
│   ├── domain-recon-audit/      # Domain recon reference script & JSON report
│   ├── lead-generation-pipeline/# Lead scoring exporter & sample CSV
│   ├── mcp-clients/             # Claude, Cursor, Cline, Zed JSON configs
│   └── README.md                # Examples index & quickstart
├── public/
│   └── index.html               # Material 3 Light Mode Recon Studio UI (Google M3 token influenced)
├── src/
│   └── subsweep_lead_scanner/   # Core Python package engine
├── tests/
│   └── test_examples.py         # Unit tests covering all examples, UI, and configs
└── README.md                    # Project README
```

---

## 🧪 Testing

Run the test suite with `pytest`:
```bash
PYTHONPATH=src pytest tests/ -v
```

---

## 💎 Founding Member Pro ($0 Lifetime)

SubSweep Recon Studio is engineered as an autonomous sovereign security and lead intelligence utility with dual checkout rails:

- **Stripe Direct Rail**: [Instant Lifetime License ($0)](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X) (Credit Cards, Apple Pay, Google Pay)
- **Solana Web3 Solana Tip**: On-chain instant checkout via Solana Tip integration (`GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK`)
- **Pro Capabilities**: Full unlocked CSV/JSON lead exports, executive dossier downloads, uncensored decision-maker direct dials, and 100% in-browser zero-egress execution.

---

## 👑 Author & Sovereignty

- **Engineered by**: [1nc0gn30 • NullAI](https://nullai.tech) ([@1nc0gn30](https://github.com/1nc0gn30))
- **Ecosystem**: [NullAI Platform](https://nullai.tech)
- **Repository**: [1nc0gn30/subsweep-lead-scanner](https://github.com/1nc0gn30/subsweep-lead-scanner)

---

## 📄 License

Released under the [MIT License](./LICENSE). Engineered with zero external runtime dependencies by 1nc0gn30 • NullAI.

---

## 🏛️ ZothOS v3.4, Zoth Studio v2 & Obsidian Second Brain Ecosystem

### Cross-Surface Integration Matrix

| Surface | Endpoint / Binary | Capabilities |
| :--- | :--- | :--- |
| **Standalone Workstation** | `http://127.0.0.1:3000` | 100% Free & Open-Access Web Deck, live `/health` & REST telemetry |
| **Zoth Studio v2 Route** | `http://127.0.0.1:3000/tools/subsweep-lead-scanner` | Interactive God-Mode component inside Zoth Studio (`https://zoth.nullai.tech`) |
| **ZothOS v3.4 CLI & TUI** | `subsweep-lead-scanner` / `subsweep-lead-scanner-tui` | Global binary in `/usr/local/bin/` with Unicode `U+2800` Braille TUI & `--json` output |
| **ZothOS-Lite Web Desktop** | `http://127.0.0.1:8145` | Browser-native KDE-style window manager & terminal launcher |
| **Zoth Obsidian Tracker** | `http://127.0.0.1:8151` | Interactive Obsidian Second Brain vault explorer (`~/Documents/Obsidian Vault/Studio/Tools/Studio subsweep-lead-scanner.md`) |
| **Neuro-Memory STDP Cortex** | `http://127.0.0.1:8094` | 3-Factor STDP synaptic memory daemon & 21-tool MCP server |

```bash
# Inspect CLI & Unicode U+2800 Braille TUI on ZothOS v3.4
subsweep-lead-scanner --help
subsweep-lead-scanner-tui --status
subsweep-lead-scanner-tui --json

# Verify Second Brain Vault & 12-Step Verification Gallery on :8151
zoth-obsidian-tracker --verify
```

