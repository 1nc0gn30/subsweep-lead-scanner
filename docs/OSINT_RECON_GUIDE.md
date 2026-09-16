# SubSweep OSINT Reconnaissance Architecture & Engineering Guide

This guide provides an in-depth architectural breakdown of the Open Source Intelligence (OSINT) reconnaissance methodologies, passive and active collection pipelines, and security fingerprinting algorithms implemented in **SubSweep**.

---

## 1. Executive Architecture Overview

SubSweep operates on a **dual-tier collection pipeline** designed to maximize asset discovery while minimizing intrusion and network overhead:

```
                      ┌───────────────────────────┐
                      │    Target Domain / Host   │
                      └─────────────┬─────────────┘
                                    │
            ┌───────────────────────┴───────────────────────┐
            ▼                                               ▼
┌───────────────────────────┐                   ┌───────────────────────────┐
│   Tier 1: Passive OSINT   │                   │    Tier 2: Active Recon   │
├───────────────────────────┤                   ├───────────────────────────┤
│ • Certificate Logs (crt)  │                   │ • DNS Resolver & CNAME    │
│ • Passive DNS (AlienVault)│                   │ • Stealth TCP Port Prober │
│ • Wayback Machine Index   │                   │ • HTTP Banner Grabber     │
│ • Search Engine Dorks     │                   │ • TLS SNI Certificate     │
│ • Public MX / SPF / DMARC │                   │ • Web Tech Fingerprinter  │
└─────────────┬─────────────┘                   └─────────────┬─────────────┘
              │                                               │
              └───────────────────────┬───────────────────────┘
                                      ▼
                        ┌───────────────────────────┐
                        │   Normalization & Merge   │
                        ├───────────────────────────┤
                        │ • FQDN Canonicalization   │
                        │ • IP & ASN Geolocation    │
                        │ • Deduplication Engine    │
                        └─────────────┬─────────────┘
                                      ▼
                        ┌───────────────────────────┐
                        │  Scoring & Output Matrix  │
                        │  (Studio UI / MCP / CLI)  │
                        └───────────────────────────┘
```

---

## 2. Passive Reconnaissance Pipeline

Passive reconnaissance gathers target metadata strictly from public, third-party aggregation databases without establishing direct network connections to the target's origin servers.

### 2.1 Certificate Transparency (CT) Log Mining
Every publicly trusted SSL/TLS certificate issued by a Certificate Authority (CA) is appended to append-only, cryptographically verifiable CT logs (RFC 6962). SubSweep queries:
- **`crt.sh`:** Extracts all Subject Alternative Names (`dNSName`) registered historically and currently for `*.target.com`.
- **CertSpotter & AlienVault OTX:** Pulls subdomains registered for short-lived staging or developer environments.

### 2.2 Passive DNS Aggregation
Queries historical DNS query logs from:
- **AlienVault OTX (Open Threat Exchange)**
- **HackerTarget DNS Database**
- **RapidDNS & Wayback Machine CDX Index**

### 2.3 DNS Record & Security Header Auditing
- **Apex A / AAAA Records:** Resolves IPv4 and IPv6 addresses and maps them to Autonomous System Numbers (ASN) and Cloud edge networks (Cloudflare, AWS CloudFront, GCP Cloud Armor, Fastly).
- **Mail Exchanger (MX):** Maps mail routing infrastructure (e.g. Google Workspace, Microsoft 365, Proofpoint).
- **SPF (Sender Policy Framework):** Parses `v=spf1` strings to uncover approved sending IP ranges, delegated third-party SaaS tools (Mailgun, SendGrid, Zendesk).
- **DMARC & DKIM:** Audits domain authentication alignment and enforcement level (`p=reject`, `p=quarantine`, `p=none`).

---

## 3. Active Reconnaissance & Network Probing

When active scanning is enabled, SubSweep verifies host reachability, service exposures, and application stacks.

### 3.1 DNS Resolution & Wildcard Detection
Before accepting brute-forced or passive subdomains, SubSweep performs wildcard detection:
1. Queries non-existent UUID hostnames (e.g. `random-uuid-9f823a.target.com`).
2. If wildcard resolution is active, records the baseline wildcard IP set.
3. Discards candidate subdomains resolving exclusively to the wildcard IP without distinct HTTP responses.

### 3.2 Non-Intrusive TCP Port Scanning
SubSweep scans a curated matrix of high-value perimeter ports:
- **Web & Proxy Ports:** `80` (HTTP), `443` (HTTPS), `8080` (Alternate Web), `8443` (Admin HTTPS).
- **Administrative & Remote Access:** `22` (SSH), `3389` (RDP), `21` (FTP), `23` (Telnet).
- **Database & Storage:** `3306` (MySQL), `5432` (PostgreSQL), `6379` (Redis), `27017` (MongoDB), `9200` (Elasticsearch).
- **Messaging & Telemetry:** `1883` (MQTT), `5672` (RabbitMQ).

### 3.3 Service Banner Grabbing & Handshake Probing
- Initiates clean TCP three-way handshakes.
- Collects initial server welcome banners (e.g., `OpenSSH_9.3p1`, `PostgreSQL 16.2`, `220 ProFTPD`).
- For port 443/8443, completes TLS client hello and extracts certificate validity, issuer, SANs, and negotiated cipher suites.

---

## 4. Web Technology Fingerprinting Heuristics

SubSweep's fingerprinting engine identifies frontend frameworks, CMS engines, cloud CDNs, analytics suites, and security headers using multi-point heuristics:

| Target Category | Detection Method | Indicators & Signatures |
|---|---|---|
| **Frontend Frameworks** | DOM & Script Bundles | `__NEXT_DATA__` (Next.js), `window.__NUXT__` (Nuxt.js), `data-reactroot` (React), `ng-version` (Angular), `vue` hydration markers |
| **CMS Engines** | Path & Meta Tags | `<meta name="generator" content="WordPress">`, `/wp-content/`, `/wp-json/`, `Webflow.js`, Shopify cart tokenization |
| **Edge & CDN** | HTTP Response Headers | `CF-RAY` / `cf-cache-status` (Cloudflare), `X-Amz-Cf-Id` (AWS CloudFront), `Fastly-Debug` (Fastly), `Via: 1.1 google` (GCP) |
| **Backend & Runtimes** | Server Headers & Cookies | `Server: uvicorn/0.29` (FastAPI), `X-Powered-By: Express` (Node.js), `X-Django-Version` (Django) |
| **Analytics & Pixel** | Injected Script Loaders | `gtag.js` (Google Analytics 4), `analytics.js` (Segment), `mixpanel.init` (Mixpanel) |
| **Security Headers** | Raw Response Headers | `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` |

---

## 5. Legal, Ethical, and Compliance Guidelines

OSINT reconnaissance must always be conducted within legal and ethical boundaries:

1. **Authorization & Scope:**
   - Passive queries against public registers (DNS, CT logs, public web pages) are non-intrusive and widely permitted under standard OSINT practices.
   - Active TCP port scanning and intrusive probing must only be performed on domains and IP addresses you own or have explicit written permission (rules of engagement / bug bounty scope) to assess.

2. **Rate Limiting & Politeness:**
   - SubSweep implements configurable concurrent connection limits (`--rate-limit 50`) and request timeouts (`--timeout 10s`) to prevent denial-of-service or server degradation.

3. **Safe Harbor:**
   - Adhere strictly to the target's published `security.txt` and responsible vulnerability disclosure programs.
