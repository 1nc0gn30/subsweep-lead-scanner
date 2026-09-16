# Domain Reconnaissance & Attack Surface Audit

This example demonstrates how to perform automated reconnaissance on an enterprise domain (`acme-cloud.io`) using SubSweep's multi-source discovery engine.

## Overview
Reconnaissance encompasses:
1. **Passive DNS & Certificate Transparency (CT) Mining:** Identifies all subdomains (`*.acme-cloud.io`) without sending intrusive packets to the target.
2. **DNS Record & Security Policy Auditing:** Verifies `A`, `AAAA`, `MX`, `TXT`, `SPF`, `DKIM`, and `DMARC` policies.
3. **TCP Perimeter Port Matrix:** Inspects external attack surface across standard service ports (80, 443, 22, 5432, 3306, 8443).
4. **Technology Stack Fingerprinting:** Detects frontend frameworks, cloud infrastructure, and CDN edges.
5. **Posture Scoring:** Computes a composite letter grade (A+ through F) based on risk exposures.

## Files
- `audit_report.json`: Realistic reference audit report covering 18+ subdomains, DNS records, open ports, and tech stack details.
- `run_audit.py`: Python CLI runner that parses, formats, and generates reconnaissance reports.

## Quickstart

### 1. View Terminal Summary
```bash
python examples/domain-recon-audit/run_audit.py --domain acme-cloud.io
```

### 2. Generate Markdown Executive Report
```bash
python examples/domain-recon-audit/run_audit.py --domain acme-cloud.io --format markdown --output acme-audit.md
```

### 3. Generate JSON Payload for Automated Pipelines
```bash
python examples/domain-recon-audit/run_audit.py --domain acme-cloud.io --format json --output output.json
```

## Sample JSON Structure
```json
{
  "scan_metadata": {
    "target": "acme-cloud.io",
    "composite_security_score": 92,
    "composite_security_grade": "A+"
  },
  "subdomains_discovery": {
    "total_discovered": 18,
    "items": [...]
  },
  "open_ports_and_services": [...],
  "technology_fingerprints": [...]
}
```
