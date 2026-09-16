# B2B Lead Generation & Decision Maker Qualification Pipeline

This production reference example demonstrates how to process domain reconnaissance data into high-converting, scored B2B business leads.

## Overview
1. **Multi-Factor Scoring Engine:** Automatically ranks leads on a `0-100` scale based on email deliverability, C-suite / VP seniority, direct phone numbers, and social footprints.
2. **Quality Tiering:**
   - 💎 **Platinum Tier (90–100):** High-level executives (CISO, CTO, VP) with verified direct email, phone, and LinkedIn.
   - 🥇 **Gold Tier (80–89):** Directors, Managers, and Staff Leads with deliverable corporate email.
   - 🥈 **Silver Tier (70–79):** Verified contacts and department switchboards.
   - 🥉 **Bronze Tier (<70):** Unverified or low-confidence email patterns.

## Files
- `sample_leads.csv`: Pre-scanned B2B sales & security decision maker leads for `acme-cloud.io`.
- `export_leads.py`: Processing script that filters, qualifies, and exports leads to CSV or JSON.

## Quickstart

### 1. View Filtered High-Value Leads (Score ≥ 80)
```bash
python examples/lead-generation-pipeline/export_leads.py --min-score 80
```

### 2. Export Executive Leads to CSV
```bash
python examples/lead-generation-pipeline/export_leads.py --exec-only --format csv --output executives.csv
```

### 3. Export CRM-Ready JSON
```bash
python examples/lead-generation-pipeline/export_leads.py --min-score 85 --format json --output prospects.json
```

## Lead Scoring Weights
| Factor | Weight | Criteria |
|---|---|---|
| **Email Deliverability** | `30%` | Syntax valid, non-disposable, high deliverability confidence |
| **Executive Seniority** | `25%` | CISO, CTO, CEO, VP of Eng, Head of Security |
| **Social Footprint** | `20%` | LinkedIn profile, verified Twitter/X handle, GitHub |
| **Direct Phone** | `15%` | Direct office line or verified phone extension |
| **Tech Stack Fit** | `10%` | High-value cloud infrastructure (GCP, AWS, Kubernetes, Next.js) |
