# SubSweep B2B Lead Scoring Methodology & Qualification Framework

This document outlines the mathematical formulation, heuristics, and algorithmic classification used by SubSweep to score, rank, and qualify B2B decision maker leads.

---

## 1. Mathematical Formulation

Every discovered contact is evaluated across **five weighted criteria dimensions**, producing a composite Lead Quality Score $S \in [0, 100]$:

$$S = \min\left(100, \, W_{\text{email}} + W_{\text{seniority}} + W_{\text{social}} + W_{\text{phone}} + W_{\text{tech}}\right)$$

Where:
- $W_{\text{email}} \in [0, 30]$: Deliverability & Email Verification
- $W_{\text{seniority}} \in [0, 25]$: Decision Maker Authority & Role
- $W_{\text{social}} \in [0, 20]$: Verified Multi-Channel Footprint
- $W_{\text{phone}} \in [0, 15]$: Direct Dial Reachability
- $W_{\text{tech}} \in [0, 10]$: Tech Stack & Cloud Maturity Alignment

---

## 2. Weight Breakdown & Scoring Rules

### 2.1 Dimension 1: Email Deliverability & Verification ($W_{\text{email}} \le 30$)
Deliverability is the foundation of high-performing outreach.

| Condition | Points Allocated |
|---|---|
| RFC 5322 Syntax Valid & Domain MX Active | `+15 pts` |
| Verification Confidence $\ge 95\%$ (SMTP handshake / catch-all check) | `+15 pts` |
| Verification Confidence $85\% - 94\%$ | `+10 pts` |
| Verification Confidence $< 85\%$ | `+5 pts` |
| **Maximum Dimension Score** | **30 pts** |

*Penalty:* If an email is flagged as disposable (Mailinator, TempMail) or MX records do not exist, $W_{\text{email}} = 0$ pts.

---

### 2.2 Dimension 2: Decision Maker Seniority ($W_{\text{seniority}} \le 25$)
Seniority ensures sales and security outreach targets individuals with budget and purchasing authority.

| Title / Role Classification | Target Examples | Points |
|---|---|---|
| **C-Level / Founders / Executive** | CISO, CTO, CEO, CIO, CSO, Co-Founder, President | `+25 pts` |
| **Vice President / Department Head / Director** | VP of Engineering, Head of Security, Director of IT | `+20 pts` |
| **Lead / Principal / Manager / Architect** | Principal Architect, SRE Manager, Lead SecOps | `+15 pts` |
| **Individual Contributor / Specialist** | Staff Engineer, Security Analyst, DevOps Specialist | `+10 pts` |
| **General / Unclassified Contact** | Inquiries, Switchboard, Info | `+5 pts` |

---

### 2.3 Dimension 3: Social & Digital Footprint ($W_{\text{social}} \le 20$)
Multi-channel social verification increases response rates and enables social selling.

| Channel Detected & Verified | Points |
|---|---|
| **LinkedIn Profile URL** (Verified slug matching name/company) | `+10 pts` |
| **Twitter / X Profile** (Active industry persona) | `+5 pts` |
| **GitHub / Technical Profile** (Public commits / engineering footprint) | `+5 pts` |
| **Maximum Dimension Score** | **20 pts** |

---

### 2.4 Dimension 4: Direct Phone Reachability ($W_{\text{phone}} \le 15$)
Direct phone numbers enable phone outreach and urgent security escalation workflows.

| Phone Availability | Points |
|---|---|
| **Direct Dial / Mobile Number** (Direct E.164 line or local mobile format) | `+15 pts` |
| **Corporate Switchboard with Extension** | `+10 pts` |
| **No Phone Number Available** | `0 pts` |

---

### 2.5 Dimension 5: Technology Stack Fit ($W_{\text{tech}} \le 10$)
Target organizations utilizing modern cloud and security technologies are higher propensity buyers.

| Infrastructure Maturity | Indicators | Points |
|---|---|---|
| **Modern Cloud / SaaS Stack** | GCP, AWS, Kubernetes, Next.js, Cloudflare, Stripe, Datadog | `+10 pts` |
| **Legacy / Standard Web Stack** | LAMP, Standard cPanel, WordPress | `+5 pts` |
| **Undetected Stack** | N/A | `0 pts` |

---

## 3. Lead Quality Tiers

| Tier | Score Range | Action & Outreach Strategy |
|---|---|---|
| 💎 **Platinum** | `90 – 100` | **Immediate Priority Outreach:** High-touch personalized executive sequence (email + LinkedIn + phone). |
| 🥇 **Gold** | `80 – 89` | **Targeted Campaign:** Director/Manager sequence with technical pitch and domain audit findings. |
| 🥈 **Silver** | `70 – 79` | **Nurture List:** Automated awareness campaign or secondary contact outreach. |
| 🥉 **Bronze** | `< 70` | **Backlog:** Requires manual data enrichment before campaign activation. |

---

## 4. Deduplication & Data Normalization

1. **Email Hash Deduplication:** Contacts are deduplicated across scans based on lowercased canonical email addresses (`john.doe@company.com`).
2. **Name & Title Cleanliness:** Titles are normalized from social profile scrapes, stripping emojis, certifications (CISSP, CISA), and extraneous whitespace.
3. **Phone Formatting:** Automated conversion to international E.164 standards (`+14158904122`).
