#!/usr/bin/env python3
"""
Lead Generation & Decision Maker Qualification Pipeline Script
Part of the SubSweep OSINT Reconnaissance Suite.

Calculates multi-factor lead quality scores (0-100) and exports
filtered high-value prospects to CSV, JSON, or console.

Usage:
    python export_leads.py --min-score 80 --output qualified_leads.csv
    python export_leads.py --format json --output leads.json
"""

import argparse
import csv
import json
import os
import sys
from typing import Any, Dict, List, Optional


def calculate_lead_score(lead: Dict[str, str]) -> int:
    """
    Computes a 0-100 lead quality score using multi-factor heuristics:
    - Deliverable Email & High Confidence: up to 30 pts
    - Decision Maker / Executive Seniority: up to 25 pts
    - Social & Digital Footprint: up to 20 pts
    - Direct Phone Presence: up to 15 pts
    - Modern Tech Stack Fit: up to 10 pts
    """
    score = 0

    # 1. Email Factor (0-30 pts)
    email = lead.get("email", "").strip()
    conf_str = lead.get("email_confidence", "0%").replace("%", "").strip()
    try:
        conf = int(conf_str)
    except ValueError:
        conf = 80

    if email and "@" in email and "." in email.split("@")[-1]:
        score += 15
        if conf >= 95:
            score += 15
        elif conf >= 85:
            score += 10
        else:
            score += 5

    # 2. Decision Maker Seniority (0-25 pts)
    title = lead.get("title_role", "").lower()
    if any(k in title for k in ["ciso", "cto", "ceo", "cio", "cso", "founder", "president"]):
        score += 25
    elif any(k in title for k in ["vp", "vice president", "head of", "director"]):
        score += 20
    elif any(k in title for k in ["lead", "principal", "staff", "manager", "architect"]):
        score += 15
    elif any(k in title for k in ["engineer", "specialist", "analyst"]):
        score += 10
    else:
        score += 5

    # 3. Social Footprint (0-20 pts)
    if lead.get("linkedin_url", "").strip():
        score += 10
    if lead.get("twitter_handle", "").strip():
        score += 5
    if lead.get("github_url", "").strip():
        score += 5

    # 4. Direct Phone Reachability (0-15 pts)
    phone = lead.get("phone", "").strip()
    if phone and len(phone) >= 7:
        if "+1 (" in phone or "+1-" in phone:
            score += 15
        else:
            score += 10

    # 5. Tech Stack & Firmographic Fit (0-10 pts)
    tech = lead.get("tech_stack_summary", "").lower()
    if any(k in tech for k in ["gcp", "aws", "kubernetes", "next.js", "cloudflare", "stripe", "react"]):
        score += 10
    elif tech:
        score += 5

    return min(100, max(0, score))


def load_leads_from_csv(file_path: str) -> List[Dict[str, Any]]:
    """Loads lead records from CSV and applies scoring."""
    leads = []
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Recalculate or sanitize lead score
            computed_score = calculate_lead_score(row)
            row_dict = dict(row)
            row_dict["lead_score"] = int(row.get("lead_score", computed_score) or computed_score)
            
            # Assign tier
            if row_dict["lead_score"] >= 90:
                row_dict["tier"] = "Platinum"
            elif row_dict["lead_score"] >= 80:
                row_dict["tier"] = "Gold"
            elif row_dict["lead_score"] >= 70:
                row_dict["tier"] = "Silver"
            else:
                row_dict["tier"] = "Bronze"

            leads.append(row_dict)

    return leads


def export_leads_to_csv(leads: List[Dict[str, Any]], output_path: str) -> None:
    """Exports structured lead records to a CSV file."""
    if not leads:
        print("[!] No leads to export.")
        return

    fieldnames = list(leads[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(leads)


def print_leads_table(leads: List[Dict[str, Any]]) -> None:
    """Prints a styled terminal table of leads."""
    print("=" * 80)
    print("  \033[1;32mSubSweep B2B Lead Harvester & Decision Maker Pipeline\033[0m")
    print(f"  Total Qualified Prospects: {len(leads)}")
    print("=" * 80)
    print(f"  {'Score':<7} {'Name':<18} {'Title / Role':<32} {'Email':<28} {'Phone'}")
    print("  " + "-" * 100)

    for l in leads:
        score = l["lead_score"]
        score_color = "\033[1;35m" if score >= 90 else ("\033[1;32m" if score >= 80 else "\033[1;34m")
        print(f"  {score_color}{score:<7}\033[0m {l['lead_name']:<18} {l['title_role'][:30]:<32} \033[34m{l['email']:<28}\033[0m {l.get('phone', 'N/A')}")

    print("=" * 80)


def main() -> int:
    parser = argparse.ArgumentParser(description="SubSweep Lead Generation Exporter")
    parser.add_argument("--input", default="sample_leads.csv", help="Input CSV file path (default: sample_leads.csv)")
    parser.add_argument("--output", help="Optional output file path")
    parser.add_argument("--min-score", type=int, default=0, help="Minimum lead score threshold (0-100)")
    parser.add_argument("--exec-only", action="store_true", help="Filter for C-Level and VP leadership only")
    parser.add_argument("--format", choices=["csv", "json", "text"], default="text", help="Output format")

    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(script_dir, args.input) if not os.path.isabs(args.input) else args.input

    leads = load_leads_from_csv(input_file)

    if args.min_score > 0:
        leads = [l for l in leads if l["lead_score"] >= args.min_score]

    if args.exec_only:
        exec_titles = ["ciso", "cto", "ceo", "cio", "vp", "vice president", "head of", "director"]
        leads = [l for l in leads if any(t in l["title_role"].lower() for t in exec_titles)]

    if args.format == "text":
        print_leads_table(leads)
    elif args.format == "json":
        json_out = json.dumps(leads, indent=2)
        print(json_out)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_out)
            print(f"[+] Exported {len(leads)} leads to JSON: {args.output}")
    elif args.format == "csv":
        if args.output:
            export_leads_to_csv(leads, args.output)
            print(f"[+] Exported {len(leads)} leads to CSV: {args.output}")
        else:
            export_leads_to_csv(leads, "exported_leads.csv")
            print(f"[+] Exported {len(leads)} leads to exported_leads.csv")

    if args.output and args.format == "text":
        export_leads_to_csv(leads, args.output)
        print(f"[+] Saved leads table to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
