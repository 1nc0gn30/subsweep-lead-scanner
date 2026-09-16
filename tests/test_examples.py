"""
Unit and Integration Tests for SubSweep Reference Examples, Configurations, UI, and CI/CD Workflows.
"""

import csv
import json
import os
import subprocess
import sys
from pathlib import Path
import pytest

# Base repository root directory
REPO_ROOT = Path(__file__).resolve().parent.parent


def test_audit_report_json_validity():
    """Verify that audit_report.json exists, is valid JSON, and has complete recon metadata."""
    report_file = REPO_ROOT / "examples" / "domain-recon-audit" / "audit_report.json"
    assert report_file.exists(), f"Missing {report_file}"

    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "scan_metadata" in data
    assert "domain_overview" in data
    assert "dns_records" in data
    assert "subdomains_discovery" in data
    assert "open_ports_and_services" in data
    assert "technology_fingerprints" in data
    assert "security_posture_grades" in data

    meta = data["scan_metadata"]
    assert meta["target"] == "acme-cloud.io"
    assert 0 <= meta["composite_security_score"] <= 100
    assert meta["composite_security_grade"] in ["A+", "A", "B+", "B", "C", "D", "F"]

    subdomains = data["subdomains_discovery"]["items"]
    assert len(subdomains) >= 15, "Expected at least 15 subdomains in production reference dataset"
    assert any(s["fqdn"] == "api.acme-cloud.io" for s in subdomains)

    ports = data["open_ports_and_services"]
    assert len(ports) >= 4, "Expected multiple port scan results"
    assert any(p["port"] == 443 for p in ports)


def test_run_audit_script_execution():
    """Verify that run_audit.py runs cleanly across text, json, and markdown formats."""
    script_path = REPO_ROOT / "examples" / "domain-recon-audit" / "run_audit.py"
    assert script_path.exists(), f"Missing {script_path}"

    # 1. Text format
    res_text = subprocess.run(
        [sys.executable, str(script_path), "--domain", "acme-cloud.io", "--format", "text"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT)
    )
    assert res_text.returncode == 0
    assert "SubSweep Reconnaissance & Attack Surface Audit" in res_text.stdout
    assert "acme-cloud.io" in res_text.stdout

    # 2. Markdown format
    res_md = subprocess.run(
        [sys.executable, str(script_path), "--domain", "acme-cloud.io", "--format", "markdown"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT)
    )
    assert res_md.returncode == 0
    assert "# Reconnaissance Audit Report: acme-cloud.io" in res_md.stdout
    assert "| Subdomain FQDN |" in res_md.stdout

    # 3. JSON format
    res_json = subprocess.run(
        [sys.executable, str(script_path), "--domain", "acme-cloud.io", "--format", "json"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT)
    )
    assert res_json.returncode == 0
    parsed = json.loads(res_json.stdout)
    assert parsed["scan_metadata"]["target"] == "acme-cloud.io"


def test_sample_leads_csv_validity():
    """Verify that sample_leads.csv is properly formatted and contains valid B2B lead records."""
    csv_path = REPO_ROOT / "examples" / "lead-generation-pipeline" / "sample_leads.csv"
    assert csv_path.exists(), f"Missing {csv_path}"

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) >= 10, "Expected at least 10 lead records in reference dataset"

    required_cols = {
        "company_domain", "company_name", "industry", "lead_name",
        "title_role", "email", "email_confidence", "phone", "linkedin_url",
        "lead_score", "outreach_status"
    }
    assert required_cols.issubset(set(rows[0].keys()))

    for row in rows:
        assert "@" in row["email"], f"Invalid email in row: {row}"
        score = int(row["lead_score"])
        assert 0 <= score <= 100, f"Score out of range: {score}"


def test_export_leads_script_execution():
    """Verify that export_leads.py calculates scores and filters leads accurately."""
    script_path = REPO_ROOT / "examples" / "lead-generation-pipeline" / "export_leads.py"
    assert script_path.exists(), f"Missing {script_path}"

    # 1. Filter min score 85 JSON
    res_json = subprocess.run(
        [sys.executable, str(script_path), "--min-score", "85", "--format", "json"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT)
    )
    assert res_json.returncode == 0
    leads = json.loads(res_json.stdout)
    assert len(leads) > 0
    for lead in leads:
        assert int(lead["lead_score"]) >= 85

    # 2. Executive only filter
    res_exec = subprocess.run(
        [sys.executable, str(script_path), "--exec-only", "--format", "json"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT)
    )
    assert res_exec.returncode == 0
    exec_leads = json.loads(res_exec.stdout)
    assert len(exec_leads) > 0
    exec_keywords = ["ciso", "cto", "ceo", "cio", "vp", "vice president", "head of", "director"]
    for lead in exec_leads:
        assert any(k in lead["title_role"].lower() for k in exec_keywords)


def test_lead_score_calculation_direct():
    """Directly test the lead score calculation heuristic function."""
    sys.path.insert(0, str(REPO_ROOT / "examples" / "lead-generation-pipeline"))
    from export_leads import calculate_lead_score

    # Platinum executive lead
    exec_lead = {
        "email": "ciso@target.com",
        "email_confidence": "99%",
        "title_role": "Chief Information Security Officer (CISO)",
        "linkedin_url": "linkedin.com/in/ciso",
        "twitter_handle": "@ciso_sec",
        "github_url": "ciso-sec",
        "phone": "+1 (415) 890-4190",
        "tech_stack_summary": "GCP / Kubernetes / Next.js"
    }
    score_exec = calculate_lead_score(exec_lead)
    assert score_exec >= 90, f"Expected Platinum score >= 90, got {score_exec}"

    # Low score lead
    minimal_lead = {
        "email": "info@target.com",
        "email_confidence": "60%",
        "title_role": "General Switchboard",
        "linkedin_url": "",
        "twitter_handle": "",
        "github_url": "",
        "phone": "",
        "tech_stack_summary": ""
    }
    score_min = calculate_lead_score(minimal_lead)
    assert score_min < 75, f"Expected lower score for minimal lead, got {score_min}"


def test_mcp_configurations_syntax_and_schema():
    """Verify all MCP client configuration JSON files are valid and well-formed."""
    mcp_dir = REPO_ROOT / "examples" / "mcp-clients"
    config_files = [
        mcp_dir / "claude_desktop_config.json",
        mcp_dir / "cursor_mcp.json",
        mcp_dir / "cline_mcp.json",
        mcp_dir / "zed_settings.json",
    ]

    for fpath in config_files:
        assert fpath.exists(), f"Missing {fpath}"
        with open(fpath, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        assert isinstance(cfg, dict)
        # Check server definitions exist
        assert "mcpServers" in cfg or "context_servers" in cfg, f"Invalid MCP root structure in {fpath.name}"


def test_ci_workflow_yaml_validity():
    """Verify .github/workflows/ci.yml configuration and matrix specs."""
    ci_file = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_file.exists(), f"Missing {ci_file}"
    content = ci_file.read_text(encoding="utf-8")

    assert "ubuntu-latest" in content
    assert "macos-latest" in content
    assert "windows-latest" in content
    for py_ver in ["3.9", "3.10", "3.11", "3.12", "3.13"]:
        assert py_ver in content, f"Missing Python version {py_ver} in CI matrix"

    assert "pytest" in content
    assert "flake8" in content


def test_release_workflow_yaml_validity():
    """Verify .github/workflows/release.yml configuration."""
    rel_file = REPO_ROOT / ".github" / "workflows" / "release.yml"
    assert rel_file.exists(), f"Missing {rel_file}"
    content = rel_file.read_text(encoding="utf-8")

    assert "build" in content
    assert "sha256sum" in content or "SHA-256" in content
    assert "twine check" in content
    assert "action-gh-release" in content or "gh release" in content


def test_docs_exist_and_comprehensive():
    """Verify all documentation guides exist and contain required sections."""
    docs_dir = REPO_ROOT / "docs"
    recon_guide = docs_dir / "OSINT_RECON_GUIDE.md"
    lead_guide = docs_dir / "LEAD_SCORING_METHODOLOGY.md"
    mcp_guide = docs_dir / "MCP_GUIDE.md"

    for doc in [recon_guide, lead_guide, mcp_guide]:
        assert doc.exists(), f"Missing {doc}"
        text = doc.read_text(encoding="utf-8")
        assert len(text) > 1000, f"Documentation file {doc.name} appears too brief"

    # Verify specific sections
    assert "Certificate Transparency" in recon_guide.read_text(encoding="utf-8")
    assert "Mathematical Formulation" in lead_guide.read_text(encoding="utf-8")
    assert "subsweep.recon_subdomains" in mcp_guide.read_text(encoding="utf-8")


def test_public_index_html_material3_elements():
    """Verify public/index.html Google Material 3 Light Mode design and interactive features."""
    index_html = REPO_ROOT / "public" / "index.html"
    assert index_html.exists(), f"Missing {index_html}"
    content = index_html.read_text(encoding="utf-8")

    # Material 3 Color tokens
    assert "--md-sys-color-primary" in content
    assert "--google-blue" in content
    assert "--google-green" in content
    assert "--google-yellow" in content
    assert "--google-red" in content

    # Google dots branding
    assert "google-dots" in content

    # Recon grade & lead score dial elements
    assert "scoreDialCircle" in content
    assert "overallScoreVal" in content

    # Interactive tabs
    assert "tab-subdomains" in content
    assert "tab-leads" in content
    assert "tab-tech" in content
    assert "tab-ports" in content
    assert "tab-mcp" in content
    assert "tab-report" in content
    assert "tab-guide" in content

    # Offline privacy check: No external tracking scripts or CDNs
    assert "google-analytics.com/analytics.js" not in content
    assert "googletagmanager.com/gtag/js" not in content


def test_readme_root_completeness():
    """Verify top-level repository README.md has badges, architecture, and guides."""
    readme = REPO_ROOT / "README.md"
    assert readme.exists(), f"Missing {readme}"
    content = readme.read_text(encoding="utf-8")

    assert "SubSweep" in content
    assert "Google Material 3" in content
    assert "Model Context Protocol" in content or "MCP" in content
    assert "Quickstart" in content
    assert "CLI Usage" in content
