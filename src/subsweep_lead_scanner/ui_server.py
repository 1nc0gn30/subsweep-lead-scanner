"""
UI Server & REST API for SubSweep Lead Scanner
==============================================
Threaded HTTP server providing REST endpoints and serving the Google
Material 3 Recon Studio Web UI with real-time audit streaming, CSV/JSON
exports, standalone zip bundle packaging, and MCP integration.

Pure Python stdlib - zero external runtime dependencies.
"""

from __future__ import annotations

import csv
import io
import json
import mimetypes
import os
import sys
import threading
import time
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from .mcp_server import (
    MCPServer,
    generate_mcp_client_config,
    enumerate_subdomains,
    fingerprint_tech,
    extract_leads,
    probe_ports,
    full_audit,
    get_diagnostics,
    MCP_TOOLS_MANIFEST,
    __version__,
)

START_TIME = time.time()

# Embedded Material 3 Recon Studio Web Application
EMBEDDED_STUDIO_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SubSweep // OSINT Recon & Lead Intelligence Studio</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #0b0f17;
      --bg-surface: #111827;
      --bg-surface-elevated: #1a2234;
      --bg-surface-high: #242f46;
      --border-subtle: #243049;
      --border-focus: #3b82f6;
      --text-main: #f3f4f6;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --primary: #38bdf8;
      --primary-hover: #0ea5e9;
      --primary-container: rgba(56, 189, 248, 0.12);
      --secondary: #a78bfa;
      --success: #34d399;
      --success-container: rgba(52, 211, 153, 0.12);
      --warning: #fbbf24;
      --danger: #f87171;
      --radius-sm: 8px;
      --radius-md: 12px;
      --radius-lg: 18px;
      --radius-full: 9999px;
      --shadow-md: 0 4px 20px -2px rgba(0, 0, 0, 0.5);
      --shadow-lg: 0 10px 30px -4px rgba(0, 0, 0, 0.7);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background-color: var(--bg-surface);
      border-bottom: 1px solid var(--border-subtle);
      padding: 0.85rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      text-decoration: none;
      color: inherit;
    }
    .brand-icon {
      width: 38px;
      height: 38px;
      background: linear-gradient(135deg, #38bdf8, #6366f1);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 1.1rem;
      color: #fff;
      box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
    }
    .brand-title {
      font-weight: 800;
      font-size: 1.15rem;
      letter-spacing: -0.02em;
    }
    .brand-title span { color: var(--primary); }
    .nav-tabs {
      display: flex;
      gap: 0.35rem;
      background: var(--bg-base);
      padding: 0.25rem;
      border-radius: var(--radius-md);
      border: 1px solid var(--border-subtle);
    }
    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.5rem 0.9rem;
      border-radius: var(--radius-sm);
      font-size: 0.825rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    .tab-btn:hover { color: var(--text-main); background: rgba(255, 255, 255, 0.05); }
    .tab-btn.active {
      background: var(--primary);
      color: #0b0f17;
      box-shadow: 0 0 12px rgba(56, 189, 248, 0.3);
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .btn {
      background: var(--bg-surface-elevated);
      color: var(--text-main);
      border: 1px solid var(--border-subtle);
      padding: 0.5rem 0.9rem;
      border-radius: var(--radius-sm);
      font-size: 0.825rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.15s ease;
      text-decoration: none;
    }
    .btn:hover { border-color: var(--primary); color: var(--primary); }
    .btn-primary {
      background: var(--primary);
      color: #0b0f17;
      border: none;
    }
    .btn-primary:hover { background: var(--primary-hover); color: #0b0f17; }
    main {
      flex: 1;
      max-width: 1380px;
      width: 100%;
      margin: 0 auto;
      padding: 1.5rem;
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    .hero-search {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: var(--shadow-md);
    }
    .search-row {
      display: flex;
      gap: 0.75rem;
      margin-top: 1rem;
    }
    .search-input {
      flex: 1;
      background: var(--bg-base);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 0.85rem 1.25rem;
      color: var(--text-main);
      font-size: 1rem;
      outline: none;
      font-family: 'Fira Code', monospace;
      transition: border-color 0.15s;
    }
    .search-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15); }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 1.25rem; margin-top: 1.25rem; }
    .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-top: 1.25rem; }
    .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-top: 1rem; }
    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 1.25rem;
      box-shadow: var(--shadow-md);
    }
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
      padding-bottom: 0.65rem;
      border-bottom: 1px solid var(--border-subtle);
    }
    .card-title {
      font-size: 0.95rem;
      font-weight: 700;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .stat-val { font-size: 1.85rem; font-weight: 800; color: var(--primary); }
    .stat-label { font-size: 0.775rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 0.25rem 0.65rem;
      border-radius: var(--radius-full);
      font-size: 0.75rem;
      font-weight: 600;
      background: var(--bg-surface-high);
      color: var(--text-main);
    }
    .badge-primary { background: var(--primary-container); color: var(--primary); border: 1px solid rgba(56, 189, 248, 0.3); }
    .badge-success { background: var(--success-container); color: var(--success); border: 1px solid rgba(52, 211, 153, 0.3); }
    .badge-warning { background: rgba(251, 191, 36, 0.12); color: var(--warning); border: 1px solid rgba(251, 191, 36, 0.3); }
    .badge-danger { background: rgba(248, 113, 113, 0.12); color: var(--danger); border: 1px solid rgba(248, 113, 113, 0.3); }
    .table-container {
      overflow-x: auto;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
      background: var(--bg-base);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.825rem;
      text-align: left;
    }
    th {
      background: var(--bg-surface-elevated);
      padding: 0.75rem 1rem;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--border-subtle);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    td {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border-subtle);
      color: var(--text-main);
      font-family: 'Fira Code', monospace;
    }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    .chips-wrap { display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .score-circle {
      width: 100px;
      height: 100px;
      border-radius: 50%;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: radial-gradient(circle, var(--bg-surface-elevated) 60%, var(--primary-container));
      border: 3px solid var(--primary);
      box-shadow: 0 0 20px rgba(56, 189, 248, 0.3);
    }
    .score-num { font-size: 1.75rem; font-weight: 800; color: #fff; line-height: 1; }
    .score-grade { font-size: 0.75rem; color: var(--primary); font-weight: 700; margin-top: 2px; }
    .loader {
      display: none;
      align-items: center;
      gap: 0.75rem;
      color: var(--primary);
      font-size: 0.9rem;
      font-weight: 600;
      margin-top: 1rem;
    }
    .spinner {
      width: 20px;
      height: 20px;
      border: 3px solid rgba(56, 189, 248, 0.2);
      border-top-color: var(--primary);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    pre {
      background: var(--bg-base);
      padding: 1rem;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
      color: #38bdf8;
      font-family: 'Fira Code', monospace;
      font-size: 0.825rem;
      overflow-x: auto;
      max-height: 400px;
    }
    footer {
      border-top: 1px solid var(--border-subtle);
      padding: 1rem 1.5rem;
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-dim);
      background: var(--bg-surface);
      margin-top: auto;
    }
  </style>
</head>
<body>
  <header>
    <a href="#" class="brand">
      <div class="brand-icon">⚡</div>
      <div class="brand-title">Sub<span>Sweep</span> Studio</div>
    </a>
    <nav class="nav-tabs">
      <button class="tab-btn active" onclick="showTab('audit')">🔎 Full Audit</button>
      <button class="tab-btn" onclick="showTab('subdomains')">📍 Subdomains</button>
      <button class="tab-btn" onclick="showTab('tech')">⚡ Tech Stack</button>
      <button class="tab-btn" onclick="showTab('leads')">🎯 Leads & Intel</button>
      <button class="tab-btn" onclick="showTab('ports')">🛡️ Ports</button>
      <button class="tab-btn" onclick="showTab('mcp')">🤖 MCP Server</button>
    </nav>
    <div class="header-actions">
      <button class="btn" onclick="exportStudioZip()">📦 Standalone ZIP</button>
      <a href="/api/health" target="_blank" class="btn">🩺 Health</a>
    </div>
  </header>

  <main>
    <!-- TAB 1: FULL AUDIT -->
    <section id="tab-audit" class="tab-content active">
      <div class="hero-search">
        <h2>360° Multi-Vector OSINT Reconnaissance & Lead Intelligence</h2>
        <p style="color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem;">
          Deep subdomain discovery, technology signature fingerprinting, business lead extraction, and port analysis.
        </p>
        <div class="search-row">
          <input type="text" id="audit-target" class="search-input" placeholder="e.g. stripe.com or github.com" value="example.com">
          <button class="btn btn-primary" onclick="runFullAudit()" style="padding: 0 1.75rem; font-size: 0.95rem;">Launch Recon</button>
        </div>
        <div id="audit-loader" class="loader">
          <div class="spinner"></div> Scanning subdomains, fingerprinting tech stack, extracting leads & probing ports...
        </div>
      </div>

      <div id="audit-results" style="display: none;">
        <div class="grid-4">
          <div class="card" style="display: flex; align-items: center; justify-content: space-between;">
            <div>
              <div class="stat-label">Lead Quality</div>
              <div class="stat-val" id="res-score">0</div>
              <div id="res-grade" class="badge badge-primary">Grade A</div>
            </div>
            <div class="score-circle">
              <div class="score-num" id="res-circle-score">0</div>
              <div class="score-grade" id="res-circle-grade">SCORE</div>
            </div>
          </div>
          <div class="card">
            <div class="stat-label">Subdomains Found</div>
            <div class="stat-val" id="res-subs-count">0</div>
            <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.25rem;">DNS Active & Passive</div>
          </div>
          <div class="card">
            <div class="stat-label">Leads Harvested</div>
            <div class="stat-val" id="res-leads-count">0</div>
            <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.25rem;">Emails & Phones</div>
          </div>
          <div class="card">
            <div class="stat-label">Open Ports</div>
            <div class="stat-val" id="res-ports-count">0</div>
            <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.25rem;">Public TCP Services</div>
          </div>
        </div>

        <div class="grid-2">
          <!-- Leads & Intelligence -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">🎯 Harvested Contacts & Business Profile</div>
              <button class="btn" onclick="exportCsvCurrent()">⬇ CSV</button>
            </div>
            <div style="margin-bottom: 1rem;">
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.4rem;">EMAILS DISCOVERED</div>
              <div id="res-emails" class="chips-wrap"></div>
            </div>
            <div style="margin-bottom: 1rem;">
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.4rem;">PHONE NUMBERS</div>
              <div id="res-phones" class="chips-wrap"></div>
            </div>
            <div style="margin-bottom: 1rem;">
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.4rem;">SOCIAL PRESENCE</div>
              <div id="res-socials" class="chips-wrap"></div>
            </div>
            <div id="res-biz-info"></div>
          </div>

          <!-- Technology Stack -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">⚡ Technology Stack & Security</div>
              <span id="res-cms-badge" class="badge badge-primary">No CMS</span>
            </div>
            <div style="margin-bottom: 1rem;">
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.4rem;">DETECTED TECHNOLOGIES</div>
              <div id="res-tech-chips" class="chips-wrap"></div>
            </div>
            <div style="margin-bottom: 1rem;">
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.4rem;">INFRASTRUCTURE & CDN</div>
              <div id="res-infra"></div>
            </div>
            <div>
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.4rem;">SECURITY HEADERS</div>
              <div id="res-sec-headers" style="font-size: 0.8rem;"></div>
            </div>
          </div>
        </div>

        <!-- Subdomains Table -->
        <div class="card" style="margin-top: 1.25rem;">
          <div class="card-header">
            <div class="card-title">📍 Discovered Subdomains & Network Map</div>
            <span id="res-sub-timer" class="badge">0 ms</span>
          </div>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Subdomain</th>
                  <th>IP Address</th>
                  <th>Latency</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody id="res-sub-table"></tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- TAB 2: SUBDOMAINS -->
    <section id="tab-subdomains" class="tab-content">
      <div class="hero-search">
        <h2>Subdomain Enumeration Engine</h2>
        <div class="search-row">
          <input type="text" id="subs-input" class="search-input" placeholder="target domain (e.g. acme.com)">
          <button class="btn btn-primary" onclick="runSubdomains()">Scan Subdomains</button>
        </div>
      </div>
      <div id="subs-tab-results"></div>
    </section>

    <!-- TAB 3: TECH STACK -->
    <section id="tab-tech" class="tab-content">
      <div class="hero-search">
        <h2>Technology Stack & CMS Fingerprinter</h2>
        <div class="search-row">
          <input type="text" id="tech-input" class="search-input" placeholder="target url (e.g. https://example.com)">
          <button class="btn btn-primary" onclick="runTech()">Fingerprint</button>
        </div>
      </div>
      <div id="tech-tab-results"></div>
    </section>

    <!-- TAB 4: LEADS -->
    <section id="tab-leads" class="tab-content">
      <div class="hero-search">
        <h2>Business Lead & Contact Intelligence Harvester</h2>
        <div class="search-row">
          <input type="text" id="leads-input" class="search-input" placeholder="target url or domain (e.g. https://company.com)">
          <button class="btn btn-primary" onclick="runLeads()">Extract Leads</button>
        </div>
      </div>
      <div id="leads-tab-results"></div>
    </section>

    <!-- TAB 5: PORTS -->
    <section id="tab-ports" class="tab-content">
      <div class="hero-search">
        <h2>TCP Port Probe & Banner Grabber</h2>
        <div class="search-row">
          <input type="text" id="ports-input" class="search-input" placeholder="target host (e.g. example.com)">
          <button class="btn btn-primary" onclick="runPorts()">Probe Ports</button>
        </div>
      </div>
      <div id="ports-tab-results"></div>
    </section>

    <!-- TAB 6: MCP INTEGRATION -->
    <section id="tab-mcp" class="tab-content">
      <div class="hero-search">
        <h2>🤖 Model Context Protocol (MCP) Server Integration</h2>
        <p style="color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem;">
          Connect SubSweep into Claude Desktop, Cursor, Cline, or Zed as an autonomous AI tool.
        </p>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-header">
            <div class="card-title">Client Configuration Generator</div>
            <select id="mcp-client-select" onchange="fetchMcpConfig()" class="btn" style="background: var(--bg-surface-high);">
              <option value="claude">Claude Desktop</option>
              <option value="cursor">Cursor IDE</option>
              <option value="cline">Cline / Roo</option>
              <option value="zed">Zed Editor</option>
              <option value="generic">Generic MCP</option>
            </select>
          </div>
          <pre id="mcp-config-code">// Loading MCP config...</pre>
          <button class="btn btn-primary" onclick="copyMcpConfig()" style="margin-top: 0.75rem;">📋 Copy Config</button>
        </div>
        <div class="card">
          <div class="card-header">
            <div class="card-title">Registered MCP Tools (Stdio)</div>
            <span class="badge badge-success">6 Tools Active</span>
          </div>
          <ul style="list-style: none; font-size: 0.85rem; line-height: 1.8;">
            <li>⚡ <code>subsweep_enumerate_subdomains</code>: Enumerate DNS records</li>
            <li>🔍 <code>subsweep_fingerprint_tech</code>: Detect CMS, frameworks & CDN</li>
            <li>🎯 <code>subsweep_extract_leads</code>: Harvest emails, phones & calculate quality score</li>
            <li>🛡️ <code>subsweep_probe_ports</code>: Fast multi-port TCP connectivity probe</li>
            <li>🌐 <code>subsweep_full_audit</code>: 360-degree multi-vector domain audit</li>
            <li>🩺 <code>subsweep_get_diagnostics</code>: Runtime & network health checks</li>
          </ul>
        </div>
      </div>
    </section>
  </main>

  <footer>
    SubSweep Recon Studio v1.0.0 &bull; Pure Python Stdlib &bull; Model Context Protocol &bull; Zero External Runtime Dependencies
  </footer>

  <script>
    let currentAuditData = null;

    function showTab(name) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById('tab-' + name).classList.add('active');
      event.target.classList.add('active');
      if (name === 'mcp') fetchMcpConfig();
    }

    async function runFullAudit() {
      const target = document.getElementById('audit-target').value.trim();
      if (!target) return alert('Please enter target domain');

      document.getElementById('audit-loader').style.display = 'flex';
      document.getElementById('audit-results').style.display = 'none';

      try {
        const resp = await fetch('/api/scan', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({domain: target})
        });
        const data = await resp.json();
        currentAuditData = data;
        renderAuditResults(data);
      } catch (err) {
        alert('Audit failed: ' + err.message);
      } finally {
        document.getElementById('audit-loader').style.display = 'none';
      }
    }

    function renderAuditResults(data) {
      document.getElementById('audit-results').style.display = 'block';
      const summary = data.lead_summary || {};
      const score = summary.score || 0;
      const grade = summary.grade || 'D';

      document.getElementById('res-score').innerText = score + '/100';
      document.getElementById('res-grade').innerText = 'Grade ' + grade;
      document.getElementById('res-circle-score').innerText = score;
      document.getElementById('res-circle-grade').innerText = grade;

      document.getElementById('res-subs-count').innerText = summary.subdomains_count || 0;
      document.getElementById('res-leads-count').innerText = (summary.emails_count || 0) + (summary.phones_count || 0);
      document.getElementById('res-ports-count').innerText = summary.open_ports_count || 0;

      // Leads
      const emailsContainer = document.getElementById('res-emails');
      emailsContainer.innerHTML = '';
      (data.leads.emails || []).forEach(e => {
        emailsContainer.innerHTML += `<span class="badge badge-success">✉ ${e}</span>`;
      });
      if (!data.leads.emails?.length) emailsContainer.innerHTML = '<span style="color:var(--text-dim);font-size:0.8rem;">No emails detected</span>';

      const phonesContainer = document.getElementById('res-phones');
      phonesContainer.innerHTML = '';
      (data.leads.phones || []).forEach(p => {
        phonesContainer.innerHTML += `<span class="badge badge-warning">📞 ${p}</span>`;
      });
      if (!data.leads.phones?.length) phonesContainer.innerHTML = '<span style="color:var(--text-dim);font-size:0.8rem;">No phone numbers detected</span>';

      const socialsContainer = document.getElementById('res-socials');
      socialsContainer.innerHTML = '';
      for (const [k, v] of Object.entries(data.leads.social_links || {})) {
        socialsContainer.innerHTML += `<a href="${v[0]}" target="_blank" class="badge badge-primary" style="text-decoration:none;">🔗 ${k}</a>`;
      }
      if (!Object.keys(data.leads.social_links || {}).length) socialsContainer.innerHTML = '<span style="color:var(--text-dim);font-size:0.8rem;">No social profiles</span>';

      // Tech Stack
      const techChips = document.getElementById('res-tech-chips');
      techChips.innerHTML = '';
      (data.technology.technologies || []).forEach(t => {
        techChips.innerHTML += `<span class="badge">${t.name}</span>`;
      });
      if (data.technology.cms) {
        document.getElementById('res-cms-badge').innerText = data.technology.cms;
      }

      document.getElementById('res-infra').innerHTML = `
        <div style="font-size:0.8rem; color:var(--text-muted);">CDN/Cloud: <b style="color:var(--primary);">${data.technology.cdn || 'Direct'}</b></div>
        <div style="font-size:0.8rem; color:var(--text-muted); margin-top:2px;">Server: <b style="color:var(--text-main);">${data.technology.server || 'Unknown'}</b></div>
      `;

      // Security Headers
      const secDiv = document.getElementById('res-sec-headers');
      secDiv.innerHTML = '';
      for (const [k, v] of Object.entries(data.technology.security_headers || {})) {
        const isPres = v !== 'Missing' && v !== 'None';
        secDiv.innerHTML += `<div>${k}: <span style="color:${isPres ? 'var(--success)' : 'var(--text-dim)'};">${v}</span></div>`;
      }

      // Subdomains Table
      const subTable = document.getElementById('res-sub-table');
      subTable.innerHTML = '';
      (data.subdomains.subdomains || []).forEach(s => {
        subTable.innerHTML += `
          <tr>
            <td style="color:var(--primary); font-weight:600;">${s.subdomain}</td>
            <td style="color:var(--success);">${s.ip || 'Unresolved'}</td>
            <td>${s.latency_ms || 0}ms</td>
            <td><span class="badge">${s.source || 'dns'}</span></td>
          </tr>
        `;
      });
      document.getElementById('res-sub-timer').innerText = data.total_duration_ms + ' ms';
    }

    async function fetchMcpConfig() {
      const client = document.getElementById('mcp-client-select').value;
      const resp = await fetch('/api/mcp/config?client=' + client);
      const data = await resp.json();
      document.getElementById('mcp-config-code').innerText = JSON.stringify(data, null, 2);
    }

    function copyMcpConfig() {
      const text = document.getElementById('mcp-config-code').innerText;
      navigator.clipboard.writeText(text);
      alert('MCP Client Configuration copied to clipboard!');
    }

    async function exportCsvCurrent() {
      if (!currentAuditData) return alert('No audit data yet.');
      const resp = await fetch('/api/export-csv', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({leads: currentAuditData.leads})
      });
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'subsweep-leads.csv';
      a.click();
    }

    async function exportStudioZip() {
      const resp = await fetch('/api/export-zip', {method: 'POST'});
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'subsweep-recon-studio.zip';
      a.click();
    }

    // Direct tab runners
    async function runSubdomains() {
      const domain = document.getElementById('subs-input').value.trim();
      if (!domain) return alert('Enter domain');
      const resp = await fetch('/api/subdomains', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain})
      });
      const data = await resp.json();
      document.getElementById('subs-tab-results').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    }

    async function runTech() {
      const target = document.getElementById('tech-input').value.trim();
      if (!target) return alert('Enter target URL');
      const resp = await fetch('/api/tech', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target})
      });
      const data = await resp.json();
      document.getElementById('tech-tab-results').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    }

    async function runLeads() {
      const target = document.getElementById('leads-input').value.trim();
      if (!target) return alert('Enter target');
      const resp = await fetch('/api/leads', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target})
      });
      const data = await resp.json();
      document.getElementById('leads-tab-results').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    }

    async function runPorts() {
      const domain = document.getElementById('ports-input').value.trim();
      if (!domain) return alert('Enter host');
      const resp = await fetch('/api/ports', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain})
      });
      const data = await resp.json();
      document.getElementById('ports-tab-results').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    }
  </script>
</body>
</html>
"""


class ReconRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for REST API and Web UI serving."""

    public_dir: Optional[str] = None

    def _set_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self._set_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _parse_json_body(self) -> Dict[str, Any]:
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len > 0:
                raw_body = self.rfile.read(content_len).decode("utf-8")
                return json.loads(raw_body)
        except Exception:
            pass
        return {}

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # 1. Health endpoint
        if path == "/api/health":
            diag = get_diagnostics()
            diag["uptime_seconds"] = round(time.time() - START_TIME, 2)
            self._send_json(diag)
            return

        # 2. MCP Config endpoint
        elif path == "/api/mcp/config":
            client = query_params.get("client", ["claude"])[0]
            config = generate_mcp_client_config(client)
            self._send_json(config)
            return

        # 3. Static UI Serving
        if self.public_dir and os.path.exists(self.public_dir):
            rel_path = path.lstrip("/") or "index.html"
            target_file = os.path.join(self.public_dir, rel_path)
            if os.path.exists(target_file) and os.path.isfile(target_file):
                mime, _ = mimetypes.guess_type(target_file)
                mime = mime or "application/octet-stream"
                with open(target_file, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self._set_cors_headers()
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        # Fallback to Embedded Material 3 Recon Studio HTML
        if path in ("/", "/index.html", ""):
            html_bytes = EMBEDDED_STUDIO_HTML.encode("utf-8")
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.end_headers()
            self.wfile.write(html_bytes)
            return

        # 404
        self.send_response(404)
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(b"Not Found")

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        body = self._parse_json_body()

        if path == "/api/scan":
            domain = body.get("domain", "")
            ports = body.get("ports")
            passive_only = bool(body.get("passive_only", False))
            timeout = float(body.get("timeout", 5.0))
            res = full_audit(domain, ports=ports, passive_only=passive_only, timeout=timeout)
            self._send_json(res)

        elif path == "/api/subdomains":
            domain = body.get("domain", "")
            wordlist = body.get("wordlist")
            passive_only = bool(body.get("passive_only", False))
            timeout = float(body.get("timeout", 3.0))
            res = enumerate_subdomains(domain, wordlist=wordlist, passive_only=passive_only, timeout=timeout)
            self._send_json(res)

        elif path == "/api/tech":
            target = body.get("target", "")
            timeout = float(body.get("timeout", 5.0))
            res = fingerprint_tech(target, timeout=timeout)
            self._send_json(res)

        elif path == "/api/leads":
            target = body.get("target", "")
            html_content = body.get("html") or body.get("html_content")
            timeout = float(body.get("timeout", 5.0))
            res = extract_leads(target, html_content=html_content, timeout=timeout)
            self._send_json(res)

        elif path == "/api/ports":
            domain = body.get("domain", body.get("host", ""))
            ports = body.get("ports")
            timeout = float(body.get("timeout", 1.5))
            res = probe_ports(domain, ports=ports, timeout=timeout)
            self._send_json(res)

        elif path == "/api/policies":
            from .policy_auditor import audit_policy_endpoints
            domain = body.get("domain", "")
            robots_content = body.get("robots_content")
            security_txt_content = body.get("security_txt_content")
            timeout = float(body.get("timeout", 4.0))
            res = audit_policy_endpoints(
                domain_or_url=domain,
                timeout=timeout,
                robots_content=robots_content,
                security_txt_content=security_txt_content,
            )
            self._send_json(res)

        elif path == "/api/export-csv":
            leads_data = body.get("leads", body)
            emails = leads_data.get("emails", [])
            phones = leads_data.get("phones", [])
            socials = leads_data.get("social_links", {})
            biz = leads_data.get("business_info", {})
            target = leads_data.get("target", "")

            rows = []
            max_len = max(len(emails), len(phones), 1)
            social_str = " | ".join(f"{k}: {', '.join(v)}" for k, v in socials.items())

            address_str = ""
            if isinstance(biz.get("address"), dict):
                addr = biz["address"]
                address_str = f"{addr.get('streetAddress', '')} {addr.get('addressLocality', '')} {addr.get('addressRegion', '')}".strip()
            elif isinstance(biz.get("address"), str):
                address_str = biz["address"]

            for i in range(max_len):
                rows.append({
                    "Target": target,
                    "Business Name": biz.get("name") or biz.get("legalName") or "",
                    "Email": emails[i] if i < len(emails) else "",
                    "Phone": phones[i] if i < len(phones) else "",
                    "Address": address_str,
                    "Social Profiles": social_str if i == 0 else "",
                    "Lead Score": leads_data.get("lead_quality_score", 0) if i == 0 else "",
                    "Lead Grade": leads_data.get("lead_score_grade", "") if i == 0 else "",
                })

            output = io.StringIO()
            fieldnames = ["Target", "Business Name", "Email", "Phone", "Address", "Social Profiles", "Lead Score", "Lead Grade"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
            csv_bytes = output.getvalue().encode("utf-8")

            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="subsweep-leads.csv"')
            self.send_header("Content-Length", str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)

        elif path == "/api/export-json":
            data_to_export = body.get("data", body)
            json_bytes = json.dumps(data_to_export, indent=2).encode("utf-8")
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="subsweep-report.json"')
            self.send_header("Content-Length", str(len(json_bytes)))
            self.end_headers()
            self.wfile.write(json_bytes)

        elif path == "/api/export-zip":
            # Generate in-memory zip archive with embedded UI and runner
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("index.html", EMBEDDED_STUDIO_HTML)
                readme_content = f"# SubSweep Recon Studio\nStandalone portable OSINT Recon Web Package v{__version__}\n\nOpen index.html in any modern browser."
                zf.writestr("README.md", readme_content)
                sample_json = json.dumps({"project": "subsweep", "version": __version__}, indent=2)
                zf.writestr("subsweep-sample.json", sample_json)

            zip_bytes = zip_buffer.getvalue()
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="subsweep-recon-studio.zip"')
            self.send_header("Content-Length", str(len(zip_bytes)))
            self.end_headers()
            self.wfile.write(zip_bytes)

        else:
            self._send_json({"error": f"Endpoint not found: {path}"}, status=404)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard request logs during testing or normal run
        pass


def create_ui_server(
    host: str = "0.0.0.0",
    port: int = 8090,
    public_dir: Optional[str] = None
) -> ThreadingHTTPServer:
    """Create configured ThreadingHTTPServer instance."""
    handler_class = ReconRequestHandler
    if public_dir:
        handler_class.public_dir = os.path.abspath(public_dir)
    server = ThreadingHTTPServer((host, port), handler_class)
    return server


def run_ui_server(
    host: str = "0.0.0.0",
    port: int = 8090,
    public_dir: Optional[str] = None,
    open_browser: bool = False
) -> None:
    """Start and run ThreadingHTTPServer event loop."""
    server = create_ui_server(host=host, port=port, public_dir=public_dir)
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()
