# Model Context Protocol (MCP) Client Integrations

Connect `subsweep-lead-scanner` directly to your favorite AI development assistant using the open Model Context Protocol (MCP) standard.

## Available MCP Tools
When connected via stdio, SubSweep registers the following tools:
1. `subsweep.recon_subdomains(domain, passive_only=True, timeout=10)`: Enumerates all subdomains via Certificate Transparency and passive DNS.
2. `subsweep.harvest_leads(domain, max_leads=20, verify_mx=True)`: Extracts verified decision maker contacts and computes lead scores.
3. `subsweep.fingerprint_tech(url, deep_scan=True)`: Analyzes web frameworks, CDN edges, CMS engines, and security headers.
4. `subsweep.scan_ports(target, ports=[80, 443, 22, 5432, 3306], timeout=2.0)`: Performs non-intrusive TCP perimeter service banner checks.
5. `subsweep.generate_recon_report(domain, format="json")`: Compiles an executive posture score and intelligence brief.

---

## 1. Claude Desktop Setup
File location:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

Add the configuration from `claude_desktop_config.json`:
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

---

## 2. Cursor IDE Setup
File location: `.cursor/mcp.json` in your workspace root, or Cursor Settings > Features > MCP.

Use `cursor_mcp.json`:
```json
{
  "mcpServers": {
    "subsweep-recon": {
      "command": "python",
      "args": ["-m", "subsweep_lead_scanner.mcp_server"]
    }
  }
}
```

---

## 3. Cline (VS Code Extension) Setup
File location: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`

Use `cline_mcp.json`:
```json
{
  "mcpServers": {
    "subsweep-lead-scanner": {
      "command": "python",
      "args": ["-m", "subsweep_lead_scanner.mcp_server"],
      "disabled": false,
      "autoApprove": [
        "subsweep.recon_subdomains",
        "subsweep.harvest_leads"
      ]
    }
  }
}
```

---

## 4. Zed Editor Setup
File location: `~/.config/zed/settings.json`

Use `zed_settings.json`:
```json
{
  "context_servers": {
    "subsweep-recon": {
      "command": {
        "path": "python",
        "args": ["-m", "subsweep_lead_scanner.mcp_server"]
      }
    }
  }
}
```

---

## Example Prompts to Test With AI Agents
- *"Perform a passive reconnaissance audit on stripe.com, extract all payment and API subdomains, and tell me what CDN they use."*
- *"Find the CISO and VP of Infrastructure at acme-cloud.io, calculate their lead score, and draft a personalized outreach email highlighting their exposed port 3306."*
- *"Run a security header check on our staging domain and generate an executive summary in Markdown."*
