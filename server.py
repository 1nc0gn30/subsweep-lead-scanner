#!/usr/bin/env python3
"""SubSweep Lead Scanner Standalone Production Server on Port 8090.

Provides real REST API endpoints:
  - /health & /api/health
  - /api/mcp/config
  - /api/scan
  - /api/subdomains
  - /api/tech
  - /api/leads
  - /api/ports
  - /api/policy
  - /api/asn
  - /api/export-bundle
  - /api/export-zip
and serves the standalone SubSweep Recon Studio from public/.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
PUBLIC_DIR = ROOT_DIR / "public"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from subsweep_lead_scanner.ui_server import run_ui_server

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SubSweep Lead Scanner Standalone Workstation")
    parser.add_argument("--port", type=int, default=8090, help="Port to listen on (default: 8090)")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    args = parser.parse_args()

    print(f"Starting SubSweep Lead Scanner Server on {args.host}:{args.port}...")
    run_ui_server(host=args.host, port=args.port, public_dir=str(PUBLIC_DIR))
