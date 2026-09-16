"""
Main executable entry point for subsweep-lead-scanner module.
Allows invocation via: python3 -m subsweep_lead_scanner <args>
"""

import sys
from subsweep_lead_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
