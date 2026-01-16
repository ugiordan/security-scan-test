#!/usr/bin/env python3
"""
Wrapper script to run the security orchestrator with proper Python path setup.
This ensures all imports work correctly when run from GitHub Actions.
"""

import sys
from pathlib import Path

# Add the security scripts directory to Python path
security_dir = Path(__file__).parent / 'security'
sys.path.insert(0, str(security_dir))

# Now import and run the orchestrator
from orchestrator import main

if __name__ == '__main__':
    sys.exit(main())
