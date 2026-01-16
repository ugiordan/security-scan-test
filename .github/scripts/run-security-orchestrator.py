#!/usr/bin/env python3
"""
Wrapper script to run the security orchestrator with proper Python path setup.
This ensures all imports work correctly when run from GitHub Actions.
"""

import sys
from pathlib import Path

# Add the parent directory (.github/scripts) to Python path so we can import 'security' as a package
scripts_dir = Path(__file__).parent
sys.path.insert(0, str(scripts_dir))

# Now import and run the orchestrator as a package module
from security.orchestrator import main

if __name__ == '__main__':
    sys.exit(main())
