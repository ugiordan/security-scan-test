"""Gitleaks parser plugin for secret detection."""

import json
import os
import hashlib
from typing import Dict, Any
from ..base import SecurityPlugin


class GitleaksParser(SecurityPlugin):
    """Parser for Gitleaks JSON output - pattern-based secret detection."""

    def parse(self) -> Dict[str, Any]:
        """Parse Gitleaks JSON output and return structured findings.

        Returns:
            Dictionary with standardized finding format
        """
        stats = {
            'tool': self.display_name,
            'status': '✅ PASS',
            'findings': 0,
            'findings_data': [],
            'metadata': {}
        }

        if not self.output_file.exists():
            stats['status'] = '⏭️ SKIPPED'
            stats['metadata']['reason'] = 'Output file not found'
            return stats

        try:
            with open(self.output_file) as f:
                data = json.load(f)

            if not data:
                return stats

            # Deduplicate findings by file:line:rule:description_hash combination
            seen = set()
            unique_findings = []

            for finding in data:
                # Strip /repo/ prefix from Docker container mount path
                file_path = finding.get('File', 'unknown')
                if file_path.startswith('/repo/'):
                    file_path = file_path[6:]  # Remove '/repo/' prefix

                # Normalize path using os.path.normpath for robust handling
                file_path = os.path.normpath(file_path).lstrip('/')

                # Ensure no leading path traversal after normalization
                while file_path.startswith('../') or file_path.startswith('./'):
                    if file_path.startswith('../'):
                        file_path = file_path[3:]
                    elif file_path.startswith('./'):
                        file_path = file_path[2:]

                # Include description hash to differentiate multiple secrets at same location
                description = finding.get('Description', 'Secret detected')
                desc_hash = hashlib.sha256(description.encode()).hexdigest()[:8]
                dedup_key = f"{file_path}:{finding.get('StartLine', '?')}:{finding.get('RuleID', 'unknown')}:{desc_hash}"

                if dedup_key not in seen:
                    seen.add(dedup_key)
                    unique_findings.append({
                        'tool': self.display_name,
                        'type': 'Hardcoded Secret',
                        'severity': 'CRITICAL',
                        'file': file_path,
                        'line': finding.get('StartLine', '?'),
                        'rule': finding.get('RuleID', 'unknown'),
                        'description': finding.get(
                            'Description',
                            'Secret detected; see Gitleaks JSON artifact for details (value redacted)'
                        ),
                        'remediation': 'Remove secret from code, rotate credential, use secret manager'
                    })

            stats['findings'] = len(unique_findings)
            stats['findings_data'] = unique_findings

            if unique_findings:
                stats['status'] = '❌ FINDINGS'

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = f'Failed to parse Gitleaks output: {str(e)}'

        return stats
