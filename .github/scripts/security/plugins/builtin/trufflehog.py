"""TruffleHog parser plugin for verified credential detection."""

import json
from typing import Dict, Any
from ..base import SecurityPlugin


class TruffleHogParser(SecurityPlugin):
    """Parser for TruffleHog JSON output - verified credential detection."""

    def parse(self) -> Dict[str, Any]:
        """Parse TruffleHog JSON output and return structured findings.

        TruffleHog outputs JSONL (one JSON object per line).

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
            findings_count = 0
            parse_errors = 0
            findings_data = []

            with open(self.output_file) as f:
                for line in f:
                    if line.strip():
                        try:
                            finding = json.loads(line)
                        except json.JSONDecodeError:
                            parse_errors += 1
                            continue

                        findings_count += 1

                        findings_data.append({
                            'tool': self.display_name,
                            'type': 'Verified Credential',
                            'severity': 'CRITICAL',
                            'file': finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'unknown'),
                            'line': '?',
                            'rule': finding.get('DetectorName', 'unknown'),
                            'description': f"Verified {finding.get('DetectorName', 'credential')} found",
                            'remediation': 'URGENT: Rotate this credential immediately - it has been verified as active'
                        })

            stats['findings'] = findings_count
            stats['findings_data'] = findings_data

            if findings_count > 0:
                stats['status'] = '❌ FINDINGS'

            if parse_errors > 0:
                stats['status'] = f"⚠️ PARTIAL: {parse_errors} unparsable lines"
                stats['metadata']['parse_errors'] = parse_errors

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = f'Failed to parse TruffleHog output: {str(e)}'

        return stats
