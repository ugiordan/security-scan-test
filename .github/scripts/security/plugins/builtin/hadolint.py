"""Hadolint parser plugin for Dockerfile security."""

import json
from typing import Dict, Any
from ..base import SecurityPlugin


class HadolintParser(SecurityPlugin):
    """Parser for Hadolint SARIF output - Dockerfile best practices."""

    def parse(self) -> Dict[str, Any]:
        """Parse Hadolint SARIF output and return structured findings.

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
                sarif = json.load(f)

            findings_data = []

            for run in sarif.get('runs', []):
                for result in run.get('results', []):
                    stats['findings'] += 1

                    level = result.get('level', 'note')
                    severity_map = {
                        'error': 'HIGH',
                        'warning': 'MEDIUM',
                        'note': 'LOW'
                    }
                    severity = severity_map.get(level, 'LOW')

                    rule = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', 'No description')

                    locations = result.get('locations') or [{}]
                    location = locations[0] if locations else {}
                    artifact = location.get('physicalLocation', {}).get('artifactLocation', {})
                    file_path = artifact.get('uri', 'unknown')

                    region = location.get('physicalLocation', {}).get('region', {})
                    line = region.get('startLine', '?')

                    findings_data.append({
                        'tool': self.display_name,
                        'type': 'Dockerfile Issue',
                        'severity': severity,
                        'file': file_path,
                        'line': line,
                        'rule': rule,
                        'description': message,
                        'remediation': 'Follow Dockerfile best practices and CIS benchmarks'
                    })

            stats['findings_data'] = findings_data

            if stats['findings'] > 0:
                stats['status'] = '❌ FINDINGS'

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = f'Failed to parse Hadolint SARIF output: {str(e)}'

        return stats
