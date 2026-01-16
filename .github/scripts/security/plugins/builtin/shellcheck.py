"""ShellCheck parser plugin for shell script security."""

import json
from typing import Dict, Any
from ..base import SecurityPlugin


class ShellCheckParser(SecurityPlugin):
    """Parser for ShellCheck JSON output - shell script security and best practices."""

    def parse(self) -> Dict[str, Any]:
        """Parse ShellCheck JSON output and return structured findings.

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

            # ShellCheck outputs either a flat list (legacy) or {comments: [...]} (json1).
            # Support both formats robustly.
            if isinstance(data, list):
                findings_iter = data
            elif isinstance(data, dict):
                # Check for json1 format with 'comments' key, or fall back to iterating all values
                if 'comments' in data:
                    findings_iter = data['comments']
                else:
                    findings_iter = [item for v in data.values() if isinstance(v, list) for item in v]
            else:
                findings_iter = []

            findings_data = []

            for finding in findings_iter:
                stats['findings'] += 1

                level = finding.get('level', 'info')
                severity_map = {
                    'error': 'HIGH',
                    'warning': 'MEDIUM',
                    'info': 'LOW',
                    'style': 'INFO'
                }
                severity = severity_map.get(level, 'LOW')

                findings_data.append({
                    'tool': self.display_name,
                    'type': 'Shell Script Issue',
                    'severity': severity,
                    'file': finding.get('file', 'unknown'),
                    'line': finding.get('line', '?'),
                    'rule': f"SC{finding.get('code', '????')}",
                    'description': finding.get('message', 'No description'),
                    'remediation': 'Follow ShellCheck recommendations for safe shell scripting'
                })

            stats['findings_data'] = findings_data

            if stats['findings'] > 0:
                stats['status'] = '❌ FINDINGS'

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = f'Failed to parse ShellCheck output: {str(e)}'

        return stats
