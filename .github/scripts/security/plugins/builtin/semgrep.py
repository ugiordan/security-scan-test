"""Semgrep parser plugin for custom SAST rules."""

import json
from typing import Dict, Any
from ..base import SecurityPlugin


class SemgrepParser(SecurityPlugin):
    """Parser for Semgrep SARIF output - custom security rules."""

    def parse(self) -> Dict[str, Any]:
        """Parse Semgrep SARIF output and return structured findings.

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
                        'note': 'INFO'
                    }
                    severity = severity_map.get(level, 'INFO')

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
                        'type': rule,
                        'severity': severity,
                        'file': file_path,
                        'line': line,
                        'rule': rule,
                        'description': message,
                        'remediation': self._get_remediation(rule)
                    })

            stats['findings_data'] = findings_data

            if stats['findings'] > 0:
                stats['status'] = '❌ FINDINGS'

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = f'Failed to parse Semgrep SARIF output: {str(e)}'

        return stats

    def _get_remediation(self, rule_id: str) -> str:
        """Get remediation guidance for Semgrep rules.

        Args:
            rule_id: Semgrep rule ID

        Returns:
            Remediation guidance string
        """
        remediations = {
            'hardcoded-secret-generic': 'Remove hardcoded secret, use environment variables or secret manager',
            'rbac-wildcard-resources': 'Replace wildcard with specific resources following least privilege',
            'rbac-wildcard-verbs': 'Replace wildcard with specific verbs needed for operation',
            'rbac-dangerous-verbs': 'Remove dangerous verbs (escalate/impersonate/bind) or justify usage',
            'insecure-tls-skip-verify': 'Remove InsecureSkipVerify, properly configure certificate validation',
            'weak-crypto-md5': 'Replace MD5 with SHA-256 or stronger hash function',
            'weak-crypto-sha1': 'Replace SHA-1 with SHA-256 or stronger hash function',
            'operator-privileged-pod': 'Remove privileged: true, use specific capabilities if needed',
        }
        return remediations.get(rule_id, 'Follow security best practices for this finding')
