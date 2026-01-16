"""yamllint parser plugin for YAML validation."""

import re
from typing import Dict, Any
from ..base import SecurityPlugin


class YamllintParser(SecurityPlugin):
    """Parser for yamllint parsable format output - YAML syntax and style validation."""

    def parse(self) -> Dict[str, Any]:
        """Parse yamllint parsable format output and return structured findings.

        Format: file:line:column: [level] message (rule)
        Example: ./config/rbac/role.yaml:10:5: [error] line too long (120 > 80 characters) (line-length)

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
                lines = f.readlines()

            # Parse each line in parsable format
            # Pattern: filepath:line:column: [level] message (rule)
            pattern = r'^(.+?):(\d+):(\d+): \[(error|warning)\] (.+?) \(([^)]+)\)$'

            findings_data = []

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                match = re.match(pattern, line)
                if not match:
                    # Skip lines that don't match expected format
                    continue

                file_path, line_num, col, level, message, rule = match.groups()
                stats['findings'] += 1

                # Map yamllint levels to severity (yamllint is code quality, not security)
                severity_map = {
                    'error': 'HIGH',
                    'warning': 'MEDIUM'
                }
                severity = severity_map.get(level, 'MEDIUM')

                findings_data.append({
                    'tool': self.display_name,
                    'type': 'YAML Issue',
                    'severity': severity,
                    'level': level,  # Keep original level for grouping
                    'file': file_path,
                    'line': int(line_num),
                    'column': int(col),
                    'rule': rule,
                    'description': message,
                    'remediation': 'Fix YAML formatting according to yamllint rules'
                })

            stats['findings_data'] = findings_data

            if stats['findings'] > 0:
                stats['status'] = '❌ FINDINGS'

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = f'Failed to parse yamllint output: {str(e)}'

        return stats
