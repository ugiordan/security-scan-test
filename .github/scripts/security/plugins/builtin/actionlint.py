"""actionlint parser plugin for GitHub Actions validation."""

import re
from typing import Dict, Any
from ..base import SecurityPlugin


class ActionlintParser(SecurityPlugin):
    """Parser for actionlint text output - GitHub Actions workflow validation."""

    def parse(self) -> Dict[str, Any]:
        """Parse actionlint text output and return structured findings.

        Format: <file>:<line>:<col>: <message> [<rule>]
        Example: .github/workflows/test.yml:10:5: invalid expression syntax [expression]

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
                content = f.read()

            # Pattern: filepath:line:col: message [rule]
            pattern = r'^(.+?):(\d+):(\d+):\s+(.+?)(?:\s+\[(.+?)\])?$'

            # Regex to strip ANSI color codes (e.g., \x1b[31m for red, \x1b[0m for reset)
            ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

            findings_data = []

            for line in content.splitlines():
                if not line.strip():
                    continue

                # Strip ANSI color codes before pattern matching
                clean_line = ansi_escape.sub('', line)

                match = re.match(pattern, clean_line)
                if not match:
                    continue

                file_path, line_num, col, message, rule = match.groups()
                stats['findings'] += 1

                # Map severity based on message content
                # GitHub Actions security issues are generally MEDIUM (workflow errors can break CI/CD)
                severity = 'MEDIUM'

                # Upgrade to HIGH for security-related issues
                if any(keyword in message.lower() for keyword in ['permission', 'token', 'secret', 'credential']):
                    severity = 'HIGH'

                findings_data.append({
                    'tool': self.display_name,
                    'type': 'GitHub Actions Workflow Issue',
                    'severity': severity,
                    'file': file_path,
                    'line': int(line_num),
                    'column': int(col),
                    'rule': rule or 'workflow-syntax',
                    'description': message,
                    'remediation': 'Fix GitHub Actions workflow syntax according to actionlint recommendation'
                })

            stats['findings_data'] = findings_data

            if stats['findings'] > 0:
                stats['status'] = '❌ FINDINGS'

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = f'Failed to parse actionlint output: {str(e)}'

        return stats
