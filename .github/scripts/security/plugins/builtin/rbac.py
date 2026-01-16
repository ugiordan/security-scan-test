"""RBAC Analyzer parser plugin for privilege escalation detection."""

import re
from typing import Dict, Any
from ..base import SecurityPlugin


class RBACAnalyzerParser(SecurityPlugin):
    """Parser for RBAC Analyzer text output - RBAC privilege chain analysis."""

    def parse(self) -> Dict[str, Any]:
        """Parse RBAC Analyzer text output and return structured findings.

        The RBAC analyzer outputs markdown format with severity headings like:
        ### CRITICAL (N findings)
        ### HIGH (N findings)
        ### WARNING (N findings)

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
                stats['metadata']['content'] = content

            # Extract actual finding counts from RBAC analyzer headings: "### CRITICAL (N findings)"
            # This prevents false matches in descriptions or remediation text
            def count_for(level: str) -> int:
                # Matches: ### CRITICAL (12 findings)
                m = re.search(rf'(?m)^###\s+{re.escape(level)}\s+\((\d+)\s+findings?\)', content)
                return int(m.group(1)) if m else 0

            critical_count = count_for('CRITICAL')
            high_count = count_for('HIGH')
            warning_count = count_for('WARNING')

            stats['findings'] = critical_count + high_count + warning_count

            if stats['findings'] > 0:
                stats['status'] = '❌ FINDINGS'
                stats['metadata']['breakdown'] = {
                    'critical': critical_count,
                    'high': high_count,
                    'warning': warning_count
                }

                # Feed RBAC findings into findings_data for consistency
                findings_data = []

                # Add critical findings
                for _ in range(critical_count):
                    findings_data.append({
                        'tool': self.display_name,
                        'type': 'RBAC Privilege Chain',
                        'severity': 'CRITICAL',
                        'file': 'rbac-analysis.md',
                        'line': '?',
                        'rule': 'RBAC_ANALYZER_CRITICAL',
                        'description': 'Critical RBAC privilege chain issue; see RBAC analysis section',
                        'remediation': 'Tighten roles/bindings; remove wildcard or dangerous verbs; apply least privilege'
                    })

                # Add high findings
                for _ in range(high_count):
                    findings_data.append({
                        'tool': self.display_name,
                        'type': 'RBAC Privilege Chain',
                        'severity': 'HIGH',
                        'file': 'rbac-analysis.md',
                        'line': '?',
                        'rule': 'RBAC_ANALYZER_HIGH',
                        'description': 'High-severity RBAC issue; see RBAC analysis section',
                        'remediation': 'Scope RBAC rules more narrowly; justify and document remaining access'
                    })

                # Add warning findings (mapped to MEDIUM)
                for _ in range(warning_count):
                    findings_data.append({
                        'tool': self.display_name,
                        'type': 'RBAC Privilege Chain',
                        'severity': 'MEDIUM',
                        'file': 'rbac-analysis.md',
                        'line': '?',
                        'rule': 'RBAC_ANALYZER_WARNING',
                        'description': 'RBAC warning; see RBAC analysis section',
                        'remediation': 'Review and tighten RBAC where feasible'
                    })

                stats['findings_data'] = findings_data

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = f'Failed to parse RBAC analyzer output: {str(e)}'

        return stats
