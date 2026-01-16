#!/usr/bin/env python3
"""
Interactive Security Findings Acknowledgment Tool

Allows teams to interactively acknowledge security findings that are false positives
or accepted risks. Updates .github/config/security-baseline.yaml with detailed justifications.

Usage:
    python .github/scripts/acknowledge-findings.py
    python .github/scripts/acknowledge-findings.py --tool gitleaks
    python .github/scripts/acknowledge-findings.py --team security-team

Supports all 9 security tools:
    - Gitleaks (secrets)
    - TruffleHog (verified credentials)
    - Semgrep (SAST)
    - ShellCheck (shell scripts)
    - Hadolint (Dockerfiles)
    - yamllint (YAML validation)
    - actionlint (GitHub Actions)
    - kube-linter (Kubernetes manifests)
    - RBAC Analyzer (privilege chains)
"""

import json
import os
import sys
import argparse
import re
import hashlib
import yaml
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


class FindingAcknowledger:
    """Interactive tool for acknowledging security findings"""

    def __init__(self, workspace: str = '.', team: Optional[str] = None):
        self.workspace = Path(workspace)
        self.baseline_path = self.workspace / '.github' / 'config' / 'security-baseline.yaml'
        self.team = team or os.getenv('USER', 'unknown-user')
        self.baseline_data = {}
        self.available_tools = []

    def detect_available_findings(self) -> Dict[str, Path]:
        """Detect which tool output files exist in workspace

        Returns:
            Dict mapping tool name to file path
        """
        tool_files = {
            'gitleaks': 'gitleaks.json',
            'trufflehog': 'trufflehog.json',
            'semgrep': 'semgrep.sarif',
            'shellcheck': 'shellcheck.json',
            'hadolint': 'hadolint.sarif',
            'yamllint': 'yamllint.txt',
            'actionlint': 'actionlint.txt',
            'kube-linter': 'kube-linter.json',
            'rbac-analyzer': 'rbac-analysis.md'
        }

        found = {}
        for tool, filename in tool_files.items():
            filepath = self.workspace / filename
            if filepath.exists() and filepath.stat().st_size > 0:
                found[tool] = filepath
                self.available_tools.append(tool)

        return found

    def load_baseline(self) -> None:
        """Load existing baseline file or create new structure

        Tries in order:
        1. .github/config/security-baseline.yaml (v2.0 - preferred)
        2. .security-baseline.json (v2.0 - backward compat)
        3. Create new baseline if neither exists
        """
        # Try YAML baseline first (preferred format)
        yaml_path = self.workspace / '.github' / 'config' / 'security-baseline.yaml'
        json_path = self.workspace / '.security-baseline.json'

        if yaml_path.exists():
            with open(yaml_path) as f:
                self.baseline_data = yaml.safe_load(f)
        elif json_path.exists():
            with open(json_path) as f:
                self.baseline_data = json.load(f)
            print("[INFO] Loaded legacy JSON baseline - will migrate to YAML on save", file=sys.stderr)
        else:
            # Create new baseline structure
            self.baseline_data = {
                'version': '2.0',
                'description': 'Acknowledged security findings that are not real issues',
                '_comment': 'Findings acknowledged by teams using CLI tool or Claude skill',
                'gitleaks': [],
                'trufflehog': [],
                'semgrep': [],
                'shellcheck': [],
                'hadolint': [],
                'yamllint': [],
                'actionlint': [],
                'kube-linter': [],
                'rbac-analyzer': []
            }

    def parse_gitleaks(self, filepath: Path) -> List[Dict[str, Any]]:
        """Parse Gitleaks JSON output"""
        findings = []
        try:
            with open(filepath) as f:
                data = json.load(f)
                if not data:
                    return []

                for item in data:
                    # Normalize file path
                    file_path = item.get('File', 'unknown')
                    if file_path.startswith('/repo/'):
                        file_path = file_path[6:]
                    file_path = os.path.normpath(file_path).lstrip('/')

                    description = item.get('Description', 'Secret detected')
                    desc_hash = hashlib.sha256(description.encode()).hexdigest()[:8]

                    findings.append({
                        'file': file_path,
                        'line': item.get('StartLine', '?'),
                        'rule': item.get('RuleID', 'unknown'),
                        'description_hash': desc_hash,
                        'description': description
                    })
        except Exception as e:
            print(f"Error parsing Gitleaks output: {e}", file=sys.stderr)

        return findings

    def parse_kube_linter(self, filepath: Path) -> List[Dict[str, Any]]:
        """Parse kube-linter JSON output"""
        findings = []
        try:
            with open(filepath) as f:
                data = json.load(f)
                reports = data.get('Reports', [])

                for report in reports:
                    k8s_obj = report.get('Object', {}).get('K8sObject', {})
                    findings.append({
                        'check': report.get('Check', 'unknown'),
                        'object': {
                            'kind': k8s_obj.get('GroupVersionKind', {}).get('Kind', 'unknown'),
                            'name': k8s_obj.get('Name', 'unknown'),
                            'namespace': k8s_obj.get('Namespace') or None
                        },
                        'message': report.get('Diagnostic', {}).get('Message', '')
                    })
        except Exception as e:
            print(f"Error parsing kube-linter output: {e}", file=sys.stderr)

        return findings

    def filter_new_findings(self, tool: str, all_findings: List[Dict]) -> List[Dict]:
        """Filter out findings that are already in baseline

        Returns:
            List of findings not in baseline
        """
        baseline_findings = self.baseline_data.get(tool, [])
        new_findings = []

        for finding in all_findings:
            is_acknowledged = False

            # Check if this finding matches any baseline entry
            for baseline_entry in baseline_findings:
                if self._findings_match(tool, finding, baseline_entry):
                    is_acknowledged = True
                    break

            if not is_acknowledged:
                new_findings.append(finding)

        return new_findings

    def _findings_match(self, tool: str, finding: Dict, baseline_entry: Dict) -> bool:
        """Check if a finding matches a baseline entry

        Each tool has different matching criteria based on unique identifiers
        """
        if tool == 'gitleaks':
            return (finding.get('file') == baseline_entry.get('file') and
                    finding.get('line') == baseline_entry.get('line') and
                    finding.get('rule') == baseline_entry.get('rule') and
                    finding.get('description_hash') == baseline_entry.get('description_hash'))

        elif tool == 'kube-linter':
            obj1 = finding.get('object', {})
            obj2 = baseline_entry.get('object', {})
            return (finding.get('check') == baseline_entry.get('check') and
                    obj1.get('kind') == obj2.get('kind') and
                    obj1.get('name') == obj2.get('name') and
                    obj1.get('namespace') == obj2.get('namespace'))

        # Add more tool-specific matching logic as needed
        return False

    def interactive_acknowledge(self, tool: str, findings: List[Dict]) -> List[Dict]:
        """Interactive workflow to acknowledge findings

        Returns:
            List of acknowledged findings with reason and metadata
        """
        print(f"\n{'='*80}")
        print(f"📋 {tool.upper()} - New Findings")
        print(f"{'='*80}\n")

        if not findings:
            print("✅ No new findings to acknowledge\n")
            return []

        print(f"Found {len(findings)} new {tool} findings:\n")

        # Display findings
        for idx, finding in enumerate(findings, 1):
            print(f"[{idx}] ", end="")
            if tool == 'gitleaks':
                print(f"CRITICAL: {finding['rule']}")
                print(f"    File: {finding['file']}:{finding['line']}")
                print(f"    Description: {finding['description']}")
            elif tool == 'kube-linter':
                obj = finding['object']
                obj_id = f"{obj['kind']}/{obj['name']}"
                if obj['namespace']:
                    obj_id = f"{obj['kind']}/{obj['namespace']}/{obj['name']}"
                print(f"{finding['check']}")
                print(f"    Object: {obj_id}")
                print(f"    Message: {finding['message']}")
            print()

        # Select findings to acknowledge
        while True:
            selection = input(f"Select findings to acknowledge (comma-separated, e.g., 1,2,3) or 'skip': ").strip()
            if selection.lower() == 'skip':
                return []

            try:
                indices = [int(x.strip()) for x in selection.split(',')]
                if all(1 <= idx <= len(findings) for idx in indices):
                    break
                else:
                    print(f"⚠️  Please enter numbers between 1 and {len(findings)}")
            except ValueError:
                print("⚠️  Invalid input. Please enter comma-separated numbers or 'skip'")

        # Acknowledge selected findings
        acknowledged = []
        for idx in indices:
            finding = findings[idx - 1]
            print(f"\n{'─'*80}")
            print(f"Acknowledging finding #{idx}")
            print(f"{'─'*80}")

            # Collect reason
            while True:
                reason = input("\nReason (required, explain why this isn't a real issue): ").strip()
                if len(reason) >= 10:
                    break
                print("⚠️  Reason must be at least 10 characters. Explain why this is safe to ignore.")

            # Collect acknowledged_by
            acknowledged_by = input(f"Acknowledged by [{self.team}]: ").strip() or self.team

            # Add metadata
            finding['reason'] = reason
            finding['acknowledged_by'] = acknowledged_by
            finding['acknowledged_date'] = datetime.now(UTC).strftime('%Y-%m-%d')

            # Remove temporary fields
            if 'description' in finding and tool == 'gitleaks':
                del finding['description']
            if 'message' in finding and tool == 'kube-linter':
                del finding['message']

            acknowledged.append(finding)
            print("✅ Finding acknowledged")

        return acknowledged

    def update_baseline(self, tool: str, new_acknowledgments: List[Dict]) -> None:
        """Update baseline file with new acknowledgments"""
        if tool not in self.baseline_data:
            self.baseline_data[tool] = []

        self.baseline_data[tool].extend(new_acknowledgments)

    def save_baseline(self) -> None:
        """Save baseline file with proper formatting (YAML)"""
        # Ensure directory exists
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.baseline_path, 'w') as f:
            yaml.dump(self.baseline_data, f,
                     default_flow_style=False,  # Use block style (more readable)
                     sort_keys=False,            # Preserve insertion order
                     allow_unicode=True)

    def run_interactive(self, tool_filter: Optional[str] = None) -> None:
        """Run interactive acknowledgment workflow"""
        print(f"\n{'='*80}")
        print("🔒 Security Findings Acknowledgment Tool")
        print(f"{'='*80}\n")

        # Detect available findings
        available = self.detect_available_findings()
        if not available:
            print("❌ No security tool output files found in current directory.")
            print("\n📥 To use this tool:")
            print("1. Download workflow artifacts from failed security scan")
            print("2. Extract output files (gitleaks.json, kube-linter.json, etc.)")
            print("3. Run this tool from the directory containing the files\n")
            sys.exit(1)

        print(f"✅ Found output files for {len(available)} tools:")
        for tool in available:
            print(f"   - {tool}")
        print()

        # Load baseline
        self.load_baseline()
        if self.baseline_path.exists():
            total_acknowledged = sum(len(entries) for entries in self.baseline_data.values() if isinstance(entries, list))
            print(f"📋 Loaded existing baseline with {total_acknowledged} acknowledged findings\n")
        else:
            print("📋 No existing baseline - will create new file\n")

        # Filter tools if specified
        if tool_filter:
            if tool_filter not in available:
                print(f"❌ Tool '{tool_filter}' output not found")
                sys.exit(1)
            tools_to_process = [tool_filter]
        else:
            tools_to_process = self.available_tools

        # Process each tool
        total_acknowledged = 0
        acknowledgments_by_tool = {}

        for tool in tools_to_process:
            # Parse findings
            if tool == 'gitleaks':
                all_findings = self.parse_gitleaks(available[tool])
            elif tool == 'kube-linter':
                all_findings = self.parse_kube_linter(available[tool])
            else:
                # TODO: Implement other parsers in Phase 2
                print(f"⏭️  Skipping {tool} (parser not yet implemented)")
                continue

            # Filter new findings
            new_findings = self.filter_new_findings(tool, all_findings)

            # Interactive acknowledgment
            acknowledged = self.interactive_acknowledge(tool, new_findings)
            if acknowledged:
                self.update_baseline(tool, acknowledged)
                total_acknowledged += len(acknowledged)
                acknowledgments_by_tool[tool] = len(acknowledged)

        # Save baseline
        if total_acknowledged > 0:
            self.save_baseline()
            print(f"\n{'='*80}")
            print(f"✅ Acknowledged {total_acknowledged} findings:")
            for tool, count in acknowledgments_by_tool.items():
                print(f"   - {tool}: {count} finding(s)")
            print(f"\n📝 Updated {self.baseline_path}")
            print(f"\n{'='*80}")
            print("\n📋 Next steps:")
            print(f"1. Review changes: git diff {self.baseline_path}")
            print(f"2. Commit: git add {self.baseline_path} && git commit -m \"chore: Acknowledge security findings\"")
            print("3. Push to re-run security checks")
            print()
        else:
            print("\n✅ No findings acknowledged\n")


def main():
    parser = argparse.ArgumentParser(
        description='Interactively acknowledge security findings as false positives or accepted risks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (recommended)
  python .github/scripts/acknowledge-findings.py

  # Acknowledge only Gitleaks findings
  python .github/scripts/acknowledge-findings.py --tool gitleaks

  # Specify team name
  python .github/scripts/acknowledge-findings.py --team security-team

Workflow:
  1. Download security scan artifacts from failed workflow
  2. Extract output files to current directory
  3. Run this tool to interactively acknowledge false positives
  4. Commit updated .github/config/security-baseline.yaml
  5. Push to re-run security checks
        """
    )
    parser.add_argument('--tool', help='Process only specific tool (gitleaks, kube-linter, etc.)')
    parser.add_argument('--team', help='Team or person acknowledging findings (default: $USER)')
    parser.add_argument('--workspace', default='.', help='Workspace directory (default: current directory)')

    args = parser.parse_args()

    try:
        acknowledger = FindingAcknowledger(workspace=args.workspace, team=args.team)
        acknowledger.run_interactive(tool_filter=args.tool)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user - no changes saved\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
