"""kube-linter parser plugin for Kubernetes manifest security."""

import json
from typing import Dict, Any
from ..base import SecurityPlugin


class KubeLinterParser(SecurityPlugin):
    """Parser for kube-linter JSON output - Kubernetes manifest security."""

    def parse(self) -> Dict[str, Any]:
        """Parse kube-linter JSON output and return structured findings.

        kube-linter JSON format:
        {
          "Reports": [
            {
              "Object": {
                "K8sObject": {
                  "Namespace": "...",
                  "Name": "...",
                  "GroupVersionKind": {...}
                }
              },
              "Check": "check-name",
              "Diagnostic": {
                "Message": "...",
                "Description": "..."
              }
            }
          ]
        }

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

            reports = data.get('Reports', [])
            if not reports:
                return stats

            # Deduplicate findings by check:object:message combination
            seen = set()
            findings_data = []

            for report in reports:
                check_name = report.get('Check', 'unknown')
                diagnostic = report.get('Diagnostic', {})
                message = diagnostic.get('Message', 'kube-linter finding')
                description = diagnostic.get('Description', '')

                # Extract object information
                k8s_obj = report.get('Object', {}).get('K8sObject', {})
                namespace = k8s_obj.get('Namespace', '')
                name = k8s_obj.get('Name', 'unknown')
                gvk = k8s_obj.get('GroupVersionKind', {})
                kind = gvk.get('Kind', 'unknown')

                # Construct object identifier
                if namespace:
                    object_id = f"{kind}/{namespace}/{name}"
                else:
                    object_id = f"{kind}/{name}"

                # Deduplication key
                dedup_key = f"{check_name}:{object_id}:{message}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Map check severity (kube-linter doesn't provide severity in JSON)
                severity = self._map_check_severity(check_name)

                findings_data.append({
                    'tool': self.display_name,
                    'type': 'Kubernetes Manifest Security',
                    'severity': severity,
                    'file': object_id,  # Use object ID as "file" for display
                    'line': check_name,  # Use check name as "line" for display
                    'rule': check_name,
                    'description': f"{message} (Object: {object_id})",
                    'remediation': description or 'Fix Kubernetes manifest according to check requirements'
                })

            stats['findings'] = len(findings_data)
            stats['findings_data'] = findings_data

            if stats['findings'] > 0:
                stats['status'] = '❌ FINDINGS'

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = f'Failed to parse kube-linter JSON: {str(e)}'

        return stats

    def _map_check_severity(self, check_name: str) -> str:
        """Map kube-linter check name to severity level.

        Args:
            check_name: kube-linter check name

        Returns:
            Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        """
        # Critical: cluster-admin, privileged containers, host access
        critical_checks = {
            'cluster-admin-role-binding', 'privileged-container',
            'host-network', 'host-pid', 'host-ipc', 'docker-sock',
            'access-to-create-pods', 'privilege-escalation-container',
            'run-as-non-root', 'no-read-only-root-fs', 'privileged-ports'
        }

        # High: RBAC wildcards, secret access, missing probes
        high_checks = {
            'access-to-secrets', 'wildcard-in-rules', 'sensitive-host-mounts',
            'writable-host-mount', 'unsafe-proc-mount', 'unsafe-sysctls',
            'default-service-account', 'env-var-secret', 'read-secret-from-env-var',
            'drop-net-raw-capability', 'exposed-services', 'non-isolated-pod',
            'ssh-port', 'latest-tag', 'no-system-group-binding'
        }

        # Medium: resource limits, namespace issues
        medium_checks = {
            'no-liveness-probe', 'no-readiness-probe',
            'unset-cpu-requirements', 'unset-memory-requirements',
            'use-namespace', 'non-existent-service-account'
        }

        if check_name in critical_checks:
            return 'CRITICAL'
        elif check_name in high_checks:
            return 'HIGH'
        elif check_name in medium_checks:
            return 'MEDIUM'
        else:
            return 'LOW'
