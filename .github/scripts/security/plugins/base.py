"""Base interface for security scanner plugins."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
from pathlib import Path


class SecurityPlugin(ABC):
    """Base class for all security scanner plugins.

    All security scanning tools (built-in and external) must implement this interface
    to integrate with the unified security reporting system.
    """

    def __init__(self, config: Dict[str, Any], workspace: Path):
        """Initialize plugin with configuration and workspace path.

        Args:
            config: Plugin configuration from security-plugins.yaml
            workspace: Path to repository being scanned
        """
        self.config = config
        self.workspace = workspace
        self.name = config['name']
        self.display_name = config['display_name']
        self.output_file = workspace / config['output_file']

    @abstractmethod
    def parse(self) -> Dict[str, Any]:
        """Parse tool output and return structured findings.

        Returns:
            Dictionary with standardized finding format:
            {
                'tool': str,              # Display name (e.g., "Gitleaks")
                'status': str,            # ✅ PASS | ❌ FINDINGS | ⏭️ SKIPPED | ⚠️ ERROR
                'findings': int,          # Total count of findings
                'findings_data': List[{   # Standardized findings
                    'tool': str,
                    'type': str,
                    'severity': str,      # CRITICAL | HIGH | MEDIUM | LOW | INFO
                    'file': str,
                    'line': int|str,
                    'rule': str,
                    'description': str,
                    'remediation': str    # Optional fix guidance
                }],
                'metadata': Dict          # Optional extra data
            }
        """
        pass

    def get_severity_mapping(self) -> Dict[str, str]:
        """Get severity mapping from config with defaults.

        Returns:
            Dictionary mapping tool-specific severity to standard levels
        """
        return self.config.get('severity_mapping', {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW',
            'INFO': 'INFO'
        })

    def map_severity(self, severity: str) -> str:
        """Map tool-specific severity to standard level.

        Args:
            severity: Tool-specific severity level

        Returns:
            Standard severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        """
        severity_map = self.get_severity_mapping()
        return severity_map.get(severity.upper(), severity.upper())
