"""Plugin registry loader for security scanning tools."""

import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional


class PluginRegistry:
    """Loads and manages security plugin configurations from YAML registry."""

    def __init__(self, registry_path: Optional[Path] = None, workspace: Optional[Path] = None):
        """Initialize plugin registry.

        Args:
            registry_path: Path to security-plugins.yaml (default: .github/config/security-plugins.yaml)
            workspace: Path to repository workspace (default: current directory)
        """
        self.workspace = workspace or Path.cwd()
        self.registry_path = registry_path or self.workspace / '.github/config/security-plugins.yaml'
        self.config: Dict[str, Any] = {}
        self.plugins: List[Dict[str, Any]] = []

        if self.registry_path.exists():
            self._load_registry()

    def _load_registry(self) -> None:
        """Load plugin registry from YAML file."""
        try:
            with open(self.registry_path) as f:
                self.config = yaml.safe_load(f) or {}

            self.plugins = self.config.get('plugins', [])

            print(f"✓ Loaded plugin registry: {len(self.plugins)} plugins configured")

        except yaml.YAMLError as e:
            print(f"⚠️  Error parsing plugin registry: {e}")
            self.plugins = []
        except Exception as e:
            print(f"⚠️  Error loading plugin registry: {e}")
            self.plugins = []

    def get_enabled_plugins(self) -> List[Dict[str, Any]]:
        """Get list of enabled plugins from registry.

        Returns:
            List of plugin configurations where enabled=true
        """
        return [p for p in self.plugins if p.get('enabled', False)]

    def get_plugins_by_type(self, plugin_type: str) -> List[Dict[str, Any]]:
        """Get plugins filtered by type (builtin or external).

        Args:
            plugin_type: Filter by 'builtin' or 'external'

        Returns:
            List of matching plugin configurations
        """
        return [p for p in self.plugins if p.get('type') == plugin_type]

    def get_plugin(self, name: str) -> Optional[Dict[str, Any]]:
        """Get specific plugin configuration by name.

        Args:
            name: Plugin name (e.g., 'gitleaks', 'fips-compliance-checker')

        Returns:
            Plugin configuration dictionary or None if not found
        """
        for plugin in self.plugins:
            if plugin.get('name') == name:
                return plugin
        return None

    def is_plugin_enabled(self, name: str) -> bool:
        """Check if a specific plugin is enabled.

        Args:
            name: Plugin name

        Returns:
            True if plugin exists and is enabled
        """
        plugin = self.get_plugin(name)
        return plugin.get('enabled', False) if plugin else False

    def get_execution_config(self) -> Dict[str, Any]:
        """Get global execution configuration.

        Returns:
            Execution settings (parallel, timeout, continue_on_error)
        """
        return self.config.get('execution', {
            'parallel': True,
            'default_timeout': 300,
            'continue_on_error': True
        })

    def __repr__(self) -> str:
        """String representation of registry."""
        enabled_count = len(self.get_enabled_plugins())
        total_count = len(self.plugins)
        return f"PluginRegistry({enabled_count}/{total_count} plugins enabled)"
