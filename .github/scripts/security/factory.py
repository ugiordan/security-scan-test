"""Plugin factory for instantiating security scanner plugins."""

from pathlib import Path
from typing import Dict, Any, Optional
from .plugins.base import SecurityPlugin

# Import all built-in plugin parsers
from .plugins.builtin.gitleaks import GitleaksParser
from .plugins.builtin.trufflehog import TruffleHogParser
from .plugins.builtin.semgrep import SemgrepParser
from .plugins.builtin.hadolint import HadolintParser
from .plugins.builtin.shellcheck import ShellCheckParser
from .plugins.builtin.yamllint import YamllintParser
from .plugins.builtin.actionlint import ActionlintParser
from .plugins.builtin.kubelinter import KubeLinterParser
from .plugins.builtin.rbac import RBACAnalyzerParser

# Import external plugin adapter
from .plugins.external.adapter import ExternalPluginAdapter


class PluginFactory:
    """Factory for creating security plugin instances."""

    # Registry of built-in plugin classes
    BUILTIN_PLUGINS: Dict[str, type] = {
        'GitleaksParser': GitleaksParser,
        'TruffleHogParser': TruffleHogParser,
        'SemgrepParser': SemgrepParser,
        'HadolintParser': HadolintParser,
        'ShellCheckParser': ShellCheckParser,
        'YamllintParser': YamllintParser,
        'ActionlintParser': ActionlintParser,
        'KubeLinterParser': KubeLinterParser,
        'RBACAnalyzerParser': RBACAnalyzerParser
    }

    # Registry of external plugin classes
    EXTERNAL_PLUGINS: Dict[str, type] = {
        'ExternalPluginAdapter': ExternalPluginAdapter
    }

    @classmethod
    def create_plugin(cls, config: Dict[str, Any], workspace: Path) -> Optional[SecurityPlugin]:
        """Create a plugin instance from configuration.

        Args:
            config: Plugin configuration from security-plugins.yaml
            workspace: Path to repository being scanned

        Returns:
            SecurityPlugin instance or None if plugin class not found

        Raises:
            ValueError: If plugin type is unknown
        """
        plugin_type = config.get('type')
        plugin_name = config.get('name')
        parser_class_name = config.get('parser_class')

        if plugin_type == 'builtin':
            return cls._create_builtin_plugin(config, workspace, parser_class_name)
        elif plugin_type == 'external':
            return cls._create_external_plugin(config, workspace, parser_class_name)
        else:
            raise ValueError(f"Unknown plugin type: {plugin_type} for plugin: {plugin_name}")

    @classmethod
    def _create_builtin_plugin(
        cls,
        config: Dict[str, Any],
        workspace: Path,
        parser_class_name: str
    ) -> Optional[SecurityPlugin]:
        """Create a built-in plugin instance.

        Args:
            config: Plugin configuration
            workspace: Workspace path
            parser_class_name: Name of parser class (e.g., 'GitleaksParser')

        Returns:
            SecurityPlugin instance or None if class not found
        """
        plugin_class = cls.BUILTIN_PLUGINS.get(parser_class_name)

        if not plugin_class:
            print(f"⚠️  Built-in plugin class not found: {parser_class_name}")
            return None

        return plugin_class(config, workspace)

    @classmethod
    def _create_external_plugin(
        cls,
        config: Dict[str, Any],
        workspace: Path,
        parser_class_name: str
    ) -> Optional[SecurityPlugin]:
        """Create an external plugin instance.

        Args:
            config: Plugin configuration
            workspace: Workspace path
            parser_class_name: Name of parser class (e.g., 'FIPSComplianceParser')

        Returns:
            SecurityPlugin instance or None if class not found
        """
        plugin_class = cls.EXTERNAL_PLUGINS.get(parser_class_name)

        if not plugin_class:
            print(f"⚠️  External plugin class not found: {parser_class_name}")
            return None

        return plugin_class(config, workspace)

    @classmethod
    def register_builtin_plugin(cls, name: str, plugin_class: type) -> None:
        """Register a built-in plugin class.

        Args:
            name: Parser class name (e.g., 'GitleaksParser')
            plugin_class: SecurityPlugin subclass
        """
        cls.BUILTIN_PLUGINS[name] = plugin_class
        print(f"✓ Registered built-in plugin: {name}")

    @classmethod
    def register_external_plugin(cls, name: str, plugin_class: type) -> None:
        """Register an external plugin class.

        Args:
            name: Parser class name (e.g., 'FIPSComplianceParser')
            plugin_class: SecurityPlugin subclass
        """
        cls.EXTERNAL_PLUGINS[name] = plugin_class
        print(f"✓ Registered external plugin: {name}")

    @classmethod
    def get_registered_plugins(cls) -> Dict[str, Any]:
        """Get information about all registered plugins.

        Returns:
            Dictionary with plugin registration information
        """
        return {
            'builtin': list(cls.BUILTIN_PLUGINS.keys()),
            'external': list(cls.EXTERNAL_PLUGINS.keys()),
            'total': len(cls.BUILTIN_PLUGINS) + len(cls.EXTERNAL_PLUGINS)
        }
