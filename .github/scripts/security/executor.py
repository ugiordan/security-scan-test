"""Plugin executor for running security scanner plugins."""

from pathlib import Path
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from .registry import PluginRegistry
from .factory import PluginFactory
from .plugins.base import SecurityPlugin


class PluginExecutor:
    """Executes security scanner plugins and aggregates findings."""

    def __init__(self, registry: PluginRegistry, workspace: Path):
        """Initialize plugin executor.

        Args:
            registry: PluginRegistry instance
            workspace: Path to repository being scanned
        """
        self.registry = registry
        self.workspace = workspace
        self.execution_config = registry.get_execution_config()

    def execute_all(self) -> List[Dict[str, Any]]:
        """Execute all enabled plugins and collect results.

        Returns:
            List of plugin results
        """
        enabled_plugins = self.registry.get_enabled_plugins()

        if not enabled_plugins:
            print("⚠️  No enabled plugins found in registry")
            return []

        print(f"\n🔍 Executing {len(enabled_plugins)} security scanner plugins...")

        if self.execution_config.get('parallel', True):
            return self._execute_parallel(enabled_plugins)
        else:
            return self._execute_sequential(enabled_plugins)

    def _execute_parallel(self, plugin_configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute plugins in parallel using ThreadPoolExecutor.

        Args:
            plugin_configs: List of plugin configurations

        Returns:
            List of plugin results
        """
        results = []
        max_workers = min(len(plugin_configs), 5)  # Limit to 5 concurrent plugins

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all plugin executions
            future_to_plugin = {
                executor.submit(self._execute_single, config): config
                for config in plugin_configs
            }

            # Collect results as they complete
            for future in as_completed(future_to_plugin):
                plugin_config = future_to_plugin[future]
                plugin_name = plugin_config.get('display_name', 'Unknown')

                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(f"❌ Plugin {plugin_name} failed: {e}")
                    if not self.execution_config.get('continue_on_error', True):
                        raise
                    # Create error result
                    results.append({
                        'tool': plugin_name,
                        'status': '⚠️ ERROR',
                        'findings': 0,
                        'findings_data': [],
                        'metadata': {'error': str(e)}
                    })

        return results

    def _execute_sequential(self, plugin_configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute plugins sequentially.

        Args:
            plugin_configs: List of plugin configurations

        Returns:
            List of plugin results
        """
        results = []

        for config in plugin_configs:
            plugin_name = config.get('display_name', 'Unknown')

            try:
                result = self._execute_single(config)
                results.append(result)
            except Exception as e:
                print(f"❌ Plugin {plugin_name} failed: {e}")
                if not self.execution_config.get('continue_on_error', True):
                    raise
                # Create error result
                results.append({
                    'tool': plugin_name,
                    'status': '⚠️ ERROR',
                    'findings': 0,
                    'findings_data': [],
                    'metadata': {'error': str(e)}
                })

        return results

    def _execute_single(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single plugin.

        Args:
            config: Plugin configuration

        Returns:
            Plugin execution result

        Raises:
            Exception: If plugin execution fails and continue_on_error is False
        """
        plugin_name = config.get('display_name', 'Unknown')
        start_time = time.time()

        print(f"\n  → Running {plugin_name}...")

        # Create plugin instance
        plugin = PluginFactory.create_plugin(config, self.workspace)

        if not plugin:
            raise RuntimeError(f"Failed to create plugin instance for {plugin_name}")

        # Check if output file exists (skip for external plugins - they generate during parse())
        is_external = config.get('type') == 'external'
        if not is_external and not plugin.output_file.exists():
            print(f"    ⏭️  Output file not found: {plugin.output_file}")
            return {
                'tool': plugin_name,
                'status': '⏭️ SKIPPED',
                'findings': 0,
                'findings_data': [],
                'metadata': {'reason': 'Output file not found'}
            }

        # Parse plugin output
        result = plugin.parse()

        elapsed_time = time.time() - start_time
        print(f"    ✓ {plugin_name} completed in {elapsed_time:.2f}s - {result['status']}")

        return result

    def aggregate_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate results from all plugins.

        Args:
            results: List of plugin results

        Returns:
            Aggregated findings summary
        """
        total_findings = sum(r.get('findings', 0) for r in results)
        total_plugins = len(results)

        findings_by_severity = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        findings_by_tool = {}

        all_findings = []

        for result in results:
            tool_name = result.get('tool', 'Unknown')
            findings_by_tool[tool_name] = result.get('findings', 0)

            for finding in result.get('findings_data', []):
                severity = finding.get('severity', 'MEDIUM')
                findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
                all_findings.append(finding)

        return {
            'total_plugins': total_plugins,
            'total_findings': total_findings,
            'findings_by_severity': findings_by_severity,
            'findings_by_tool': findings_by_tool,
            'all_findings': all_findings,
            'plugin_results': results
        }
