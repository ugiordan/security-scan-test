#!/usr/bin/env python3
"""
Security Plugin System Orchestrator

This is a simplified orchestrator that demonstrates how the plugin system works.
In production, this logic will be integrated into the main security scanning workflow.
"""

from pathlib import Path
import sys
import json

from .registry import PluginRegistry
from .factory import PluginFactory
from .executor import PluginExecutor


def main():
    """Main orchestrator function."""
    print("=" * 80)
    print("Security Plugin System v3.0 - Orchestrator")
    print("=" * 80)

    # Determine workspace (current directory or first argument)
    workspace = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    print(f"\n📁 Workspace: {workspace}")

    # Load plugin registry
    print("\n📋 Loading plugin registry...")
    registry = PluginRegistry(workspace=workspace)

    if not registry.plugins:
        print("❌ No plugins configured. Please create .github/config/security-plugins.yaml")
        return 1

    print(f"   {registry}")

    # Display execution configuration
    exec_config = registry.get_execution_config()
    print(f"\n⚙️  Execution Configuration:")
    print(f"   • Parallel: {exec_config['parallel']}")
    print(f"   • Timeout: {exec_config['default_timeout']}s")
    print(f"   • Continue on Error: {exec_config['continue_on_error']}")

    # List enabled plugins
    enabled_plugins = registry.get_enabled_plugins()
    print(f"\n✅ Enabled Plugins ({len(enabled_plugins)}):")
    for plugin in enabled_plugins:
        print(f"   • {plugin['display_name']} ({plugin['type']})")

    # Execute all enabled plugins
    print("\n" + "=" * 80)
    executor = PluginExecutor(registry, workspace)
    results = executor.execute_all()

    # Aggregate results
    print("\n" + "=" * 80)
    print("📊 Aggregating Results...")
    aggregated = executor.aggregate_results(results)

    # Display summary
    print("\n" + "=" * 80)
    print("Summary Report")
    print("=" * 80)
    print(f"\n📈 Overall Statistics:")
    print(f"   • Total Plugins Executed: {aggregated['total_plugins']}")
    print(f"   • Total Findings: {aggregated['total_findings']}")

    print(f"\n🔍 Findings by Severity:")
    for severity, count in aggregated['findings_by_severity'].items():
        if count > 0:
            print(f"   • {severity}: {count}")

    print(f"\n🔧 Findings by Tool:")
    for tool, count in aggregated['findings_by_tool'].items():
        if count > 0:
            print(f"   • {tool}: {count}")

    # Save aggregated results to JSON
    output_file = workspace / "security-scan-results.json"
    with open(output_file, 'w') as f:
        json.dump(aggregated, f, indent=2)

    print(f"\n💾 Results saved to: {output_file}")

    # Return exit code based on findings
    if aggregated['total_findings'] > 0:
        print("\n⚠️  Security findings detected!")
        return 1
    else:
        print("\n✅ No security findings detected!")
        return 0


if __name__ == '__main__':
    sys.exit(main())
