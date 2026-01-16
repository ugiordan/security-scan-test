"""External plugin runner for executing plugins from external repositories."""

import json
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from ..base import SecurityPlugin


class ExternalPluginRunner(SecurityPlugin):
    """Generic runner for external security scanner plugins.

    This class automatically integrates external security scanners by:
    1. Cloning the plugin repository (with authentication support)
    2. Executing the scanner script
    3. Reading and parsing JSON output
    4. Normalizing findings using field_mapping configuration
    """

    def parse(self) -> Dict[str, Any]:
        """Execute external plugin and parse its output.

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

        # Check if plugin execution is configured
        execution_config = self.config.get('execution', {})
        if not execution_config:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = 'No execution configuration found'
            return stats

        plugin_dir = None
        is_temp_dir = False
        try:
            # Clone plugin repository or use local path
            source_type = self.config.get('execution', {}).get('source', {}).get('type', 'git')
            is_temp_dir = (source_type == 'git')
            plugin_dir = self._clone_plugin()
            stats['metadata']['plugin_dir'] = str(plugin_dir)

            # Find scanner entrypoint
            scanner_path = self._find_scanner(plugin_dir)

            # Execute scanner
            self._execute_scanner(scanner_path, plugin_dir)

            # Parse output file
            if self.output_file.exists():
                findings_data = self._parse_output()
                stats['findings_data'] = findings_data
                stats['findings'] = len(findings_data)

                if findings_data:
                    stats['status'] = '❌ FINDINGS'
            else:
                stats['status'] = '⏭️ SKIPPED'
                stats['metadata']['reason'] = f'Output file not found: {self.output_file}'

        except Exception as e:
            stats['status'] = '⚠️ ERROR'
            stats['metadata']['error'] = str(e)

        finally:
            # Cleanup temporary directory (only for git clones, not local paths)
            if is_temp_dir and plugin_dir and plugin_dir.exists():
                try:
                    shutil.rmtree(plugin_dir)
                except Exception as cleanup_error:
                    stats['metadata']['cleanup_error'] = str(cleanup_error)

        return stats

    def _clone_plugin(self) -> Path:
        """Clone plugin repository or use local path.

        Returns:
            Path to plugin directory

        Raises:
            RuntimeError: If clone fails or local path not found
        """
        source_config = self.config['execution']['source']
        source_type = source_config.get('type', 'git')

        # Handle local paths (for testing)
        if source_type == 'local':
            local_path = Path(source_config['path'])
            if not local_path.exists():
                raise RuntimeError(f"Local plugin path not found: {local_path}")
            return local_path

        # Handle git repositories
        repo_url = source_config['repository']
        ref = source_config.get('ref', 'main')
        plugin_path = source_config.get('path', '')

        # Handle authentication
        auth_config = source_config.get('auth', {})
        auth_type = auth_config.get('type', 'none')

        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix='external-plugin-')
        plugin_dir = Path(temp_dir)

        # Prepare git clone URL with authentication if needed
        clone_url = repo_url
        if auth_type == 'token':
            token_secret = auth_config.get('token_secret')
            if not token_secret:
                raise ValueError("token_secret must be specified when auth type is 'token'")

            token = os.getenv(token_secret)
            if not token:
                raise ValueError(f"Authentication token {token_secret} not found in environment")

            # Inject token into URL
            clone_url = self._inject_token(repo_url, token)

        # Clone repository
        try:
            clone_cmd = [
                'git', 'clone',
                '--depth', '1',
                '--branch', ref,
                '--single-branch',
                clone_url,
                str(plugin_dir)
            ]

            result = subprocess.run(
                clone_cmd,
                timeout=300,  # 5 minute timeout
                check=True,
                capture_output=True,
                text=True
            )

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Plugin clone timeout (network issue?)")
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            raise RuntimeError(f"Plugin clone failed: {error_msg}")

        # If plugin is in subdirectory, return that path
        if plugin_path:
            plugin_subdir = plugin_dir / plugin_path
            if not plugin_subdir.exists():
                raise RuntimeError(f"Plugin path not found: {plugin_path}")
            return plugin_subdir

        return plugin_dir

    def _inject_token(self, url: str, token: str) -> str:
        """Inject authentication token into git URL.

        Args:
            url: Original git URL
            token: Authentication token

        Returns:
            URL with injected token
        """
        # Handle HTTPS URLs
        if url.startswith('https://'):
            # Format: https://token@host/repo.git
            return url.replace('https://', f'https://{token}@')
        elif url.startswith('http://'):
            # Upgrade to HTTPS and inject token
            return url.replace('http://', f'https://{token}@')
        else:
            # SSH or other protocols - return as-is
            return url

    def _find_scanner(self, plugin_dir: Path) -> Path:
        """Find scanner entrypoint in plugin directory.

        Checks for:
        1. .claude-plugin/security-tool.yaml metadata
        2. User-configured command in execution config

        Args:
            plugin_dir: Path to plugin directory

        Returns:
            Path to scanner script

        Raises:
            RuntimeError: If scanner not found
        """
        execution_config = self.config['execution']

        # Option 1: Check for .claude-plugin metadata
        metadata_file = plugin_dir / '.claude-plugin' / 'security-tool.yaml'
        if metadata_file.exists():
            try:
                import yaml
                with open(metadata_file) as f:
                    metadata = yaml.safe_load(f)

                entrypoint = metadata.get('scanner', {}).get('entrypoint')
                if entrypoint:
                    scanner_path = plugin_dir / entrypoint
                    if scanner_path.exists():
                        return scanner_path
            except Exception:
                pass  # Fall through to manual configuration

        # Option 2: Use user-configured command
        command = execution_config.get('command')
        if command:
            scanner_path = plugin_dir / command
            if scanner_path.exists():
                return scanner_path
            else:
                raise RuntimeError(f"Scanner command not found: {command}")

        raise RuntimeError("No scanner entrypoint found (check .claude-plugin/security-tool.yaml or execution.command)")

    def _execute_scanner(self, scanner_path: Path, plugin_dir: Path) -> None:
        """Execute scanner script.

        Args:
            scanner_path: Path to scanner script
            plugin_dir: Plugin directory (working directory for execution)

        Raises:
            RuntimeError: If scanner execution fails
        """
        execution_config = self.config['execution']
        timeout = execution_config.get('timeout', 600)  # Default 10 minutes
        args = execution_config.get('args', [])

        # Replace placeholders in arguments
        processed_args = []
        for arg in args:
            if arg == '${WORKSPACE}':
                processed_args.append(str(self.workspace))
            else:
                processed_args.append(arg)

        # Make scanner executable
        scanner_path.chmod(0o755)

        # Execute scanner
        try:
            cmd = [str(scanner_path)] + processed_args

            result = subprocess.run(
                cmd,
                cwd=plugin_dir,
                timeout=timeout,
                check=True,
                capture_output=True,
                text=True
            )

            # If scanner outputs to stdout, write it to the output file
            if result.stdout:
                with open(self.output_file, 'w') as f:
                    f.write(result.stdout)

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Scanner execution timeout ({timeout}s)")
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            raise RuntimeError(f"Scanner execution failed: {error_msg}")

    def _parse_output(self) -> List[Dict[str, Any]]:
        """Parse scanner output using field_mapping configuration.

        Returns:
            List of normalized findings
        """
        try:
            with open(self.output_file) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON output: {str(e)}")

        # Get field mapping from config
        field_mapping = self.config.get('field_mapping', {})
        severity_mapping = self.config.get('severity_mapping', {})

        # Get findings array from output
        # Default key is 'findings', but can be configured
        findings_key = field_mapping.get('findings_key', 'findings')
        raw_findings = data.get(findings_key, [])

        if not isinstance(raw_findings, list):
            raise RuntimeError(f"Expected findings to be a list, got {type(raw_findings)}")

        # Normalize findings using field mapping
        normalized_findings = []
        for finding in raw_findings:
            normalized = self._normalize_finding(finding, field_mapping, severity_mapping)
            normalized_findings.append(normalized)

        return normalized_findings

    def _get_nested_value(self, data: Dict[str, Any], path: str, default: Any = None) -> Any:
        """Get value from nested dictionary using dot notation.

        Args:
            data: Dictionary to extract from
            path: Dot-separated path (e.g., 'location.file')
            default: Default value if path not found

        Returns:
            Value at path or default
        """
        keys = path.split('.')
        current = data

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default

        return current

    def _normalize_finding(
        self,
        finding: Dict[str, Any],
        field_mapping: Dict[str, str],
        severity_mapping: Dict[str, str]
    ) -> Dict[str, Any]:
        """Normalize a single finding using field mapping.

        Supports nested field paths using dot notation (e.g., 'location.file').

        Args:
            finding: Raw finding from scanner
            field_mapping: Field name mapping
            severity_mapping: Severity level mapping

        Returns:
            Normalized finding
        """
        # Map fields (supports nested paths like 'location.file')
        file_field = field_mapping.get('file', 'file')
        line_field = field_mapping.get('line', 'line')
        rule_field = field_mapping.get('rule', 'rule')
        description_field = field_mapping.get('description', 'description')
        severity_field = field_mapping.get('severity', 'severity')

        # Extract values with defaults (supports nested paths)
        file_path = self._get_nested_value(finding, file_field, 'unknown')
        line = self._get_nested_value(finding, line_field, '?')
        rule = self._get_nested_value(finding, rule_field, 'unknown')
        description = self._get_nested_value(finding, description_field, '')
        raw_severity = self._get_nested_value(finding, severity_field, 'MEDIUM')

        # Map severity
        severity = severity_mapping.get(str(raw_severity).upper(), str(raw_severity).upper())

        return {
            'tool': self.display_name,
            'type': rule,
            'severity': severity,
            'file': file_path,
            'line': line,
            'rule': rule,
            'description': description,
            'remediation': finding.get('remediation', 'Follow scanner recommendations')
        }
