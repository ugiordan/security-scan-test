#!/usr/bin/env python3
"""Install external security plugins from git repositories.

This script is run during GitHub Actions workflow setup to automatically
install external plugins based on their git source configuration.
"""

import os
import sys
import subprocess
import yaml
from pathlib import Path
from typing import Dict, Any, List


def load_plugin_config(config_path: Path) -> Dict[str, Any]:
    """Load plugin configuration from YAML file.

    Args:
        config_path: Path to security-plugins.yaml

    Returns:
        Plugin configuration dictionary
    """
    with open(config_path) as f:
        return yaml.safe_load(f)


def get_external_plugins(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get list of external plugins that need installation.

    Args:
        config: Plugin configuration

    Returns:
        List of external plugin configurations
    """
    plugins = config.get('plugins', [])
    external_plugins = [
        p for p in plugins
        if p.get('type') == 'external' and p.get('enabled', False)
    ]
    return external_plugins


def inject_token(url: str, token: str) -> str:
    """Inject authentication token into git URL.

    Args:
        url: Original git URL
        token: Authentication token

    Returns:
        URL with injected token
    """
    if url.startswith('https://'):
        return url.replace('https://', f'https://{token}@')
    elif url.startswith('http://'):
        return url.replace('http://', f'https://{token}@')
    return url


def install_plugin(plugin: Dict[str, Any], plugins_dir: Path) -> bool:
    """Install a single external plugin from git.

    Args:
        plugin: Plugin configuration
        plugins_dir: Base directory for plugin installations

    Returns:
        True if installation successful, False otherwise
    """
    plugin_name = plugin.get('name', 'unknown')
    display_name = plugin.get('display_name', plugin_name)

    print(f"\n📦 Installing {display_name}...")

    # Get source configuration
    source = plugin.get('source', {})
    if not source or source.get('type') != 'git':
        print(f"  ⏭️  Skipping - no git source configured")
        return True

    repo_url = source.get('repository')
    repo_path = source.get('path', '')
    ref = source.get('ref', 'main')
    auth = source.get('auth', {})

    if not repo_url:
        print(f"  ❌ Error: repository URL not specified")
        return False

    # Handle authentication
    clone_url = repo_url
    auth_type = auth.get('type', 'none')

    if auth_type == 'token':
        token_secret = auth.get('token_secret')
        if not token_secret:
            print(f"  ❌ Error: token_secret not specified")
            return False

        token = os.getenv(token_secret)
        if not token:
            print(f"  ❌ Error: {token_secret} not found in environment")
            return False

        clone_url = inject_token(repo_url, token)
        print(f"  🔐 Using token authentication")

    # Determine installation directory
    # Extract owner from repository URL (e.g., "gryan" from gitlab.com/gryan/repo)
    try:
        url_parts = repo_url.rstrip('/').rstrip('.git').split('/')
        owner = url_parts[-2] if len(url_parts) >= 2 else 'external'
    except:
        owner = 'external'

    # If plugin is in subdirectory, install parent repo and reference subdir
    if repo_path:
        install_dir = plugins_dir / owner
        final_plugin_dir = install_dir / repo_path
    else:
        install_dir = plugins_dir / owner / plugin_name
        final_plugin_dir = install_dir

    # Create parent directory
    install_dir.parent.mkdir(parents=True, exist_ok=True)

    # Clone repository
    try:
        print(f"  📥 Cloning from {repo_url}")
        print(f"  📂 Installing to {install_dir}")

        cmd = [
            'git', 'clone',
            '--depth', '1',
            '--branch', ref,
            '--single-branch',
            clone_url,
            str(install_dir)
        ]

        result = subprocess.run(
            cmd,
            timeout=300,  # 5 minute timeout
            check=True,
            capture_output=True,
            text=True
        )

        # Verify final plugin directory exists
        if not final_plugin_dir.exists():
            print(f"  ❌ Error: plugin path not found: {repo_path}")
            return False

        # Make scripts executable
        for script_dir in ['scripts', 'bin']:
            script_path = final_plugin_dir / script_dir
            if script_path.exists():
                subprocess.run(['chmod', '-R', '+x', str(script_path)], check=False)

        print(f"  ✓ Successfully installed to {final_plugin_dir}")
        return True

    except subprocess.TimeoutExpired:
        print(f"  ❌ Error: Clone timeout (network issue?)")
        return False
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else str(e)
        print(f"  ❌ Error: Clone failed: {error_msg}")
        return False
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
        return False


def main():
    """Main installation workflow."""
    print("🔧 Security Plugin Installer")
    print("=" * 60)

    # Get configuration paths
    script_dir = Path(__file__).parent
    config_path = script_dir.parent.parent / 'config' / 'security-plugins.yaml'

    if not config_path.exists():
        print(f"❌ Configuration not found: {config_path}")
        sys.exit(1)

    # Get plugins directory from environment or use default
    plugins_dir = os.getenv('SECURITY_PLUGINS_DIR', '/opt/security-plugins')
    plugins_dir = Path(plugins_dir)

    print(f"\n📁 Installation directory: {plugins_dir}")
    print(f"📄 Configuration file: {config_path}")

    # Load configuration
    try:
        config = load_plugin_config(config_path)
    except Exception as e:
        print(f"❌ Failed to load configuration: {e}")
        sys.exit(1)

    # Get external plugins
    external_plugins = get_external_plugins(config)

    if not external_plugins:
        print("\n✓ No external plugins to install")
        sys.exit(0)

    print(f"\n📊 Found {len(external_plugins)} external plugin(s) to install")

    # Install each plugin
    installed = 0
    failed = 0
    skipped = 0

    for plugin in external_plugins:
        success = install_plugin(plugin, plugins_dir)
        if success:
            installed += 1
        else:
            failed += 1

    # Summary
    print("\n" + "=" * 60)
    print("📊 Installation Summary:")
    print(f"  ✓ Installed: {installed}")
    if failed > 0:
        print(f"  ❌ Failed: {failed}")
    print(f"  📂 Location: {plugins_dir}")
    print("=" * 60)

    if failed > 0:
        print("\n⚠️  Some plugins failed to install")
        sys.exit(1)
    else:
        print("\n✓ All plugins installed successfully!")
        sys.exit(0)


if __name__ == '__main__':
    main()
