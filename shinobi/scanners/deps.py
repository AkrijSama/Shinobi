"""Scanner for known CVEs in pip/npm dependencies."""

import json
import subprocess
import re
from pathlib import Path

from shinobi.utils import format_relative_path


def _scan_pip(target_dir: str) -> list[dict]:
    """Scan Python dependencies for vulnerabilities."""
    findings = []
    req_file = Path(target_dir) / 'requirements.txt'

    if not req_file.exists():
        return findings

    # Try pip audit first
    try:
        result = subprocess.run(
            ['pip', 'audit', '--format', 'json', '-r', str(req_file)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode in (0, 1):  # 1 means vulnerabilities found
            try:
                audit_data = json.loads(result.stdout)
                for vuln in audit_data.get('vulnerabilities', []):
                    severity = _map_pip_severity(vuln.get('fix_versions', []))
                    findings.append({
                        'file': 'requirements.txt',
                        'line': 0,
                        'package': vuln.get('name', 'unknown'),
                        'installed_version': vuln.get('version', 'unknown'),
                        'vulnerability_id': vuln.get('id', 'unknown'),
                        'severity': severity,
                        'description': vuln.get('description', 'Known vulnerability')[:200],
                        'fix_versions': vuln.get('fix_versions', []),
                        'source': 'pip-audit',
                    })
                return findings
            except json.JSONDecodeError:
                pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: parse requirements.txt and report unpinned dependencies
    try:
        with open(req_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # Check for unpinned dependencies
                if '==' not in line and '>=' not in line:
                    pkg_name = re.split(r'[<>=!~]', line)[0].strip()
                    if pkg_name:
                        findings.append({
                            'file': 'requirements.txt',
                            'line': 0,
                            'package': pkg_name,
                            'installed_version': 'unpinned',
                            'vulnerability_id': 'UNPINNED',
                            'severity': 'medium',
                            'description': f'{pkg_name} has no pinned version — builds may pull vulnerable versions',
                            'fix_versions': [],
                            'source': 'version-check',
                        })
    except OSError:
        pass

    return findings


def _scan_npm(target_dir: str) -> list[dict]:
    """Scan npm dependencies for vulnerabilities."""
    findings = []
    pkg_file = Path(target_dir) / 'package.json'

    if not pkg_file.exists():
        return findings

    # Try npm audit
    try:
        result = subprocess.run(
            ['npm', 'audit', '--json'],
            capture_output=True, text=True, timeout=30,
            cwd=target_dir,
        )
        try:
            audit_data = json.loads(result.stdout)
            vulnerabilities = audit_data.get('vulnerabilities', {})
            for pkg_name, vuln_info in vulnerabilities.items():
                findings.append({
                    'file': 'package.json',
                    'line': 0,
                    'package': pkg_name,
                    'installed_version': vuln_info.get('range', 'unknown'),
                    'vulnerability_id': vuln_info.get('via', [{}])[0].get('url', 'N/A') if isinstance(vuln_info.get('via', [{}])[0], dict) else 'N/A',
                    'severity': vuln_info.get('severity', 'unknown'),
                    'description': _get_npm_vuln_description(vuln_info),
                    'fix_versions': [vuln_info.get('fixAvailable', {}).get('version', 'unknown')] if isinstance(vuln_info.get('fixAvailable'), dict) else [],
                    'source': 'npm-audit',
                })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        findings.append({
            'file': 'package.json',
            'line': 0,
            'package': 'npm',
            'installed_version': 'N/A',
            'vulnerability_id': 'TOOL_MISSING',
            'severity': 'info',
            'description': 'npm not available — could not audit JavaScript dependencies',
            'fix_versions': [],
            'source': 'skip',
        })

    return findings


def _get_npm_vuln_description(vuln_info: dict) -> str:
    """Extract a human-readable description from npm audit data."""
    via = vuln_info.get('via', [])
    if via and isinstance(via[0], dict):
        return via[0].get('title', 'Known vulnerability')[:200]
    if via and isinstance(via[0], str):
        return f'Dependency vulnerability via {via[0]}'
    return 'Known vulnerability in package'


def _map_pip_severity(fix_versions: list) -> str:
    """Map pip audit data to severity level."""
    if not fix_versions:
        return 'high'
    return 'medium'


def scan(target_dir: str) -> dict:
    """Scan dependencies for known vulnerabilities."""
    results = {
        "scanner": "deps",
        "findings": [],
        "dep_files_found": [],
    }

    # Check which dependency files exist
    for dep_file in ['requirements.txt', 'package.json', 'Cargo.toml', 'Pipfile', 'poetry.lock']:
        dep_path = Path(target_dir) / dep_file
        if dep_path.exists():
            results['dep_files_found'].append(dep_file)

    # Run scans
    results['findings'].extend(_scan_pip(target_dir))
    results['findings'].extend(_scan_npm(target_dir))

    return results
