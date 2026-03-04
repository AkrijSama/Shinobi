"""Core scanning orchestrator."""

import os
import time
import subprocess
import tempfile
import shutil
from pathlib import Path

from shinobi.scanners import secrets, defaults, deps, armor, ai_risks, git_history


def count_files(target_dir: str) -> int:
    """Count scannable files in directory."""
    count = 0
    skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env'}
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        count += len(files)
    return count


def clone_repo(repo_url: str) -> str:
    """Clone a remote repo to a temp directory. Returns the path."""
    tmp_dir = tempfile.mkdtemp(prefix='shinobi_')
    try:
        subprocess.run(
            ['git', 'clone', '--depth', '1', repo_url, tmp_dir],
            capture_output=True, text=True, timeout=120, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to clone repo: {e}")
    return tmp_dir


def run_scan(target_dir: str, deep: bool = False, repo_url: str = None) -> dict:
    """Run all scanners against the target directory."""
    start_time = time.time()
    target_dir = str(Path(target_dir).resolve())

    file_count = count_files(target_dir)

    results = {
        'project': repo_url or os.path.basename(target_dir),
        'target_dir': target_dir,
        'file_count': file_count,
        'scan_time': 0,
        'deep_scan': deep,
        'scanners': {},
        'errors': [],
    }

    # Run each scanner with error handling
    scanner_list = [
        ('secrets', secrets),
        ('defaults', defaults),
        ('deps', deps),
        ('armor', armor),
        ('ai_risks', ai_risks),
    ]

    if deep:
        scanner_list.append(('git_history', git_history))

    for name, scanner_module in scanner_list:
        try:
            results['scanners'][name] = scanner_module.scan(target_dir)
        except Exception as e:
            results['errors'].append({
                'scanner': name,
                'error': str(e),
            })
            results['scanners'][name] = {
                'scanner': name,
                'findings': [],
                'skipped': True,
                'skip_reason': str(e),
            }

    results['scan_time'] = round(time.time() - start_time, 2)

    # Calculate threat level
    results['threat_level'] = _calculate_threat_level(results)
    results['summary'] = _build_summary(results)

    return results


def _calculate_threat_level(results: dict) -> dict:
    """Calculate overall threat level from scan results."""
    critical = 0
    high = 0
    medium = 0
    low = 0

    for scanner_name, scanner_results in results['scanners'].items():
        for finding in scanner_results.get('findings', []):
            sev = finding.get('severity', 'medium')
            if sev == 'critical':
                critical += 1
            elif sev == 'high':
                high += 1
            elif sev == 'medium':
                medium += 1
            elif sev == 'low':
                low += 1

        # Count env warnings from secrets scanner
        for warning in scanner_results.get('env_warnings', []):
            sev = warning.get('severity', 'medium')
            if sev == 'high':
                high += 1
            elif sev == 'medium':
                medium += 1

    total = critical + high + medium + low

    if critical > 0:
        level = 'CRITICAL'
        emoji = '\U0001f534'  # red circle
        color = 'red'
    elif high > 0:
        level = 'HIGH'
        emoji = '\U0001f7e0'  # orange circle
        color = 'orange'
    elif medium > 0:
        level = 'MEDIUM'
        emoji = '\U0001f7e1'  # yellow circle
        color = 'yellow'
    elif low > 0:
        level = 'LOW'
        emoji = '\U0001f535'  # blue circle
        color = 'blue'
    else:
        level = 'CLEAN'
        emoji = '\U0001f7e2'  # green circle
        color = 'green'

    return {
        'level': level,
        'emoji': emoji,
        'color': color,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'total': total,
    }


def _build_summary(results: dict) -> dict:
    """Build a summary of findings per scanner."""
    summary = {}
    for scanner_name, scanner_results in results['scanners'].items():
        findings = scanner_results.get('findings', [])
        env_warnings = scanner_results.get('env_warnings', [])
        skipped = scanner_results.get('skipped', False)

        summary[scanner_name] = {
            'count': len(findings) + len(env_warnings),
            'skipped': skipped,
            'skip_reason': scanner_results.get('skip_reason', ''),
        }

        if scanner_name == 'deps':
            critical_cves = sum(1 for f in findings if f.get('severity') == 'critical')
            moderate = sum(1 for f in findings if f.get('severity') in ('medium', 'moderate'))
            summary[scanner_name]['critical_cves'] = critical_cves
            summary[scanner_name]['moderate'] = moderate

    return summary
