"""Terminal output formatter and JSON report generator."""

import json
import os
from pathlib import Path

from shinobi.logo import print_logo


# ANSI color codes
class Colors:
    RED = '\033[91m'
    ORANGE = '\033[38;5;208m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def _c(text: str, color: str, use_color: bool) -> str:
    """Wrap text in ANSI color if color is enabled."""
    if not use_color:
        return text
    color_map = {
        'red': Colors.RED,
        'orange': Colors.ORANGE,
        'yellow': Colors.YELLOW,
        'blue': Colors.BLUE,
        'green': Colors.GREEN,
        'gray': Colors.GRAY,
        'bold': Colors.BOLD,
    }
    code = color_map.get(color, '')
    return f"{code}{text}{Colors.RESET}" if code else text


def _severity_color(severity: str) -> str:
    """Map severity to color name."""
    return {
        'critical': 'red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'blue',
        'info': 'gray',
    }.get(severity, 'gray')


def print_report(results: dict, use_color: bool = True):
    """Print the formatted terminal report."""
    print_logo(use_color)
    print()

    threat = results['threat_level']
    project = results['project']
    file_count = results['file_count']
    scan_time = results['scan_time']

    # Header
    print(f"  \U0001f50d {_c('shinobi v1.0', 'bold', use_color)} — security scan complete\n")
    print(f"  Project: {project}")
    print(f"  Scanned: {file_count} files in {scan_time}s")

    if results.get('deep_scan'):
        git_results = results['scanners'].get('git_history', {})
        commits = git_results.get('commits_scanned', 0)
        print(f"  Git history: {commits} commits analyzed")

    print()

    # Threat level box
    level_color = threat['color']
    level_text = f"  THREAT LEVEL: {threat['level']} {threat['emoji']}"
    box_width = 44
    print(f"  {_c('╔' + '═' * box_width + '╗', level_color, use_color)}")
    print(f"  {_c('║', level_color, use_color)}  {_c(level_text, level_color, use_color)}{' ' * (box_width - len(level_text) + 1)}{_c('║', level_color, use_color)}")
    print(f"  {_c('╚' + '═' * box_width + '╝', level_color, use_color)}")
    print()

    # Secrets
    secrets_data = results['scanners'].get('secrets', {})
    secrets_findings = secrets_data.get('findings', [])
    env_warnings = secrets_data.get('env_warnings', [])
    secrets_total = len(secrets_findings) + len(env_warnings)

    print(f"  \U0001f511 {_c('SECRETS EXPOSED', 'bold', use_color)}          {_c(f'{secrets_total} found', _severity_color('critical') if secrets_total else 'green', use_color)}")
    for f in secrets_findings:
        color = _severity_color(f['severity'])
        print(f"     {_c('→', color, use_color)} {f['file']}:{f['line']} — {f['name']}: {f['masked_value']}")
    for w in env_warnings:
        print(f"     {_c('→', 'yellow', use_color)} {w['description']}")
    if not secrets_total:
        print(f"     {_c('✓ No secrets detected', 'green', use_color)}")
    print()

    # Defaults
    defaults_data = results['scanners'].get('defaults', {})
    defaults_findings = defaults_data.get('findings', [])
    defaults_count = len(defaults_findings)

    print(f"  \u26a0\ufe0f  {_c('DANGEROUS DEFAULTS', 'bold', use_color)}       {_c(f'{defaults_count} found', _severity_color('high') if defaults_count else 'green', use_color)}")
    for f in defaults_findings:
        color = _severity_color(f['severity'])
        print(f"     {_c('→', color, use_color)} {f['file']}:{f['line']} — {f['description']}")
    if not defaults_count:
        print(f"     {_c('✓ No dangerous defaults found', 'green', use_color)}")
    print()

    # Dependencies
    deps_data = results['scanners'].get('deps', {})
    deps_findings = deps_data.get('findings', [])
    deps_count = len([f for f in deps_findings if f.get('source') != 'skip'])
    critical_cves = sum(1 for f in deps_findings if f.get('severity') == 'critical')
    moderate = sum(1 for f in deps_findings if f.get('severity') in ('medium', 'moderate'))

    print(f"  \U0001f4e6 {_c('DEPENDENCY RISKS', 'bold', use_color)}          {_c(f'{deps_count} found', _severity_color('critical') if critical_cves else ('yellow' if deps_count else 'green'), use_color)}")
    if critical_cves:
        print(f"     {_c('→', 'red', use_color)} {critical_cves} critical CVEs")
    if moderate:
        print(f"     {_c('→', 'yellow', use_color)} {moderate} moderate vulnerabilities")
    for f in deps_findings:
        if f.get('source') == 'skip':
            print(f"     {_c('→', 'gray', use_color)} {f['description']}")
        elif f.get('severity') not in ('critical', 'medium', 'moderate'):
            color = _severity_color(f.get('severity', 'medium'))
            print(f"     {_c('→', color, use_color)} {f['package']}: {f['description']}")
    if not deps_count:
        print(f"     {_c('✓ No dependency vulnerabilities found', 'green', use_color)}")
    print()

    # Armor
    armor_data = results['scanners'].get('armor', {})
    armor_findings = armor_data.get('findings', [])
    armor_count = len(armor_findings)

    print(f"  \U0001f6e1\ufe0f  {_c('MISSING ARMOR', 'bold', use_color)}            {_c(f'{armor_count} gaps', _severity_color('medium') if armor_count else 'green', use_color)}")
    for f in armor_findings:
        color = _severity_color(f['severity'])
        print(f"     {_c('→', color, use_color)} {f['description']}")
    if not armor_count:
        print(f"     {_c('✓ Security fundamentals in place', 'green', use_color)}")
    print()

    # AI Risks
    ai_data = results['scanners'].get('ai_risks', {})
    ai_findings = ai_data.get('findings', [])
    ai_count = len(ai_findings)

    print(f"  \U0001f916 {_c('AI-SPECIFIC RISKS', 'bold', use_color)}         {_c(f'{ai_count} found', _severity_color('high') if ai_count else 'green', use_color)}")
    for f in ai_findings:
        color = _severity_color(f['severity'])
        loc = f"{f['file']}:{f['line']}" if f.get('line') else f['file']
        print(f"     {_c('→', color, use_color)} {loc} — {f['description']}")
    if not ai_count:
        print(f"     {_c('✓ No AI-specific risks detected', 'green', use_color)}")
    print()

    # Git history (deep scan only)
    if results.get('deep_scan'):
        git_data = results['scanners'].get('git_history', {})
        git_findings = git_data.get('findings', [])
        git_count = len(git_findings)
        skipped = git_data.get('skipped', False)

        print(f"  \U0001f4dc {_c('GIT HISTORY', 'bold', use_color)}              ", end='')
        if skipped:
            skip_reason = git_data.get('skip_reason', 'unknown')
            print(f"{_c(f'skipped — {skip_reason}', 'gray', use_color)}")
        else:
            print(f"{_c(f'{git_count} found', _severity_color('critical') if git_count else 'green', use_color)}")
            for f in git_findings:
                color = _severity_color(f['severity'])
                print(f"     {_c('→', color, use_color)} [{f['commit']}] {f['name']} in {f['file']} ({f['date'][:10]})")
            if not git_count:
                print(f"     {_c('✓ No secrets found in git history', 'green', use_color)}")
        print()

    # Errors
    for err in results.get('errors', []):
        scanner_name = err['scanner']
        error_msg = err['error']
        print(f"  {_c(f'[{scanner_name}] skipped — {error_msg}', 'gray', use_color)}")
    if results.get('errors'):
        print()

    # Divider and summary
    print(f"  {'─' * 42}")
    t = threat
    parts = [
        f"Total issues: {t['total']}",
        f"Critical: {_c(str(t['critical']), 'red', use_color)}",
        f"High: {_c(str(t['high']), 'red', use_color)}",
        f"Medium: {_c(str(t['medium']), 'yellow', use_color)}",
    ]
    print(f"  {'  |  '.join(parts)}")
    print()

    # Report path
    output_path = results.get('output_path', './shinobi-report.json')
    print(f"  \U0001f4c4 Full report: {output_path}")
    print()

    # Rashomon plug
    print(f"  {'─' * 42}")
    print(f"  Want continuous monitoring? {_c('Rashomon', 'bold', use_color)} catches")
    print(f"  these in real-time before they hit production.")
    print(f"  {_c('→ https://soliddark.net/rashomon', 'blue', use_color)}")
    print()


def save_json_report(results: dict, output_path: str):
    """Save the full scan results as a JSON report."""
    # Clean up internal fields
    report = {
        'shinobi_version': '1.0.0',
        'project': results['project'],
        'file_count': results['file_count'],
        'scan_time': results['scan_time'],
        'deep_scan': results.get('deep_scan', False),
        'threat_level': results['threat_level']['level'],
        'summary': {
            'total': results['threat_level']['total'],
            'critical': results['threat_level']['critical'],
            'high': results['threat_level']['high'],
            'medium': results['threat_level']['medium'],
            'low': results['threat_level']['low'],
        },
        'scanners': {},
    }

    for name, data in results['scanners'].items():
        report['scanners'][name] = {
            'findings': data.get('findings', []),
            'skipped': data.get('skipped', False),
            'skip_reason': data.get('skip_reason', ''),
        }
        if name == 'secrets':
            report['scanners'][name]['env_warnings'] = data.get('env_warnings', [])
        if name == 'git_history':
            report['scanners'][name]['commits_scanned'] = data.get('commits_scanned', 0)

    if results.get('errors'):
        report['errors'] = results['errors']

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
