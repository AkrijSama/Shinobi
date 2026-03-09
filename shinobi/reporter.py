"""Terminal output formatter and JSON report generator."""

import json
from pathlib import Path

from shinobi.logo import print_logo


class Colors:
    """ANSI color codes."""

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
    }.get(str(severity).lower(), 'gray')


def _severity_rank(severity: str) -> int:
    """Rank severities from most to least severe."""
    return {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4,
    }.get(str(severity).lower(), 99)


def _severity_tag(severity: str, confidence: str, use_color: bool) -> str:
    """Render a severity/confidence badge."""
    severity_label = str(severity).upper()
    confidence_label = str(confidence).upper()
    return _c(f'[{severity_label}/{confidence_label}]', _severity_color(severity), use_color)


def _finding_location(finding: dict) -> str | None:
    """Format finding location for display."""
    file_path = finding.get('file')
    line = int(finding.get('line') or 0)
    if not file_path or file_path == '.':
        return None
    if line > 0:
        return f'{file_path}:{line}'
    return str(file_path)


def _finding_text(finding: dict) -> str:
    """Build a concise finding message for terminal output."""
    location = _finding_location(finding)
    if finding.get('package'):
        package = finding['package']
        if location:
            return f'{package} ({location}) — {finding["description"]}'
        return f'{package} — {finding["description"]}'
    if finding.get('scanner') == 'git_history' and finding.get('commit'):
        commit = finding.get('commit', 'unknown')
        date = str(finding.get('date', 'unknown'))[:10]
        masked = finding.get('masked_value')
        suffix = f' ({masked})' if masked else ''
        return f'[{commit}] {finding["file"]} {date} — {finding["name"]}{suffix}'
    if location:
        return f'{location} — {finding["description"]}'
    return finding['description']


def _section_color(findings: list[dict]) -> str:
    """Pick the highest-severity color for a section."""
    if not findings:
        return 'green'
    highest = min(findings, key=lambda item: _severity_rank(item.get('severity', 'info')))
    return _severity_color(highest.get('severity', 'info'))


def _print_findings(findings: list[dict], use_color: bool):
    """Print normalized finding lines."""
    for finding in findings:
        color = _severity_color(finding.get('severity', 'info'))
        print(
            f"     {_c('→', color, use_color)} "
            f"{_severity_tag(finding.get('severity', 'info'), finding.get('confidence', 'low'), use_color)} "
            f"{_finding_text(finding)}"
        )


def print_report(results: dict, use_color: bool = True):
    """Print the formatted terminal report."""
    print_logo(use_color)
    print()

    threat = results['threat_level']
    project = results['project']
    file_count = results['file_count']
    scan_time = results['scan_time']

    print(f"  \U0001f50d {_c('shinobi v1.0', 'bold', use_color)} — security scan complete\n")
    print(f"  Project: {project}")
    print(f"  Scanned: {file_count} files in {scan_time}s")

    if results.get('deep_scan'):
        git_results = results['scanners'].get('git_history', {})
        commits = git_results.get('commits_scanned', 0)
        print(f"  Git history: {commits} commits analyzed")

    print()

    level_color = threat['color']
    level_text = f"  THREAT LEVEL: {threat['level']} {threat['emoji']}"
    box_width = 44
    print(f"  {_c('╔' + '═' * box_width + '╗', level_color, use_color)}")
    print(f"  {_c('║', level_color, use_color)}  {_c(level_text, level_color, use_color)}{' ' * (box_width - len(level_text) + 1)}{_c('║', level_color, use_color)}")
    print(f"  {_c('╚' + '═' * box_width + '╝', level_color, use_color)}")
    print()

    secrets_data = results['scanners'].get('secrets', {})
    secrets_findings = secrets_data.get('findings', [])
    env_warnings = secrets_data.get('env_warnings', [])
    secrets_all = secrets_findings + env_warnings
    print(f"  \U0001f511 {_c('SECRETS EXPOSED', 'bold', use_color)}          {_c(f'{len(secrets_all)} found', _section_color(secrets_all), use_color)}")
    if secrets_all:
        _print_findings(secrets_all, use_color)
    else:
        print(f"     {_c('✓ No secrets detected', 'green', use_color)}")
    print()

    defaults_findings = results['scanners'].get('defaults', {}).get('findings', [])
    print(f"  \u26a0\ufe0f  {_c('DANGEROUS DEFAULTS', 'bold', use_color)}       {_c(f'{len(defaults_findings)} found', _section_color(defaults_findings), use_color)}")
    if defaults_findings:
        _print_findings(defaults_findings, use_color)
    else:
        print(f"     {_c('✓ No dangerous defaults found', 'green', use_color)}")
    print()

    deps_findings = results['scanners'].get('deps', {}).get('findings', [])
    print(f"  \U0001f4e6 {_c('DEPENDENCY RISKS', 'bold', use_color)}          {_c(f'{len(deps_findings)} found', _section_color(deps_findings), use_color)}")
    if deps_findings:
        _print_findings(deps_findings, use_color)
    else:
        print(f"     {_c('✓ No dependency vulnerabilities found', 'green', use_color)}")
    print()

    armor_findings = results['scanners'].get('armor', {}).get('findings', [])
    print(f"  \U0001f6e1\ufe0f  {_c('MISSING ARMOR', 'bold', use_color)}            {_c(f'{len(armor_findings)} gaps', _section_color(armor_findings), use_color)}")
    if armor_findings:
        _print_findings(armor_findings, use_color)
    else:
        print(f"     {_c('✓ Security fundamentals in place', 'green', use_color)}")
    print()

    code_risk_findings = results['scanners'].get('code_risks', {}).get('findings', [])
    print(f"  \U0001f9e0 {_c('CODE RISKS', 'bold', use_color)}               {_c(f'{len(code_risk_findings)} found', _section_color(code_risk_findings), use_color)}")
    if code_risk_findings:
        _print_findings(code_risk_findings, use_color)
    else:
        print(f"     {_c('✓ No risky code patterns detected', 'green', use_color)}")
    print()

    ai_findings = results['scanners'].get('ai_risks', {}).get('findings', [])
    print(f"  \U0001f916 {_c('AI-SPECIFIC RISKS', 'bold', use_color)}         {_c(f'{len(ai_findings)} found', _section_color(ai_findings), use_color)}")
    if ai_findings:
        _print_findings(ai_findings, use_color)
    else:
        print(f"     {_c('✓ No AI-specific risks detected', 'green', use_color)}")
    print()

    if results.get('deep_scan'):
        git_data = results['scanners'].get('git_history', {})
        git_findings = git_data.get('findings', [])
        skipped = git_data.get('skipped', False)

        print(f"  \U0001f4dc {_c('GIT HISTORY', 'bold', use_color)}              ", end='')
        if skipped:
            skip_reason = git_data.get('skip_reason', 'unknown')
            print(f"{_c(f'skipped — {skip_reason}', 'gray', use_color)}")
        else:
            print(f"{_c(f'{len(git_findings)} found', _section_color(git_findings), use_color)}")
            if git_findings:
                _print_findings(git_findings, use_color)
            else:
                print(f"     {_c('✓ No secrets found in git history', 'green', use_color)}")
        print()

    for err in results.get('errors', []):
        scanner_name = err.get('scanner', 'scanner')
        error_msg = err.get('error', 'unknown error')
        print(f"  {_c(f'[{scanner_name}] skipped — {error_msg}', 'gray', use_color)}")
    if results.get('errors'):
        print()

    print(f"  {'─' * 42}")
    parts = [
        f"Total issues: {threat['total']}",
        f"Critical: {_c(str(threat['critical']), 'red', use_color)}",
        f"High: {_c(str(threat['high']), 'red', use_color)}",
        f"Medium: {_c(str(threat['medium']), 'yellow', use_color)}",
        f"Low: {_c(str(threat['low']), 'blue', use_color)}",
        f"Info: {_c(str(threat.get('info', 0)), 'gray', use_color)}",
    ]
    print(f"  {'  |  '.join(parts)}")
    print()

    output_path = results.get('output_path', './shinobi-report.json')
    print(f"  \U0001f4c4 Full report: {output_path}")
    print()

    print(f"  {'─' * 42}")
    print(f"  Want continuous monitoring? {_c('Rashomon', 'bold', use_color)} catches")
    print(f"  these in real-time before they hit production.")
    print(f"  {_c('→ https://soliddark.net/rashomon', 'blue', use_color)}")
    print()


def build_machine_report(results: dict) -> dict:
    """Build the compact machine-readable JSON report."""
    findings = []
    confidence_breakdown = {
        'high': 0,
        'medium': 0,
        'low': 0,
    }
    for finding in results.get('findings', []):
        confidence = str(finding.get('confidence', 'low')).upper()
        confidence_key = confidence.lower()
        if confidence_key in confidence_breakdown:
            confidence_breakdown[confidence_key] += 1
        findings.append({
            'severity': str(finding.get('severity', 'info')).upper(),
            'confidence': confidence,
            'confidence_note': finding.get('confidence_note', ''),
            'rule': finding.get('name', 'Unknown Rule'),
            'file': finding.get('file', '.'),
            'line': int(finding.get('line') or 0),
            'description': finding.get('description', ''),
            'context': finding.get('context'),
            'context_note': finding.get('context_note'),
        })

    return {
        'scan_target': results['target_dir'],
        'timestamp': results['timestamp'],
        'total_findings': len(findings),
        'critical': results['threat_level']['critical'],
        'high': results['threat_level']['high'],
        'medium': results['threat_level']['medium'],
        'low': results['threat_level']['low'],
        'confidence_breakdown': confidence_breakdown,
        'findings': findings,
    }


def save_json_report(results: dict, output_path: str):
    """Save the machine-readable JSON report."""
    report = build_machine_report(results)
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open('w', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
