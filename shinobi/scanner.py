"""Core scanning orchestrator."""

import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from shinobi.scanners import ai_risks, armor, code_risks, defaults, deps, git_history, secrets


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
        'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
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
        ('code_risks', code_risks),
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
    _normalize_results(results)

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
    info = 0

    for finding in results.get('findings', []):
        sev = finding.get('severity', 'medium')
        if sev == 'critical':
            critical += 1
        elif sev == 'high':
            high += 1
        elif sev == 'medium':
            medium += 1
        elif sev == 'low':
            low += 1
        elif sev == 'info':
            info += 1

    total = critical + high + medium + low + info

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
        'info': info,
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
            high_risks = sum(1 for f in findings if f.get('severity') == 'high')
            moderate = sum(1 for f in findings if f.get('severity') == 'medium')
            summary[scanner_name]['high_risks'] = high_risks
            summary[scanner_name]['moderate'] = moderate

    return summary


def _normalize_results(results: dict):
    """Normalize severities and flatten findings for downstream output."""
    all_findings = []
    for scanner_name, scanner_results in results['scanners'].items():
        normalized_findings = []
        for finding in scanner_results.get('findings', []):
            normalized = _normalize_finding(scanner_name, finding)
            normalized_findings.append(normalized)
            all_findings.append(normalized)
        scanner_results['findings'] = normalized_findings

        if scanner_name == 'secrets':
            normalized_warnings = []
            for warning in scanner_results.get('env_warnings', []):
                normalized = _normalize_finding(scanner_name, warning, is_env_warning=True)
                normalized_warnings.append(normalized)
                all_findings.append(normalized)
            scanner_results['env_warnings'] = normalized_warnings

    results['findings'] = sorted(all_findings, key=_finding_sort_key)


def _normalize_finding(scanner_name: str, finding: dict, is_env_warning: bool = False) -> dict:
    """Ensure findings have a consistent shape and rubric-aligned severity."""
    normalized = dict(finding)
    normalized['scanner'] = scanner_name
    normalized['name'] = normalized.get('name') or (
        'Untracked Env File' if is_env_warning else str(normalized.get('type', scanner_name)).replace('_', ' ').title()
    )
    if not normalized.get('description'):
        if normalized.get('masked_value'):
            normalized['description'] = f"{normalized['name']} detected ({normalized['masked_value']})"
        else:
            normalized['description'] = normalized['name']
    normalized['severity'] = _normalize_severity(scanner_name, normalized, is_env_warning=is_env_warning)
    normalized['line'] = int(normalized.get('line') or 0)
    if not normalized.get('file'):
        normalized['file'] = '.env.example' if normalized.get('type') == 'missing_env_example' else '.'
    confidence, confidence_note = _normalize_confidence(scanner_name, normalized, is_env_warning=is_env_warning)
    normalized['confidence'] = confidence
    normalized['confidence_note'] = confidence_note
    return normalized


def _normalize_severity(scanner_name: str, finding: dict, is_env_warning: bool = False) -> str:
    """Map scanner findings to the requested severity rubric."""
    severity = str(finding.get('severity') or 'info').lower()
    finding_type = str(finding.get('type') or '').lower()
    source = str(finding.get('source') or '').lower()

    if severity == 'moderate':
        severity = 'medium'

    if scanner_name in {'secrets', 'git_history'} and not is_env_warning:
        return 'critical'
    if finding_type in {'eval_exec_user_input', 'prompt_injection_risk', 'prompt_injection_risk_alt'}:
        return 'high'
    if finding_type == 'input_sanitization':
        return 'high'
    if scanner_name == 'deps':
        if source == 'skip':
            return 'info'
        if source == 'version-check' or str(finding.get('vulnerability_id')) == 'UNPINNED':
            return 'medium'
        return 'high'
    if finding_type == 'console_log_production':
        return 'medium'
    if finding_type == 'rate_limiting':
        return 'medium'
    if finding_type == 'insecure_http_url':
        return 'low'
    if finding_type == 'missing_env_example':
        return 'info'
    return severity


def _normalize_confidence(scanner_name: str, finding: dict, is_env_warning: bool = False) -> tuple[str, str]:
    """Map scanner findings to a confidence level and explanation."""
    finding_type = str(finding.get('type') or '').lower()
    finding_name = str(finding.get('name') or '').lower()
    file_path = str(finding.get('file') or '')
    source = str(finding.get('source') or '').lower()
    masked_value = str(finding.get('masked_value') or '')

    if is_env_warning:
        return ('HIGH', 'file exists and is not covered by .gitignore')

    if scanner_name in {'secrets', 'git_history'}:
        return _secret_confidence(finding_type, finding_name, masked_value)

    if finding_type == 'eval_exec_user_input':
        return ('HIGH', 'eval/exec call uses a variable sourced from request, input, or argv')

    if finding_type in {'prompt_injection_risk', 'prompt_injection_risk_alt'}:
        return ('HIGH', 'direct user-controlled input is matched flowing into an LLM call')

    if finding_type == 'unvalidated_ai_route':
        return ('LOW', 'route pattern suggests AI endpoint exposure, but validation absence is heuristic')

    if finding_type == 'input_sanitization':
        return ('LOW', 'project-wide sanitization absence is inferred heuristically, not traced per sink')

    if scanner_name == 'deps':
        if source in {'pip-audit', 'npm-audit'}:
            return ('HIGH', f'{source} reported a known vulnerable dependency from audit data')
        if source == 'version-check' or str(finding.get('vulnerability_id')) == 'UNPINNED':
            return ('LOW', 'package appears outdated or unpinned, but no specific CVE was confirmed')
        if source == 'skip':
            return ('HIGH', 'scanner directly confirmed the audit tool was unavailable')

    if finding_type == 'console_log_production':
        return ('HIGH', 'console.log match in application code is unambiguous')

    if finding_type == 'insecure_http_url':
        return _http_confidence(file_path)

    if finding_type in {'rate_limiting', 'csrf_protection', 'authentication', 'security_headers'}:
        return ('LOW', 'missing-control finding is based on project-wide heuristics only')

    if finding_type == 'missing_env_example':
        return ('HIGH', '.env.example presence is a direct filesystem check')

    if scanner_name == 'ai_risks':
        return ('MEDIUM', 'pattern matched directly in source, but exploitability depends on surrounding code')

    if scanner_name == 'defaults':
        return ('HIGH', 'configuration pattern matched directly in source or config')

    if scanner_name == 'code_risks':
        return ('MEDIUM', 'direct code pattern matched, but runtime reachability is not proven')

    if scanner_name == 'armor':
        return ('LOW', 'structural project-wide check only')

    return ('MEDIUM', 'direct pattern match found, but impact depends on surrounding context')


def _secret_confidence(finding_type: str, finding_name: str, masked_value: str) -> tuple[str, str]:
    """Confidence rules for secrets and tokens."""
    vendor_prefix_rules = {
        'openai_key': 'matches OpenAI API key prefix sk-',
        'anthropic_key': 'matches Anthropic API key prefix sk-ant-',
        'stripe_live_key': 'matches Stripe live key prefix sk_live_',
        'stripe_test_key': 'matches Stripe test key prefix sk_test_',
        'aws_access_key': 'matches AWS access key prefix AKIA',
        'github_pat': 'matches GitHub token prefix ghp_',
        'github_fine_pat': 'matches GitHub fine-grained token prefix github_pat_',
        'slack_token': 'matches Slack token prefix xox',
        'discord_token': 'matches Discord bot token structure',
        'google_api_key': 'matches Google API key prefix AIza',
        'private_key': 'matches private key block header',
        'heroku_key': 'matches Heroku API token pattern',
    }
    if finding_type in vendor_prefix_rules:
        return ('HIGH', vendor_prefix_rules[finding_type])
    if finding_type in {'generic_api_key', 'generic_token', 'generic_secret', 'generic_password'}:
        if len(masked_value) >= 32:
            return ('MEDIUM', 'generic secret assignment is long enough to resemble a real credential')
        return ('LOW', 'generic secret-like string may be a placeholder, UUID, or example value')
    if 'secret' in finding_name or 'token' in finding_name or 'key' in finding_name:
        return ('MEDIUM', 'secret pattern matched, but it is not a vendor-specific prefix')
    return ('LOW', 'string resembles a secret pattern, but may also be an example or non-secret token')


def _http_confidence(file_path: str) -> tuple[str, str]:
    """Confidence rules for insecure HTTP URLs."""
    ext = Path(file_path).suffix.lower()
    if ext in {'.env', '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf'}:
        return ('MEDIUM', 'hardcoded http:// URL found in configuration-style file')
    return ('HIGH', 'hardcoded http:// URL found in source code pointing to an external endpoint')


def _finding_sort_key(finding: dict):
    """Sort findings by severity, then location."""
    severity_rank = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4,
    }
    return (
        severity_rank.get(finding.get('severity', 'info'), 99),
        finding.get('file', ''),
        int(finding.get('line') or 0),
        finding.get('name', ''),
    )
