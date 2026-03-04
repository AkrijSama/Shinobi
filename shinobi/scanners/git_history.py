"""Scanner for secrets in git commit history."""

import re
import subprocess
from pathlib import Path

from shinobi.utils import load_patterns, mask_secret


def scan(target_dir: str) -> dict:
    """Scan git history for previously committed secrets."""
    results = {
        "scanner": "git_history",
        "findings": [],
        "commits_scanned": 0,
    }

    # Check if this is a git repo
    git_dir = Path(target_dir) / '.git'
    if not git_dir.exists():
        results['skipped'] = True
        results['skip_reason'] = 'Not a git repository'
        return results

    # Load secret patterns
    pattern_data = load_patterns('secrets.json')
    compiled_patterns = []
    for p in pattern_data['patterns']:
        try:
            compiled_patterns.append({
                'regex': re.compile(p['regex']),
                'name': p['name'],
                'type': p['type'],
                'severity': p['severity'],
            })
        except re.error:
            continue

    try:
        # Get last 500 commit hashes
        result = subprocess.run(
            ['git', 'rev-list', '--all', '--max-count=500'],
            capture_output=True, text=True, timeout=30,
            cwd=target_dir,
        )
        if result.returncode != 0:
            results['skipped'] = True
            results['skip_reason'] = 'Failed to read git history'
            return results

        commit_hashes = result.stdout.strip().split('\n')
        commit_hashes = [h for h in commit_hashes if h]
        results['commits_scanned'] = len(commit_hashes)

        seen_findings = set()

        for commit_hash in commit_hashes:
            # Get the diff for this commit
            try:
                diff_result = subprocess.run(
                    ['git', 'show', '--format=%H|%ai|%an', '--diff-filter=ADM', '-p', commit_hash],
                    capture_output=True, text=True, timeout=10,
                    cwd=target_dir,
                )
                if diff_result.returncode != 0:
                    continue

                output = diff_result.stdout
                lines = output.split('\n')

                # Parse commit metadata
                if lines and '|' in lines[0]:
                    parts = lines[0].split('|', 2)
                    commit_info = {
                        'hash': parts[0][:8],
                        'date': parts[1] if len(parts) > 1 else 'unknown',
                        'author': parts[2] if len(parts) > 2 else 'unknown',
                    }
                else:
                    commit_info = {
                        'hash': commit_hash[:8],
                        'date': 'unknown',
                        'author': 'unknown',
                    }

                current_file = None
                for line in lines:
                    if line.startswith('diff --git'):
                        # Extract filename
                        parts = line.split(' b/')
                        current_file = parts[-1] if len(parts) > 1 else None
                    elif line.startswith('+') and not line.startswith('+++'):
                        # Added line — check for secrets
                        added_content = line[1:]
                        for pattern in compiled_patterns:
                            match = pattern['regex'].search(added_content)
                            if match:
                                # Dedup by pattern type + file + masked value
                                finding_key = f"{pattern['type']}:{current_file}:{mask_secret(match.group(0))}"
                                if finding_key not in seen_findings:
                                    seen_findings.add(finding_key)
                                    results['findings'].append({
                                        'commit': commit_info['hash'],
                                        'date': commit_info['date'],
                                        'author': commit_info['author'],
                                        'file': current_file or 'unknown',
                                        'type': pattern['type'],
                                        'name': pattern['name'],
                                        'severity': pattern['severity'],
                                        'masked_value': mask_secret(match.group(0)),
                                    })
                                break

            except subprocess.TimeoutExpired:
                continue

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        results['skipped'] = True
        results['skip_reason'] = f'Git not available: {e}'

    return results
