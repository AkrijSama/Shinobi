"""Scanner for exposed API keys, tokens, and passwords."""

import re
from pathlib import Path

from shinobi.utils import (
    load_patterns, walk_files, read_lines_safe,
    mask_secret, format_relative_path, is_gitignored,
)


def scan(target_dir: str) -> dict:
    """Scan for exposed secrets in project files."""
    results = {
        "scanner": "secrets",
        "findings": [],
        "env_warnings": [],
    }

    # Load patterns
    pattern_data = load_patterns('secrets.json')
    compiled_patterns = []
    for p in pattern_data['patterns']:
        try:
            compiled_patterns.append({
                'regex': re.compile(p['regex']),
                'name': p['name'],
                'type': p['type'],
                'severity': p['severity'],
                'description': p['description'],
            })
        except re.error:
            continue

    # Scan all text files
    for filepath in walk_files(target_dir):
        lines = read_lines_safe(filepath)
        if lines is None:
            continue

        rel_path = format_relative_path(filepath, target_dir)

        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            # Skip lines that reference env vars (not actual secrets)
            if re.search(r'(?:os\.environ|process\.env|getenv|ENV\[)', line):
                continue

            for pattern in compiled_patterns:
                match = pattern['regex'].search(line)
                if match:
                    matched_value = match.group(0)
                    results['findings'].append({
                        'file': rel_path,
                        'line': line_num,
                        'type': pattern['type'],
                        'name': pattern['name'],
                        'severity': pattern['severity'],
                        'description': pattern['description'],
                        'masked_value': mask_secret(matched_value),
                    })
                    break  # One finding per line

    # Check for .env files not in .gitignore
    target = Path(target_dir).resolve()
    for filepath in walk_files(target_dir):
        if filepath.name == '.env' or filepath.name.endswith('.env'):
            if filepath.name.startswith('.env') and not is_gitignored(target_dir, str(filepath)):
                rel_path = format_relative_path(filepath, target_dir)
                results['env_warnings'].append({
                    'file': rel_path,
                    'severity': 'high',
                    'description': f'{rel_path} exists but is NOT in .gitignore — secrets may be committed',
                })

    return results
