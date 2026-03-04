"""Scanner for AI-specific security risks."""

import re
from pathlib import Path

from shinobi.utils import (
    load_patterns, walk_files, walk_all_files, read_lines_safe,
    format_relative_path, MODEL_EXTENSIONS,
)


def scan(target_dir: str) -> dict:
    """Scan for AI-specific vulnerabilities."""
    results = {
        "scanner": "ai_risks",
        "findings": [],
    }

    pattern_data = load_patterns('ai_risks.json')
    client_extensions = set(pattern_data['client_side_extensions'])
    model_extensions = set(pattern_data['model_file_extensions'])
    ai_route_keywords = pattern_data['ai_route_patterns']

    compiled_patterns = []
    for p in pattern_data['patterns']:
        if 'regex' in p:
            try:
                compiled_patterns.append({
                    'regex': re.compile(p['regex']),
                    'name': p['name'],
                    'type': p['type'],
                    'severity': p['severity'],
                    'description': p['description'],
                    'client_only': p.get('check_client_side_only', False),
                })
            except re.error:
                continue

    # Scan source files for patterns
    for filepath in walk_files(target_dir):
        ext = filepath.suffix.lower()
        is_client_side = ext in client_extensions
        lines = read_lines_safe(filepath)
        if lines is None:
            continue

        rel_path = format_relative_path(filepath, target_dir)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern in compiled_patterns:
                # Skip client-only patterns for non-client files
                if pattern['client_only'] and not is_client_side:
                    continue

                match = pattern['regex'].search(line)
                if match:
                    results['findings'].append({
                        'file': rel_path,
                        'line': line_num,
                        'type': pattern['type'],
                        'name': pattern['name'],
                        'severity': pattern['severity'],
                        'description': pattern['description'],
                        'context': stripped[:120],
                    })
                    break

    # Check for model files committed to repo
    for filepath in walk_all_files(target_dir):
        ext = filepath.suffix.lower()
        if ext in model_extensions:
            rel_path = format_relative_path(filepath, target_dir)
            size_mb = filepath.stat().st_size / (1024 * 1024)
            results['findings'].append({
                'file': rel_path,
                'line': 0,
                'type': 'model_file',
                'name': 'Model File in Repo',
                'severity': 'medium',
                'description': f'ML model file ({size_mb:.1f}MB) committed to repo — use Git LFS or external storage',
            })

    # Check for prompt template files
    for filepath in walk_files(target_dir):
        name_lower = filepath.name.lower()
        if ('prompt' in name_lower or 'system_message' in name_lower) and filepath.suffix in {'.txt', '.md', '.j2', '.jinja', '.jinja2', '.tmpl'}:
            rel_path = format_relative_path(filepath, target_dir)
            results['findings'].append({
                'file': rel_path,
                'line': 0,
                'type': 'prompt_template_file',
                'name': 'Prompt Template File',
                'severity': 'medium',
                'description': 'Prompt template file found — system prompts can be extracted if repo is public',
            })

    return results
