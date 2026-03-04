"""Scanner for dangerous default configurations."""

import re
from shinobi.utils import (
    load_patterns, walk_files, read_lines_safe, format_relative_path,
)


def scan(target_dir: str) -> dict:
    """Scan for dangerous default configurations."""
    results = {
        "scanner": "defaults",
        "findings": [],
    }

    pattern_data = load_patterns('defaults.json')
    compiled_patterns = []
    for p in pattern_data['patterns']:
        try:
            compiled_patterns.append({
                'regex': re.compile(p['regex']),
                'name': p['name'],
                'type': p['type'],
                'severity': p['severity'],
                'description': p['description'],
                'file_patterns': p.get('file_patterns'),
            })
        except re.error:
            continue

    for filepath in walk_files(target_dir):
        lines = read_lines_safe(filepath)
        if lines is None:
            continue

        rel_path = format_relative_path(filepath, target_dir)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern in compiled_patterns:
                # Filter by file patterns if specified
                if pattern['file_patterns']:
                    from fnmatch import fnmatch
                    if not any(fnmatch(filepath.name, fp) for fp in pattern['file_patterns']):
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
                        'context': stripped[:100],
                    })
                    break

    return results
