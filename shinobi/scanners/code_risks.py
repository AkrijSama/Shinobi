"""Scanner for risky code patterns not covered by config scanners."""

import re

from shinobi.utils import format_relative_path, read_lines_safe, walk_files


SOURCE_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf',
}
JS_EXTENSIONS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
COMMENT_PREFIXES = ('#', '//', '/*', '*', '<!--')
LOCAL_HTTP_PREFIXES = ('http://127.0.0.1', 'http://localhost', 'http://0.0.0.0')
EVAL_EXEC_RE = re.compile(
    r'\b(?:eval|exec)\s*\([^)]*(?:'
    r'req(?:uest)?\.(?:body|query|params)|'
    r'request\.(?:data|json|form|args)|'
    r'input\s*\(|sys\.argv|argv|user[_-]?input|userInput'
    r')',
    re.IGNORECASE,
)
HTTP_URL_RE = re.compile(r'http://[A-Za-z0-9._:-]+(?:/[^\s"\'`)]+)?', re.IGNORECASE)


def scan(target_dir: str) -> dict:
    """Scan application code for risky patterns."""
    results = {
        'scanner': 'code_risks',
        'findings': [],
    }

    for filepath in walk_files(target_dir, extensions=SOURCE_EXTENSIONS):
        lines = read_lines_safe(filepath)
        if lines is None:
            continue

        rel_path = format_relative_path(filepath, target_dir)
        is_js_like = filepath.suffix.lower() in JS_EXTENSIONS
        is_test_file = _is_test_file(rel_path)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(COMMENT_PREFIXES):
                continue

            if EVAL_EXEC_RE.search(line):
                results['findings'].append({
                    'file': rel_path,
                    'line': line_num,
                    'type': 'eval_exec_user_input',
                    'name': 'Eval/Exec on User Input',
                    'severity': 'high',
                    'description': 'eval/exec receives user-controlled input — this can lead to code execution',
                    'context': stripped[:120],
                })
                continue

            if is_js_like and not is_test_file and 'console.log' in line:
                results['findings'].append({
                    'file': rel_path,
                    'line': line_num,
                    'type': 'console_log_production',
                    'name': 'Console Log in Production',
                    'severity': 'medium',
                    'description': 'console.log found in application code — remove noisy debug logging from production builds',
                    'context': stripped[:120],
                })
                continue

            for match in HTTP_URL_RE.finditer(line):
                url = match.group(0)
                if url.startswith(LOCAL_HTTP_PREFIXES):
                    continue
                results['findings'].append({
                    'file': rel_path,
                    'line': line_num,
                    'type': 'insecure_http_url',
                    'name': 'HTTP URL',
                    'severity': 'low',
                    'description': f'Public HTTP URL found ({url}) — prefer HTTPS for production traffic',
                    'context': stripped[:120],
                })
                break

    return results


def _is_test_file(rel_path: str) -> bool:
    """Skip console.log findings in tests and fixtures."""
    lowered = rel_path.lower()
    markers = ('/test', '/tests', '/spec', '.spec.', '.test.', '__tests__', '/fixtures/', '/mocks/')
    return any(marker in lowered for marker in markers)
