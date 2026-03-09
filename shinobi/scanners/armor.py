"""Scanner for missing security basics."""

import re
from pathlib import Path

from shinobi.utils import walk_files, read_file_safe, format_relative_path


# Patterns that indicate security measures are in place
SECURITY_PATTERNS = {
    'rate_limiting': {
        'name': 'Rate Limiting',
        'patterns': [
            r'express-rate-limit', r'ratelimit', r'rate_limit', r'RateLimit',
            r'django-ratelimit', r'slowapi', r'Limiter', r'throttle',
            r'RateLimiter', r'@ratelimit', r'flask.limiter', r'rate\.limit',
        ],
        'severity': 'medium',
        'gap_message': 'No rate limiting detected — your API endpoints have no protection against abuse',
    },
    'csrf_protection': {
        'name': 'CSRF Protection',
        'patterns': [
            r'csrf', r'CSRF', r'csurf', r'csrf_token', r'csrfmiddleware',
            r'CsrfViewMiddleware', r'@csrf_protect', r'csrf_exempt',
            r'anti.?forgery', r'AntiForgery', r'_csrf',
        ],
        'severity': 'medium',
        'gap_message': 'No CSRF protection detected — forms are vulnerable to cross-site request forgery',
    },
    'security_headers': {
        'name': 'Security Headers',
        'patterns': [
            r'helmet', r'Helmet', r'SecurityMiddleware',
            r'Content-Security-Policy', r'X-Frame-Options',
            r'X-Content-Type-Options', r'Strict-Transport-Security',
            r'secure_headers', r'SecureHeaders',
        ],
        'severity': 'medium',
        'gap_message': 'No security headers middleware detected — missing protections against XSS, clickjacking, and MIME sniffing',
    },
    'input_sanitization': {
        'name': 'Input Sanitization',
        'patterns': [
            r'bleach', r'DOMPurify', r'sanitize', r'validator',
            r'escape_html', r'html\.escape', r'xss', r'purify',
            r'sanitizer', r'clean_html', r'strip_tags',
        ],
        'severity': 'high',
        'gap_message': 'No input sanitization library detected — user input may contain malicious HTML or scripts',
    },
    'authentication': {
        'name': 'Authentication',
        'patterns': [
            r'passport', r'jwt', r'JWT', r'jsonwebtoken', r'auth0',
            r'authenticate', r'@login_required', r'IsAuthenticated',
            r'session\.user', r'currentUser', r'firebase\.auth',
            r'bcrypt', r'argon2', r'@requires_auth', r'oauth',
            r'AuthenticationMiddleware', r'flask.login', r'django\.contrib\.auth',
        ],
        'severity': 'medium',
        'gap_message': 'No authentication middleware detected — endpoints may be accessible without login',
    },
}


def scan(target_dir: str) -> dict:
    """Scan for missing security patterns in the codebase."""
    results = {
        "scanner": "armor",
        "findings": [],
        "detected": [],
    }
    target_path = Path(target_dir)

    if not (target_path / '.env.example').exists():
        results['findings'].append({
            'type': 'missing_env_example',
            'name': 'Missing .env.example',
            'file': '.env.example',
            'line': 0,
            'severity': 'info',
            'description': 'Missing .env.example — document required environment variables for safer setup',
        })

    # Collect all source content for pattern matching
    all_content = []
    file_count = 0
    source_extensions = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte',
        '.rb', '.go', '.java', '.rs', '.php', '.cs',
    }

    for filepath in walk_files(target_dir, extensions=source_extensions):
        content = read_file_safe(filepath)
        if content:
            all_content.append(content)
            file_count += 1

    if file_count == 0:
        results['findings'].append({
            'type': 'no_source',
            'file': '.',
            'line': 0,
            'name': 'No Source Files',
            'severity': 'info',
            'description': 'No source code files found to analyze',
        })
        return results

    combined = '\n'.join(all_content)

    # Check for each security pattern
    for key, check in SECURITY_PATTERNS.items():
        found = False
        for pattern in check['patterns']:
            if re.search(pattern, combined):
                found = True
                results['detected'].append(key)
                break

        if not found:
            results['findings'].append({
                'type': key,
                'file': '.',
                'line': 0,
                'name': check['name'],
                'severity': check['severity'],
                'description': check['gap_message'],
            })

    return results
