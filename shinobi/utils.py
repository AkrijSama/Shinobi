"""Utility functions for file walking and pattern matching."""

import os
import re
import json
from pathlib import Path
from typing import Generator


# Directories to always skip
SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env',
    '.env', '.tox', '.mypy_cache', '.pytest_cache', 'dist', 'build',
    '.eggs', '*.egg-info', '.idea', '.vscode', '.next', '.nuxt',
    'vendor', 'target', 'coverage', 'htmlcov', '.terraform',
}

# Binary file extensions to skip
BINARY_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
    '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.exe', '.dll', '.so', '.dylib', '.o', '.a',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav',
    '.pyc', '.pyo', '.class', '.jar',
    '.sqlite', '.db', '.sqlite3',
}

# Model file extensions (checked separately by ai_risks scanner)
MODEL_EXTENSIONS = {'.bin', '.onnx', '.pt', '.safetensors', '.h5', '.pkl', '.pth'}


def get_patterns_dir() -> Path:
    """Get the path to the patterns directory."""
    return Path(__file__).parent.parent / 'patterns'


def load_patterns(pattern_file: str) -> dict:
    """Load a JSON pattern file from the patterns directory."""
    pattern_path = get_patterns_dir() / pattern_file
    with open(pattern_path, 'r') as f:
        return json.load(f)


def walk_files(target_dir: str, extensions: set = None) -> Generator[Path, None, None]:
    """Walk directory yielding text files, skipping binary and ignored dirs."""
    target = Path(target_dir).resolve()
    for root, dirs, files in os.walk(target):
        # Filter out skip directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith('.egg-info')]

        for filename in files:
            filepath = Path(root) / filename
            ext = filepath.suffix.lower()

            # Skip binary files
            if ext in BINARY_EXTENSIONS:
                continue

            # If specific extensions requested, filter
            if extensions and ext not in extensions:
                continue

            yield filepath


def walk_all_files(target_dir: str) -> Generator[Path, None, None]:
    """Walk directory yielding ALL files including model files."""
    target = Path(target_dir).resolve()
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith('.egg-info')]
        for filename in files:
            yield Path(root) / filename


def read_file_safe(filepath: Path) -> str | None:
    """Read a file safely, returning None if it can't be read."""
    try:
        if is_probably_binary(filepath):
            return None
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except (OSError, PermissionError):
        return None


def read_lines_safe(filepath: Path) -> list[str] | None:
    """Read file lines safely, returning None if it can't be read."""
    try:
        if is_probably_binary(filepath):
            return None
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except (OSError, PermissionError):
        return None


def is_probably_binary(filepath: Path) -> bool:
    """Quick binary-file heuristic for files with misleading extensions."""
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(2048)
    except (OSError, PermissionError):
        return True
    if not chunk:
        return False
    return b'\x00' in chunk


def mask_secret(value: str) -> str:
    """Mask a secret value showing first 4 and last 4 chars."""
    value = value.strip().strip("\"'`")
    if len(value) <= 8:
        return '*' * len(value)
    return value[:4] + '*' * (len(value) - 8) + value[-4:]


def matches_glob(filename: str, patterns: list[str]) -> bool:
    """Check if a filename matches any of the given glob-style patterns."""
    from fnmatch import fnmatch
    return any(fnmatch(filename, p) for p in patterns)


def is_gitignored(target_dir: str, filepath: str) -> bool:
    """Check if a file path is listed in .gitignore."""
    gitignore_path = Path(target_dir) / '.gitignore'
    if not gitignore_path.exists():
        return False

    relative = os.path.relpath(filepath, target_dir)
    try:
        with open(gitignore_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Simple gitignore matching
                pattern = line.rstrip('/')
                if pattern in relative or relative.startswith(pattern + '/'):
                    return True
                # Handle wildcard patterns
                from fnmatch import fnmatch
                if fnmatch(relative, pattern) or fnmatch(os.path.basename(filepath), pattern):
                    return True
    except OSError:
        pass
    return False


def format_relative_path(filepath: Path, target_dir: str) -> str:
    """Format a file path relative to the target directory."""
    try:
        return str(filepath.relative_to(Path(target_dir).resolve()))
    except ValueError:
        return str(filepath)
