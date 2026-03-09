"""Main CLI entry point for Shinobi."""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from shinobi import __version__
from shinobi.scanner import run_scan, clone_repo
from shinobi.reporter import build_machine_report, print_report, save_json_report


def main():
    parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]) or 'shinobi-scan',
        description='Shinobi — 10-second security scan for developers who ship fast',
    )
    parser.add_argument(
        'path',
        nargs='?',
        default='.',
        help='Directory to scan (default: current directory)',
    )
    parser.add_argument(
        '--repo',
        type=str,
        help='Clone and scan a remote public repo URL',
    )
    parser.add_argument(
        '--deep',
        action='store_true',
        help='Include full git history scan (slower)',
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Save JSON report to a specific file path',
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output only machine-readable JSON with severity counts and findings',
    )
    parser.add_argument(
        '--gate',
        action='store_true',
        help='Write the last machine-readable scan to ~/.gate/shinobi/last-scan.json for Gate integration',
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output',
    )
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'shinobi {__version__}',
    )

    args = parser.parse_args()

    # Determine target directory
    tmp_dir = None
    target_dir = args.path

    if args.repo:
        try:
            if not args.json:
                print(f"  Cloning {args.repo}...")
            tmp_dir = clone_repo(args.repo)
            target_dir = tmp_dir
        except RuntimeError as e:
            print(f"\033[91mError: {e}\033[0m", file=sys.stderr)
            sys.exit(1)

    # Validate target
    target_dir = os.path.abspath(target_dir)
    if not os.path.isdir(target_dir):
        print(f"\033[91mError: {target_dir} is not a valid directory\033[0m", file=sys.stderr)
        sys.exit(1)

    use_color = not args.no_color

    try:
        # Run the scan
        results = run_scan(
            target_dir=target_dir,
            deep=args.deep,
            repo_url=args.repo,
        )
        machine_report = build_machine_report(results)

        default_output_path = os.path.join(target_dir, 'shinobi-report.json')
        output_path = args.output or default_output_path
        gate_output_path = str(Path.home() / '.gate' / 'shinobi' / 'last-scan.json')
        results['output_path'] = output_path if not args.gate else gate_output_path

        if args.output or not args.json:
            save_json_report(results, output_path)
        if args.gate:
            save_json_report(results, gate_output_path)

        if args.json:
            sys.stdout.write(json.dumps(machine_report, indent=2))
            sys.stdout.write('\n')
        else:
            print_report(results, use_color=use_color)

    finally:
        # Clean up cloned repo
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
