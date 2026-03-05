#!/usr/bin/env python3
"""Shinobi Batch Scanner — scan multiple GitHub repos and log all results."""

import argparse
import csv
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import date

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(SCRIPT_DIR, "scan_results.csv")
MD_PATH = os.path.join(SCRIPT_DIR, "scan_results.md")
DEFAULT_REPOS_FILE = os.path.join(SCRIPT_DIR, "repos_to_scan.txt")
TEMP_REPORT = "/tmp/shinobi-batch-report.json"
HEADERS = ["repo", "stars", "secrets", "defaults", "armor", "ai_risks", "threat_level", "scan_date"]

THREAT_EMOJIS = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f535",
    "CLEAN": "\U0001f7e2",
}

RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GREEN = "\033[92m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

THREAT_COLORS = {
    "CRITICAL": RED,
    "HIGH": YELLOW,
    "MEDIUM": YELLOW,
    "LOW": BLUE,
    "CLEAN": GREEN,
}


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

def ensure_csv():
    """Create CSV with headers if it doesn't exist."""
    if not os.path.exists(CSV_PATH):
        with open(CSV_PATH, "w", newline="") as f:
            csv.writer(f).writerow(HEADERS)


def read_rows() -> list[dict]:
    """Read all data rows from the CSV. Returns empty list if no file."""
    if not os.path.exists(CSV_PATH):
        return []
    with open(CSV_PATH, "r", newline="") as f:
        return list(csv.DictReader(f))


def append_row(row: dict):
    """Append a single row to the CSV."""
    ensure_csv()
    with open(CSV_PATH, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=HEADERS).writerow(row)


def existing_repos() -> set[str]:
    """Return set of repo names already in the CSV."""
    return {r["repo"] for r in read_rows()}


# ---------------------------------------------------------------------------
# Repo URL parsing
# ---------------------------------------------------------------------------

def parse_repo_name(url: str) -> str | None:
    """Extract owner/repo from a GitHub URL. Returns None if malformed."""
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)$", url)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------

def fetch_stars(repo_name: str) -> int:
    """Fetch star count from GitHub API. Returns 0 on failure."""
    api_url = f"https://api.github.com/repos/{repo_name}"
    req = urllib.request.Request(api_url, headers={"User-Agent": "shinobi-batch/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return int(data.get("stargazers_count", 0))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  {YELLOW}Warning: GitHub API rate limited — star counts may be inaccurate{RESET}")
        elif e.code == 404:
            print(f"  {YELLOW}Warning: Repo not found on GitHub API{RESET}")
        else:
            print(f"  {YELLOW}Warning: GitHub API error {e.code}{RESET}")
        return 0
    except Exception as e:
        print(f"  {YELLOW}Warning: Could not fetch stars — {e}{RESET}")
        return 0


# ---------------------------------------------------------------------------
# Report parsing
# ---------------------------------------------------------------------------

def parse_report(report_path: str) -> dict | None:
    """Parse a shinobi JSON report. Returns dict with counts or None."""
    try:
        with open(report_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  {YELLOW}Warning: Could not parse report — {e}{RESET}")
        return None

    try:
        scanners = data.get("scanners", {})
        secrets_count = len(scanners.get("secrets", {}).get("findings", []))
        secrets_count += len(scanners.get("secrets", {}).get("env_warnings", []))
        defaults_count = len(scanners.get("defaults", {}).get("findings", []))
        armor_count = len(scanners.get("armor", {}).get("findings", []))
        ai_count = len(scanners.get("ai_risks", {}).get("findings", []))
        threat = data.get("threat_level", "UNKNOWN").upper()

        return {
            "secrets": secrets_count,
            "defaults": defaults_count,
            "armor": armor_count,
            "ai_risks": ai_count,
            "threat_level": threat,
        }
    except (AttributeError, TypeError) as e:
        print(f"  {YELLOW}Warning: Unexpected JSON structure — {e}{RESET}")
        return None


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def cleanup_temp():
    """Remove temp report and any shinobi clone dirs in /tmp."""
    if os.path.exists(TEMP_REPORT):
        os.remove(TEMP_REPORT)
    # Clean up shinobi_ prefixed temp dirs
    for d in glob.glob("/tmp/shinobi_*"):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Summary and export (imported logic from scan_tracker.py)
# ---------------------------------------------------------------------------

def print_summary():
    """Print formatted summary table from scan_results.csv."""
    rows = read_rows()
    if not rows:
        print("No scan results recorded.")
        return

    col_repo = max(len("Repo"), max(len(r["repo"]) for r in rows)) + 2
    col_stars = max(len("Stars"), 7)
    col_secrets = max(len("Secrets"), 7)
    col_defaults = max(len("Defaults"), 8)
    col_armor = max(len("Armor"), 5)
    col_ai = max(len("AI Risks"), 8)
    col_threat = max(len("Threat Level"), 14)

    cols = [col_repo, col_stars, col_secrets, col_defaults, col_armor, col_ai, col_threat]
    total_inner = sum(cols) + len(cols) + 1

    def fmt_threat(level: str) -> str:
        emoji = THREAT_EMOJIS.get(level, "")
        color = THREAT_COLORS.get(level, "")
        text = f"{level} {emoji}"
        if color:
            return f"{color}{text:<{col_threat}}{RESET}"
        return f"{text:<{col_threat}}"

    title = "SHINOBI SCAN TRACKER"
    print(f"\n{'╔' + '═' * total_inner + '╗'}")
    print(f"║{BOLD}{title:^{total_inner}}{RESET}║")
    print(f"{'╠' + '╦'.join('═' * w for w in cols) + '╣'}")
    print(
        f"║{BOLD}{'Repo':^{col_repo}}{RESET}"
        f"║{BOLD}{'Stars':^{col_stars}}{RESET}"
        f"║{BOLD}{'Secrets':^{col_secrets}}{RESET}"
        f"║{BOLD}{'Defaults':^{col_defaults}}{RESET}"
        f"║{BOLD}{'Armor':^{col_armor}}{RESET}"
        f"║{BOLD}{'AI Risks':^{col_ai}}{RESET}"
        f"║{BOLD}{'Threat Level':^{col_threat}}{RESET}║"
    )
    print(f"{'╠' + '╬'.join('═' * w for w in cols) + '╣'}")

    for r in rows:
        threat_display = fmt_threat(r["threat_level"])
        print(
            f"║ {r['repo']:<{col_repo - 1}}"
            f"║{int(r['stars']):>{col_stars - 1}} "
            f"║{int(r['secrets']):>{col_secrets - 1}} "
            f"║{int(r['defaults']):>{col_defaults - 1}} "
            f"║{int(r['armor']):>{col_armor - 1}} "
            f"║{int(r['ai_risks']):>{col_ai - 1}} "
            f"║ {threat_display}║"
        )

    print(f"{'╠' + '╩'.join('═' * w for w in cols) + '╣'}")

    total = len(rows)
    with_secrets = sum(1 for r in rows if int(r["secrets"]) > 0)
    with_critical = sum(1 for r in rows if r["threat_level"] in ("CRITICAL", "HIGH"))
    with_zero_armor = sum(1 for r in rows if int(r["armor"]) == 0)

    categories = {
        "Secrets": sum(int(r["secrets"]) for r in rows),
        "Defaults": sum(int(r["defaults"]) for r in rows),
        "Missing armor": sum(int(r["armor"]) for r in rows),
        "AI risks": sum(int(r["ai_risks"]) for r in rows),
    }
    most_common = max(categories, key=categories.get)
    most_common_count = categories[most_common]
    total_issues = sum(categories.values())
    avg_issues = total_issues / total if total else 0

    def sline(text):
        print(f"║ {text:<{total_inner - 1}}║")

    sline(f"{BOLD}SUMMARY{RESET}")
    sline(f"Total repos scanned: {total}")
    pct = lambda n: round(n / total * 100) if total else 0
    sline(f"Repos with exposed secrets: {with_secrets}/{total} ({pct(with_secrets)}%)")
    sline(f"Repos with critical/high threat: {with_critical}/{total} ({pct(with_critical)}%)")
    sline(f"Repos with zero armor gaps: {with_zero_armor}/{total} ({pct(with_zero_armor)}%)")
    sline(f"Most common issue: {most_common} ({most_common_count} total findings)")
    sline(f"Average issues per repo: {avg_issues:.1f}")

    print(f"{'╚' + '═' * total_inner + '╝'}")


def export_markdown():
    """Export scan results to markdown file."""
    rows = read_rows()
    if not rows:
        return

    total = len(rows)
    with_secrets = sum(1 for r in rows if int(r["secrets"]) > 0)
    with_critical = sum(1 for r in rows if r["threat_level"] in ("CRITICAL", "HIGH"))
    with_zero_armor = sum(1 for r in rows if int(r["armor"]) == 0)

    categories = {
        "Secrets": sum(int(r["secrets"]) for r in rows),
        "Defaults": sum(int(r["defaults"]) for r in rows),
        "Missing armor": sum(int(r["armor"]) for r in rows),
        "AI risks": sum(int(r["ai_risks"]) for r in rows),
    }
    most_common = max(categories, key=categories.get)
    most_common_count = categories[most_common]
    total_issues = sum(categories.values())
    avg_issues = total_issues / total if total else 0
    pct = lambda n: round(n / total * 100) if total else 0

    lines = [
        "# Shinobi Security Scan Results",
        "",
        f"*Generated on {date.today().isoformat()}*",
        "",
        "| Repo | Stars | Secrets | Defaults | Armor | AI Risks | Threat Level |",
        "|------|------:|--------:|---------:|------:|---------:|--------------|",
    ]
    for r in rows:
        emoji = THREAT_EMOJIS.get(r["threat_level"], "")
        lines.append(
            f"| {r['repo']} | {r['stars']} | {r['secrets']} | {r['defaults']} "
            f"| {r['armor']} | {r['ai_risks']} | {r['threat_level']} {emoji} |"
        )
    lines += [
        "",
        "## Summary",
        "",
        f"- **Total repos scanned:** {total}",
        f"- **Repos with exposed secrets:** {with_secrets}/{total} ({pct(with_secrets)}%)",
        f"- **Repos with critical/high threat:** {with_critical}/{total} ({pct(with_critical)}%)",
        f"- **Repos with zero armor gaps:** {with_zero_armor}/{total} ({pct(with_zero_armor)}%)",
        f"- **Most common issue:** {most_common} ({most_common_count} total findings)",
        f"- **Average issues per repo:** {avg_issues:.1f}",
        "",
        "---",
        "",
        "*Scanned with shinobi — 10-second security scan for developers who ship fast*",
        "",
    ]

    with open(MD_PATH, "w") as f:
        f.write("\n".join(lines))


# ---------------------------------------------------------------------------
# Main batch logic
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="batch_scan",
        description="Shinobi Batch Scanner — scan multiple GitHub repos automatically",
    )
    parser.add_argument(
        "--file", "-f",
        default=DEFAULT_REPOS_FILE,
        help="File with GitHub repo URLs, one per line (default: repos_to_scan.txt)",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip repos already present in scan_results.csv",
    )
    args = parser.parse_args()

    # Validate input file
    if not os.path.exists(args.file):
        print("Create repos_to_scan.txt with one GitHub repo URL per line")
        sys.exit(1)

    # Read and filter URLs
    with open(args.file, "r") as f:
        raw_lines = f.readlines()

    urls = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)

    if not urls:
        print("No repo URLs found in the input file.")
        sys.exit(1)

    # Parse repo names and validate
    repos = []
    for url in urls:
        name = parse_repo_name(url)
        if name is None:
            print(f"{YELLOW}Warning: Malformed URL, skipping: {url}{RESET}")
            continue
        repos.append((url, name))

    if not repos:
        print("No valid repo URLs found.")
        sys.exit(1)

    # Handle --skip-existing
    already_scanned = existing_repos() if args.skip_existing else set()

    total_repos = len(repos)
    scanned = 0
    skipped = 0
    start_time = time.time()

    print(f"\n{BOLD}Shinobi Batch Scanner{RESET}")
    print(f"Repos to scan: {total_repos}")
    if args.skip_existing and already_scanned:
        print(f"Already in CSV: {len(already_scanned)} (will skip if found)")
    print(f"{'─' * 60}\n")

    for idx, (url, repo_name) in enumerate(repos, 1):
        # Skip if already scanned
        if args.skip_existing and repo_name in already_scanned:
            print(f"  {GRAY}[{idx}/{total_repos}] {repo_name} — already scanned, skipping{RESET}")
            skipped += 1
            continue

        print(f"  [{idx}/{total_repos}] Scanning {repo_name}...")

        # Fetch stars
        stars = fetch_stars(repo_name)

        # Clean up any previous temp report
        cleanup_temp()

        # Run shinobi
        try:
            result = subprocess.run(
                ["shinobi", "--repo", url, "--output", TEMP_REPORT],
                capture_output=True, text=True, timeout=180,
            )
        except FileNotFoundError:
            print(f"  {RED}Error: shinobi not found on PATH. Is the venv activated?{RESET}")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            print(f"  {YELLOW}Warning: Scan timed out for {repo_name}, skipping{RESET}")
            cleanup_temp()
            if idx < total_repos:
                time.sleep(2)
            continue

        if result.returncode != 0 and not os.path.exists(TEMP_REPORT):
            # Check if report ended up in stdout or a different location
            stderr_msg = result.stderr.strip()[:200] if result.stderr else "unknown error"
            print(f"  {YELLOW}Warning: Scan failed for {repo_name} — {stderr_msg}{RESET}")
            cleanup_temp()
            if idx < total_repos:
                time.sleep(2)
            continue

        # Find the report — check --output path first, then fallback locations
        report_path = None
        if os.path.exists(TEMP_REPORT):
            report_path = TEMP_REPORT
        else:
            # Check /tmp for shinobi_ dirs that might contain a report
            for d in glob.glob("/tmp/shinobi_*"):
                candidate = os.path.join(d, "shinobi-report.json")
                if os.path.exists(candidate):
                    report_path = candidate
                    break

        if report_path is None:
            print(f"  {YELLOW}Warning: No report generated for {repo_name}, skipping{RESET}")
            cleanup_temp()
            if idx < total_repos:
                time.sleep(2)
            continue

        # Parse the report
        parsed = parse_report(report_path)
        if parsed is None:
            cleanup_temp()
            if idx < total_repos:
                time.sleep(2)
            continue

        # Write to CSV
        row = {
            "repo": repo_name,
            "stars": stars,
            "secrets": parsed["secrets"],
            "defaults": parsed["defaults"],
            "armor": parsed["armor"],
            "ai_risks": parsed["ai_risks"],
            "threat_level": parsed["threat_level"],
            "scan_date": date.today().isoformat(),
        }
        append_row(row)
        scanned += 1

        # Print result line
        emoji = THREAT_EMOJIS.get(parsed["threat_level"], "")
        color = THREAT_COLORS.get(parsed["threat_level"], "")
        print(
            f"  [{idx}/{total_repos}] {repo_name} — "
            f"{color}{parsed['threat_level']} {emoji}{RESET} "
            f"({parsed['secrets']} secrets, {parsed['defaults']} defaults, "
            f"{parsed['armor']} armor, {parsed['ai_risks']} ai_risks)"
        )

        # Cleanup
        cleanup_temp()

        # Rate limit pause between scans
        if idx < total_repos:
            time.sleep(2)

    # Final summary
    elapsed = time.time() - start_time
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)

    print(f"\n{'─' * 60}")
    print(f"  Scanned: {scanned}  |  Skipped: {skipped}  |  Failed: {total_repos - scanned - skipped}")

    # Print summary table
    print_summary()

    # Export markdown
    export_markdown()

    print(f"\n  Results saved to {BOLD}scan_results.csv{RESET} and {BOLD}scan_results.md{RESET}")
    print(f"  Batch complete in {mins} minutes {secs} seconds\n")


if __name__ == "__main__":
    main()
