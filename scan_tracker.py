#!/usr/bin/env python3
"""Shinobi Scan Tracker — log, summarize, and export security scan results."""

import argparse
import csv
import json
import os
import sys
from datetime import date

CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results.csv")
MD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results.md")
HEADERS = ["repo", "stars", "secrets", "defaults", "armor", "ai_risks", "threat_level", "scan_date"]

THREAT_EMOJIS = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f535",
    "CLEAN": "\U0001f7e2",
}

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

THREAT_COLORS = {
    "CRITICAL": RED,
    "HIGH": YELLOW,
    "MEDIUM": YELLOW,
    "LOW": BLUE,
    "CLEAN": GREEN,
}


def _ensure_csv():
    """Create CSV with headers if it doesn't exist."""
    if not os.path.exists(CSV_PATH):
        with open(CSV_PATH, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(HEADERS)


def _read_rows() -> list[dict]:
    """Read all data rows from the CSV."""
    if not os.path.exists(CSV_PATH):
        return None  # file doesn't exist
    with open(CSV_PATH, "r", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def _append_row(row: dict):
    """Append a single row to the CSV."""
    _ensure_csv()
    with open(CSV_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writerow(row)


def cmd_add(args):
    """Add a scan result manually."""
    row = {
        "repo": args.repo,
        "stars": args.stars,
        "secrets": args.secrets,
        "defaults": args.defaults,
        "armor": args.armor,
        "ai_risks": args.ai_risks,
        "threat_level": args.threat.upper(),
        "scan_date": date.today().isoformat(),
    }
    _append_row(row)
    emoji = THREAT_EMOJIS.get(row["threat_level"], "")
    print(f"Added: {row['repo']} — {row['threat_level']} {emoji}")


def cmd_parse(args):
    """Parse a shinobi JSON report and add a row."""
    if not os.path.exists(args.report):
        print(f"Error: File not found: {args.report}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.report, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.report}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        scanners = data.get("scanners", {})

        secrets_count = len(scanners.get("secrets", {}).get("findings", []))
        secrets_count += len(scanners.get("secrets", {}).get("env_warnings", []))
        defaults_count = len(scanners.get("defaults", {}).get("findings", []))
        armor_count = len(scanners.get("armor", {}).get("findings", []))
        ai_count = len(scanners.get("ai_risks", {}).get("findings", []))
        threat = data.get("threat_level", "UNKNOWN").upper()
    except (AttributeError, TypeError) as e:
        print(f"Error: Unexpected JSON structure in {args.report}: {e}", file=sys.stderr)
        sys.exit(1)

    row = {
        "repo": args.repo,
        "stars": args.stars,
        "secrets": secrets_count,
        "defaults": defaults_count,
        "armor": armor_count,
        "ai_risks": ai_count,
        "threat_level": threat,
        "scan_date": date.today().isoformat(),
    }
    _append_row(row)
    emoji = THREAT_EMOJIS.get(threat, "")
    print(f"Parsed and added: {row['repo']} — {threat} {emoji}")


def cmd_summary(_args):
    """Print a formatted summary table."""
    rows = _read_rows()
    if rows is None:
        print("No scan results yet. Run 'python scan_tracker.py add' or 'python scan_tracker.py parse' first.")
        return
    if not rows:
        print("No scan results recorded yet.")
        return

    # Column widths
    col_repo = max(len("Repo"), max(len(r["repo"]) for r in rows)) + 2
    col_stars = max(len("Stars"), 7)
    col_secrets = max(len("Secrets"), 7)
    col_defaults = max(len("Defaults"), 8)
    col_armor = max(len("Armor"), 5)
    col_ai = max(len("AI Risks"), 8)
    col_threat = max(len("Threat Level"), 14)

    cols = [col_repo, col_stars, col_secrets, col_defaults, col_armor, col_ai, col_threat]
    total_inner = sum(cols) + len(cols) + 1  # separators

    def hline_top():
        return "╔" + "═" * total_inner + "╗"

    def hline_header_sep():
        return "╠" + "╦".join("═" * w for w in cols) + "╣"

    def hline_row_sep():
        return "╠" + "╬".join("═" * w for w in cols) + "╣"

    def hline_summary_top():
        return "╠" + "╩".join("═" * w for w in cols) + "╣"

    def hline_bottom():
        return "╚" + "═" * total_inner + "╝"

    def fmt_threat(level: str) -> str:
        emoji = THREAT_EMOJIS.get(level, "")
        color = THREAT_COLORS.get(level, "")
        text = f"{level} {emoji}"
        if color:
            return f"{color}{text:<{col_threat}}{RESET}"
        return f"{text:<{col_threat}}"

    def fmt_threat_plain(level: str) -> str:
        emoji = THREAT_EMOJIS.get(level, "")
        return f"{level} {emoji}"

    # Title
    title = "SHINOBI SCAN TRACKER"
    print(hline_top())
    print(f"║{BOLD}{title:^{total_inner}}{RESET}║")

    # Header row
    print(hline_header_sep())
    print(
        f"║{BOLD}{'Repo':^{col_repo}}{RESET}"
        f"║{BOLD}{'Stars':^{col_stars}}{RESET}"
        f"║{BOLD}{'Secrets':^{col_secrets}}{RESET}"
        f"║{BOLD}{'Defaults':^{col_defaults}}{RESET}"
        f"║{BOLD}{'Armor':^{col_armor}}{RESET}"
        f"║{BOLD}{'AI Risks':^{col_ai}}{RESET}"
        f"║{BOLD}{'Threat Level':^{col_threat}}{RESET}║"
    )
    print(hline_row_sep())

    # Data rows
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

    # Summary section
    print(hline_summary_top())

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

    def summary_line(text):
        print(f"║ {text:<{total_inner - 1}}║")

    summary_line(f"{BOLD}SUMMARY{RESET}")
    summary_line(f"Total repos scanned: {total}")
    pct_secrets = round(with_secrets / total * 100) if total else 0
    summary_line(f"Repos with exposed secrets: {with_secrets}/{total} ({pct_secrets}%)")
    pct_critical = round(with_critical / total * 100) if total else 0
    summary_line(f"Repos with critical/high threat: {with_critical}/{total} ({pct_critical}%)")
    pct_armor = round(with_zero_armor / total * 100) if total else 0
    summary_line(f"Repos with zero armor gaps: {with_zero_armor}/{total} ({pct_armor}%)")
    summary_line(f"Most common issue: {most_common} ({most_common_count} total findings)")
    summary_line(f"Average issues per repo: {avg_issues:.1f}")

    print(hline_bottom())


def cmd_export(_args):
    """Export scan results to markdown."""
    rows = _read_rows()
    if rows is None:
        print("No scan results yet. Run 'python scan_tracker.py add' or 'python scan_tracker.py parse' first.")
        return
    if not rows:
        print("No scan results recorded yet.")
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

    pct_secrets = round(with_secrets / total * 100) if total else 0
    pct_critical = round(with_critical / total * 100) if total else 0
    pct_armor = round(with_zero_armor / total * 100) if total else 0

    lines = []
    lines.append("# Shinobi Security Scan Results")
    lines.append("")
    lines.append(f"*Generated on {date.today().isoformat()}*")
    lines.append("")

    # Table
    lines.append("| Repo | Stars | Secrets | Defaults | Armor | AI Risks | Threat Level |")
    lines.append("|------|------:|--------:|---------:|------:|---------:|--------------|")
    for r in rows:
        emoji = THREAT_EMOJIS.get(r["threat_level"], "")
        lines.append(
            f"| {r['repo']} | {r['stars']} | {r['secrets']} | {r['defaults']} "
            f"| {r['armor']} | {r['ai_risks']} | {r['threat_level']} {emoji} |"
        )

    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total repos scanned:** {total}")
    lines.append(f"- **Repos with exposed secrets:** {with_secrets}/{total} ({pct_secrets}%)")
    lines.append(f"- **Repos with critical/high threat:** {with_critical}/{total} ({pct_critical}%)")
    lines.append(f"- **Repos with zero armor gaps:** {with_zero_armor}/{total} ({pct_armor}%)")
    lines.append(f"- **Most common issue:** {most_common} ({most_common_count} total findings)")
    lines.append(f"- **Average issues per repo:** {avg_issues:.1f}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*Scanned with shinobi — 10-second security scan for developers who ship fast*")
    lines.append("")

    with open(MD_PATH, "w") as f:
        f.write("\n".join(lines))

    print(f"Exported to {MD_PATH}")


def main():
    parser = argparse.ArgumentParser(
        prog="scan_tracker",
        description="Shinobi Scan Tracker — log and summarize security scan results",
    )
    subs = parser.add_subparsers(dest="command")

    # add
    add_p = subs.add_parser("add", help="Add a scan result manually")
    add_p.add_argument("--repo", required=True, help="Repository name (owner/repo)")
    add_p.add_argument("--stars", type=int, required=True, help="GitHub star count")
    add_p.add_argument("--secrets", type=int, default=0, help="Number of secrets found")
    add_p.add_argument("--defaults", type=int, default=0, help="Number of dangerous defaults")
    add_p.add_argument("--armor", type=int, default=0, help="Number of missing armor gaps")
    add_p.add_argument("--ai-risks", type=int, default=0, help="Number of AI-specific risks")
    add_p.add_argument("--threat", required=True, help="Threat level (CRITICAL/HIGH/MEDIUM/LOW/CLEAN)")

    # parse
    parse_p = subs.add_parser("parse", help="Parse a shinobi JSON report")
    parse_p.add_argument("--report", required=True, help="Path to shinobi-report.json")
    parse_p.add_argument("--repo", required=True, help="Repository name (owner/repo)")
    parse_p.add_argument("--stars", type=int, required=True, help="GitHub star count")

    # summary
    subs.add_parser("summary", help="Print formatted summary table")

    # export
    subs.add_parser("export", help="Export results to markdown")

    args = parser.parse_args()

    if args.command == "add":
        cmd_add(args)
    elif args.command == "parse":
        cmd_parse(args)
    elif args.command == "summary":
        cmd_summary(args)
    elif args.command == "export":
        cmd_export(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
