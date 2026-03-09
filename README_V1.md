# Shinobi Scan — AI Vibe Coding Security Scanner

## What it is

Shinobi Scan is a free open-source CLI security scanner for AI-generated codebases.
It is built for vibe coders who ship fast and need a safety net before code reaches production.

## What it does

- Scans repos for hardcoded secrets, API keys, and tokens
- Detects `eval` and `exec` patterns tied to user input
- Flags missing authentication, CSRF protection, and rate limiting
- Checks for insecure `http://` URLs and `console.log` in production code
- Severity scoring: `CRITICAL / HIGH / MEDIUM / LOW / INFO`
- Confidence scoring: `HIGH / MEDIUM / LOW` per finding
- Machine-readable JSON output with `--json`
- Gate integration with `--gate`
- Deeper git-history scanning with `--deep`

## Install

```bash
pip install shinobi-scan
```

## Usage

```bash
shinobi-scan /path/to/repo
shinobi-scan /path/to/repo --json
shinobi-scan /path/to/repo --gate
shinobi-scan /path/to/repo --deep
```

## Output format `[SEVERITY/CONFIDENCE]`

```text
[CRITICAL/HIGH]  Hardcoded Anthropic API key — config.js:12
[HIGH/MEDIUM]    Eval on user input — server.js:47
[MEDIUM/LOW]     No authentication middleware detected
```

## Gate integration

```bash
shinobi-scan /path/to/repo --gate
```

Writes results to `~/.gate/shinobi/last-scan.json`.
Gate reads this file to display scan results in the Auditor desk monitor.

## JSON output schema

```json
{
  "scan_target": "/path",
  "timestamp": "iso",
  "total_findings": 15,
  "critical": 0,
  "high": 2,
  "medium": 10,
  "low": 2,
  "confidence_breakdown": {
    "high": 4,
    "medium": 6,
    "low": 5
  },
  "findings": [
    {
      "severity": "HIGH",
      "confidence": "HIGH",
      "confidence_note": "matches known vendor prefix",
      "context": "production",
      "context_note": null,
      "rule": "Hardcoded Secret",
      "file": "config.js",
      "line": 12,
      "description": "Hardcoded API key detected"
    }
  ]
}
```

## SolidDark

Built by Akrij — Digital Architect  
soliddark.net  
Free forever. Part of the SolidDark security toolkit.
