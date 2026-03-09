![Shinobi](https://raw.githubusercontent.com/AkrijSama/shinobi/main/shinobi/assets/banner.png)

# Shinobi Scan — AI Vibe Coding Security Scanner

Shinobi Scan is a free open-source CLI security scanner for AI-generated codebases.
It is built for vibe coders who ship fast and need a safety net before code reaches production.

> 100% local. Zero source code leaves your machine.

## What It Does

- Scans repos for hardcoded secrets, API keys, and tokens
- Detects `eval` and `exec` patterns tied to user input
- Flags missing authentication, CSRF protection, and rate limiting
- Checks for insecure `http://` URLs and `console.log` in production code
- Scores every finding with severity: `CRITICAL / HIGH / MEDIUM / LOW / INFO`
- Adds confidence scoring per finding: `HIGH / MEDIUM / LOW`
- Outputs machine-readable JSON with `--json`
- Writes Gate-compatible results with `--gate`
- Supports deeper git-history scanning with `--deep`

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

Shinobi also installs the shorter `shinobi` command as an alias for the same CLI.

## Output Format

Terminal findings are rendered as `[SEVERITY/CONFIDENCE]`:

```text
[CRITICAL/HIGH]  Hardcoded Anthropic API key — config.js:12
[HIGH/MEDIUM]    Eval on user input — server.js:47
[MEDIUM/LOW]     No authentication middleware detected
```

## JSON Output

Use `--json` to emit only valid JSON:

```json
{
  "scan_target": "/path/to/repo",
  "timestamp": "2026-03-09T03:28:11.335618Z",
  "total_findings": 3,
  "critical": 0,
  "high": 1,
  "medium": 0,
  "low": 0,
  "confidence_breakdown": {
    "high": 2,
    "medium": 0,
    "low": 1
  },
  "findings": [
    {
      "severity": "HIGH",
      "confidence": "HIGH",
      "confidence_note": "file exists and is not covered by .gitignore",
      "rule": "Untracked Env File",
      "file": ".env",
      "line": 0,
      "description": ".env exists but is NOT in .gitignore — secrets may be committed",
      "context": null,
      "context_note": null
    }
  ]
}
```

## Gate Integration

```bash
shinobi-scan /path/to/repo --gate
```

This writes the last machine-readable scan to:

```text
~/.gate/shinobi/last-scan.json
```

Gate can read that file and surface Shinobi findings in the Auditor desk monitor.

## What Shinobi Scans

| Scanner | Coverage |
|---------|----------|
| Secrets | Hardcoded API keys, tokens, passwords, private keys, untracked `.env` files |
| Defaults | Debug mode, permissive CORS, weak bindings, insecure config defaults |
| Dependencies | Known CVEs from dependency audit tools and risky version states |
| Armor | Missing auth, CSRF protection, rate limiting, security headers, sanitization gaps |
| Code Risks | `eval`/`exec`, production `console.log`, insecure external `http://` URLs |
| AI Risks | Prompt-injection patterns, exposed LLM assets, client-side key exposure |
| Git History | Previously committed secrets when `--deep` is enabled |

## Privacy

Shinobi runs entirely on your machine. It does not upload your repository contents. Dependency auditing may call ecosystem tooling such as `pip-audit` or `npm audit`, but Shinobi itself does not phone home.

## SolidDark

Built by Akrij — Digital Architect  
https://soliddark.net  
Free forever. Part of the SolidDark security toolkit.
