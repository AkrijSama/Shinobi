![Shinobi](shinobi/assets/banner.png)

# Shinobi

**10-second security scan for developers who ship fast**

Shinobi is a local-first security scanner that checks your codebase for exposed secrets, dangerous defaults, vulnerable dependencies, missing security basics, and AI-specific risks — all in seconds, right from the terminal.

> **100% local. Zero data ever leaves your machine.**

## Install

```bash
pip install shinobi-scan
```

Or install from source:

```bash
git clone https://github.com/soliddark/shinobi.git
cd shinobi
python generate_logo.py
pip install .
```

## Usage

```bash
# Scan current directory (fast mode)
shinobi

# Scan a specific directory
shinobi /path/to/project

# Clone and scan a remote public repo
shinobi --repo https://github.com/user/project

# Deep scan — includes git history for previously committed secrets
shinobi --deep

# Save JSON report to a specific file
shinobi --output report.json

# Plain text output (no ANSI colors)
shinobi --no-color
```

## What It Scans

| Scanner | What It Checks |
|---------|---------------|
| **Secrets** | API keys (OpenAI, Stripe, AWS, GitHub, etc), passwords, tokens, private keys, .env files not in .gitignore |
| **Defaults** | DEBUG=True, CORS wildcards, 0.0.0.0 bindings, default database passwords, weak SECRET_KEYs |
| **Dependencies** | Known CVEs via pip-audit/npm-audit, unpinned versions |
| **Armor** | Missing rate limiting, CSRF protection, security headers, input sanitization, authentication |
| **AI Risks** | LLM keys in client code, prompt injection patterns, model files in repo, exposed system prompts |
| **Git History** | Previously committed secrets across last 500 commits (with `--deep`) |

## Sample Output

```
   __ _     _             _     _
  / _\ |__ (_)_ __   ___ | |__ (_)
  \ \| '_ \| | '_ \ / _ \| '_ \| |
  _\ \ | | | | | | | (_) | |_) | |
  \__/_| |_|_|_| |_|\___/|_.__/|_|

  v1.0 — shadow guard for your code

  🔍 shinobi v1.0 — security scan complete

  Project: my-app
  Scanned: 342 files in 2.1s

  ╔══════════════════════════════════════════════╗
  ║  THREAT LEVEL: CRITICAL 🔴                    ║
  ╚══════════════════════════════════════════════╝

  🔑 SECRETS EXPOSED          3 found
     → src/config.py:12 — OpenAI API Key: sk-a****...x9f2
     → .env:5 — AWS Access Key: AKIA****...XMPL

  ⚠️  DANGEROUS DEFAULTS       1 found
     → settings.py:8 — Debug mode is enabled

  🛡️  MISSING ARMOR            2 gaps
     → No rate limiting detected
     → No CSRF protection detected

  Total issues: 6  |  Critical: 3  |  High: 1  |  Medium: 2
```

## Privacy

Shinobi runs **entirely on your machine**. It does not make network requests, phone home, or transmit any data. The only external calls are to `pip audit` and `npm audit` (which are your own local tools calling their own registries).

## License

MIT

---

Built by **SolidDark** — [https://soliddark.net](https://soliddark.net)
