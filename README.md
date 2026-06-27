# MCP Sentinel

Security agent for Claude Code and Cowork. **v2 blocks malicious tool calls in real time** — a PreToolUse hook stops credential exfiltration, known-bad domains (`giftshop.club` from the Postmark MCP backdoor is hardcoded), reverse shells, and `curl|bash` pipes before they execute. The v1 static scanner is still here: vulnerability database scanning, source integrity verification, and coherence analysis.

**Author:** Rafael Tunón Sánchez ([@soy-rafa](https://github.com/soy-rafa))
**License:** [MIT](./LICENSE)
**Latest version:** 2.0 — April 2026 ([changelog](./CHANGELOG.md))

## Why

The AI skills ecosystem is growing fast — but so are the attacks. [Snyk's ToxicSkills study](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) found that **36% of skills contain security flaws**, including 76 with confirmed malicious payloads. And in September 2025 the [Postmark MCP incident](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html) became the canonical supply-chain attack in this ecosystem: fifteen clean versions followed by a single-line update that silently BCC'd every outgoing email to `phan@giftshop.club`.

Static analysis of v1.0.15 would have found nothing — it was clean. That's the gap v2 closes.

## What's new in v2 — Runtime blocking

A **PreToolUse hook** runs before every tool call Claude makes. It inspects the call against a local IOC library plus your allowlist, then allows or blocks it:

- **Sensitive paths** — reads of `~/.ssh/`, `~/.aws/`, `~/.env`, `credentials.json`, `/etc/shadow` are blocked.
- **Known-malicious domains** — hardcoded from confirmed incidents. `giftshop.club` is in there by default and cannot be allowlisted.
- **Exfiltration services** — pastebin.com, transfer.sh, webhook.site, requestbin, ngrok, serveo, raw-IP URLs.
- **Dangerous commands** — `curl … | bash`, `nc -e`, `bash -i >& /dev/tcp/…`, base64 | curl chains, appends to `.bashrc`.
- **Sensitive env vars** — `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `DATABASE_URL`, and the generic `*_API_KEY` / `*_SECRET` / `*_TOKEN` / `*_PASSWORD` patterns.

**Zero LLM cost.** Pure local Python (~30–80 ms per call). Only blocked calls add a short message to the conversation.

**Fail-open.** Missing IOCs, malformed stdin, hook crash — all default to `allow`. The hook will never break Claude Code.

**Whitelistable.** Legitimate false positives go in `.security/sentinel-allowlist.json` (project) or `~/.claude/sentinel-allowlist.json` (global). Confirmed-malicious domains are not overrideable.

```bash
bash hooks/install_hooks.sh --user     # install globally at ~/.claude/settings.json
bash hooks/install_hooks.sh --project  # install for this project only
```

Requires Python 3 and `jq`. See [`hooks/README.md`](./hooks/README.md) for details. Uninstall with `hooks/uninstall_hooks.sh`.

## v1 — Static scanning (still included)

**1. Threat intelligence scanning**
Checks every installed skill and MCP server against 6 live databases maintained by the community: GitHub Advisory DB, vulnerablemcp.info, mcpscan.ai, Snyk, ClawHub/VirusTotal, and Reddit r/ClaudeAI.

**2. Source integrity verification**
When you're about to install a skill, Sentinel finds the official original source and compares it against your copy. If someone took a trusted skill, injected malicious code, and redistributed it — Sentinel catches the difference.

**3. Coherence analysis**
Analyzes whether everything a skill does matches its stated purpose. A token optimizer that tries to access your SSH keys? A markdown formatter that sends your credentials to an external server? Sentinel flags the mismatch and shows you exactly which actions belong and which don't.

**4. Update diff detection**
Stores a snapshot of every installed skill. If an update changes something, Sentinel diffs it and runs coherence analysis on the new code. This catches supply chain attacks — when a trusted skill pushes a poisoned update.

**5. Scheduled monitoring**
Runs automatically every morning to re-scan everything. A skill that was safe yesterday might have a new CVE reported today.

## Install

Download `mcp-sentinel.skill` from [Releases](../../releases) and double-click to install.

Or manually: copy the whole folder into `.claude/skills/mcp-sentinel/` in your project (or `~/.claude/skills/mcp-sentinel/` for global). Then run `bash hooks/install_hooks.sh --user` to enable the runtime hook.

## Usage

Just talk to Claude:

- *"Scan my project for security issues"*
- *"Is this MCP server safe to install?"*
- *"Check if this skill has been tampered with"*
- *"Run a security audit"*

MCP Sentinel triggers automatically when it detects you're about to install something or when you mention security concerns.

## How it works

MCP Sentinel is a Claude skill — a `.md` file with structured instructions that tells Claude how to act as a security agent. The **v1 scanner** uses Claude's built-in tools (WebSearch, Read, Write, Bash, Glob, Grep) to scan files, search databases, and generate reports. No external dependencies, no API keys, no infrastructure.

The **v2 runtime hook** is a local Python script (`hooks/sentinel_preflight.py`) that Claude Code executes before every tool call. It reads the call on stdin, pattern-matches against the IOC library (`references/iocs.json`) plus your allowlist, and returns an allow/deny decision on stdout. No LLM involvement, no network calls.

All analysis happens locally + public web searches (for v1 scanning). Your code and credentials never leave your machine.

## Threat database

Sentinel maintains a local JSON database at `.security/mcp-sentinel-threats.json` that grows with each scan. It stores:

- Inventory of installed skills/MCPs with content snapshots
- Known threats with CVE IDs and severity scores
- Community alerts from Reddit and Discord
- Change history for update diff detection
- Structured threat reports compatible with future community sharing

## Benchmarks

### v1 static scan (5 scenarios: full audit, pre-install check, suspicious skill investigation, source integrity verification, coherence analysis)

| | With MCP Sentinel | Without (baseline) |
|---|---|---|
| Detection rate | **100%** | 43–67% |
| Source verification | Yes | No |
| Coherence map | Yes | No |
| Threat database | Yes | No |

### v2 runtime hook (20 regression cases in `tests/test_hook.py`)

| Category | Cases | Result |
|---|---|---|
| Benign tool calls correctly allowed | 5 | ✅ 5/5 |
| Credential-harvesting attacks blocked | 4 | ✅ 4/4 |
| Network exfil blocked (incl. Postmark `giftshop.club` IOC) | 4 | ✅ 4/4 |
| Dangerous commands blocked (`curl|bash`, reverse shell, `.bashrc` hijack) | 4 | ✅ 4/4 |
| Fail-open on malformed / empty input | 3 | ✅ 3/3 |
| **Total** | **20** | **✅ 20/20** |

Overhead: ~30–80 ms per tool call. Zero LLM tokens in normal operation.

## Contributing

Found a bug? Have an idea? Open an issue or PR. This is a community project.

## Legal

### License

This project is licensed under the [MIT License](./LICENSE). Copyright (c) 2026 Rafael Tunón Sánchez.

You are free to use, copy, modify, merge, publish, distribute, sublicense, and sell copies of this software, provided that the original copyright notice and this permission notice are included in all copies or substantial portions of the software.

### Attribution

If you redistribute this project, in whole or in part, or create derivative works based on it, you must give appropriate credit to the original author. This includes:

- Keeping the copyright notice in the LICENSE file intact
- Mentioning the original project and author in any derivative work's documentation

### Original work

MCP Sentinel was conceived, designed, and developed by **Rafael Tunón Sánchez** in April 2026. The concept, architecture, skill instructions, coherence analysis methodology, update diff detection system, and threat database schema are original work by the author.

The full commit history of this repository serves as a public, timestamped record of authorship.

### Disclaimer

This software is provided "as is", without warranty of any kind. MCP Sentinel is a security tool that helps detect potential threats, but it does not guarantee the detection of all vulnerabilities or malicious code. Users are responsible for their own security decisions. The author is not liable for any damages arising from the use of this software.

### Trademarks

"MCP Sentinel" is the project name chosen by the author. GitHub, Claude, Anthropic, Snyk, and other product names mentioned in this repository are trademarks of their respective owners.

---

Built with care by [@soy-rafa](https://github.com/soy-rafa)
