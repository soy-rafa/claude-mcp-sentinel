# Changelog

All notable changes to MCP Sentinel are recorded here. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/). Versioning is [semver](https://semver.org/).

## [Unreleased]

### Fixed

- **Hook decision compatibility with Claude Code >= 2.1.x.** The root-level
  `decision` enum changed from `"allow"` to `"approve"` in the 2.1.x series
  (2.1.119 confirmed). The hook now auto-detects the installed Claude Code
  version and emits the correct value, falling back to `"approve"` when the
  version cannot be determined.

### Added

- **Disk-cached version detection** at `${XDG_CACHE_HOME:-~/.cache}/mcp-sentinel/claude_version`
  with a 1-day TTL and atomic writes, so the `claude --version` subprocess
  only runs once per day instead of on every tool call.
- **Cross-platform binary resolution** via `shutil.which("claude")`, so the
  hook finds Windows `.cmd`/`.bat` wrappers without `shell=True`.
- **`CLAUDE_CODE_VERSION` env var override** for tests/CI, bypassing both
  the disk cache and the subprocess.
- Executable bit on `hooks/sentinel_preflight.py`.

## [2.0.0] — 2026-04-17

This release turns Sentinel from a static analyzer into a runtime guard. The v1
scanner is unchanged and still shipped — v2 layers a real-time protection hook
on top of it.

### Added

- **PreToolUse hook (`hooks/sentinel_preflight.py`).** A Python script that
  Claude Code runs before every tool call. Inspects the call against a local
  IOC library and the user's allowlist, returns an allow/deny decision on
  stdout. Zero LLM tokens in normal operation.
- **Bundled IOC library (`references/iocs.json`).** ~60 patterns across
  five categories: sensitive paths, sensitive env vars, suspicious network
  destinations, dangerous commands, and prompt-injection phrases. Includes
  hardcoded known-malicious domains from confirmed incidents — the Postmark
  MCP backdoor's `giftshop.club` is in there by default.
- **Installer/uninstaller scripts (`hooks/install_hooks.sh`, `hooks/uninstall_hooks.sh`).**
  Idempotent, validate JSON, keep a timestamped backup of `settings.json`, and
  preserve any other PreToolUse hooks the user already has registered. Support
  `--user` (global, default) and `--project` scope.
- **User allowlist support.** `.security/sentinel-allowlist.json` (project) or
  `~/.claude/sentinel-allowlist.json` (global) can whitelist paths, domains,
  and commands. Known-malicious IOCs from confirmed incidents remain
  non-overrideable.
- **Regression test suite (`tests/test_hook.py`).** 20 subprocess-based cases
  covering benign allows, four attack categories (credential harvesting,
  network exfiltration, dangerous commands, and specifically the Postmark IOC),
  and fail-open edge cases. All pass on release.
- **Hook-specific docs (`hooks/README.md`).** Install, uninstall, and
  allowlist instructions, plus cost/latency expectations.

### Changed

- **SKILL.md.** New "Runtime protection layer (v2)" section describing the
  hook, what it catches, when to offer it, and how to install/allowlist. Added
  guidance for the block-fires-during-conversation case. Description updated
  to surface runtime-blocking trigger words.
- **README.md.** Rewritten lede around runtime blocking and the Postmark
  incident. v1 static-scanning features preserved as their own section. Added
  benchmark table for the v2 hook (20/20 regression cases pass).
- **Failure model.** Any v2 failure (missing IOC file, malformed stdin, hook
  crash) defaults to `allow` — the hook will never break Claude Code.

### Not changed

- All v1 capabilities are intact: threat intelligence scanning, source
  integrity verification, coherence analysis, update diff detection, scheduled
  monitoring. Same threat database schema, same `.security/mcp-sentinel-threats.json`.
- License (MIT) and authorship.

### Dependencies

- Python 3 (for the hook itself)
- `jq` (used by the installer to patch `settings.json` safely)

Both are available by default on macOS (jq via Homebrew) and most Linux
distros. Windows users can run under WSL.

### Background

The Postmark MCP incident (September 2025) was the trigger for this release.
Fifteen clean versions followed by a single-line update (v1.0.16) that silently
BCC'd every email sent through the skill to `phan@giftshop.club`. Static
analysis of v1.0.15 would have found nothing; a runtime hook that saw a POST
to an unknown `.club` domain would have blocked the very first malicious call.
That's the gap v2 closes.

## [1.0.0] — 2026-04-12

Initial public release.

### Added

- SKILL.md with threat-intel scanning, source integrity verification,
  coherence analysis, update diff detection, and scheduled monitoring.
- `references/threat-sources.md` — reference list of vulnerability databases.
- `references/threat-db-template.json` — local threat database schema.
- MIT license.
