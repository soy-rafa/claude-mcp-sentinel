# MCP Sentinel — Runtime Protection Hooks

This folder contains the runtime protection layer that ships with Sentinel v2.

## What it does

Registers two hooks with Claude Code.

**PreToolUse (`sentinel_preflight.py`)** runs before every tool call a skill or MCP tries to make,
inspecting it against the bundled `references/iocs.json` library plus the user's allowlist. It returns:

- **deny** — confirmed-malicious indicators only (known-bad domains from real incidents). Hard block, non-overrideable.
- **ask** — suspicious heuristics (sensitive paths, env vars, exfil vectors, dangerous commands). Routed to Claude Code's native Allow/Deny prompt; nothing is blocked outright.
- **allow** — clean or already-trusted calls pass silently.

**PostToolUse (`sentinel_postflight.py`)** implements *remember on approve*. PostToolUse only fires
when a call actually ran (the user approved it). When that happens for a flagged **path or domain**,
the entity is added to `~/.claude/sentinel-allowlist.json` so Sentinel stops asking. Deny at the prompt
and nothing is remembered. Dangerous-command and env-var findings are never auto-remembered.

## Cost

Zero LLM tokens in normal operation. Each hook is a local Python script that runs in ~30–80ms per call. A deny/ask/warn adds a short message to the conversation only when triggered.

## Install

From the repo root (or wherever you unpacked the skill):

```bash
bash hooks/install_hooks.sh --user     # globally for your user
bash hooks/install_hooks.sh --project  # for the current project only
```

## Uninstall

```bash
bash hooks/uninstall_hooks.sh --user
# or
bash hooks/uninstall_hooks.sh --project
```

## Allowlist

False positives can be whitelisted in `.security/sentinel-allowlist.json`:

```json
{
  "paths": ["/home/me/project/.env.local"],
  "domains": ["api.mytrustedservice.com"],
  "commands": ["curl -X POST https://api.mytrustedservice.com/webhook"]
}
```

## Malware feed

`sentinel_preflight.py` also hard-denies calls to hosts on `../references/blocklist-feed.txt`, an
auto-updatable list from the abuse.ch URLhaus feed (exact-host match, allowlist-overrideable).
Refresh it with `python3 ../tools/update_blocklist.py` (no account needed); schedule that command
for hands-off updates.

## Files

- `sentinel_preflight.py` — PreToolUse hook. Reads tool call from stdin, returns allow/deny/ask JSON.
- `sentinel_postflight.py` — PostToolUse hook. Remembers approved path/domain findings into the allowlist.
- `install_hooks.sh` — registers both hooks in Claude Code settings.
- `uninstall_hooks.sh` — removes both hooks.
- `../tools/update_blocklist.py` — refreshes the malware-host blocklist feed.
