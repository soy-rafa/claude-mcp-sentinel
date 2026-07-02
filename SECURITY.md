# Security Policy: MCP Sentinel

## What leaves your machine

By default: **nothing.** MCP Sentinel is a local hook. The detection engine is
deterministic and runs entirely offline against a bundled signature base.

- **Telemetry** (`~/.claude/sentinel/stats.json`), **session state**, **quarantine
  holds** and the **allowlist** are local files. They are never sent anywhere.
- **Blocklist feed** (`tools/update_blocklist.py`) makes ONE outbound request, to
  abuse.ch/URLhaus, only when you run it. It downloads a hostfile; it uploads nothing.
- **AI escalation** is **off by default**. It only sends data when you set
  `SENTINEL_AI=on`, and even then:
  - only for the rare ambiguous `ask` case (never the allow hot path),
  - only the scoped tool fields (command / file_path / url), truncated,
  - **secrets are redacted first** (tokens, keys) via the quarantine redactor,
  - within a **daily token budget**, with a short timeout, failing back to the
    local decision.
  - You can point it at a **local/self-hosted endpoint** with `SENTINEL_AI_ENDPOINT`
    so nothing reaches a third party.
- **Explanations** are static, local text (`SENTINEL_EXPLAIN`), never a model call.

Set `SENTINEL_EXPLAIN=off` for the leanest messages, and leave `SENTINEL_AI` unset
for a strictly zero-network, zero-token tool.

## Threat model (summary)

Sentinel guards the boundary where a Claude Code (or compatible) agent runs a tool
call. It defends against malicious or compromised **skills / MCP servers** that try
to: steal credentials, exfiltrate data, run reverse shells / RCE, gain persistence,
inject prompts, redirect LLM traffic, or **disable Sentinel itself**. Detection is
layered (per-field signatures, host-boundary domain matching, config/MCP static
scan, integrity + capability-drift baseline, multi-step attack-chain, cross-server
data-flow), with an optional AI layer for ambiguous cases.

Out of scope: a fully offline attacker with local code execution outside the agent's
tool calls, kernel/OS compromise, or a user who deliberately allowlists malicious
infrastructure. Sentinel raises the cost of an attack via the agent; it is not a
general-purpose EDR.

## Reporting a vulnerability

Found a bypass or a false-negative? Please report it privately first:
- Open a **private** security advisory on the repository, or email the maintainer.
- Include: the tool call / config that slips through, the expected detection, and
  (if possible) an **inert** reproduction (data only, nothing that executes).
- Please do not open a public issue with a working exploit before a fix ships.

Bypasses become regression tests in `tests/redteam_check.py`, a confirmed,
reproducible bypass is the most valuable contribution you can make.

## Distribution integrity

Threat data (IOC library, blocklist feed, attack corpora) ships **base64-at-rest**
so a host antivirus does not false-flag the install on the plaintext signatures
(see `ANTIVIRUS.md`). Verify your install with `python3 tools/sentinel_status.py`.
