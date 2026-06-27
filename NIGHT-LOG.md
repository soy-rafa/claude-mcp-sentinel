# MCP Sentinel — autonomous v3.0 night build log

> Rafa asked for an autonomous overnight build → v3.0 by morning. This file is
> the plan, the safety rails, and the live progress log. Newest report at top.

## MORNING REPORT (filled in as work completes)

- Status: **IN PROGRESS** — started 2026-06-28 ~00:10.
- (This section gets a summary of what shipped, what's green, what's pending,
  and total token cost, before the session ends.)

---

## Objective

A spectacular but **functional, non-disruptive, intelligent** v3.0:
- Never stops the user's workflow (hot path stays local/fast/fail-open).
- Optional **AI-in-the-loop** escalation (selected model, ONLY ambiguous cases,
  token-reported, economical). Off by default.
- Sentinel **integrated into the statusline** (`~/.claude/custom_bar.sh`) with
  **token transparency** (what Sentinel spent).
- Bring the best **classic-antivirus** features, adapted to Claude Code/agents.

## Mechanism & budget

- Driven by `/loop` (self-paced) + Rafa's `claude-auto-resume` daemon (resumes on
  rate-limit cuts). Token budget for the night: **~2.5M output tokens**, and stop
  well before exhausting the 5h/7d rate limits.
- Feature research running in background: workflow **wz072zaap** → merges into the
  backlog below when it lands.

## Safety rails (NON-NEGOTIABLE each iteration)

1. **One feature per iteration.** Implement → test → commit → log → next.
2. **Tests gate every commit:** `python3 tests/test_hook.py` must stay green AND
   `python3 tests/precision_check.py` must keep **FP=0, recall≥38/40**. If red,
   fix or revert; NEVER commit red.
3. **git commit per feature** (already a repo). Everything reversible. Conventional
   commit messages in Spanish.
4. **Hot path stays local & fail-open.** No LLM call in the PreToolUse hot path.
   AI-escalation is a separate, opt-in, off-by-default layer.
5. **AV-safe:** any new threat data base64 at rest. No plaintext IOC dumps.
6. **Self-block:** when editing files that contain IOC strings, disable the live
   Sentinel hook first, reinstall after (or rely on field-scoping for content).
7. **Nothing destructive / no external side effects** without it being inert by
   default. No network actions on the user's behalf.
8. Update this log every iteration (move items pending→done, note commits).
9. **Rate-limit backoff (retry ~hourly until tokens resume).** Each iteration,
   read `~/.claude/usage-cache.json` (`rate_limits.five_hour|seven_day` →
   `used_percentage`, `resets_at` epoch). If `five_hour.used_percentage >= 95`
   OR `seven_day.used_percentage >= 98` (rate-limited / about to cut), do NOT use
   the 270s cadence: set the next `ScheduleWakeup` `delaySeconds` to
   `clamp(resets_at - now, 60, 3600)` — i.e. wait until the limit resets, capped
   at 1h (runtime max), so it effectively retries hourly until tokens are back.
   Log "rate-limited, backing off to <when>". Resume the 270s cadence once usage
   drops below the thresholds. (Rafa's `claude-auto-resume` daemon already
   resumes the SESSION on a hard cut; this rail just stops the LOOP from
   hammering during the wait.) If `usage-cache.json` is missing/unreadable,
   fail-safe to a 1800s delay rather than 270s.

## Build backlog (starter — research workflow will extend/reorder)

P0 / foundations (no research needed, from Rafa's directives + v3 proposal):

1. [x] **Session event log + counters.** DONE. `record_event()` in preflight
   writes per-session counters to `~/.claude/sentinel-state/<sid>.json` (deny/
   ask/warn/escalated/ai_tokens + last). Only flagged calls recorded; allow hot
   path untouched. `SENTINEL_STATE_DIR` override for tests. Foundation for 2 & 3.
2. [ ] **Statusbar integration.** A Sentinel segment in `custom_bar.sh`: shield +
   protection status, threats blocked/asked this session, feed freshness,
   integrity (baseline OK/drift), and AI tokens spent. Reads a tiny state file
   the hooks write (no jq-heavy work, fast).
3. [ ] **Token transparency.** Sentinel records its own AI-escalation token spend
   to `~/.claude/sentinel-tokens.json`; surfaced in the bar and in a
   `sentinel_stats` command.
4. [ ] **AI-escalation layer (opt-in, off by default).** Local engine tags a call
   `ambiguous` (e.g. medium-confidence heuristic, novel domain). An escalation
   module calls the **selected model** via the Anthropic API with a tiny
   structured prompt (cached by call signature) to decide allow/ask/deny + a
   one-line reason; logs tokens. Requires `ANTHROPIC_API_KEY`; degrades to local
   if absent. Config in settings/allowlist.
5. [ ] **v3 P1: `.mcp.json` endpoint/proxy scanner** in config_scan (flag
   unexpected URLs / proxies / env injection in MCP server specs).
6. [ ] **v3 P1: cross-server shadowing / tool-name collision** detection in the
   scanner (two MCP servers exposing the same tool name).
7. [ ] **Classic-AV analogs** (from research — examples to expect): quarantine +
   rollback of a flagged write, scheduled scan (cron), reputation/decision cache,
   ransomware-canary files, PUA/over-permissioned-skill detection, tamper
   protection of Sentinel's own files, an alerts summary command.

(Research backlog items get appended here with build_order once wz072zaap lands.)

## Iteration log

- 00:10 — repo git-init'd (`c65be75` baseline v2.7.0); tar backup at
  `~/mcp-sentinel-backup-*.tar.gz`; research workflow wz072zaap launched; this
  plan written. Engaging the loop.
- 00:20 — Feature #1 (session event log + counters) implemented + tested
  (51/51). Committed `cd1301a`.
- 00:25 — Research wz072zaap landed: 48 ideas -> 16-item backlog, saved to
  `docs/v3-backlog.md` (+ raw). Build order set. Note: backlog #3 (bypass sigs)
  ALREADY done in v2.7.0; backlog #5 (telemetry) overlaps Feature #1.
- 00:30 — Backlog #1 (integrity hash -> full SHA-256 + stale-baseline migration)
  done + tested (53/53, FP=0, recall=40/40). Real baseline re-established with
  full hashes; live scan clean. Committed. Next: backlog #2 (FP regression for
  IOC-in-content), then #4 (injection/obfuscation corpus), #5/#6 (telemetry+bar).
