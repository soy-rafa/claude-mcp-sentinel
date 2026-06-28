# MCP Sentinel — autonomous v3.0 night build log

> Rafa asked for an autonomous overnight build → v3.0 by morning. This file is
> the plan, the safety rails, and the live progress log. Newest report at top.

## RELAUNCH — 2026-06-28 (root cause fixed)

- Status: **IN PROGRESS (relaunched).** Root-cause fix applied: the Sentinel
  Pre/Post hooks are now **DISABLED for the entire autonomous build** so they
  can't self-block the builder. At the END (backlog done / budget / rate limit):
  reinstall the hooks (`bash hooks/install_hooks.sh --user`), run the full suite
  + precision, re-establish the integrity baseline, and write the final report.
- Each iteration NO LONGER disables/reinstalls per-edit (global disable handles
  it). Picks up from backlog #4.

## PRIOR MORNING REPORT — 2026-06-28 (first run, stopped early)

- Status: **STOPPED EARLY — NOT FINISHED.** Reached ~backlog item #2-3 of 16.
- **Root cause it stalled:** the live Sentinel hook self-blocked the autonomous
  loop. The hook issues `ask` (interactive permission prompt) and `deny` on the
  loop's OWN tool calls when they contain IOC strings (commit messages, test
  commands, fixtures with attack samples). Unattended, an `ask` has nobody to
  approve → the loop freezes. Confirmed: a commit message containing the
  Postmark-incident domain got a hard `deny`.
- **Shipped + green (53/53 tests, FP=0/88, recall=40/40, all committed):**
  - `record_event` per-session counters (foundation for statusbar/stats).
  - Backlog #1: integrity hash → full SHA-256 + stale-baseline migration.
  - Backlog #2: FP regression lock for IOC-in-content (field-scoping).
  - Ops rails: rate-limit hourly backoff; private/local-only no-push.
  - (Backlog #3 bypass sigs was already done in v2.7.0.)
- **NOT built (13 of 16 backlog):** telemetry stats module, statusbar Sentinel
  segment + AI tokens, **AI-escalation layer**, quarantine/forensic hold, MCP
  tool-description scanner, IOC auto-sync, injection/obfuscation corpus, etc.
- **Fix before re-running autonomously:** DISABLE the Sentinel hook for the whole
  autonomous build (it must not screen its own construction), reinstall + full
  verify at the end. (Or add a self-exempt for the builder.)
- Backup intact: tar + git (`c65be75` baseline). Nothing broken; all reversible.

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
   ALSO: never put IOC literals (e.g. the Postmark-incident domain, raw reverse
   shells) in **commit messages or Bash commands** — the live hook scans the
   command field and will deny them. Refer to them descriptively instead.
7. **Nothing destructive / no external side effects** without it being inert by
   default. No network actions on the user's behalf.
7b. **PRIVATE / LOCAL ONLY (hard rule).** Commit to the local `main` only. NEVER
   `git push`, NEVER add a remote, NEVER create/publish a branch, NEVER open a
   PR. The repo has no remote and must keep none. Any GitHub publishing is a
   separate, explicit, owner-approved step done LATER — and PRIVATE first (a
   private repo), never public, never a public branch. Read-only network
   (research) is fine; pushing code is forbidden.
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
  done + tested. Committed `633082f`. Real baseline re-established.
- 00:38 — Ops rails added: rate-limit hourly backoff (`63bd296`), private/local
  only never-push (`12d5c26`).
- 00:45 — Backlog #2 (FP regression IOC-in-content) done. `c15dd88`.
- ~08:30 — RELAUNCH (Rafa awake, chose option 2). Root-cause fix: Sentinel
  Pre/Post hooks DISABLED for the whole build. Operative updated.
- 08:40 — Backlog #4 (injection corpus + obfuscation: zero-width/RTL/Unicode-
  tags/ANSI/HTML comments) done + tested (54/54, FP=0/88, recall=40/40), real
  scan clean. Committed `0ffd77d`.
- 09:01 — Backlog #5 (telemetry `sentinel_stats.py`) done. `e5e5c18`.
- 09:08 — Backlog #6 (statusbar segment) done. Extended ~/.claude/custom_bar.sh
  (live, OUTSIDE repo, backed up): shows `🛡 SNTL:ON/OFF ⚑N AI:Nk` from
  stats.json, Bash+jq only, clean fallback when no stats. Versioned copy at
  docs/statusbar-snippet.sh. Render verified both paths; suite 55/55, FP=0/88.
- 09:16 — Backlog #7 (quarantine / forensic hold) done. `hooks/sentinel_quarantine.py`:
  PostToolUse files a REDACTED record (command+output, secrets stripped) of any
  flagged-but-approved action; list/review/release/purge CLI; bumps stats.
  Wired into postflight. 57/57, FP=0/88, recall=40/40. Committed `b62233b`.
- 09:23 — Backlog #8 (AI escalation) DONE — the headline. `hooks/sentinel_ai.py`:
  opt-in (`SENTINEL_AI=on`, OFF default), only escalates ambiguous `ask` calls,
  tiny prompt + max_tokens, daily budget (`SENTINEL_AI_BUDGET`), 3s timeout,
  FAIL-OPEN to local decision, records tokens in sentinel_stats (shown in bar).
  Wired into preflight.main AFTER decide (never on allow hot path). Model via
  `SENTINEL_AI_MODEL`. Tested offline via `SENTINEL_AI_MOCK`. 59/59, FP=0/88,
  recall=40/40. Committed `e547ca5`.
- 09:30 — Backlog #9 (AI daily budget hard-cap + reset) done. `budget_status()`
  in sentinel_ai; escalation skipped once today's spend >= SENTINEL_AI_BUDGET
  (resets per UTC day via stats buckets). 60/60, FP=0/88. Committed.
  Next: #10 MCP tool-description scanner (anti line-jumping), #11-#16.
- 09:36 — Backlog #10 (MCP server-spec scanner, anti line-jumping) done.
  `scan_server_spec` in config_scan: flags dangerous commands AND hidden
  instructions/obfuscation in any spec field (command/args/env/url/description).
  Wired into run_scan. 63/63, FP=0/88, real scan clean. Committed.
- INSERTED (Rafa): AV-safety hardening — the build reintroduced plaintext IOCs
  (iocs.json, test literals). Doing it next before continuing backlog.
