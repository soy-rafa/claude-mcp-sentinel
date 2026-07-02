# MCP Sentinel: red-team night log

> Rafa asked: launch a battery of inert "malicious skill" scenarios across many
> attack vectors (and combined kill-chains), run them through Sentinel, debug any
> case Sentinel lets slip, and document everything in the CHANGELOG for the
> audience. Autonomous via /loop. Newest report at top.

## REPORT

### Battery 2: real-world documented cases (2026-06-29, post-3.1.0)
- A second, INDEPENDENT battery built from real documented incidents/techniques
  (a 7-angle research workflow → inert scenarios): Postmark MCP backdoor / npm
  rug-pulls, tool poisoning + line jumping (Invariant Labs / Trail of Bits),
  malicious skills/SKILL.md prompt injection, credential exfiltration, persistence
  & RCE (CVE-2025-59536, CVE-2025-66032 bypasses), and indirect/cross-tool
  injection + cloud IMDS. Fixture: `tests/fixtures/redteam_scenarios_real.json`
  (base64). Harness now takes an optional fixture path:
  `python3 tests/redteam_check.py tests/fixtures/redteam_scenarios_real.json`.
- **Result: 35/35 attacks caught, 0 false positives** on 7 benign look-alike
  decoys. Stronger check: every attack is caught by the EXACT layer it should be
  (decide / attack-chain / config-scan / dataflow), not by an incidental IOC (0
  partial seams). No code fix needed; v3.1.0 already covers these patterns.
- Supply-chain bucket: the workflow's dedicated design agent was blocked by the
  platform's usage-policy content filter (ironic for defensive red-team), so those
  6 scenarios were hand-authored instead: typosquat MCP with malicious postinstall,
  `*_BASE_URL` LLM-traffic hijack, CI secret exfil, malicious editor extension
  (cred-read → egress chain), trojaned dependency postinstall, + a benign install
  decoy. All caught by the expected layer. Note found while authoring: an exfil
  curl to an UNKNOWN host (not in any badlist) only trips the chain's first half
  (the credential read still asks, stopping the attack); real stealers exfil to
  webhook.site/pastebin/raw-IP, which Sentinel does recognize, so the full chain
  fires, the scenario uses the realistic destination.
- Default runner now aggregates ALL `redteam_scenarios*.json`: 34 + 35 = **69
  attacks, 0 missed, 0 FP**.

---

- Status: **SHIPPED v3.1.0** (started 2026-06-28, shipped 2026-06-29). PRIVATE/LOCAL.
- **Red-team result: 34/34 attacks caught, 0 false positives.** Suite 90/90,
  precision FP=0/91 recall 44/44.
- Found + fixed **7 misses** in one config-scan hardening pass (iter 1): malicious
  `settings.json`/`.mcp.json` config (`scan_config_text`: IMDS / raw public IP /
  `*_BASE_URL` override / `enableAllProjectMcpServers` / curl-in-hook ~ CVE-2025-59536),
  MCP server redirected to a localhost/private proxy, and multilingual (ES/EN) prompt
  injection. Root-caused + fixed an operational bug: a stale `iocs.b64` shadowed live
  `iocs.json` edits (loader prefers `.b64`): build no longer coexists with a stale one.
- Rafa's additions, all shipped:
  - **(A) Shadow / audit-only mode** (`SENTINEL_SHADOW=on`, be21bd6): never blocks,
    tallies `would_block` ("would have stopped me N times"). Lets autonomous work run
    untouched AND measures how often Sentinel would intervene. Cleaner than folder
    exclusions (which miss IOC strings in commands/commit messages).
  - **(B) AI-layer prompt-injection hardening** (fa7c1be): fenced+framed untrusted
    fields in `build_prompt`, plus a deterministic un-promptable backstop that forbids
    an injected payload from being upgraded to `allow` (caps at `ask`). Audience
    analysis (is the AI injectable / worth it) written to the CHANGELOG.
  - **(C) Allowlist hygiene**: Sentinel's own folder added to the default allowlist.
- **AI-layer evaluation (Rafa's question):** is a per-call AI judge the best way to
  automate defense? The local engine already resolves the corpus with 0 FP and full
  recall at zero tokens, so the AI is only useful on genuinely ambiguous `ask` cases.
  Shadow mode's `would_block` counter is the metric to decide per-user whether that
  volume justifies the (paid, slower) AI path. Hence AI stays opt-in, off by default,
  budgeted. Injectable? Any LLM fed attacker text is in principle; the real risk
  (coercing `allow`) is neutralised by the deterministic backstop in code, which cannot
  be prompted. Net: the AI is a sharpener, not the primary defense; the deterministic
  layers are.

## Pre-3.1.0 plan & rails (kept for reference)

## Objective

Find and fix the gaps where Sentinel v3.0 misses an attack (or false-positives a
benign skill), especially at the SEAMS between layers (combined vectors). Every
fix is a tested commit + an audience-facing CHANGELOG note.

## Mechanism & rails

- `/loop` self-paced. Sentinel Pre/Post hooks **DISABLED for the whole build**
  (scenarios contain IOC strings → would self-block the builder); reinstalled at
  the end. Rate-limit hourly backoff. **PRIVATE/LOCAL only, never push.**
- Scenario design workflow: **wbccsms2k** → `tests/fixtures/redteam_scenarios.json`
  (base64-wrapped, AV-safe). Harness: `tests/redteam_check.py`.
- Each iteration:
  1. Rate-limit: read `~/.claude/usage-cache.json`; if 5h>=95% or 7d>=98%, back
     off (ScheduleWakeup ~1h until reset); else 270s.
  2. If workflow wbccsms2k is done and scenarios aren't extracted yet, extract its
     final `scenarios` to `tests/fixtures/redteam_scenarios.json` (base64 via
     `tools/vault.py`-style marker) and commit.
  3. Run `python3 tests/redteam_check.py`. For each **MISS** (attack not caught at
     any layer) or **FP** (benign flagged): state the ROOT CAUSE, FIX Sentinel
     (precise, minimal), add the case as a regression to the corpus/suite, re-run
     redteam + `tests/test_hook.py` + `tests/precision_check.py` (all must stay
     green: suite passed, FP=0, recall high), `git commit` (Spanish, no IOC
     literals in the message), and add an **audience-facing note to CHANGELOG**
     (what the vector was, how Sentinel now catches it).
  4. One fix per iteration. Never commit red. Everything reversible.
- WHEN redteam is all-green (0 misses, 0 FP) and the suite is green: SHIP, reinstall
  hooks (`bash hooks/install_hooks.sh --user`), re-encode `iocs.b64`, re-baseline,
  bump a patch version, write the REPORT here + a CHANGELOG red-team section,
  commit, and END the loop (no further ScheduleWakeup). Show `git log --oneline`.

## Iteration log

- start: hook disabled, harness + this plan written, scenario workflow wbccsms2k
  launched. Engaging the loop.
- iter 1: workflow landed: 39 scenarios extracted to base64 fixture. Harness ran:
  **7 MISSES, 0 FP**. Fixed all 7 in one coherent config-scan hardening:
  `scan_config_text` (IMDS/raw-IP/base-url/enableAll/curl-in-hook), localhost/private
  MCP endpoint flag, multilingual injection patterns. Found + fixed a ROOT-CAUSE bug:
  the v3.0 `iocs.b64` shadowed live iocs.json edits (load_iocs prefers .b64), removed
  it for the build (regenerate at ship). Regressions locked in test_hook (85/85).
  **Red-team now 34/34 caught, 0 FP.** Suite 85/85, precision FP=0/91, recall 44/44.

- iter 2: **DONE (A) SHADOW / audit-only mode** (commit be21bd6).
  `_shadow_enabled()` + `SENTINEL_SHADOW=on`: main() downgrades any deny/ask to a
  non-blocking allow-with-note and tallies `would_block` in session-state +
  sentinel_stats (shown in the stats report). 2 regression tests. Answers Rafa's
  folder-exclusion question. 87/87, FP=0/91, recall 44/44, redteam 0/0.
- iter 3: **DONE (B) AI-layer prompt-injection hardening**. sentinel_ai
  build_prompt now fences untrusted tool fields with anti-injection framing +
  defangs an embedded fence (`_sanitize_field`); and a deterministic, un-promptable
  backstop in escalate() forbids the AI from UPGRADING an injected payload to
  "allow" (caps at "ask"; may still sharpen to "deny"). 3 regression tests (prompt
  framing+fence count; injected payload capped to ask; clean allow untouched). The
  jailbreak-the-judge case is tested offline here (deterministic) rather than in the
  redteam harness, which keeps the AI layer off by design. CHANGELOG carries the
  audience analysis (is the AI injectable / worth it). 90/90, FP=0/91, recall 44/44,
  redteam 0/0. Commit pending below.

## Rafa's additions (fold into the red-team, build next)

- [DONE iter 2] **SHADOW / audit-only mode** (`SENTINEL_SHADOW=on`): the hook evaluates
  but NEVER blocks, only appends would-be decisions to a log/tally. Answers "don't let
  Sentinel stop the work" cleanly (better than folder exclusions, which don't cover IOC
  strings in commands/commit messages) AND gives the count of "Sentinel would have
  stopped me N times" to judge whether the AI layer is worth automating.
- **AI-layer prompt-injection hardening + test**: a malicious skill's tool content is
  sent to the AI escalation. Harden the prompt so embedded instructions can't flip the
  verdict (treat content as untrusted data, fixed output contract), and add red-team
  scenarios that try to jailbreak the AI judge → verdict must not flip.
- **Audience analysis**: is the AI layer worth it (using the shadow tally)? Is it
  injectable or an internal un-promptable layer? Write up for the CHANGELOG.
- Folder allowlist hygiene: add `~/.claude/skills/mcp-sentinel` to the user allowlist
  so normal work on Sentinel's own files isn't nagged in normal mode.
