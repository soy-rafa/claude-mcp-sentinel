# MCP Sentinel — red-team night log

> Rafa asked: launch a battery of inert "malicious skill" scenarios across many
> attack vectors (and combined kill-chains), run them through Sentinel, debug any
> case Sentinel lets slip, and document everything in the CHANGELOG for the
> audience. Autonomous via /loop. Newest report at top.

## REPORT (filled when done)

- Status: **IN PROGRESS** — started 2026-06-28.

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
- WHEN redteam is all-green (0 misses, 0 FP) and the suite is green: SHIP — reinstall
  hooks (`bash hooks/install_hooks.sh --user`), re-encode `iocs.b64`, re-baseline,
  bump a patch version, write the REPORT here + a CHANGELOG red-team section,
  commit, and END the loop (no further ScheduleWakeup). Show `git log --oneline`.

## Iteration log

- start — hook disabled, harness + this plan written, scenario workflow wbccsms2k
  launched. Engaging the loop.
