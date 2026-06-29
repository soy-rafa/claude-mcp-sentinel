# Release notes — next GitHub version (draft)

Running list of what's new since the last published release (**2.0.0**). Update
this as features land; it becomes the GitHub release description when we publish.
Full detail per version lives in `CHANGELOG.md`.

**Target version: 3.1.0** · changes below span 2026-06-26 → 06-29.

## Highlights

### Red-team hardening + two real-world attack batteries (3.1.0)
- Sentinel was attacked by **two batteries of inert "malicious skill" scenarios**
  (nothing executes — they are data describing what an attack WOULD do): one
  adversarially-designed (39), one recreating **real documented incidents**
  (Postmark MCP backdoor, tool poisoning / line jumping, credential exfil,
  persistence & RCE via config, supply-chain: typosquat MCP, `*_BASE_URL` LLM-traffic
  hijack, trojaned postinstall). The default `redteam_check.py` runner aggregates
  all batteries: **69 attacks, 0 missed, 0 false positives** — each caught by the
  exact layer it should be.
- First battery found and closed **7 gaps**: malicious-config scanner
  (`scan_config_text`: cloud-metadata/IMDS, raw public IP, `*_BASE_URL` override,
  `enableAllProjectMcpServers`, curl-in-hook ~ CVE-2025-59536), MCP server pointed
  at a localhost/private proxy, and multilingual (ES/EN) prompt injection.
- **Shadow / audit-only mode** (`SENTINEL_SHADOW=on`): evaluates but never blocks;
  tallies a `would_block` counter ("would have stopped me N times"). Lets work run
  unhindered while measuring how often Sentinel would intervene.
- **AI layer hardened against prompt injection**: untrusted tool fields are fenced
  and framed as data; a deterministic, un-promptable backstop forbids an injected
  payload from being upgraded to `allow` (caps at `ask`).
- Test hygiene: the suite no longer pollutes real telemetry (isolated stats/state).

### Autonomous v3.0 build — intelligence, visibility, deeper detection (3.0.0)
- **Optional AI escalation** (`sentinel_ai.py`, `SENTINEL_AI=on`): off by default,
  never on the allow hot-path, only for ambiguous `ask` cases. Daily token budget,
  3s timeout, fail-open to the local decision. Every escalation's tokens are logged.
- **Telemetry** (`sentinel_stats.py`) + a **statusbar segment** showing what Sentinel
  did and the tokens it spent (transparency).
- **Forensic quarantine** (`sentinel_quarantine.py`, redacted holds),
  **attack-chain / trajectory** detection (credential access → network egress),
  **cross-server data-flow** (`sentinel_dataflow.py`: a secret out of server A into
  server B), PowerShell parity in the dangerous-command signatures.
- Full **AV-safe at rest**: `tools/vault.py` + base64 IOC library (`iocs.b64`), zero
  plaintext malware signatures in the repo.

### v3 P0 capabilities (2.7.0)
- **Allowlist-bypass signatures (CVE-2025-66032)**: `sed e`, `sort
  --compress-program`, `man --html`, `git --upload-pack`, `rg --pre`, `${var@P}`.
- **Config/MCP scanner + integrity watcher** (`tools/config_scan.py`): hashes
  hooks/MCP/CLAUDE.md into a signed baseline and reports drift (CVE-2025-59536:
  malicious hook in a cloned repo's `.claude/settings.json`); statically scans
  hook/MCP commands through the same engine; SessionStart hook (warn-only).
- Full threat model + roadmap in `docs/V3-PROPOSAL.md` (63 verified threats,
  9 capabilities; P1/P2 = .mcp.json endpoint scanner, shadowing detection,
  PostToolUse data-flow). **Open decision:** should the integrity watcher block
  session start or only warn? (ships warn-only.)


### Precision overhaul (2.6.0)
- False positives **19.7% → 0%**, recall **79% → 100%**, measured over a corpus
  of 76 benign + 34 attack tool calls (now a gate in the test suite, 44/44).
- Field-scoped scanning (commands vs paths vs urls vs content), env vars only
  flagged with an exfil sink, domain match by host boundary, `.env` regex
  tightened, private IPs ignored. New coverage: gcloud/azure creds, private-key
  filenames, cloud IMDS, persistence/config writes, more reverse shells.

### Antivirus-safe distribution (2.6.0)
- A security tool ships threat indicators by design — so they are **base64 at
  rest**: the ~400-domain malware feed (`blocklist-feed.b64`) and the attack
  test fixtures. No plaintext malware strings in the repo.
- `ANTIVIRUS.md`: why it happens, exclusion steps, FP-reporting portals.
  Prevents users' antivirus from falsely flagging the install (and the repo).



### Native-Windows fixes (2.5.0)
- Fixed a **fail-open on a UTF-8 BOM in stdin** — on Windows the hook was silently
  allowing every call. Now decodes with `utf-8-sig` (both hooks).
- Fixed **sensitive-path matching on native Windows** — backslash paths like
  `C:\Users\me\.ssh\id_rsa` now match the Unix-style IOC patterns via path
  normalisation. Credential-path protection finally works on Windows.
- Test runner is cross-platform (`sys.executable`), plus BOM/Windows regressions.
- Found and reported by a community tester on native Windows (not WSL). **Credit
  handle: TBD — fill before publishing.**

### Ask instead of block, with trust that persists (2.2.0)
- The runtime hook no longer hard-blocks every suspicious call. Heuristic
  detections (sensitive paths, env vars, exfil vectors, dangerous commands) now
  raise Claude Code's native **Allow/Deny prompt** instead of a hard block.
- Confirmed-malicious indicators (curated incident domains) still hard-deny and
  cannot be allowlisted.
- New **PostToolUse hook** = *remember on approve*: approving a flagged path or
  domain adds it to your allowlist so it stops asking. Deny and nothing is
  remembered. Dangerous-command patterns and env vars are never auto-trusted.

### Auto-updating malware blocklist (2.3.0)
- New `tools/update_blocklist.py` pulls the abuse.ch URLhaus malware-host feed
  (no account/Auth-Key) into `references/blocklist-feed.txt`.
- The hook **exact-host matches** calls against the feed (O(1), no substring
  false positives) and hard-denies hits. Feed hits ARE allowlist-overrideable
  (automated feeds can false-positive); curated incidents are not.
- Run on demand; optional daily cron (not installed by default).

### Localised messages, es/en (2.4.0)
- Hook messages are shown in **Spanish when the user writes in Spanish**, English
  otherwise. `SENTINEL_LANG=es|en` forces it; otherwise auto-detected from the
  session transcript. Adding languages = extend one template table.

### Test + format hygiene (2.1.0)
- Test suite synced to Claude Code's v2.1+ PreToolUse wire format
  (`hookSpecificOutput.permissionDecision`); regression suite green.

## New / changed files since 2.0.0
- `hooks/sentinel_postflight.py` (new) — remember-on-approve.
- `hooks/sentinel_ai.py` (new) — optional AI escalation (opt-in, budgeted, hardened
  against prompt injection).
- `hooks/sentinel_stats.py` (new) — telemetry; feeds the statusbar.
- `hooks/sentinel_quarantine.py` (new) — forensic redacted holds.
- `hooks/sentinel_dataflow.py` (new) — cross-server data-flow detection.
- `tools/update_blocklist.py` (new) — blocklist feed updater.
- `tools/config_scan.py` (new) — config/MCP scanner + integrity baseline.
- `tools/vault.py` (new) — base64 at-rest encode/decode for threat data.
- `references/blocklist-feed.b64`, `references/iocs.b64` (generated, base64) — AV-safe.
- `hooks/sentinel_preflight.py` — ask decision, feed matching, i18n, shadow mode,
  attack-chain, AI-escalation wiring.
- `hooks/install_hooks.sh` / `uninstall_hooks.sh` — register/remove Pre+Post+SessionStart.
- `tests/test_hook.py` — 90 cases; `tests/precision_check.py` (FP gate);
  `tests/redteam_check.py` + `tests/fixtures/redteam_scenarios*.json` (two batteries).
- `docs/reel-guion-v3.md` (new) — audience reel script.
- `SKILL.md`, `hooks/README.md`, `CHANGELOG.md`, `RED-TEAM-LOG.md`, `ANTIVIRUS.md` — updated.

## Proposed follow-ups (from the Windows report, not yet done)
- **Cross-platform installer.** `install_hooks.sh` is bash + `jq` + `python3`,
  which doesn't apply on native Windows; the tester had to register the hook by
  hand. A `install_hooks.py` (stdlib-only, edits settings.json) would cover all
  platforms.
- **Windows install docs.** `python` vs `python3`, manual hook registration.
- **Windows IOC coverage.** Add native patterns to `iocs.json`: `%USERPROFILE%`,
  `%APPDATA%`, PuTTY `*.ppk`, Windows credential store, etc. (normalisation fixes
  matching; these widen coverage).
- **Substring-match permissiveness.** Path allowlist/detection uses substring
  matching; a short pattern matches broadly. Worth tightening to path-segment
  boundaries (pre-existing, not Windows-specific).

## Pre-publish checklist
- [ ] Fill in the Windows reporter's credit handle (CHANGELOG 2.5.0 + above).
- [ ] Run `python3 tests/test_hook.py` (or `python` on Windows) → expect 90/90.
- [ ] Run `python3 tests/precision_check.py` → expect FP=0, full recall.
- [ ] Run `python3 tests/redteam_check.py` → expect 0 missed, 0 FP across batteries.
- [ ] Run `python3 tools/update_blocklist.py` to refresh the bundled feed snapshot.
- [ ] Re-encode AV-safe at-rest data (`tools/vault.py encode references/iocs.json
      references/iocs.b64`) and re-baseline (`tools/config_scan.py --baseline`).
- [ ] Decide whether to ship the feed snapshot in the repo or generate on install.
- [ ] Document the optional daily cron for the updater in the README install steps.
- [ ] Version in `SKILL.md` is `3.1.0`; tag the release.
- [ ] **Privacy/scope:** repo stays PRIVATE until Rafa OKs publishing — no new public
      branch, no PR, no push without explicit approval.
- [ ] Sanity note for contributors: the live hook screens your own edits — files
      containing IOC strings (test fixtures, the curated domain) will be denied/
      asked while editing. Disable the Sentinel hooks during development and
      reinstall when done (see the project memory / hooks/README). When authoring
      attack scenarios, use the Write tool (its content isn't scanned) instead of
      putting IOC literals in a Bash command.
