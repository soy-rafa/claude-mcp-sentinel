# Release notes — next GitHub version (draft)

Running list of what's new since the last published release (**2.0.0**). Update
this as features land; it becomes the GitHub release description when we publish.
Full detail per version lives in `CHANGELOG.md`.

**Target version: 2.7.0** · changes below are 2026-06-26/27.

## Highlights

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
- `tools/update_blocklist.py` (new) — blocklist feed updater.
- `references/blocklist-feed.txt` (new, generated) — URLhaus feed snapshot.
- `hooks/sentinel_preflight.py` — ask decision, feed matching, i18n.
- `hooks/install_hooks.sh` / `uninstall_hooks.sh` — register/remove both hooks.
- `tests/test_hook.py` — 38 cases (ask, postflight, feed, i18n).
- `SKILL.md`, `hooks/README.md`, `CHANGELOG.md` — updated.

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
- [ ] Run `python3 tests/test_hook.py` (or `python` on Windows) → expect 42/42.
- [ ] Run `python3 tools/update_blocklist.py` to refresh the bundled feed snapshot.
- [ ] Decide whether to ship `references/blocklist-feed.txt` in the repo or have
      users generate it on install (it's a point-in-time snapshot).
- [ ] Document the optional daily cron for the updater in the README install steps.
- [ ] Bump version in `SKILL.md` frontmatter and tag the release.
- [ ] Sanity note for contributors: the live hook screens your own edits — files
      containing IOC strings (test fixtures, the curated domain) will be denied/
      asked while editing. Disable the Sentinel hooks during development and
      reinstall when done (see the project memory / hooks/README).
