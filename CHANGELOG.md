# Changelog

All notable changes to MCP Sentinel are recorded here. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/). Versioning is [semver](https://semver.org/).

## [3.0.0] - 2026-06-28

Major release. An autonomous build pass turned Sentinel from a runtime hook into
a full agent-security suite: a fast local hot path, an optional AI brain for the
ambiguous cases, off-hot-path scanners, telemetry + a statusbar, and antivirus-
safe distribution. Driven by multi-agent threat research (`docs/V3-PROPOSAL.md`,
`docs/v3-backlog.md`). Built feature-by-feature, each a tested commit; the suite
stayed green throughout (81/81, precision FP=0/91, recall 44/44).

### Added — intelligence
- **AI escalation layer (`hooks/sentinel_ai.py`)** — opt-in (`SENTINEL_AI=on`,
  off by default), **never on the allow hot path**. Only the rare ambiguous
  `ask` escalates to the selected model with a tiny prompt; daily token budget
  (`SENTINEL_AI_BUDGET`) with a hard cap, 3s timeout, **fail-open to the local
  decision**, and every token reported in telemetry + the statusbar.

### Added — visibility
- **Telemetry (`hooks/sentinel_stats.py`)** — atomic, fail-open daily/session/
  totals (decisions, AI tokens, quarantine, chains).
- **Statusbar segment** in `~/.claude/custom_bar.sh` — `🛡 SNTL ⚑N AI:Nk`
  (threats flagged today + AI token spend), Bash+jq, clean fallback.
- **Quarantine / forensic hold (`hooks/sentinel_quarantine.py`)** — redacted
  post-facto record of approved-but-flagged actions; `list/review/release/purge`.

### Added — detection (off the hot path)
- **Config/MCP static scanner** grew anti-line-jumping (hidden instructions /
  Unicode-ANSI-HTML obfuscation in tool descriptions), endpoint/proxy-redirection
  and risky-env (`NODE_OPTIONS`/`LD_PRELOAD`/proxy) checks, and env-injection /
  command-substitution in MCP args.
- **Attack-chain / trajectory detection** — credential-access→egress and
  credential-harvesting across a session.
- **Cross-server data-flow** — fingerprints secrets output by one MCP server and
  flags them entering another (laundered exfiltration).
- **Cross-platform parity** — PowerShell dangerous patterns (IEX DownloadString,
  `iwr|iex`, `-EncodedCommand`, `Net.Sockets.TCPClient`).
- **Allowlist-bypass signatures** (CVE-2025-66032) and an **expanded injection +
  obfuscation corpus**.

### Added — robustness & safety
- **Integrity baseline** uses full SHA-256 with stale-baseline migration.
- **Feed auto-sync hardening** — anti-poisoning guard (refuse a >50% shrink) +
  version/provenance metadata.
- **Antivirus-safe distribution** — `tools/vault.py` encodes threat data base64
  at rest; `iocs.b64` (loaded by `load_iocs`), the URLhaus feed, and the attack
  corpus ship with **no plaintext signatures**, so a defended machine's antivirus
  does not raise false alarms. See `ANTIVIRUS.md`.

### Notes
- The PreToolUse hot path stays pure-local, fast, and fail-open. All new
  subsystems are opt-in or off-hot-path. Cross-server data-flow ships as the
  detector core (deep MCP-call wiring is a follow-up).

## [2.7.0] - 2026-06-27

v3 P0 capabilities. Driven by a multi-agent threat-research pass over the Claude
Code attack surface (see `docs/V3-PROPOSAL.md`, 63 verified threats). Closes two
gaps that have public PoCs today, and adds the first subsystem that sees beyond
a single tool call.

### Added

- **Allowlist-bypass command signatures (CVE-2025-66032).** New
  `dangerous_commands` patterns for the GMO Flatt bypass techniques: `sed` with
  the `e` (execute) flag, `sort --compress-program`, `man --html=`, `git
  --upload-pack=`/`--receive-pack=`, `rg --pre`/`--pre-glob`, and the bash
  `${var@P}` prompt-expansion trick. The `sed` matcher is escape-aware so normal
  substitutions with `/`-containing replacements don't false-positive.
- **Config / MCP scanner + integrity watcher (`tools/config_scan.py`).** A
  deterministic, off-the-hot-path scanner that the PreToolUse hook structurally
  cannot do (it only sees one tool call):
  - **Integrity baseline (CVE-2025-59536).** Hashes every hook command, MCP
    server command, and CLAUDE.md into a trusted baseline
    (`~/.claude/sentinel-baseline.b64`, base64 at rest) and reports drift — a
    malicious hook planted in a cloned repo's `.claude/settings.json` shows up as
    a NEW hook.
  - **Static scan.** Runs every hook/MCP command through the SAME
    `sentinel_preflight.decide` engine (so a hook that does `curl | bash`,
    reaches a known-bad domain, or hits cloud metadata is flagged), and scans
    SKILL.md/CLAUDE.md for prompt-injection phrases. Sentinel's own files are
    excluded (they contain indicators by design).
  - Modes: default report, `--json`, `--baseline`, `--session`.
- **SessionStart hook (warn-only).** The installer now also registers
  `config_scan.py --session` at SessionStart, so each session opens with a quick,
  non-blocking config/MCP/integrity check. Whether it should ever BLOCK a session
  is a deliberate maintainer decision (left as warn-only for now).
- **`docs/V3-PROPOSAL.md`** — the full v3 threat model and 9 prioritised
  capabilities (P0 done here; P1/P2 are the deterministic .mcp.json endpoint
  scanner, cross-server shadowing detection, and PostToolUse data-flow tracking).

### Tests

- Corpus grew to 85 benign + 40 attacks (incl. the bypass techniques); still
  **FP=0, recall=100%**. Added config-scan tests (malicious-hook detection,
  injection phrases, base64 baseline round-trip, drift detection). Suite 50/50.

## [2.6.0] - 2026-06-27

Precision overhaul + antivirus-safe distribution. The runtime layer was firing
on far too much benign developer activity (impractical to use); and shipping a
security tool full of plaintext threat indicators was getting the package and
users' session logs flagged by antivirus. Both are now measured and fixed.

### Precision (false positives: 19.7% -> 0%, recall: 79% -> 100%)

Measured against a corpus of 76 realistic benign tool calls and 34 attacks
(`tests/fixtures/`, `tests/precision_check.py`, now also a gate in the suite):

- **Field-scoped scanning.** Checks no longer flatten the whole tool input.
  Commands are matched only on `command`, paths on file/path targets, URLs on
  `url`(+command). File **content** being written (Write.content/Edit.new_string)
  is no longer scanned for commands/URLs/domains — writing text that *mentions*
  an attack is not performing it. This also ends the "hook blocks its own edits"
  problem when working on Sentinel.
- **Env vars need an exfil sink.** A secret env var is flagged only when a
  command dereferences it (or dumps `env`) AND pipes it to network egress —
  not when code, docs, or `rg 'GITHUB_TOKEN'` merely mention the name.
- **Domain matching by host boundary**, per host. `transfer.sh` no longer
  matches `mytransfer.shopify.com`; an allowlisted host in a command (e.g.
  `github.com`) clears only itself, so a malicious `webhook.site` in the same
  command still fires. Closes the `github.com.evil.ru` allowlist hole too.
- **`.env` regex tightened.** Matches real dotenv files, not `.env.example`/
  `.sample`/`.template` or `process.env`/`import.meta.env`.
- **Private/loopback IPs** (RFC1918 + 127 + link-local) no longer flagged;
  `chmod 777`/noise demoted; high-abuse free TLDs (`.tk .ml .ga .cf .gq`) →
  ask, while `.xyz/.top/.work/.click` are dropped (too common).
- **New coverage:** gcloud/azure credential paths, private-key filenames
  (`*_ed25519`, `*.pem`, `*.ppk`), cloud metadata / IMDS endpoints
  (`169.254.169.254`, `metadata.google.internal`), persistence/config writes
  (`settings.json` hooks, `.mcp.json`, shell rc, `authorized_keys`), reverse
  shells (`pty.spawn`, nc-to-IP, fifo), `curl | sudo bash`, `crontab -`.

### Antivirus-safe distribution

A security tool ships threat indicators by design — the exact strings antivirus
looks for. So they are now encoded at rest:

- **Malware-domain feed is base64 at rest** (`blocklist-feed.b64`, marker
  `#MCP-SENTINEL-B64`); the hook decodes ~400 domains in memory. The plaintext
  feed is gone. The updater writes encoded by default (`--plain` to opt out).
- **Attack test fixtures are base64** (`attack_corpus.b64.json`). No plaintext
  reverse shells or exfil payloads anywhere in the repo.
- **`ANTIVIRUS.md`** documents why, plus exclusion steps (Defender/Norton/macOS)
  and false-positive reporting portals (Microsoft, Symantec/Norton).
- Approach validated against industry practice (ClamAV, YARA, URLhaus): encode
  at rest + document + report FPs; base64 breaks literal-signature matching.

### Tests

- `tests/precision_check.py` corpus harness; precision/recall gate added to
  `test_hook.py` (now 44/44; FP=0/76, recall=34/34).

### Release-prep follow-ups (not yet done)

- Encode `references/iocs.json` at rest and source `test_hook.py`'s inline
  attack strings from the base64 corpus (kept readable during this tuning).

## [2.5.0] - 2026-06-26

Native-Windows fixes. A community tester running Claude Code natively on Windows
(not WSL) found that the runtime hook installed, ran, returned answers, and yet
protected nothing. Two root causes, both in the I/O layer (detection logic and
`iocs.json` untouched). Credit to the reporter (handle TBD — fill in before
publishing).

### Fixed

- **Fail-open on a UTF-8 BOM in stdin (critical, all platforms).** On Windows the
  stdin handed to the hook can start with a BOM (EF BB BF); `json.loads` rejects
  it, and the hook's fail-open path then allowed **every** call silently — the
  worst failure mode for a security tool. New `_read_stdin_payload()` reads raw
  bytes and decodes with `utf-8-sig`, stripping the BOM. Shared by both hooks.
- **Sensitive-path matching missed native Windows paths.** IOC patterns are
  Unix-style (`~/.ssh/`); Windows passes `C:\Users\me\.ssh\id_rsa` with
  backslashes and arbitrary case, so substring/prefix matching never fired and
  credential paths (the headline protection) slipped through as `allow`. New
  `_norm_path()` folds `\` to `/` and lowercases; `path_matches()` compares in
  that normalised space. SSH/AWS/etc. paths are now detected on Windows.

### Changed

- **Test runner is cross-platform.** `tests/test_hook.py` invokes the hooks via
  `sys.executable` instead of a hardcoded `python3` (absent on native Windows).
- **4 new regression tests**: BOM-on-stdin no longer fails open; backslash paths
  to `.ssh` are flagged; backslash benign paths still pass; `_norm_path` unit.
  Suite is now 42/42.

### Note

- This release's predecessor already fixed the output-schema bug the same report
  flagged (`{"decision": ...}` → `hookSpecificOutput.permissionDecision`); see
  2.1.0. The published 2.0.0 still has it, so publishing this line resolves all
  three reported issues at once.

## [2.4.0] - 2026-06-26

Localised messages. The hook now speaks the user's language: Spanish when they
write in Spanish, English otherwise.

### Added

- **Bilingual hook messages (es/en).** Every deny/ask/warn message from the
  PreToolUse hook and the "remembered" note from the PostToolUse hook is shown
  in Spanish or English. New `detect_language()`, `render()`, and a `_MSG`
  template table in `sentinel_preflight.py`; the postflight reuses them.
- **Language detection.** `SENTINEL_LANG=es|en` forces a language; otherwise the
  hook sniffs the tail of the session transcript (`transcript_path` from the hook
  payload) for the user's recent prompts and picks Spanish on accent/ñ/¿¡ or
  Spanish-stopword signals, English otherwise. Detection runs only when a message
  is actually emitted, never on the hot allow path, so there is no added latency
  for clean calls.
- **5 localisation tests** (forced-language both ways, transcript auto-detect
  both ways, `_looks_spanish` unit). Suite is now 38/38.

### Notes

- The technical `reason` token (e.g. `[CRITICAL] sensitive path: ...`) stays in
  English by design; only the surrounding framing is localised. Adding more
  languages is a matter of extending the `_MSG` table.

## [2.3.0] - 2026-06-26

Auto-updating malware blocklist. The runtime hook can now hard-deny calls to
hosts on a continuously-updated threat feed, in addition to the hand-curated
incident list.

### Added

- **Blocklist feed updater (`tools/update_blocklist.py`).** Downloads the
  abuse.ch URLhaus "hostfile" feed (currently-active malware hosts; no account
  or Auth-Key required), parses it, dedupes, and writes a one-domain-per-line
  `references/blocklist-feed.txt` (atomic). Accepts `--source` (URL or local
  file, for offline/tests) and `--output`. On network/parse failure it leaves
  the existing feed untouched and exits non-zero — never clobbers with an empty
  list. Initial fetch: 418 domains.
- **Exact-host feed matching in the PreToolUse hook.** New `load_feed_domains()`
  loads the feed into a set; `extract_hosts()` pulls hostnames from URLs and
  bare domains in a tool call; `check_feed_blocklist()` tests **exact** set
  membership. Exact (not substring) matching means a few-hundred-entry feed adds
  O(1) lookup and zero substring false positives ("a.com" never matches
  "data.com"). A hit is a hard deny (`feed_blocklist` category).
- **4 feed tests + 1 updater test** (exact match, sibling/parent non-match,
  allowlist override, parse+dedupe). Suite is now 33/33.

### Changed

- **`SENTINEL_FEED_PATH` env override** points the hook at an alternate feed file
  (tests use it for hermetic runs).
- **Two tiers of hard deny.** `known_malicious` (curated incidents) stays
  non-overrideable; `feed_blocklist` (automated feed) IS allowlist-overrideable,
  since automated feeds can carry the occasional false positive. The deny message
  differs accordingly.

### Operating it

- Refresh on demand: `python3 tools/update_blocklist.py`. To keep it current
  automatically, schedule that command (e.g. a daily cron). No cron is installed
  by default.

## [2.2.0] - 2026-06-26

Ask instead of block, with trust that persists. Until now the runtime hook
hard-blocked every critical/high detection. This release keeps the hard block
only for confirmed-malicious indicators and turns the heuristic detections into
a user decision, remembered once approved.

### Added

- **"ask" decision in the PreToolUse hook (`hooks/sentinel_preflight.py`).**
  Suspicious heuristics (sensitive paths, sensitive env vars, exfil vectors,
  dangerous command patterns) now return `permissionDecision: "ask"`, routing
  the call to Claude Code's native Allow/Deny prompt instead of blocking. The
  message names the entity and, when applicable, says approving will trust it.
- **PostToolUse hook (`hooks/sentinel_postflight.py`) — "remember on approve".**
  PostToolUse only fires when a call actually ran (the user approved at the
  prompt). For a flagged **path or domain** it appends that concrete entity to
  `~/.claude/sentinel-allowlist.json` (atomic write, deduped) so Sentinel stops
  asking. Deny at the prompt and nothing is remembered. This is how trust
  builds incrementally as the user confirms what they use.
- **`SENTINEL_ALLOWLIST_PATH` env override.** Points both hooks at an isolated
  allowlist file; used by the test suite for hermetic runs, and available to
  users who keep their allowlist somewhere non-standard.
- **7 new regression tests** covering ask-vs-deny routing and the postflight
  remember/skip logic. Suite is now 27/27.

### Changed

- **Severity → decision mapping.** `known_malicious` → deny (hard,
  non-overrideable); other critical/high → ask; medium → warn (unchanged).
  Previously all critical/high were deny.
- **`decide()` now returns `(decision, reason, category, entity)`** and the
  `check_*` functions return a matching 4-tuple, so the approved entity can be
  remembered precisely.
- **Installer/uninstaller register both hooks.** `install_hooks.sh` now adds
  PreToolUse *and* PostToolUse (preserving unrelated hooks such as gitnexus);
  `uninstall_hooks.sh` removes both.
- **SKILL.md / hooks/README.md** rewritten around the deny/ask/allow model and
  the remember-on-approve flow. Version bumped to 2.2.0.

### Safety

- Confirmed-malicious indicators are never downgraded to "ask" and never
  auto-remembered. Dangerous-command patterns and sensitive env vars are asked
  every time but never auto-trusted (no wholesale `curl | bash` allowlisting);
  the user adds those by hand. Auto-remember writes to the allowlist only after
  an explicit human approval at the native prompt.

## [2.1.0] - 2026-06-26

Wire-format migration. The hook's behaviour (what it blocks and allows) is
unchanged; only how it reports its decision to Claude Code changed, plus the
test suite that asserts it.

### Changed

- **Hook output schema (`hooks/sentinel_preflight.py`).** Migrated from the
  flat `{"decision": ..., "reason": ...}` shape to Claude Code's native
  PreToolUse permission protocol:
  - `allow` now emits **empty stdout** (silent; nothing added to context),
    instead of a `{"decision": "allow"}` object.
  - `deny` emits `{"hookSpecificOutput": {"hookEventName": "PreToolUse",
    "permissionDecision": "deny", "permissionDecisionReason": <message>}}`.
  - `warn` emits `permissionDecision: "allow"` plus `additionalContext`
    carrying the warning, so the call proceeds but the note reaches the model.
- **Fail-open path.** Non-JSON or empty stdin now returns silently (empty
  stdout = implicit allow) rather than printing an allow object. Same
  guarantee: a hook failure never blocks a tool call.

### Fixed

- **Test suite (`tests/test_hook.py`) was stale.** It still asserted the old
  flat format and the old `"block"` decision value, so it reported `0/20
  passed` even though the hook was blocking attacks correctly in production.
  `run_hook()` now normalises the v2.1+ wire format (empty stdout /
  `hookSpecificOutput`) into `{"decision", "reason"}`; the 20 test cases are
  unchanged. Result: **20/20 passed**.

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
