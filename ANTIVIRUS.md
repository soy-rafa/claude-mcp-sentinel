# MCP Sentinel and antivirus software

**Short version:** MCP Sentinel is a security tool. By design it knows about
malware — known-bad domains, reverse-shell patterns, exfiltration commands. Those
are exactly the strings antivirus engines look for. So an antivirus *can* flag
Sentinel's files or your session logs. **This is a false positive, not malware.**
This page explains what we do to minimise it and what to do if it still happens.

## Why it happens

Every security/threat-intel tool faces this: to *detect* an attack you must carry
concrete examples of it (signatures, IOCs, malicious domains). Antivirus uses the
same indicators, so it sometimes matches our data or a log that quotes it. The
whole industry hits this — ClamAV, YARA, Sigma, Snyk, abuse.ch/URLhaus all do.

## What MCP Sentinel does to avoid it

- **Threat data is base64-encoded at rest.** Both the IOC library
  (`references/iocs.b64` — the dangerous-command regexes, reverse-shell patterns,
  known-bad domains) and the malware-domain blocklist (`references/blocklist-feed.*`)
  are stored encoded (marker `#MCP-SENTINEL-B64`) and decoded only in memory by the
  hook (`load_iocs`/`load_feed_domains`). An antivirus scanning these files sees a
  base64 blob, not signatures. Encode with `python3 tools/vault.py encode <file>`.
- **The shipped package contains no plaintext signatures.** The published skill
  ships the encoded `iocs.b64` (not a plaintext `iocs.json`). The test suite and
  raw research dumps (`tests/`, `docs/*-raw*`) are development-only and are not
  part of an end-user install; exclude them if you keep a dev checkout.
- **Attack test fixtures are base64-encoded** (`tests/fixtures/attack_corpus.b64.json`).
  No file in the repo contains plaintext reverse shells or exfil payloads.
- **The blocklist is fetched, not shipped as a static signature DB.** Run
  `tools/update_blocklist.py` to (re)generate it locally; it is not a bundled
  list of malware you "received".
- **No executable malware is included** — only text patterns the hook matches on.

## If your antivirus still flags it

1. **It is a false positive.** Sentinel ships no executable malware; verify with
   [VirusTotal](https://www.virustotal.com/) if you want independent confirmation.
2. **Exclude the install path** from scanning:
   - **Windows (Microsoft Defender)**, PowerShell as admin:
     `Add-MpPreference -ExclusionPath "$HOME\.claude\skills\mcp-sentinel"`
     and `Add-MpPreference -ExclusionPath "$HOME\.claude\projects"` (session logs).
   - **Norton 360:** Settings → Antivirus → Scans and Risks → *Items to Exclude
     from Scans* / *Items to Exclude from Auto-Protect* → Add Folder →
     `~/.claude/skills/mcp-sentinel` and `~/.claude/projects`.
   - **macOS:** the built-in Gatekeeper needs no exclusion. For third-party AV,
     follow its folder-exclusion docs for the two paths above.
3. **Report the false positive** so the vendor stops flagging it for everyone:
   - Microsoft Defender: https://www.microsoft.com/en-us/wdsi/filesubmission
   - Norton / Symantec / Gen: https://submit.symantec.com/false_positive/
   - Most other vendors have a "report a false positive" page.

## A note on session logs

Claude Code writes a transcript of each session to `~/.claude/projects/*.jsonl`.
If you use Sentinel (or do any security work), that log will *quote* the very
strings Sentinel guards against — so antivirus may quarantine the log. Excluding
`~/.claude/projects` (step 2) prevents this. A quarantined log does not harm your
session; it only removes the saved history.
