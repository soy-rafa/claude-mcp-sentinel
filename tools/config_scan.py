#!/usr/bin/env python3
"""
MCP Sentinel — config & MCP static scanner + integrity watcher (v3).

The PreToolUse hook only sees individual tool calls; it CANNOT see a malicious
hook planted in a cloned repo's .claude/settings.json (it runs before any tool
call, e.g. at SessionStart — CVE-2025-59536), nor the descriptions/commands of
installed MCP servers. This deterministic scanner closes that gap. It is NOT on
the hot path: run on demand, on a schedule, or from a SessionStart hook.

What it does:
  1. Integrity (CVE-2025-59536): hashes the security-relevant config (hook
     commands, MCP server commands, CLAUDE.md) and compares against a trusted
     baseline, flagging drift (new/changed hooks, new MCP servers).
  2. Static scan: runs every hook command and MCP server command through the
     SAME detection logic as the runtime hook (sentinel_preflight.decide), so a
     hook or MCP server that does `curl ... | bash`, reaches a known-malicious
     domain, or hits cloud metadata is flagged. Scans SKILL.md / CLAUDE.md /
     tool descriptions for prompt-injection phrases.

Modes:
  config_scan.py            full scan + drift report (human readable)
  config_scan.py --json     machine-readable findings
  config_scan.py --baseline (re)establish the trusted baseline after you review
  config_scan.py --session  brief, non-blocking output for a SessionStart hook

Fail-open: any error prints a warning and exits 0 — the scanner never blocks
Claude Code. Whether the integrity watcher should DENY a session (blocking) is a
deliberate maintainer decision; this ships in WARN mode.

The baseline is stored base64 at rest (B64_MARKER) like the blocklist feed, so a
host antivirus never sees a file full of hook commands and flags it.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))
try:
    import sentinel_preflight as pf
except Exception:
    pf = None

HOME = Path.home()
BASELINE_PATH = HOME / ".claude" / "sentinel-baseline.b64"
B64_MARKER = "#MCP-SENTINEL-B64"


def _read_json(path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _sha(s):
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]


def settings_files():
    return [
        HOME / ".claude" / "settings.json",
        HOME / ".claude" / "settings.local.json",
        Path.cwd() / ".claude" / "settings.json",
        Path.cwd() / ".claude" / "settings.local.json",
    ]


def mcp_files():
    return [
        HOME / ".claude.json",
        HOME / ".claude" / ".mcp.json",
        Path.cwd() / ".mcp.json",
        Path.cwd() / ".claude" / ".mcp.json",
    ]


def doc_files():
    out = [HOME / ".claude" / "CLAUDE.md", Path.cwd() / "CLAUDE.md"]
    for base in (HOME / ".claude" / "skills", Path.cwd() / ".claude" / "skills"):
        if base.is_dir():
            for sk in base.glob("*/SKILL.md"):
                out.append(sk)
    return out


def collect_hooks():
    """All hook commands across every settings file, as (source, event, command)."""
    out = []
    for f in settings_files():
        data = _read_json(f) if f.exists() else None
        if not isinstance(data, dict):
            continue
        hooks = data.get("hooks", {})
        if not isinstance(hooks, dict):
            continue
        for event, entries in hooks.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                for h in (entry or {}).get("hooks", []) or []:
                    cmd = h.get("command")
                    if isinstance(cmd, str) and cmd:
                        out.append((str(f), event, cmd))
    return out


def collect_mcp():
    """All MCP servers, as (source, name, command_string)."""
    out = []
    for f in mcp_files():
        data = _read_json(f) if f.exists() else None
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers") or data.get("mcp_servers") or {}
        if not isinstance(servers, dict):
            continue
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            parts = []
            if spec.get("command"):
                parts.append(str(spec["command"]))
            args = spec.get("args")
            if isinstance(args, list):
                parts.extend(str(a) for a in args)
            if spec.get("url"):
                parts.append(str(spec["url"]))
            out.append((str(f), name, " ".join(parts)))
    return out


def scan_command(cmd):
    """Reuse the runtime detection logic on a hook/MCP command string."""
    if pf is None:
        return None
    decision, reason, category, entity = pf.decide(
        {"tool_name": "Bash", "tool_input": {"command": cmd}})
    if decision in ("deny", "ask"):
        return f"[{decision}] {reason}"
    return None


def scan_injection(text):
    if pf is None:
        return []
    import re
    iocs = pf.load_iocs()
    phrases = iocs.get("prompt_injection_phrases", {}).get("patterns", [])
    hits = []
    for rx in phrases:
        if re.search(rx, text):
            hits.append(rx)
    return hits


def current_state():
    """Security-relevant fingerprint for the integrity baseline."""
    state = {"hooks": {}, "mcp": {}, "docs": {}}
    for src, event, cmd in collect_hooks():
        state["hooks"][f"{event}:{cmd}"] = _sha(cmd)
    for src, name, cmd in collect_mcp():
        state["mcp"][name] = _sha(cmd)
    for f in doc_files():
        if f.exists():
            try:
                state["docs"][str(f)] = _sha(f.read_text())
            except Exception:
                pass
    return state


def load_baseline():
    if not BASELINE_PATH.exists():
        return None
    try:
        txt = BASELINE_PATH.read_text()
        if txt.splitlines() and txt.splitlines()[0].strip() == B64_MARKER:
            txt = base64.b64decode("".join(txt.splitlines()[1:])).decode("utf-8", "replace")
        return json.loads(txt)
    except Exception:
        return None


def save_baseline(state):
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    blob = base64.b64encode(json.dumps(state, indent=1).encode()).decode("ascii")
    wrapped = "\n".join(blob[i:i + 100] for i in range(0, len(blob), 100))
    BASELINE_PATH.write_text(B64_MARKER + "\n" + wrapped + "\n")


def diff_baseline(state, baseline):
    """Return list of drift findings (new/changed hooks, mcp, docs)."""
    drift = []
    if not baseline:
        return drift
    for section, label in (("hooks", "hook"), ("mcp", "MCP server"), ("docs", "config file")):
        cur, old = state.get(section, {}), baseline.get(section, {})
        for k, v in cur.items():
            if k not in old:
                drift.append(f"NEW {label}: {k}")
            elif old[k] != v:
                drift.append(f"CHANGED {label}: {k}")
    return drift


def run_scan():
    findings = {"commands": [], "injection": [], "drift": []}
    for src, event, cmd in collect_hooks():
        hit = scan_command(cmd)
        if hit:
            findings["commands"].append(f"hook {event} ({src}): {hit}  ::  {cmd[:120]}")
    for src, name, cmd in collect_mcp():
        hit = scan_command(cmd)
        if hit:
            findings["commands"].append(f"MCP '{name}' ({src}): {hit}  ::  {cmd[:120]}")
    for f in doc_files():
        # Sentinel's own files contain injection phrases by design (it documents
        # and tests them) — never flag the tool against itself.
        if str(f).startswith(str(ROOT)):
            continue
        if f.exists():
            try:
                hits = scan_injection(f.read_text())
            except Exception:
                hits = []
            for rx in hits:
                findings["injection"].append(f"{f}: prompt-injection phrase /{rx}/")
    findings["drift"] = diff_baseline(current_state(), load_baseline())
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(description="MCP Sentinel config/MCP scanner + integrity watcher.")
    ap.add_argument("--baseline", action="store_true", help="(re)establish the trusted baseline")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--session", action="store_true", help="brief non-blocking output for SessionStart")
    args = ap.parse_args(argv)

    if pf is None:
        print("⚠️  MCP Sentinel: could not load detection engine; config scan skipped.", file=sys.stderr)
        return 0

    if args.baseline:
        save_baseline(current_state())
        print(f"✅ Trusted baseline written to {BASELINE_PATH}")
        return 0

    try:
        findings = run_scan()
    except Exception as e:
        print(f"⚠️  MCP Sentinel config scan error (ignored): {e}", file=sys.stderr)
        return 0

    total = sum(len(v) for v in findings.values())
    if args.json:
        print(json.dumps(findings, indent=2))
        return 0

    if args.session:
        if total:
            print(f"🛡️ MCP Sentinel: {total} config/MCP finding(s). Run "
                  f"`python3 {Path(__file__)} ` to review (hooks/MCP servers/drift).")
        return 0

    if not total:
        print("✅ MCP Sentinel config scan: no findings. Hooks, MCP servers and docs look clean.")
        if load_baseline() is None:
            print("   (No integrity baseline yet — run with --baseline to establish one.)")
        return 0

    print(f"🛡️ MCP Sentinel config scan: {total} finding(s)\n")
    if findings["commands"]:
        print("Dangerous hook / MCP commands:")
        for x in findings["commands"]:
            print(f"  - {x}")
    if findings["injection"]:
        print("Prompt-injection phrases in config/skills:")
        for x in findings["injection"]:
            print(f"  - {x}")
    if findings["drift"]:
        print("Integrity drift vs trusted baseline:")
        for x in findings["drift"]:
            print(f"  - {x}")
    print("\nReview these. If legitimate, re-baseline with --baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
