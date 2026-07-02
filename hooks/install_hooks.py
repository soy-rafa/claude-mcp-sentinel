#!/usr/bin/env python3
"""
MCP Sentinel — cross-platform installer (stdlib only, no bash/jq).

Mirrors install_hooks.sh for machines without bash+jq (native Windows especially,
where a community tester had to register the hook by hand). Registers three hooks
in Claude Code's settings.json:
  - sentinel_preflight.py  as PreToolUse  (allow / deny / ask)
  - sentinel_postflight.py as PostToolUse (remember on approve)
  - config_scan.py --session as SessionStart (config/MCP scan + integrity)

Idempotent and reversible. Existing non-Sentinel hooks (e.g. gitnexus) are kept;
prior Sentinel entries are matched by FILENAME (so re-running, or switching from
the .sh installer, never double-registers).

Usage:
  python install_hooks.py [--user|--project] [--uninstall]
    --user     (default) ~/.claude/settings.json
    --project  ./.claude/settings.json
"""

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent
TOOLS_DIR = HOOKS_DIR.parent / "tools"

# (settings event, script path, extra args, filename used to match prior entries)
SPECS = [
    ("PreToolUse", HOOKS_DIR / "sentinel_preflight.py", [], "sentinel_preflight.py"),
    ("PostToolUse", HOOKS_DIR / "sentinel_postflight.py", [], "sentinel_postflight.py"),
    ("SessionStart", TOOLS_DIR / "config_scan.py", ["--session"], "config_scan.py"),
]


def _interpreter():
    """A Python command that will exist on the target. Prefer a name on PATH
    (readable in settings.json); fall back to this interpreter's absolute path."""
    for name in ("python3", "python"):
        if shutil.which(name):
            return name
    return sys.executable


def _command_for(script, extra, interp):
    parts = [interp, f'"{script}"'] + list(extra)
    return " ".join(parts)


def _drop_ours(entries, filename):
    """Remove any hook entry whose command references our script filename."""
    kept = []
    for entry in entries or []:
        hooks = (entry or {}).get("hooks", []) or []
        if any(filename in (h.get("command") or "") for h in hooks):
            continue
        kept.append(entry)
    return kept


def install(settings_path, interp=None, uninstall=False):
    """Install (or uninstall) the three hooks into settings_path. Returns the
    resulting settings dict. Pure w.r.t. the given path (testable)."""
    interp = interp or _interpreter()
    settings_path = Path(settings_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    if settings_path.exists() and settings_path.stat().st_size > 0:
        data = json.loads(settings_path.read_text())
        if not isinstance(data, dict):
            raise ValueError(f"{settings_path} is not a JSON object")
    else:
        data = {}

    hooks = data.setdefault("hooks", {})
    for event, script, extra, filename in SPECS:
        entries = hooks.get(event, []) or []
        entries = _drop_ours(entries, filename)  # always strip stale Sentinel entries
        if not uninstall:
            entry = {"hooks": [{"type": "command", "command": _command_for(script, extra, interp)}]}
            if event != "SessionStart":
                entry["matcher"] = ""
            entries = entries + [entry]
        hooks[event] = entries
    return data


def _write_with_backup(settings_path, data):
    settings_path = Path(settings_path)
    if settings_path.exists():
        backup = settings_path.with_suffix(settings_path.suffix + f".sentinel.bak.{int(time.time())}")
        shutil.copy2(settings_path, backup)
        print(f"📦 Backup saved to {backup}")
    tmp = settings_path.with_suffix(settings_path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, settings_path)


def main(argv=None):
    ap = argparse.ArgumentParser(description="MCP Sentinel cross-platform hook installer.")
    ap.add_argument("--project", action="store_true", help="install into ./.claude/settings.json")
    ap.add_argument("--user", action="store_true", help="install into ~/.claude/settings.json (default)")
    ap.add_argument("--uninstall", action="store_true", help="remove the Sentinel hooks")
    args = ap.parse_args(argv)

    for _event, script, _extra, _fn in SPECS:
        if not script.exists():
            print(f"❌ Could not find {script}", file=sys.stderr)
            return 1

    if args.project:
        settings_path = Path.cwd() / ".claude" / "settings.json"
    else:
        settings_path = Path.home() / ".claude" / "settings.json"

    try:
        data = install(settings_path, uninstall=args.uninstall)
        _write_with_backup(settings_path, data)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"❌ {settings_path}: {e}. Fix or remove it, then retry.", file=sys.stderr)
        return 1

    if args.uninstall:
        print(f"✅ MCP Sentinel hooks removed from {settings_path}")
    else:
        print(f"✅ MCP Sentinel runtime protection installed in {settings_path}")
        print("   PreToolUse -> preflight | PostToolUse -> postflight | SessionStart -> config_scan")
        print("   Verify:  python tools/sentinel_status.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
