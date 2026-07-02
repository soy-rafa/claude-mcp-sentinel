#!/usr/bin/env python3
"""
MCP Sentinel: quarantine / forensic hold (PostToolUse, post-facto).

Classic antivirus keeps a quarantine of what it caught. Sentinel's analog: when a
tool call that PreToolUse FLAGGED (ask) was nonetheless approved and ran,
PostToolUse files a redacted forensic record (command + truncated output +
metadata) under ~/.claude/sentinel/quarantine/. This is NOT an execution
sandbox; it is an audit trail of risky-but-approved actions, with secrets
redacted so the record itself never leaks credentials.

CLI:
  sentinel_quarantine.py list            list held records
  sentinel_quarantine.py review <id>     print one record
  sentinel_quarantine.py release <id>    delete one record
  sentinel_quarantine.py purge           delete all records

Fail-open: holding never raises. SENTINEL_QUARANTINE_DIR overrides the location.
"""

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

_MAX_HOLDS = 100
_MAX_OUTPUT = 2000

# Secret shapes to redact from any held text (command + output).
_REDACT_PATTERNS = [
    re.compile(r"(?i)\b(AKIA|ASIA)[A-Z0-9]{8,}\b"),                       # AWS access key id
    re.compile(r"(?i)\b(gh[posru]|github_pat)_[A-Za-z0-9_]{10,}\b"),      # GitHub tokens
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),                              # OpenAI/Stripe-style
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),                       # Slack tokens
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),  # JWT
    # name=value for secret-named vars -> redact the value
    re.compile(r"(?i)\b(\w*(?:_API_KEY|_SECRET|_TOKEN|_PASSWORD|SECRET_ACCESS_KEY))\b(\s*[:=]\s*)\S+"),
]


def quarantine_dir():
    override = os.environ.get("SENTINEL_QUARANTINE_DIR")
    return Path(override) if override else (Path.home() / ".claude" / "sentinel" / "quarantine")


def redact(text):
    """Replace credential-shaped substrings with a marker."""
    if not isinstance(text, str) or not text:
        return text
    out = text
    for rx in _REDACT_PATTERNS[:-1]:
        out = rx.sub("***REDACTED***", out)
    # name=value: keep the name, redact the value
    out = _REDACT_PATTERNS[-1].sub(lambda m: f"{m.group(1)}{m.group(2)}***REDACTED***", out)
    return out


def hold(payload, decision, category, reason=""):
    """File a redacted forensic record for an approved-but-flagged action.
    Best-effort; never raises. Returns the record id or None."""
    try:
        tool_name = payload.get("tool_name") or payload.get("tool", "")
        tool_input = payload.get("tool_input") or payload.get("input") or {}
        command = ""
        if isinstance(tool_input, dict):
            command = tool_input.get("command") or tool_input.get("file_path") or tool_input.get("url") or ""
        output = payload.get("tool_response") or payload.get("tool_output") or ""
        if not isinstance(output, str):
            output = json.dumps(output)[:_MAX_OUTPUT]
        else:
            output = output[:_MAX_OUTPUT]
        ts = int(time.time())
        rid = f"{ts}-{hashlib.sha256(str(command).encode()).hexdigest()[:8]}"
        record = {
            "id": rid,
            "ts": ts,
            "tool": tool_name,
            "decision": decision,
            "category": category,
            "reason": redact(reason),
            "command": redact(str(command))[:_MAX_OUTPUT],
            "output": redact(output),
        }
        d = quarantine_dir()
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{rid}.json").write_text(json.dumps(record, indent=1))
        _prune(d)
        return rid
    except Exception:
        return None


def _prune(d):
    holds = sorted(d.glob("*.json"))
    for old in holds[:-_MAX_HOLDS]:
        try:
            old.unlink()
        except OSError:
            pass


def list_holds():
    d = quarantine_dir()
    if not d.is_dir():
        return []
    out = []
    for f in sorted(d.glob("*.json")):
        try:
            out.append(json.loads(f.read_text()))
        except Exception:
            continue
    return out


def release(rid):
    f = quarantine_dir() / f"{rid}.json"
    try:
        f.unlink()
        return True
    except OSError:
        return False


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    cmd = argv[0] if argv else "list"
    if cmd == "list":
        holds = list_holds()
        if not holds:
            print("🛡️ MCP Sentinel quarantine: empty.")
            return 0
        print(f"🛡️ MCP Sentinel quarantine: {len(holds)} held record(s)")
        for h in holds:
            print(f"  {h.get('id')}  {h.get('tool')}  [{h.get('decision')}/{h.get('category')}]  {h.get('command','')[:60]}")
        return 0
    if cmd == "review" and len(argv) > 1:
        f = quarantine_dir() / f"{argv[1]}.json"
        print(f.read_text() if f.exists() else "not found")
        return 0
    if cmd == "release" and len(argv) > 1:
        print("released" if release(argv[1]) else "not found")
        return 0
    if cmd == "purge":
        d = quarantine_dir()
        n = 0
        for f in d.glob("*.json") if d.is_dir() else []:
            f.unlink()
            n += 1
        print(f"purged {n}")
        return 0
    print("usage: sentinel_quarantine.py [list|review <id>|release <id>|purge]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
