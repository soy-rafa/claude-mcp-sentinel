#!/usr/bin/env python3
"""
MCP Sentinel: PostToolUse hook ("remember on approve").

Runs AFTER a tool call has executed. Claude Code only fires PostToolUse when the
call actually ran, which means the user approved it at the native permission
prompt that the PreToolUse hook asked for. We use that signal to persist trust:

  PreToolUse flagged it -> returned "ask" -> user approved -> call ran ->
  PostToolUse fires -> we add the concrete entity (a path or domain) to the
  allowlist so Sentinel stops asking about it.

Only path/domain findings are remembered (AUTO_REMEMBER_CATEGORIES). Dangerous
command patterns and sensitive env vars are never auto-trusted, and confirmed-
malicious indicators are hard-denied by PreToolUse so they never reach here.

Fail-safe: any error exits silently with code 0. PostToolUse cannot block a call
(it already ran); the worst case of a failure is that nothing gets remembered.

Decision logic is imported from sentinel_preflight to avoid duplication.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# The hook runs as a standalone script; its own directory is on sys.path[0],
# so a sibling import of the preflight module works without packaging.
try:
    from sentinel_preflight import (
        decide,
        load_user_allowlist,
        is_allowlisted_path,
        is_allowlisted_domain,
        detect_language,
        render,
        session_trust_path,
        _read_stdin_payload,
        AUTO_REMEMBER_CATEGORIES,
    )
except Exception:
    # If the preflight module can't be imported, there's nothing safe to do.
    sys.exit(0)


# Which allowlist bucket each rememberable category writes to.
KEY_BY_CATEGORY = {
    "sensitive_path": "paths",
    "suspicious_network": "domains",
}


def allowlist_write_target(payload=None):
    """Where to persist auto-remembered trust.

    With SENTINEL_TRUST=session, trust is scoped to THIS session (a per-session
    file that expires with it), so approving something 'just for now' does not
    grant permanent trust. Otherwise (default 'permanent'): SENTINEL_ALLOWLIST_PATH
    if set, else the global ~/.claude/sentinel-allowlist.json.
    """
    if os.environ.get("SENTINEL_TRUST", "permanent").strip().lower() == "session" and payload:
        sid = payload.get("session_id") or payload.get("sessionId")
        if sid:
            return session_trust_path(sid)
    override = os.environ.get("SENTINEL_ALLOWLIST_PATH")
    if override:
        return Path(override)
    return Path.home() / ".claude" / "sentinel-allowlist.json"


def already_trusted(entity, key, existing):
    """True if the entity is already covered by the current allowlist bucket."""
    values = existing.get(key, [])
    if not isinstance(values, list):
        return False
    if key == "paths":
        return is_allowlisted_path(entity, values)
    return is_allowlisted_domain(entity, values)


def add_entity(target, key, entity):
    """Append entity to target[key] with dedupe and atomic replace.

    Returns True if the file was written, False if it was already present.
    """
    try:
        data = json.loads(target.read_text()) if target.exists() else {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}

    bucket = data.get(key)
    if not isinstance(bucket, list):
        bucket = []
    if entity in bucket:
        return False
    bucket.append(entity)
    data[key] = bucket

    target.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: temp file in the same dir, then replace, so a concurrent
    # reader never sees a half-written allowlist.
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return True


def main():
    payload = _read_stdin_payload()  # BOM-safe (shared with preflight)
    if not isinstance(payload, dict):
        return

    decision, reason, category, entity = decide(payload)

    # A flagged (ask) call that reached PostToolUse was approved and RAN. File a
    # redacted forensic record (quarantine / forensic hold) and tally it.
    # Best-effort, never blocks.
    if decision == "ask":
        try:
            import sentinel_quarantine
            sentinel_quarantine.hold(payload, decision, category, reason or "")
            import sentinel_stats
            sentinel_stats.bump(session_id=payload.get("session_id"), quarantined=1)
        except Exception:
            pass

    # Only persist when PreToolUse would have asked AND the finding carries a
    # precise, safe-to-trust entity. Anything else: nothing to remember.
    if decision != "ask":
        return
    if category not in AUTO_REMEMBER_CATEGORIES or not entity:
        return

    key = KEY_BY_CATEGORY.get(category)
    if not key:
        return

    # Skip if a merged read of the live allowlist already covers it (e.g. the
    # user added it by hand in a project-local file).
    if already_trusted(entity, key, load_user_allowlist()):
        return

    target = allowlist_write_target(payload)
    if add_entity(target, key, entity):
        tool_name = payload.get("tool_name") or payload.get("tool", "this tool")
        message = render("remembered", detect_language(payload),
                         tool=tool_name, entity=entity, target=target)
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": message,
            },
        }))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never let a PostToolUse failure surface as an error.
        sys.exit(0)
