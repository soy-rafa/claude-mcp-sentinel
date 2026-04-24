#!/usr/bin/env python3
"""
MCP Sentinel — PreToolUse hook.

Runs before every tool call made by Claude. Reads the tool call JSON from stdin,
checks it against bundled IOCs (paths, domains, command patterns, env vars) and
the user's allowlist. Returns an allow / deny decision as JSON on stdout.

Zero LLM cost — pure local pattern matching. Adds <50ms latency per tool call
in typical cases. Only the decision message (if deny/warn) is inserted into the
conversation, and only when something is actually blocked.

Protocol: Claude Code passes the tool call payload on stdin and expects a JSON
response on stdout. Exit 0 always; the "decision" field controls behavior.

Decision values:
  "approve" / "allow"  — tool call proceeds normally. No message added to context.
                         Claude Code >= 2.1.x uses "approve"; older versions use "allow".
                         The script detects the version automatically.
  "deny"   — tool call blocked. "reason" is shown to the user and Claude.
  "warn"   — tool call proceeds but with a warning message in context.

Usage (registered via install_hooks.sh, or manually):
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{"type": "command",
                 "command": "python3 ~/.claude/skills/mcp-sentinel/hooks/sentinel_preflight.py"}]
    }]
  }
"""

import json
import os
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path


# Claude Code changed the root-level "decision" enum from "allow"→"approve"
# somewhere in the 2.1.x series. 2.1.119 confirmed requires "approve".
# Older versions (1.x / early 2.x) required "allow".
_APPROVE_MIN_VERSION = (2, 1, 0)


@lru_cache(maxsize=1)
def _claude_version():
    """Return Claude Code version as (major, minor, patch) or None. Cached."""
    version_str = os.environ.get("CLAUDE_CODE_VERSION", "")
    if not version_str:
        try:
            result = subprocess.run(
                ["claude", "--version"],
                capture_output=True, text=True, timeout=2,
            )
            version_str = result.stdout.strip()
        except Exception:
            return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    return tuple(int(x) for x in m.groups()) if m else None


def _allow_value():
    """Return the correct root-level 'allow' decision string for this Claude version."""
    version = _claude_version()
    if version is None or version >= _APPROVE_MIN_VERSION:
        return "approve"
    return "allow"


def load_iocs():
    """Load the bundled IOCs file. Falls back to empty if missing."""
    # The script lives in hooks/ and iocs.json lives in ../references/.
    # Try relative first, then absolute via common install locations.
    candidates = [
        Path(__file__).parent.parent / "references" / "iocs.json",
        Path.home() / ".claude" / "skills" / "mcp-sentinel" / "references" / "iocs.json",
        Path.cwd() / ".claude" / "skills" / "mcp-sentinel" / "references" / "iocs.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                continue
    return {}


def load_user_allowlist():
    """Load user-specific allowlist if it exists. Takes precedence over IOC allowlist."""
    for candidate in (
        Path.cwd() / ".security" / "sentinel-allowlist.json",
        Path.home() / ".claude" / "sentinel-allowlist.json",
    ):
        if candidate.exists():
            try:
                return json.loads(candidate.read_text())
            except Exception:
                continue
    return {"paths": [], "domains": [], "commands": []}


def expand_path(p):
    """Expand ~ and env vars in a path string."""
    return os.path.expandvars(os.path.expanduser(p))


def path_matches(actual, pattern):
    """Match actual path against a pattern (supports ~ and substring match).

    Note: pattern strings often appear inside shell commands (e.g.
    ``cat ~/.aws/credentials``) where ``~`` is not at the start of the text.
    ``os.path.expanduser`` only expands leading ``~``, so we also test the
    pattern in its *unexpanded* form to catch those cases.
    """
    actual_expanded = expand_path(actual)
    pattern_expanded = expand_path(pattern)
    pattern_norm = pattern_expanded.rstrip("/")
    pattern_raw = pattern.rstrip("/")

    candidates = [actual, actual_expanded]
    for text in candidates:
        if not text:
            continue
        if text == pattern_expanded or text == pattern:
            return True
        if text.startswith(pattern_norm + "/") or text.startswith(pattern_raw + "/"):
            return True
        if pattern_norm and pattern_norm in text:
            return True
        if pattern_raw and pattern_raw in text:
            return True
    return False


def is_allowlisted_path(path, allowlist_paths):
    return any(path_matches(path, p) for p in allowlist_paths)


def is_allowlisted_domain(url_or_domain, allowlist_domains):
    url_lc = url_or_domain.lower()
    return any(d.lower() in url_lc for d in allowlist_domains)


def check_sensitive_paths(tool_input, iocs, allowlist):
    """Return (hit_pattern, severity) or (None, None)."""
    patterns = iocs.get("sensitive_paths", {}).get("patterns", [])
    regexes = iocs.get("sensitive_paths", {}).get("regex_patterns", [])
    allowed = allowlist.get("paths", []) + iocs.get("allowlist", {}).get("paths", [])

    # Collect all string values from the tool input — path might live in file_path,
    # command, pattern, etc. depending on which tool is being called.
    haystack = _collect_strings(tool_input)

    for text in haystack:
        if is_allowlisted_path(text, allowed):
            continue
        for p in patterns:
            if path_matches(text, p):
                return (f"sensitive path: {p}", "critical")
        for rx in regexes:
            if re.search(rx, text):
                return (f"sensitive path pattern: /{rx}/", "critical")
    return (None, None)


def check_sensitive_env(tool_input, iocs):
    """Detect reads of known-sensitive environment variables."""
    patterns = iocs.get("sensitive_env_vars", {}).get("patterns", [])
    regexes = iocs.get("sensitive_env_vars", {}).get("regex_patterns", [])

    haystack = _collect_strings(tool_input)
    for text in haystack:
        # Look for constructs like $VAR, ${VAR}, env[VAR], os.environ[VAR], etc.
        for var in patterns:
            # Word boundaries so AWS_SECRET_ACCESS_KEY doesn't match X_AWS_SECRET_ACCESS_KEY_FOO
            if re.search(rf"\b{re.escape(var)}\b", text):
                return (f"sensitive env var: {var}", "high")
        for rx in regexes:
            if re.search(rx, text):
                return (f"env var pattern: /{rx}/", "high")
    return (None, None)


def check_suspicious_network(tool_input, iocs, allowlist):
    """Detect known-malicious or suspicious network destinations."""
    net = iocs.get("suspicious_network", {})
    known_malicious = net.get("known_malicious_domains", [])
    suspicious_tlds = net.get("suspicious_tlds", [])
    pastebin = net.get("pastebin_style", [])
    suspicious_patterns = net.get("suspicious_patterns", [])

    allowed_domains = allowlist.get("domains", []) + iocs.get("allowlist", {}).get("domains", [])

    haystack = _collect_strings(tool_input)

    for text in haystack:
        # Known malicious — critical, no allowlist override
        for entry in known_malicious:
            if entry.get("domain", "").lower() in text.lower():
                return (f"known-malicious domain: {entry['domain']} ({entry.get('incident', 'confirmed incident')})", "critical")

        # Allowlisted? Skip remaining checks.
        if is_allowlisted_domain(text, allowed_domains):
            continue

        # Pastebin-style services — high severity (exfil vector)
        for ps in pastebin:
            if ps.lower() in text.lower():
                return (f"pastebin-style service: {ps}", "high")

        # Raw IPs in URLs — high severity
        for rx in suspicious_patterns:
            if re.search(rx, text):
                # First entry in iocs.json is the raw-IP detector; label it
                # with a human-readable reason so the UI and the tests can
                # distinguish it from other suspicious patterns.
                if "\\d+\\.\\d+\\.\\d+\\.\\d+" in rx:
                    return ("raw IP address in URL (no domain)", "high")
                return (f"suspicious network pattern: /{rx}/", "high")

        # Suspicious TLDs — medium (too noisy for critical)
        for tld in suspicious_tlds:
            if re.search(rf"https?://[^\s/]+{re.escape(tld)}(/|\s|$|\"|')", text):
                return (f"suspicious TLD: {tld}", "medium")

    return (None, None)


def check_dangerous_commands(tool_input, iocs, allowlist):
    """Detect dangerous shell command patterns."""
    patterns = iocs.get("dangerous_commands", {}).get("patterns", [])
    allowed_commands = allowlist.get("commands", [])

    haystack = _collect_strings(tool_input)

    for text in haystack:
        if any(a in text for a in allowed_commands):
            continue
        for rx in patterns:
            if re.search(rx, text):
                return (f"dangerous command pattern: /{rx}/", "critical")
    return (None, None)


def _collect_strings(obj):
    """Walk a dict/list recursively and return all leaf strings."""
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_collect_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_collect_strings(v))
    return out


def decide(payload):
    """Given a PreToolUse payload, return (decision, reason).

    Decision is one of: "allow", "deny", "warn".
    """
    iocs = load_iocs()
    allowlist = load_user_allowlist()

    tool_name = payload.get("tool_name") or payload.get("tool", "")
    tool_input = payload.get("tool_input") or payload.get("input") or {}

    # Severity -> decision mapping:
    #   critical -> deny
    #   high     -> deny (err on the side of caution)
    #   medium   -> warn
    checks = [
        check_sensitive_paths,
        check_suspicious_network,
        check_dangerous_commands,
        check_sensitive_env,
    ]

    highest = None
    highest_reason = None
    severity_rank = {"medium": 1, "high": 2, "critical": 3}

    for fn in checks:
        reason, severity = fn(tool_input, iocs, allowlist) if fn is not check_sensitive_env else fn(tool_input, iocs)
        if severity:
            if not highest or severity_rank[severity] > severity_rank[highest]:
                highest = severity
                highest_reason = reason

    if not highest:
        return "allow", None

    if highest in ("critical", "high"):
        return "deny", f"[{highest.upper()}] {highest_reason}"
    return "warn", f"[{highest.upper()}] {highest_reason}"


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # If stdin is not JSON, err on the side of allowing — we don't want to
        # break Claude Code because of our hook.
        print(json.dumps({"decision": _allow_value()}))
        return

    decision, reason = decide(payload)

    if decision == "allow":
        print(json.dumps({"decision": _allow_value()}))
        return

    tool_name = payload.get("tool_name") or payload.get("tool", "<unknown>")
    if decision == "deny":
        message = (
            f"🛡️ MCP Sentinel blocked a {tool_name} call.\n"
            f"Reason: {reason}\n"
            f"If this is a false positive, add an exception to "
            f".security/sentinel-allowlist.json and retry."
        )
        print(json.dumps({
            "decision": "block",
            "reason": message,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            },
        }))
    else:  # warn
        message = (
            f"⚠️ MCP Sentinel: suspicious {tool_name} call allowed with warning.\n"
            f"Reason: {reason}"
        )
        print(json.dumps({
            "decision": _allow_value(),
            "reason": message,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": message,
            },
        }))


if __name__ == "__main__":
    main()
