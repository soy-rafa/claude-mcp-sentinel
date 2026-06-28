#!/usr/bin/env python3
"""
MCP Sentinel — optional AI escalation layer (v3).

The local engine resolves ~99% of calls with zero tokens. For the AMBIGUOUS ones
(a heuristic `ask`), and ONLY when explicitly enabled, this module escalates to
an LLM for a sharper verdict — turning a vague "ask the user" into a confident
allow / ask / deny with a one-line reason.

Economics & safety (the whole point):
- **Off by default.** Nothing happens unless `SENTINEL_AI=on`.
- **Never on the hot path.** The common `allow` path never reaches here; only the
  rare `ask` path can escalate.
- **Tiny prompt** (tool + scoped fields + local reason), `max_tokens` small.
- **Daily token budget** (`SENTINEL_AI_BUDGET`, default 50k). Over budget → skip.
- **Timeout** (default 3s). Timeout / error / no key / over budget → return None
  and the caller keeps the safe local decision (fail-open to local).
- **Transparent**: every escalation's tokens are recorded in sentinel_stats and
  shown in the statusbar.

Model: `SENTINEL_AI_MODEL` (default the selected top model). A cheaper model can
be set there to economise further.

Testable offline: set `SENTINEL_AI_MOCK` to a canned API-response JSON to exercise
the full path without a network call.
"""

import json
import os
import re
import urllib.request

DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_BUDGET = 50000


def enabled():
    return os.environ.get("SENTINEL_AI", "").strip().lower() in ("on", "1", "true", "yes")


def _model():
    return os.environ.get("SENTINEL_AI_MODEL", DEFAULT_MODEL)


def _budget():
    try:
        return int(os.environ.get("SENTINEL_AI_BUDGET", str(DEFAULT_BUDGET)))
    except Exception:
        return DEFAULT_BUDGET


def _today_ai_tokens():
    try:
        import sentinel_stats
        d = sentinel_stats.summary().get("today", {})
        return int(d.get("ai_in", 0)) + int(d.get("ai_out", 0))
    except Exception:
        return 0


def build_prompt(payload, local_reason, category):
    tool = payload.get("tool_name") or payload.get("tool", "")
    ti = payload.get("tool_input") or payload.get("input") or {}
    fields = {}
    if isinstance(ti, dict):
        for k in ("command", "file_path", "url"):
            v = ti.get(k)
            if isinstance(v, str) and v:
                fields[k] = v[:300]
    return ("A local security pre-filter flagged this Claude Code tool call as possibly risky.\n"
            f"Local reason: {local_reason} (category: {category}).\n"
            f"Tool: {tool}. Fields: {json.dumps(fields)[:400]}.\n"
            "Decide if it is genuinely dangerous to the user (credential theft, exfiltration, RCE, "
            "persistence) versus benign developer activity.\n"
            'Respond ONLY with compact JSON: {"verdict":"allow|ask|deny","reason":"<=12 words"}.')


def _call_api(prompt, model, key, timeout):
    mock = os.environ.get("SENTINEL_AI_MOCK")
    if mock:
        return json.loads(mock)
    body = json.dumps({
        "model": model,
        "max_tokens": 60,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body,
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _parse_verdict(text):
    try:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            return None
        o = json.loads(m.group(0))
        v = o.get("verdict")
        if v in ("allow", "ask", "deny"):
            return {"decision": v, "reason": str(o.get("reason", ""))[:120]}
    except Exception:
        pass
    return None


def escalate(payload, local_reason, category, timeout=3.0):
    """Return {decision, reason, model, tokens_in, tokens_out} or None (fall back
    to the local decision). Never raises; records token spend in sentinel_stats."""
    try:
        if not enabled():
            return None
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key and not os.environ.get("SENTINEL_AI_MOCK"):
            return None
        if _today_ai_tokens() >= _budget():
            return None
        resp = _call_api(build_prompt(payload, local_reason, category), _model(), key, timeout)
        content = resp.get("content")
        if isinstance(content, list):
            text = "".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
        elif isinstance(content, str):
            text = content
        else:
            text = ""
        verdict = _parse_verdict(text)
        if verdict is None:
            return None
        usage = resp.get("usage", {}) or {}
        ai_in = int(usage.get("input_tokens", 0))
        ai_out = int(usage.get("output_tokens", 0))
        try:
            import sentinel_stats
            sentinel_stats.bump(session_id=payload.get("session_id"),
                                ai_in=ai_in, ai_out=ai_out, escalated=1)
        except Exception:
            pass
        verdict.update({"model": _model(), "tokens_in": ai_in, "tokens_out": ai_out})
        return verdict
    except Exception:
        return None
