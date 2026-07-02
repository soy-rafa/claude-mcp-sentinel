#!/usr/bin/env python3
"""
MCP Sentinel — status command.

One place to answer "is Sentinel on, what mode, what has it done, and how do I
change it?". Read-only, never on the hot path, fail-open per section (a broken
section prints a dash, never crashes the report).

Run:  python3 tools/sentinel_status.py
"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))
sys.path.insert(0, str(ROOT / "tools"))


def _safe(fn, default="-"):
    try:
        return fn()
    except Exception:
        return default


def _onoff(env, default="off"):
    return "on" if os.environ.get(env, "").strip().lower() in ("1", "on", "true", "yes") else default


def build_report():
    import sentinel_preflight as pf
    lines = ["🛡️  MCP Sentinel — status", ""]

    # --- Hooks registered in settings.json (are we actually wired in?) --------
    def hooks_section():
        import config_scan as cs
        want = {"PreToolUse": "sentinel_preflight.py",
                "PostToolUse": "sentinel_postflight.py",
                "SessionStart": "config_scan.py"}
        seen = {k: False for k in want}
        for _src, event, cmd in cs.collect_hooks():
            for ev, needle in want.items():
                if event == ev and needle in cmd:
                    seen[ev] = True
        return seen
    seen = _safe(hooks_section, {})
    lines.append("Protection hooks (settings.json):")
    if isinstance(seen, dict) and seen:
        for ev in ("PreToolUse", "PostToolUse", "SessionStart"):
            ok = seen.get(ev)
            lines.append(f"  {ev:<12} {'✅ registered' if ok else '❌ NOT registered — run hooks/install_hooks.sh'}")
    else:
        lines.append("  (could not read settings.json)")

    # --- Signature base / feed / baseline -------------------------------------
    present = _safe(lambda: pf._iocs_present(), False)
    lines.append(f"Signature base (IOCs): {'✅ present' if present else '⚠️ MISSING — protection degraded, reinstall the skill'}")
    feed_n = _safe(lambda: len(pf.load_feed_domains()), "-")
    lines.append(f"Blocklist feed: {feed_n} domains")

    def baseline_line():
        import config_scan as cs
        p = cs.BASELINE_PATH
        if not p.exists():
            return "not set — run tools/config_scan.py --baseline"
        ts = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).strftime("%Y-%m-%d")
        return f"set (updated {ts})"
    lines.append(f"Integrity baseline: {_safe(baseline_line)}")

    # --- Mode / AI / language -------------------------------------------------
    lines.append("")
    shadow = _onoff("SENTINEL_SHADOW")
    lines.append(f"Mode: {'SHADOW (audit-only, never blocks)' if shadow == 'on' else 'NORMAL (allow / ask / deny)'}"
                 f"   [SENTINEL_SHADOW={shadow}]"
                 + ("   → set SENTINEL_SHADOW=on for audit-only" if shadow != "on" else ""))

    def ai_line():
        import sentinel_ai as ai
        if not ai.enabled():
            return "OFF   [SENTINEL_AI=off]   → set SENTINEL_AI=on to enable (opt-in, budgeted)"
        b = ai.budget_status()
        return (f"ON   model={ai._model()}   budget {b['used']}/{b['budget']} tokens today "
                f"({b['remaining']} left)")
    lines.append(f"AI escalation: {_safe(ai_line)}")
    enforce = _onoff("SENTINEL_INTEGRITY_ENFORCE")
    lines.append(f"Integrity enforcement: {'ON (self-tamper = hard block)' if enforce == 'on' else 'off (self-tamper = ask)'}"
                 f"   [SENTINEL_INTEGRITY_ENFORCE={enforce}]")
    lang = os.environ.get("SENTINEL_LANG", "").strip() or "auto"
    lines.append(f"Language: {lang}   [SENTINEL_LANG]")

    # --- Telemetry ------------------------------------------------------------
    def tele():
        import sentinel_stats as ss
        s = ss.summary()
        t, tot = s.get("today", {}), s.get("totals", {})
        keys = ("deny", "ask", "warn", "would_block", "escalated")
        body = "  ".join(f"{k} {t.get(k,0)}/{tot.get(k,0)}" for k in keys)
        ai_tok = (tot.get("ai_in", 0) + tot.get("ai_out", 0))
        return body + f"  ai_tokens {ai_tok}"
    lines.append("")
    lines.append(f"Telemetry (today/total): {_safe(tele)}")

    # --- Allowlist + knobs ----------------------------------------------------
    def allow_line():
        al = pf.load_user_allowlist()
        return f"{len(al.get('paths', []))} paths, {len(al.get('domains', []))} domains trusted"
    lines.append(f"Allowlist: {_safe(allow_line)}")
    lines.append("")
    lines.append("Config knobs (environment variables):")
    for env, desc in (
        ("SENTINEL_SHADOW", "on = evaluate but never block (audit-only)"),
        ("SENTINEL_AI", "on = optional AI escalation for ambiguous cases"),
        ("SENTINEL_AI_MODEL", "model for the AI layer"),
        ("SENTINEL_AI_BUDGET", "daily token budget for the AI layer"),
        ("SENTINEL_INTEGRITY_ENFORCE", "on = hard-block commands that tamper with Sentinel's own config"),
        ("SENTINEL_EXPLAIN", "static (default, zero-token why) | off (leanest) | ai (reuse AI reason)"),
        ("SENTINEL_LANG", "es | en (default: auto-detect)"),
        ("SENTINEL_ALLOWLIST_PATH", "override the allowlist location"),
    ):
        val = os.environ.get(env) or "(default/unset)"
        lines.append(f"  {env}={val}   — {desc}")
    return "\n".join(lines)


def main():
    print(build_report())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
