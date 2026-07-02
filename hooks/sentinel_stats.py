#!/usr/bin/env python3
"""
MCP Sentinel: shared telemetry (atomic, fail-open).

A single tiny module the hooks and the AI-escalation layer call to record what
Sentinel did: decisions by type, AI-escalation token spend, pending alerts. The
statusbar and the `--show` stats view read it. Aggregated by UTC day and by
session, with totals.

Design:
- Atomic read-modify-write (tempfile + os.replace) so concurrent hooks never
  corrupt the file.
- **Fail-open**: every public function swallows errors, telemetry must never
  break a security decision or the hook.
- `SENTINEL_STATS_PATH` overrides the location (tests).
- Self-pruning: keeps the last 14 daily buckets and 50 session buckets.

File: ~/.claude/sentinel/stats.json
  {"daily": {"YYYY-MM-DD": {...counters}}, "sessions": {sid: {...}},
   "totals": {...}, "updated": <epoch>}
"""

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

_MAX_DAILY = 14
_MAX_SESSIONS = 50


def stats_path():
    override = os.environ.get("SENTINEL_STATS_PATH")
    return Path(override) if override else (Path.home() / ".claude" / "sentinel" / "stats.json")


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def read():
    try:
        return json.loads(stats_path().read_text())
    except Exception:
        return {}


def bump(session_id=None, **deltas):
    """Atomically add integer deltas to today's bucket, totals, and the session.
    Never raises."""
    try:
        deltas = {k: int(v) for k, v in deltas.items() if isinstance(v, (int, float))}
        if not deltas and session_id is None:
            return
        p = stats_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            st = json.loads(p.read_text())
        except Exception:
            st = {}
        st.setdefault("daily", {})
        st.setdefault("sessions", {})
        st.setdefault("totals", {})

        day = _today()
        for bucket in (st["daily"].setdefault(day, {}), st["totals"]):
            for k, v in deltas.items():
                bucket[k] = bucket.get(k, 0) + v
        if session_id is not None:
            sb = st["sessions"].setdefault(str(session_id)[:64], {})
            for k, v in deltas.items():
                sb[k] = sb.get(k, 0) + v
            sb["updated"] = int(time.time())

        # Prune to keep the file tiny.
        if len(st["daily"]) > _MAX_DAILY:
            for k in sorted(st["daily"])[:-_MAX_DAILY]:
                del st["daily"][k]
        if len(st["sessions"]) > _MAX_SESSIONS:
            oldest = sorted(st["sessions"].items(),
                            key=lambda kv: kv[1].get("updated", 0))[:-_MAX_SESSIONS]
            for k, _ in oldest:
                del st["sessions"][k]

        st["updated"] = int(time.time())
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
        with os.fdopen(fd, "w") as fh:
            json.dump(st, fh)
        os.replace(tmp, p)
    except Exception:
        pass


def summary():
    """Compact view for the stats command / report: today + totals."""
    st = read()
    return {"today": st.get("daily", {}).get(_today(), {}),
            "totals": st.get("totals", {}),
            "updated": st.get("updated", 0)}


def main():
    s = summary()
    t, tot = s["today"], s["totals"]
    print("🛡️ MCP Sentinel telemetry")
    print(f"  Today : deny={t.get('deny',0)} ask={t.get('ask',0)} warn={t.get('warn',0)} "
          f"would_block={t.get('would_block',0)} "
          f"escalated={t.get('escalated',0)} ai_tokens={t.get('ai_in',0)+t.get('ai_out',0)}")
    print(f"  Totals: deny={tot.get('deny',0)} ask={tot.get('ask',0)} warn={tot.get('warn',0)} "
          f"would_block={tot.get('would_block',0)} "
          f"escalated={tot.get('escalated',0)} ai_tokens={tot.get('ai_in',0)+tot.get('ai_out',0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
