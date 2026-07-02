#!/usr/bin/env python3
"""
sentinel suggest — turn repeated asks into one-click trust (the ask-fatigue fix).

Sentinel records every path/domain it asked about (only auto-trustable categories;
never commands or env). This aggregates them across sessions and offers to add the
recurring ones to your allowlist so it stops asking. Zero-token, read-only unless
you pass --apply. You stay in control: it only ever suggests concrete path/domain
entities you already faced, and applying is an explicit, deliberate command.

Run:  python3 tools/sentinel_suggest.py            # show suggestions
      python3 tools/sentinel_suggest.py --apply    # trust them (writes allowlist)
"""

import argparse
import json
import os
from pathlib import Path


def _state_dir():
    base = os.environ.get("SENTINEL_STATE_DIR")
    return Path(base) if base else (Path.home() / ".claude" / "sentinel-state")


def _allowlist_path():
    ov = os.environ.get("SENTINEL_ALLOWLIST_PATH")
    return Path(ov) if ov else (Path.home() / ".claude" / "sentinel-allowlist.json")


def aggregate():
    """Sum per-entity ask counts across all session state files.
    Returns {(category, entity): count}."""
    agg = {}
    d = _state_dir()
    if not d.exists():
        return agg
    for f in d.glob("*.json"):
        try:
            st = json.loads(f.read_text())
        except Exception:
            continue
        for key, n in (st.get("suggest") or {}).items():
            cat, _, ent = str(key).partition("|")
            if ent:
                agg[(cat, ent)] = agg.get((cat, ent), 0) + int(n)
    return agg


def load_allowlist(p):
    try:
        d = json.loads(Path(p).read_text())
        if isinstance(d, dict):
            d.setdefault("paths", [])
            d.setdefault("domains", [])
            return d
    except Exception:
        pass
    return {"paths": [], "domains": []}


def apply(entries):
    """Add (category, entity) pairs to the allowlist (atomic). Returns (paths, domains) added."""
    p = _allowlist_path()
    al = load_allowlist(p)
    added_paths, added_domains = [], []
    for cat, ent in entries:
        if cat == "sensitive_path" and ent not in al["paths"]:
            al["paths"].append(ent)
            added_paths.append(ent)
        elif cat == "suspicious_network" and ent not in al["domains"]:
            al["domains"].append(ent)
            added_domains.append(ent)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(al, indent=2))
    os.replace(tmp, p)
    return added_paths, added_domains


def main(argv=None):
    ap = argparse.ArgumentParser(description="Suggest allowlist entries from repeated Sentinel asks.")
    ap.add_argument("--apply", action="store_true", help="add the suggestions to your allowlist")
    ap.add_argument("--min", type=int, default=1, help="only suggest entities seen at least N times")
    args = ap.parse_args(argv)

    agg = aggregate()
    ranked = sorted((e for e in agg.items() if e[1] >= args.min), key=lambda kv: -kv[1])
    if not ranked:
        print("🛡️ MCP Sentinel: nothing to suggest yet (no repeated path/domain asks recorded).")
        return 0

    if args.apply:
        ap_, ad_ = apply([k for k, _ in ranked])
        print(f"✅ Trusted {len(ap_)} path(s) and {len(ad_)} domain(s). Sentinel will stop asking about them.")
        for x in ap_ + ad_:
            print(f"   + {x}")
        return 0

    print("🛡️ MCP Sentinel — trust suggestions (from repeated asks):")
    for (cat, ent), n in ranked:
        kind = "path" if cat == "sensitive_path" else "domain"
        print(f"   {n:>3}x  {kind}: {ent}")
    print("\nTrust them (stops the asks) with:  python3 tools/sentinel_suggest.py --apply")
    print("Review first — only trust what you recognize.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
