#!/usr/bin/env python3
"""
MCP Sentinel — red-team harness.

Runs a battery of INERT malicious-skill scenarios (what a malicious skill WOULD
do, as data — nothing executes) through every Sentinel layer and reports which
are caught and which slip through. A MISS on an attack scenario, or a false
positive on a benign one, is a bug to fix.

Scenarios: tests/fixtures/redteam_scenarios.json — a list of objects with any of:
  - tool_calls: [{tool_name, tool_input}]   -> PreToolUse decide() + attack-chain
  - mcp_spec:   {name, command, args, url, env, description} -> config_scan
  - skill_doc:  "<SKILL.md/CLAUDE.md text>" -> injection scan
  - dataflow:   {source, output, dest, dest_text} -> cross-server flow
  - expected_layers: [...]  (empty == benign, must NOT be flagged)

Run:  python3 tests/redteam_check.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))
sys.path.insert(0, str(ROOT / "tools"))
import sentinel_preflight as pf      # noqa: E402
import config_scan as cs            # noqa: E402
import sentinel_dataflow as df      # noqa: E402

SCEN = ROOT / "tests" / "fixtures" / "redteam_scenarios.json"


def _hermetic_env():
    d = tempfile.mkdtemp(prefix="redteam-")
    al = Path(d) / "al.json"
    al.write_text(json.dumps({"paths": [], "domains": [], "commands": []}))
    fe = Path(d) / "feed.txt"
    fe.write_text("# empty\n")
    os.environ["SENTINEL_ALLOWLIST_PATH"] = str(al)
    os.environ["SENTINEL_FEED_PATH"] = str(fe)


def caught_layers(s):
    """Which Sentinel layers flag this scenario."""
    hit = []
    cats = []
    for tc in s.get("tool_calls") or []:
        payload = {"tool_name": tc.get("tool_name", ""), "tool_input": tc.get("tool_input") or {}}
        dec, _r, cat, _e = pf.decide(payload)
        if dec in ("deny", "ask"):
            hit.append("decide")
        if cat:
            cats.append(cat)
    if cats:
        chain = pf.detect_attack_chain([{"category": c} for c in cats])
        if chain:
            hit.append("attack-chain")
    spec = s.get("mcp_spec")
    if isinstance(spec, dict) and spec:
        if cs.scan_server_spec(spec.get("name", "x"), spec):
            hit.append("config-scan")
    doc = s.get("skill_doc")
    if isinstance(doc, str) and doc:
        if cs.scan_injection(doc) or cs.scan_config_text(doc):
            hit.append("config-scan")
    flow = s.get("dataflow")
    if isinstance(flow, dict) and flow:
        prior = {}
        df.record_outputs(prior, flow.get("source", "A"), flow.get("output", ""))
        if df.detect_cross_server_flow(prior, flow.get("dest", "B"), flow.get("dest_text", "")):
            hit.append("dataflow")
    return sorted(set(hit))


def main():
    # Optional fixture path arg lets us run alternative batteries (e.g. real-world
    # cases) without touching the default one.
    scen = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else SCEN
    if not scen.exists():
        print(f"No scenarios at {scen} yet.")
        return 0
    _hermetic_env()
    print(f"battery: {scen.name}")
    # Fixture may be base64-wrapped (AV-safe, it holds attack payloads).
    scenarios = json.loads(pf._maybe_decode(scen.read_text()))
    misses, fps, caught, benign_ok = [], [], 0, 0
    for s in scenarios:
        expected = s.get("expected_layers") or []
        layers = caught_layers(s)
        is_benign = (len(expected) == 0)
        if is_benign:
            if layers:
                fps.append((s.get("id"), s.get("name"), layers))
            else:
                benign_ok += 1
        else:
            if layers:
                caught += 1
            else:
                misses.append((s.get("id"), s.get("name"), s.get("vectors"), s.get("why_dangerous", "")[:80]))

    attacks = sum(1 for s in scenarios if (s.get("expected_layers") or []))
    benign = len(scenarios) - attacks
    print(f"ATTACKS: {attacks} | caught: {caught} | MISSED: {len(misses)}")
    for mid, name, vec, why in misses:
        print(f"   MISS  {mid}: {name}  vectors={vec}  ({why})")
    print(f"BENIGN: {benign} | allowed: {benign_ok} | FALSE POSITIVES: {len(fps)}")
    for fid, name, layers in fps:
        print(f"   FP    {fid}: {name}  flagged-by={layers}")
    print(f"\nSUMMARY  attacks-missed={len(misses)}  benign-FP={len(fps)}")
    sys.exit(0 if (not misses and not fps) else 1)


if __name__ == "__main__":
    main()
