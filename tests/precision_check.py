#!/usr/bin/env python3
"""
Precision / recall harness for MCP Sentinel.

Runs decide() over two corpora and reports:
  - FALSE POSITIVES: benign tool calls that did NOT resolve to "allow".
  - RECALL: attack tool calls that fired (deny/ask) vs. misses (allow/warn).

Corpora live in tests/fixtures/:
  - benign_corpus.json   : plain JSON list of {tool_name, tool_input, label}
  - attack_corpus.b64.json: list of {label, b64} where b64 decodes to the
    {tool_name, tool_input} payload. Stored base64 so antivirus (and the repo on
    a cloner's machine) never quarantines a file full of live attack strings.

Run:  python3 tests/precision_check.py
Uses a realistic allowlist (the user's own server IP) and an empty feed so the
result reflects pattern precision, not feed/allowlist coincidences.
"""

import base64
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))
import sentinel_preflight as s  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def load_benign():
    return json.loads((FIX / "benign_corpus.json").read_text())


def load_attacks():
    out = []
    for it in json.loads((FIX / "attack_corpus.b64.json").read_text()):
        payload = json.loads(base64.b64decode(it["b64"]).decode())
        payload["label"] = it.get("label", "")
        out.append(payload)
    return out


def main():
    # Realistic but minimal allowlist: the user's own known server. Empty feed.
    tmp = tempfile.mkdtemp(prefix="sentinel-prec-")
    al = Path(tmp) / "al.json"
    al.write_text(json.dumps({"paths": [], "domains": ["91.99.146.181"], "commands": ["91.99.146.181"]}))
    feed = Path(tmp) / "feed.txt"
    feed.write_text("# empty\n")
    os.environ["SENTINEL_ALLOWLIST_PATH"] = str(al)
    os.environ["SENTINEL_FEED_PATH"] = str(feed)

    benign = load_benign()
    attacks = load_attacks()

    fp = []
    for b in benign:
        decision, reason, cat, ent = s.decide(b)
        if decision != "allow":
            fp.append((b.get("label", ""), b.get("tool_name"), decision, reason))

    misses = []
    caught = 0
    for a in attacks:
        decision, reason, cat, ent = s.decide(a)
        if decision in ("deny", "ask"):
            caught += 1
        else:
            misses.append((a.get("label", ""), a.get("tool_name"), decision, reason))

    nb, na = len(benign), len(attacks)
    print(f"BENIGN: {nb} total | false positives (not allow): {len(fp)}  -> FP rate {100*len(fp)/nb:.1f}%")
    for label, tool, dec, reason in fp:
        print(f"   FP  [{dec}] {tool}: {label}  ({reason})")
    print()
    print(f"ATTACKS: {na} total | caught (deny/ask): {caught}  -> recall {100*caught/na:.1f}%")
    for label, tool, dec, reason in misses:
        print(f"   MISS [{dec}] {tool}: {label}  ({reason})")
    print()
    print(f"SUMMARY  FP={len(fp)}/{nb}  recall={caught}/{na}")
    # Exit non-zero if precision/recall below targets (tunable gates).
    sys.exit(0 if (len(fp) <= 2 and caught >= int(0.9 * na)) else 1)


if __name__ == "__main__":
    main()
