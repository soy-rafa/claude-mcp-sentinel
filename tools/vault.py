#!/usr/bin/env python3
"""
MCP Sentinel — vault: encode/decode threat-data files base64 at rest.

A security tool ships indicators of compromise (malware domains, reverse-shell
regexes, injection phrases) — exactly what antivirus signatures look for. Shipped
as plaintext, they get the package (and the user's machine) falsely flagged. This
tool wraps such a file in base64 with the `#MCP-SENTINEL-B64` marker; the hook
decodes it in memory (load_iocs / load_feed_domains understand the marker).

Used at release to ship `references/iocs.json` as `references/iocs.b64` (the
loader prefers the encoded form). Kept readable in the dev tree.

Usage:
  vault.py encode <file> [out]   # default out: <stem>.b64
  vault.py decode <file> [out]   # default out: <stem>.json
"""

import base64
import sys
from pathlib import Path

B64_MARKER = "#MCP-SENTINEL-B64"


def encode(path, out=None):
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    blob = base64.b64encode(text.encode("utf-8")).decode("ascii")
    wrapped = "\n".join(blob[i:i + 100] for i in range(0, len(blob), 100))
    out = Path(out) if out else p.with_name(p.stem + ".b64")
    out.write_text(B64_MARKER + "\n" + wrapped + "\n", encoding="utf-8")
    return out


def decode(path, out=None):
    p = Path(path)
    lines = p.read_text(encoding="utf-8").splitlines()
    if lines and lines[0].strip() == B64_MARKER:
        text = base64.b64decode("".join(lines[1:])).decode("utf-8")
    else:
        text = "\n".join(lines)
    out = Path(out) if out else p.with_name(p.stem + ".json")
    out.write_text(text, encoding="utf-8")
    return out


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 2 or argv[0] not in ("encode", "decode"):
        print("usage: vault.py encode|decode <file> [out]")
        return 2
    out = argv[2] if len(argv) > 2 else None
    result = (encode if argv[0] == "encode" else decode)(argv[1], out)
    print(f"✅ {argv[0]}d -> {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
