#!/usr/bin/env python3
"""
MCP Sentinel: blocklist feed updater.

Downloads a machine-readable feed of currently-active malware hosts and writes
a deduped, one-domain-per-line file that the PreToolUse hook loads for exact
host matching (references/blocklist-feed.txt).

Default source: abuse.ch URLhaus "hostfile" feed
  https://urlhaus.abuse.ch/downloads/hostfile/
which lists only currently-online malware distribution hosts (small, current,
low false-positive). Format is a hosts file: "127.0.0.1\t<domain>" per line.
No account or Auth-Key is required for this endpoint.

Why exact-host matching (vs the curated substring list in iocs.json): a feed has
hundreds of entries. Substring-matching each against every tool call would be
slow and false-positive-prone ("a.com" matching "data.com"). The hook instead
extracts hostnames from a call and tests exact set membership: O(1), precise.

Usage:
  python3 tools/update_blocklist.py                 # fetch default feed -> default output
  python3 tools/update_blocklist.py --source FILE   # parse a local hostfile (offline/tests)
  python3 tools/update_blocklist.py --output PATH    # write somewhere else

Failure policy: on any network/parse error, the existing feed file is left
untouched (never clobbered with an empty list) and the script exits non-zero.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SOURCE = "https://urlhaus.abuse.ch/downloads/hostfile/"
# Default output is base64-encoded at rest: a file of ~400 live malware domains
# in plaintext gets quarantined by antivirus on the user's machine (and on
# anyone who clones the repo). The hook decodes it in memory. See B64_MARKER.
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "references" / "blocklist-feed.b64"
B64_MARKER = "#MCP-SENTINEL-B64"

# Reject obviously-invalid host tokens. Keep it permissive (feeds are trusted to
# contain domains) but drop comments, IPs, and localhost noise.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_SKIP_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost"}


def fetch(source):
    """Return the raw feed text from a URL or a local file path."""
    if "://" not in source and Path(source).exists():
        return Path(source).read_text(encoding="utf-8", errors="replace")
    req = urllib.request.Request(source, headers={"User-Agent": "mcp-sentinel-blocklist-updater"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_hostfile(text):
    """Extract domains from hosts-file or plain-domain feed text.

    Handles lines like "127.0.0.1 domain", "0.0.0.0 domain", or a bare "domain".
    Skips comments (#), blanks, IPs, and localhost noise.
    """
    domains = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        # hosts-file form: "<ip>\t<domain>"; plain form: "<domain>"
        candidate = parts[-1].strip().lower().rstrip(".")
        if candidate in _SKIP_HOSTS:
            continue
        if _DOMAIN_RE.match(candidate):
            domains.add(candidate)
    return domains


def write_feed(domains, output, encode=True):
    """Atomically write sorted domains to output, with a provenance header.

    When encode=True (default) the payload is base64-wrapped with B64_MARKER so a
    host antivirus never sees ~400 plaintext malware domains and quarantines the
    file. The hook decodes it in memory. Use --plain to write readable text.
    """
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# MCP Sentinel blocklist feed (exact-host match).",
        f"# Generated: {stamp}",
        f"# Count: {len(domains)}",
        "# One domain per line. Regenerate with tools/update_blocklist.py.",
    ]
    lines.extend(sorted(domains))
    plain = "\n".join(lines) + "\n"
    if encode:
        blob = base64.b64encode(plain.encode("utf-8")).decode("ascii")
        # Wrap at 100 cols for readability of the encoded file.
        wrapped = "\n".join(blob[i:i + 100] for i in range(0, len(blob), 100))
        out_text = B64_MARKER + "\n" + wrapped + "\n"
    else:
        out_text = plain
    fd, tmp = tempfile.mkstemp(dir=str(output.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(out_text)
        os.replace(tmp, output)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _existing_count(output):
    """How many domains the current feed file holds (decoding b64 if needed)."""
    p = Path(output)
    if not p.exists():
        return 0
    try:
        text = p.read_text(encoding="utf-8")
        lines = text.splitlines()
        if lines and lines[0].strip() == B64_MARKER:
            text = base64.b64decode("".join(lines[1:])).decode("utf-8", "replace")
        return sum(1 for ln in text.splitlines() if ln.strip() and not ln.startswith("#"))
    except Exception:
        return 0


def passes_sanity(new_count, prev_count):
    """Refuse a drastic shrink (a feed that suddenly loses >50% of its domains
    is likely a truncated download or a poisoned/empty source). Keep the old one."""
    if prev_count > 20 and new_count < prev_count * 0.5:
        return False
    return True


def write_meta(output, domains, source, meta_path=None):
    """Record provenance/version next to the feed (atomic, best-effort)."""
    try:
        version = hashlib.sha256("".join(sorted(domains)).encode()).hexdigest()[:12]
        meta = {"ts": int(time.time()), "count": len(domains), "source": source,
                "version": version, "output": str(output)}
        mp = Path(meta_path) if meta_path else (Path.home() / ".claude" / "sentinel" / "feed-meta.json")
        mp.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(mp.parent), suffix=".tmp")
        with os.fdopen(fd, "w") as fh:
            json.dump(meta, fh, indent=1)
        os.replace(tmp, mp)
        return meta
    except Exception:
        return None


def _meta_path():
    return Path.home() / ".claude" / "sentinel" / "feed-meta.json"


def _prev_version():
    """Version string of the feed we last wrote (to detect a real change)."""
    try:
        return json.loads(_meta_path().read_text()).get("version")
    except Exception:
        return None


def _notify(title, text):
    """Best-effort desktop notification (macOS). Never raises."""
    try:
        import platform
        import subprocess
        if platform.system() == "Darwin":
            safe = text.replace('"', "'")
            subprocess.run(
                ["osascript", "-e", f'display notification "{safe}" with title "{title}"'],
                timeout=5, check=False)
        else:
            print(f"[{title}] {text}")
    except Exception:
        pass


def collect_domains(sources):
    """Fetch + parse every source and union the domains. Tolerant: a source that
    fails or parses empty is skipped, not fatal. Returns (domains, used, failed)."""
    domains, used, failed = set(), [], []
    for src in sources:
        try:
            d = parse_hostfile(fetch(src))
        except Exception as e:
            failed.append(src)
            print(f"⚠️  source failed: {src}: {e}", file=sys.stderr)
            continue
        if d:
            domains |= d
            used.append(src)
        else:
            failed.append(src)
            print(f"⚠️  source parsed to zero domains: {src}", file=sys.stderr)
    return domains, used, failed


def main(argv=None):
    ap = argparse.ArgumentParser(description="Update the MCP Sentinel blocklist feed.")
    ap.add_argument("--source", action="append", default=None,
                    help="Feed URL or local hostfile path (repeatable; union of all). "
                         "Default: URLhaus hostfile. Add MCP-specific feeds here as they mature.")
    ap.add_argument("--output", default=str(DEFAULT_OUTPUT),
                    help="Where to write the deduped domain list.")
    ap.add_argument("--plain", action="store_true",
                    help="Write human-readable text instead of the AV-safe base64 form.")
    ap.add_argument("--notify", action="store_true",
                    help="Show a desktop notification when the feed actually changed (for cron/launchd).")
    args = ap.parse_args(argv)

    prev_ver = _prev_version()
    sources = args.source or [DEFAULT_SOURCE]
    domains, used, failed = collect_domains(sources)

    if not domains:
        print("❌ All sources failed or parsed to zero domains: keeping the existing feed.",
              file=sys.stderr)
        return 1

    prev = _existing_count(args.output)
    if not passes_sanity(len(domains), prev):
        print(f"❌ New feed has {len(domains)} domains vs {prev} existing (drastic "
              "shrink, truncated/poisoned fetch?). Keeping the existing feed.", file=sys.stderr)
        return 1

    write_feed(domains, args.output, encode=not args.plain)
    meta = write_meta(args.output, domains, ", ".join(used))
    ver = meta.get("version") if meta else "?"
    print(f"✅ Wrote {len(domains)} domains to {args.output} (version {ver}) "
          f"from {len(used)}/{len(sources)} source(s)"
          + (f"; {len(failed)} failed" if failed else ""))
    if args.notify and ver != prev_ver:
        _notify("MCP Sentinel", f"Lista de malware actualizada: {len(domains)} dominios.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
