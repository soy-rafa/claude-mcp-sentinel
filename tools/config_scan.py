#!/usr/bin/env python3
"""
MCP Sentinel: config & MCP static scanner + integrity watcher (v3).

The PreToolUse hook only sees individual tool calls; it CANNOT see a malicious
hook planted in a cloned repo's .claude/settings.json (it runs before any tool
call, e.g. at SessionStart, CVE-2025-59536), nor the descriptions/commands of
installed MCP servers. This deterministic scanner closes that gap. It is NOT on
the hot path: run on demand, on a schedule, or from a SessionStart hook.

What it does:
  1. Integrity (CVE-2025-59536): hashes the security-relevant config (hook
     commands, MCP server commands, CLAUDE.md) and compares against a trusted
     baseline, flagging drift (new/changed hooks, new MCP servers).
  2. Static scan: runs every hook command and MCP server command through the
     SAME detection logic as the runtime hook (sentinel_preflight.decide), so a
     hook or MCP server that does `curl ... | bash`, reaches a known-malicious
     domain, or hits cloud metadata is flagged. Scans SKILL.md / CLAUDE.md /
     tool descriptions for prompt-injection phrases.

Modes:
  config_scan.py            full scan + drift report (human readable)
  config_scan.py --json     machine-readable findings
  config_scan.py --baseline (re)establish the trusted baseline after you review
  config_scan.py --session  brief, non-blocking output for a SessionStart hook

Fail-open: any error prints a warning and exits 0, the scanner never blocks
Claude Code. Whether the integrity watcher should DENY a session (blocking) is a
deliberate maintainer decision; this ships in WARN mode.

The baseline is stored base64 at rest (B64_MARKER) like the blocklist feed, so a
host antivirus never sees a file full of hook commands and flags it.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))
try:
    import sentinel_preflight as pf
except Exception:
    pf = None

HOME = Path.home()
BASELINE_PATH = HOME / ".claude" / "sentinel-baseline.b64"
B64_MARKER = "#MCP-SENTINEL-B64"

# Env vars that redirect traffic or inject code at process start, a malicious
# MCP server setting these in its spec is hijacking the agent's network/runtime.
_RISKY_ENV = {
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NODE_OPTIONS", "NODE_EXTRA_CA_CERTS",
    "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP", "BROWSER",
}


def _read_json(path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _sha(s):
    # Full SHA-256. Earlier builds truncated to [:16] (64 bits); a tampered hook
    # could in principle be crafted to collide. Full digest, no shortcut.
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def _baseline_is_stale(baseline):
    """Old baselines used 16-char truncated hashes. Detect them so we re-baseline
    rather than silently mis-comparing 16-char vs 64-char hashes (false drift)."""
    if not isinstance(baseline, dict):
        return False
    for section in ("hooks", "mcp", "docs"):
        for v in (baseline.get(section) or {}).values():
            if isinstance(v, str) and len(v) and len(v) != 64:
                return True
    return False


def settings_files():
    return [
        HOME / ".claude" / "settings.json",
        HOME / ".claude" / "settings.local.json",
        Path.cwd() / ".claude" / "settings.json",
        Path.cwd() / ".claude" / "settings.local.json",
    ]


def mcp_files():
    return [
        HOME / ".claude.json",
        HOME / ".claude" / ".mcp.json",
        Path.cwd() / ".mcp.json",
        Path.cwd() / ".claude" / ".mcp.json",
    ]


def doc_files():
    out = [HOME / ".claude" / "CLAUDE.md", Path.cwd() / "CLAUDE.md"]
    for base in (HOME / ".claude" / "skills", Path.cwd() / ".claude" / "skills"):
        if base.is_dir():
            for sk in base.glob("*/SKILL.md"):
                out.append(sk)
    return out


def collect_hooks():
    """All hook commands across every settings file, as (source, event, command)."""
    out = []
    for f in settings_files():
        data = _read_json(f) if f.exists() else None
        if not isinstance(data, dict):
            continue
        hooks = data.get("hooks", {})
        if not isinstance(hooks, dict):
            continue
        for event, entries in hooks.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                for h in (entry or {}).get("hooks", []) or []:
                    cmd = h.get("command")
                    if isinstance(cmd, str) and cmd:
                        out.append((str(f), event, cmd))
    return out


def collect_mcp():
    """All MCP servers, as (source, name, command_string)."""
    out = []
    for f in mcp_files():
        data = _read_json(f) if f.exists() else None
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers") or data.get("mcp_servers") or {}
        if not isinstance(servers, dict):
            continue
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            parts = []
            if spec.get("command"):
                parts.append(str(spec["command"]))
            args = spec.get("args")
            if isinstance(args, list):
                parts.extend(str(a) for a in args)
            if spec.get("url"):
                parts.append(str(spec["url"]))
            out.append((str(f), name, " ".join(parts)))
    return out


def collect_mcp_specs():
    """All MCP servers as (source, name, spec_dict)."""
    out = []
    for f in mcp_files():
        data = _read_json(f) if f.exists() else None
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers") or data.get("mcp_servers") or {}
        if isinstance(servers, dict):
            for name, spec in servers.items():
                if isinstance(spec, dict):
                    out.append((str(f), name, spec))
    return out


def _collect_strings(obj):
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


def scan_server_spec(name, spec):
    """Scan one MCP server spec for (a) dangerous commands and (b) prompt-injection
    or obfuscation hidden in ANY string field: command, args, env values, url, or
    a tool/description/instructions field. This is the anti-line-jumping check the
    PreToolUse hook structurally cannot do (it never sees tools/list)."""
    findings = []
    cmd_parts = []
    if isinstance(spec, dict):
        if spec.get("command"):
            cmd_parts.append(str(spec["command"]))
        if isinstance(spec.get("args"), list):
            cmd_parts.extend(str(a) for a in spec["args"])
        if spec.get("url"):
            cmd_parts.append(str(spec["url"]))
    hit = scan_command(" ".join(cmd_parts)) if cmd_parts else None
    if hit:
        findings.append(f"MCP '{name}': dangerous command {hit}")
    for s in _collect_strings(spec):
        for rx in scan_injection(s):
            findings.append(f"MCP '{name}': hidden-instruction/obfuscation in config /{rx}/")
        # Command substitution or secret-env dereference embedded in a config arg
        # the MCP server captures secrets/output and becomes the exfil channel.
        if re.search(r"\$\([^)]+\)", s) or re.search(r"`[^`]+`", s):
            findings.append(f"MCP '{name}': command substitution in config arg ({s[:60]})")
        if pf is not None and getattr(pf, "_SECRET_DEREF_RE", None) and pf._SECRET_DEREF_RE.search(s):
            findings.append(f"MCP '{name}': secret env var dereferenced in config arg (forwarded to server?)")
    # Endpoint redirection: run the server url through the network detection.
    url = spec.get("url") if isinstance(spec, dict) else None
    if isinstance(url, str) and url and pf is not None:
        try:
            decision, reason, _c, _e = pf.decide({"tool_name": "WebFetch", "tool_input": {"url": url}})
            if decision in ("deny", "ask"):
                findings.append(f"MCP '{name}': suspicious endpoint -> {reason}")
        except Exception:
            pass
        if re.search(r"(?i)https?://(127\.0\.0\.1|0\.0\.0\.0|localhost|10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)", url):
            findings.append(f"MCP '{name}': endpoint on localhost/private network: verify it is not a proxy/MITM redirect ({url})")
    # Proxy / loader env overrides = traffic redirection or code injection.
    env = spec.get("env") if isinstance(spec, dict) else None
    if isinstance(env, dict):
        for k in env:
            if str(k).upper() in _RISKY_ENV:
                findings.append(f"MCP '{name}': risky env override '{k}' (traffic/loader hijack)")
    return findings


def scan_config_text(text):
    """Scan raw config text (settings.json / .mcp.json / CLAUDE.md / SKILL.md) for
    dangerous settings the structured scanners miss: cloud-metadata / raw-public-IP
    endpoints, LLM *_BASE_URL overrides (credential interception), the MCP trust
    bypass `enableAllProjectMcpServers`, and dangerous commands embedded in hooks."""
    findings = []
    if pf is None or not isinstance(text, str) or not text:
        return findings
    low = text.lower()
    for h in pf.load_iocs().get("cloud_metadata", {}).get("hosts", []):
        if h.lower() in low:
            findings.append(f"cloud metadata endpoint in config: {h}")
    for m in re.finditer(r"https?://\[?(\d{1,3}(?:\.\d{1,3}){3})", text):
        ip = m.group(1)
        if not pf._is_private_ip(ip):
            findings.append(f"raw public IP endpoint in config: {ip}")
    if re.search(r"(?i)enableallprojectmcpservers\s*[\"']?\s*[:=]\s*true", text):
        findings.append("enableAllProjectMcpServers:true (auto-approves unreviewed MCP servers)")
    if re.search(r"(?i)[a-z_]*_base_url\s*[\"']?\s*[:=]", text) and re.search(r"https?://", text):
        if not re.search(r"(?i)_base_url[\"']?\s*[:=]\s*[\"']?https?://(api\.anthropic\.com|api\.openai\.com)", text):
            findings.append("LLM *_BASE_URL overridden to a non-official endpoint (credential interception)")
    hit = scan_command(text)
    if hit:
        findings.append(f"dangerous command embedded in config: {hit}")
    return findings


def scan_command(cmd):
    """Reuse the runtime detection logic on a hook/MCP command string."""
    if pf is None:
        return None
    decision, reason, category, entity = pf.decide(
        {"tool_name": "Bash", "tool_input": {"command": cmd}})
    if decision in ("deny", "ask"):
        return f"[{decision}] {reason}"
    return None


def scan_injection(text):
    if pf is None:
        return []
    import re
    iocs = pf.load_iocs()
    phrases = iocs.get("prompt_injection_phrases", {}).get("patterns", [])
    hits = []
    for rx in phrases:
        if re.search(rx, text):
            hits.append(rx)
    return hits


def collect_capabilities():
    """Capability-EXPANDING settings that grant the agent new powers. Tracked in the
    integrity baseline so a NEW capability (a broad permission grant, MCP auto-enable,
    an auto-approve mode, a new MCP server) is flagged even when no hook/MCP COMMAND
    changed. This is 'unknown = suspicious' applied to capabilities, the durable
    answer to new models/clients quietly gaining new powers."""
    caps = {}
    for f in settings_files():
        data = _read_json(f) if f.exists() else None
        if not isinstance(data, dict):
            continue
        if str(data.get("enableAllProjectMcpServers")).strip().lower() == "true":
            caps["enableAllProjectMcpServers=true"] = "1"
        perms = data.get("permissions")
        if isinstance(perms, dict):
            mode = perms.get("defaultMode")
            if isinstance(mode, str) and mode.strip().lower() in ("acceptedits", "bypasspermissions"):
                caps[f"permission-defaultMode={mode}"] = "1"
            for entry in perms.get("allow", []) or []:
                if isinstance(entry, str) and entry:
                    caps[f"permission-allow:{entry}"] = "1"
    for _src, name, _cmd in collect_mcp():
        caps[f"mcp-server:{name}"] = "1"
    return caps


def current_state():
    """Security-relevant fingerprint for the integrity baseline."""
    state = {"hooks": {}, "mcp": {}, "docs": {}, "caps": {}}
    state["caps"] = collect_capabilities()
    for src, event, cmd in collect_hooks():
        state["hooks"][f"{event}:{cmd}"] = _sha(cmd)
    for src, name, cmd in collect_mcp():
        state["mcp"][name] = _sha(cmd)
    for f in doc_files():
        if f.exists():
            try:
                state["docs"][str(f)] = _sha(f.read_text())
            except Exception:
                pass
    return state


def load_baseline():
    if not BASELINE_PATH.exists():
        return None
    try:
        txt = BASELINE_PATH.read_text()
        if txt.splitlines() and txt.splitlines()[0].strip() == B64_MARKER:
            txt = base64.b64decode("".join(txt.splitlines()[1:])).decode("utf-8", "replace")
        return json.loads(txt)
    except Exception:
        return None


def save_baseline(state):
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    blob = base64.b64encode(json.dumps(state, indent=1).encode()).decode("ascii")
    wrapped = "\n".join(blob[i:i + 100] for i in range(0, len(blob), 100))
    BASELINE_PATH.write_text(B64_MARKER + "\n" + wrapped + "\n")


def diff_baseline(state, baseline):
    """Return list of drift findings (new/changed hooks, mcp, docs)."""
    drift = []
    if not baseline:
        return drift
    if _baseline_is_stale(baseline):
        return ["BASELINE STALE: hash format upgraded to full SHA-256. "
                "Re-run `config_scan.py --baseline` to re-establish trust."]
    sections = [("hooks", "hook"), ("mcp", "MCP server"), ("docs", "config file")]
    # Only diff capabilities once the baseline actually tracks them, so upgrading
    # to a caps-aware Sentinel doesn't dump a wall of "NEW capability" on an old
    # baseline. Re-running --baseline opts in.
    if "caps" in baseline:
        sections.append(("caps", "capability"))
    for section, label in sections:
        cur, old = state.get(section, {}), baseline.get(section, {})
        for k, v in cur.items():
            if k not in old:
                drift.append(f"NEW {label}: {k}")
            elif old[k] != v:
                drift.append(f"CHANGED {label}: {k}")
        # A REMOVED entry matters as much as a new one: deleting Sentinel's own
        # hook from settings.json is the obvious way to disable protection, and
        # a NEW/CHANGED-only diff would miss it entirely.
        for k in old:
            if k not in cur:
                if "sentinel" in k.lower():
                    drift.append(f"REMOVED {label}: SENTINEL PROTECTION MAY BE DISABLED: {k}")
                else:
                    drift.append(f"REMOVED {label}: {k}")
    return drift


def run_scan():
    findings = {"commands": [], "injection": [], "drift": []}
    for src, event, cmd in collect_hooks():
        hit = scan_command(cmd)
        if hit:
            findings["commands"].append(f"hook {event} ({src}): {hit}  ::  {cmd[:120]}")
    for src, name, spec in collect_mcp_specs():
        for finding in scan_server_spec(name, spec):
            findings["commands"].append(f"{finding} ({src})")
    for f in doc_files():
        # Sentinel's own files contain injection phrases by design (it documents
        # and tests them), never flag the tool against itself.
        if str(f).startswith(str(ROOT)):
            continue
        if f.exists():
            try:
                hits = scan_injection(f.read_text())
            except Exception:
                hits = []
            for rx in hits:
                findings["injection"].append(f"{f}: prompt-injection phrase /{rx}/")
    findings["drift"] = diff_baseline(current_state(), load_baseline())
    return findings


_DOC_EXT = {".md", ".mdx", ".txt", ".rst"}
_SCRIPT_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1"}
_SCAN_MAX_FILE = 512 * 1024


def scan_path(target):
    """Vet a skill/MCP directory (or file) BEFORE trusting/installing it. Static,
    zero-token: reuses the same detectors as the runtime hook. Returns
    {findings: [(kind, path, detail)], score, verdict}. Intentionally cautious,
    a pre-install vet should over-flag rather than miss."""
    target = Path(target).expanduser()
    findings = []
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = [p for p in target.rglob("*") if p.is_file()]
    else:
        return {"findings": [], "score": 0, "verdict": "LOW", "error": f"not found: {target}"}

    for f in files:
        try:
            if f.stat().st_size > _SCAN_MAX_FILE:
                continue
            text = f.read_text(errors="replace")
        except Exception:
            continue
        ext = f.suffix.lower()
        name = f.name.lower()
        rel = str(f)
        if ext in _DOC_EXT or name in ("skill.md", "claude.md", "readme.md"):
            for rx in scan_injection(text):
                findings.append(("injection", rel, f"prompt-injection phrase /{rx}/"))
            for hit in scan_config_text(text):
                findings.append(("config", rel, hit))
        if ext == ".json":
            for hit in scan_config_text(text):
                findings.append(("config", rel, hit))
            try:
                data = json.loads(text)
                servers = (data.get("mcpServers") or data.get("mcp_servers") or {}) if isinstance(data, dict) else {}
                for sname, spec in (servers.items() if isinstance(servers, dict) else []):
                    if isinstance(spec, dict):
                        for hit in scan_server_spec(sname, spec):
                            findings.append(("mcp", rel, f"{sname}: {hit}"))
            except Exception:
                pass
        if ext in _SCRIPT_EXT:
            hit = scan_command(text)
            if hit:
                findings.append(("command", rel, hit))

    weight = {"injection": 3, "command": 3, "mcp": 2, "config": 2}
    score = sum(weight.get(k, 1) for k, _r, _m in findings)
    verdict = "LOW" if score == 0 else "MEDIUM" if score <= 3 else "HIGH" if score <= 8 else "CRITICAL"
    return {"findings": findings, "score": score, "verdict": verdict}


def session_alarm(findings):
    """A prominent alarm if integrity drift indicates Sentinel's OWN protection may
    have been removed or altered (the self-disable case surfaced by diff_baseline).
    Returned separately so it is never buried in a generic finding count."""
    for d in findings.get("drift", []) or []:
        if "SENTINEL PROTECTION" in d:
            return ("🚨 MCP Sentinel: PROTECTION MAY BE DISABLED: " + d
                    + f"\n   Reinstall with: python3 {ROOT / 'hooks' / 'install_hooks.py'}")
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="MCP Sentinel config/MCP scanner + integrity watcher.")
    ap.add_argument("--baseline", action="store_true", help="(re)establish the trusted baseline")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--session", action="store_true", help="brief non-blocking output for SessionStart")
    ap.add_argument("--scan-path", metavar="DIR", help="vet a skill/MCP directory or file before trusting it")
    args = ap.parse_args(argv)

    if args.scan_path:
        r = scan_path(args.scan_path)
        if r.get("error"):
            print(f"⚠️  {r['error']}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(r, indent=2))
            return 0
        print(f"🛡️ MCP Sentinel pre-install scan: {args.scan_path}")
        print(f"   Risk: {r['verdict']} (score {r['score']}, {len(r['findings'])} finding(s))")
        for kind, rel, detail in r["findings"]:
            print(f"   [{kind}] {rel}: {detail}")
        if not r["findings"]:
            print("   No suspicious patterns found. Still review the code yourself before trusting it.")
        return 0 if r["verdict"] in ("LOW", "MEDIUM") else 1

    if pf is None:
        print("⚠️  MCP Sentinel: could not load detection engine; config scan skipped.", file=sys.stderr)
        return 0

    if args.baseline:
        save_baseline(current_state())
        print(f"✅ Trusted baseline written to {BASELINE_PATH}")
        return 0

    try:
        findings = run_scan()
    except Exception as e:
        print(f"⚠️  MCP Sentinel config scan error (ignored): {e}", file=sys.stderr)
        return 0

    total = sum(len(v) for v in findings.values())
    if args.json:
        print(json.dumps(findings, indent=2))
        return 0

    if args.session:
        alarm = session_alarm(findings)
        if alarm:
            print(alarm)
        if total:
            print(f"🛡️ MCP Sentinel: {total} config/MCP finding(s). Run "
                  f"`python3 {Path(__file__)} ` to review (hooks/MCP servers/drift).")
        return 0

    if not total:
        print("✅ MCP Sentinel config scan: no findings. Hooks, MCP servers and docs look clean.")
        if load_baseline() is None:
            print("   (No integrity baseline yet, run with --baseline to establish one.)")
        return 0

    alarm = session_alarm(findings)
    if alarm:
        print(alarm + "\n")
    print(f"🛡️ MCP Sentinel config scan: {total} finding(s)\n")
    if findings["commands"]:
        print("Dangerous hook / MCP commands:")
        for x in findings["commands"]:
            print(f"  - {x}")
    if findings["injection"]:
        print("Prompt-injection phrases in config/skills:")
        for x in findings["injection"]:
            print(f"  - {x}")
    if findings["drift"]:
        print("Integrity drift vs trusted baseline:")
        for x in findings["drift"]:
            print(f"  - {x}")
    print("\nReview these. If legitimate, re-baseline with --baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
