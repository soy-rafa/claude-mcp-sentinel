#!/usr/bin/env python3
"""
MCP Sentinel — PreToolUse hook.

Runs before every tool call made by Claude. Reads the tool call JSON from stdin,
checks it against bundled IOCs (paths, domains, command patterns, env vars) and
the user's allowlist. Returns an allow / deny decision as JSON on stdout.

Zero LLM cost — pure local pattern matching. Adds <50ms latency per tool call
in typical cases. Only the decision message (if deny/warn) is inserted into the
conversation, and only when something is actually blocked.

Protocol: Claude Code passes the tool call payload on stdin (read BOM-tolerant,
see _read_stdin_payload) and reads a JSON object on stdout. Exit 0 always. Output
uses the v2.1+ schema: hookSpecificOutput.permissionDecision (allow/deny/ask),
with permissionDecisionReason or additionalContext. An empty stdout = allow.

Internal decision values from decide():
  "allow"  — clean / trusted. Emits nothing (silent allow).
  "deny"   — confirmed-malicious / feed hit. permissionDecision=deny.
  "ask"    — suspicious heuristic. permissionDecision=ask (user decides).
  "warn"   — low-signal. permissionDecision=allow + additionalContext note.

Usage (registered via install_hooks.sh, or manually):
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{"type": "command",
                 "command": "python3 ~/.claude/skills/mcp-sentinel/hooks/sentinel_preflight.py"}]
    }]
  }
"""

import base64
import json
import os
import re
import sys
import time
from pathlib import Path

# Bundled threat data (the malware-domain feed, and optionally the IOC library)
# is stored base64-encoded at rest so a host antivirus scanning the installed
# skill never sees a file full of live malware indicators and falsely flags the
# user. Encoded files start with this marker line; loaders decode in memory.
B64_MARKER = "#MCP-SENTINEL-B64"


def _maybe_decode(text):
    """If text is a base64-wrapped threat file, return the decoded text.

    Format: first line is B64_MARKER, the rest is base64 of the real content.
    Plain (non-marked) text is returned unchanged, so dev/test files and the
    SENTINEL_FEED_PATH override can stay human-readable.
    """
    lines = text.splitlines()
    if lines and lines[0].strip() == B64_MARKER:
        try:
            return base64.b64decode("".join(lines[1:])).decode("utf-8", "replace")
        except Exception:
            return ""
    return text


def load_iocs():
    """Load the bundled IOC library. Prefers the base64-encoded `iocs.b64` (so a
    host antivirus never sees plaintext malware signatures and flags the install)
    and falls back to readable `iocs.json` for development. Decodes in memory."""
    override = os.environ.get("SENTINEL_IOCS_PATH")
    if override:
        candidates = [Path(override)]
    else:
        candidates = []
        for base in (Path(__file__).parent.parent / "references",
                     Path.home() / ".claude" / "skills" / "mcp-sentinel" / "references",
                     Path.cwd() / ".claude" / "skills" / "mcp-sentinel" / "references"):
            candidates += [base / "iocs.b64", base / "iocs.json"]
    for path in candidates:
        if path.exists():
            try:
                return json.loads(_maybe_decode(path.read_text()))
            except Exception:
                continue
    return {}


def load_feed_domains():
    """Load the auto-updated blocklist feed as a set of exact hostnames.

    Populated by tools/update_blocklist.py from a malware-host feed (URLhaus).
    Matching is exact (set membership), not substring, so a large feed adds no
    false positives and O(1) lookup. Returns an empty set if no feed exists yet.
    """
    override = os.environ.get("SENTINEL_FEED_PATH")
    if override:
        candidates = [Path(override)]
    else:
        ref = Path(__file__).parent.parent / "references"
        home_ref = Path.home() / ".claude" / "skills" / "mcp-sentinel" / "references"
        # Prefer the base64-encoded shipped file; fall back to a plain one.
        candidates = [
            ref / "blocklist-feed.b64", ref / "blocklist-feed.txt",
            home_ref / "blocklist-feed.b64", home_ref / "blocklist-feed.txt",
        ]
    for path in candidates:
        if path.exists():
            try:
                domains = set()
                for line in _maybe_decode(path.read_text()).splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.add(line.lower())
                return domains
            except Exception:
                continue
    return set()


def load_user_allowlist():
    """Merge user-specific allowlists from cwd-local and home-global locations.

    Both candidates are read and combined so that a project-local allowlist does
    not hide a global one (which is what users intuitively expect when they keep
    personal exceptions in ~/.claude and per-project ones in .security/).
    """
    merged = {"paths": [], "domains": [], "commands": []}
    # SENTINEL_ALLOWLIST_PATH overrides the default locations entirely. Used by
    # the test suite to read/write an isolated allowlist, and available to users
    # who keep their allowlist somewhere non-standard.
    override = os.environ.get("SENTINEL_ALLOWLIST_PATH")
    if override:
        candidates = (Path(override),)
    else:
        candidates = (
            Path.cwd() / ".security" / "sentinel-allowlist.json",
            Path.home() / ".claude" / "sentinel-allowlist.json",
        )
    for candidate in candidates:
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                for key in merged:
                    values = data.get(key, [])
                    if isinstance(values, list):
                        merged[key].extend(values)
            except Exception:
                continue
    return merged


def expand_path(p):
    """Expand ~ and env vars in a path string."""
    return os.path.expandvars(os.path.expanduser(p))


def _norm_path(s):
    """Normalise a path for separator- and case-insensitive comparison.

    On native Windows, Claude Code passes tool calls real paths with backslashes,
    a drive letter, and arbitrary case (e.g. ``C:\\Users\\me\\.ssh\\id_rsa``).
    The IOC patterns are Unix-style with ``/``, so a substring/prefix match never
    fires on a Windows path. Folding ``\\`` to ``/`` and lowercasing bridges the
    gap (Windows paths are case-insensitive) so the same patterns also cover
    Windows. On Unix this is a harmless, slightly more permissive comparison.
    """
    return s.replace("\\", "/").lower()


def path_matches(actual, pattern):
    """Match actual path against a pattern (supports ~ and substring match).

    Note: pattern strings often appear inside shell commands (e.g.
    ``cat ~/.aws/credentials``) where ``~`` is not at the start of the text.
    ``os.path.expanduser`` only expands leading ``~``, so we also test the
    pattern in its *unexpanded* form to catch those cases. All comparisons run in
    a normalised space (see ``_norm_path``) so native Windows paths match too.
    """
    actual_expanded = expand_path(actual)
    pattern_expanded = expand_path(pattern)

    pe = _norm_path(pattern_expanded)
    pp = _norm_path(pattern)
    pattern_norm = pe.rstrip("/")
    pattern_raw = pp.rstrip("/")

    candidates = [actual, actual_expanded]
    for text in candidates:
        if not text:
            continue
        t = _norm_path(text)
        if t == pe or t == pp:
            return True
        if t.startswith(pattern_norm + "/") or t.startswith(pattern_raw + "/"):
            return True
        if pattern_norm and pattern_norm in t:
            return True
        if pattern_raw and pattern_raw in t:
            return True
    return False


def is_allowlisted_path(path, allowlist_paths):
    return any(path_matches(path, p) for p in allowlist_paths)


# ---------------------------------------------------------------------------
# Field-scoped extraction. Earlier versions flattened the whole tool_input with
# _collect_strings and matched every string against every check — so a Write of
# documentation that *quoted* `curl | bash`, or a config file that *mentioned*
# GITHUB_TOKEN, was flagged. We now scope each check to the fields where the
# signal is real: commands in `command`, paths in file/path targets, URLs in
# `url` (+ commands). Content being written (Write.content / Edit.new_string) is
# NOT scanned for commands/URLs — writing text that mentions an attack is not
# performing it. Persistence writes are caught by check_config_write on the path.
# ---------------------------------------------------------------------------

def _fields(tool_input, *keys):
    out = []
    if isinstance(tool_input, dict):
        for k in keys:
            v = tool_input.get(k)
            if isinstance(v, str) and v:
                out.append(v)
    return out


def command_strings(tool_input):
    return _fields(tool_input, "command")


def target_paths(tool_input):
    return _fields(tool_input, "file_path", "path", "notebook_path")


def net_strings(tool_input):
    """Strings where a URL/host legitimately appears: an explicit url, or a command."""
    return _fields(tool_input, "url") + command_strings(tool_input)


def _host_matches(host, domain):
    """True if host is `domain` or a subdomain of it (boundary match, not substring)."""
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


def is_allowlisted_domain(text, allowlist_domains):
    """Allowlist by host boundary, not substring.

    Substring matching let `github.com.evil.ru` pass because it *contains*
    `github.com`. We extract hosts and require an exact or subdomain match.
    """
    hosts = extract_hosts(text)
    low = text.lower()
    for d in allowlist_domains:
        dl = d.lower()
        if any(_host_matches(h, dl) for h in hosts):
            return True
        # Bare IP / non-host allowlist entries: direct token containment.
        if re.fullmatch(r"[\d.]+", dl) and dl in low:
            return True
    return False


def _is_allowlisted_host(host, allowlist_domains):
    """Per-host allowlist check. Used so an allowlisted host in a command (e.g.
    `security ... github.com ... | curl webhook.site`) does NOT exempt the whole
    command — only the matching host is cleared, the malicious one still fires."""
    host = host.lower().rstrip(".")
    for d in allowlist_domains:
        dl = d.lower()
        if _host_matches(host, dl):
            return True
        if re.fullmatch(r"[\d.]+", dl) and host == dl:
            return True
    return False


def _is_private_ip(ip):
    """RFC1918 + loopback + link-local. Link-local (169.254) includes the IMDS
    address, which is handled by check_cloud_metadata, so we treat it as private
    here to avoid double-flagging while still catching it dedicated."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a in (0, 127, 10):
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 169 and b == 254:
        return True
    return False


def check_sensitive_paths(tool_name, tool_input, iocs, allowlist):
    """Sensitive credential paths, scanned on file targets and command strings."""
    patterns = iocs.get("sensitive_paths", {}).get("patterns", [])
    regexes = iocs.get("sensitive_paths", {}).get("regex_patterns", [])
    allowed = allowlist.get("paths", []) + iocs.get("allowlist", {}).get("paths", [])

    targets = target_paths(tool_input)
    for t in targets:
        if is_allowlisted_path(t, allowed):
            return (None, None, None, None)

    # (text, is_precise_target). Only a direct target yields an auto-rememberable
    # entity; a path inside a command stays ask-only.
    haystack = [(t, True) for t in targets] + [(c, False) for c in command_strings(tool_input)]
    for text, is_target in haystack:
        if is_allowlisted_path(text, allowed):
            continue
        entity = text if is_target else None
        for p in patterns:
            if path_matches(text, p):
                return (f"sensitive path: {p}", "critical", "sensitive_path", entity)
        for rx in regexes:
            if re.search(rx, text):
                return (f"sensitive path pattern: /{rx}/", "critical", "sensitive_path", entity)
    return (None, None, None, None)


_EGRESS_RE = re.compile(r"(?i)(\b(curl|wget|nc|ncat|telnet|scp|sftp)\b|/dev/tcp)")
_ENV_DUMP_RE = re.compile(r"(?i)(^|[|;&]|\s)(env|printenv)\b")
_SECRET_DEREF_RE = re.compile(
    r"(?i)\$\{?\w*(_API_KEY|_SECRET_ACCESS_KEY|_SERVICE_ROLE_KEY|_SECRET|_TOKEN|_PASSWORD)\w*\}?")


def check_sensitive_env(tool_name, tool_input, iocs, allowlist):
    """Flag a secret env var ONLY when it is exfiltrated: dereferenced (or env is
    dumped) AND piped/sent to a network egress tool. Mentioning a var name (code,
    docs, `rg 'GITHUB_TOKEN'`) is not flagged — that was the biggest false-positive
    source. entity is None (never auto-trusted)."""
    names = iocs.get("sensitive_env_vars", {}).get("patterns", [])
    for cmd in command_strings(tool_input):
        if not _EGRESS_RE.search(cmd):
            continue
        named = any(re.search(rf"\$\{{?{re.escape(v)}\}}?", cmd) for v in names)
        if named or _SECRET_DEREF_RE.search(cmd) or _ENV_DUMP_RE.search(cmd):
            return ("environment secret piped to network (exfiltration)",
                    "critical", "sensitive_env", None)
    return (None, None, None, None)


def check_cloud_metadata(tool_name, tool_input, iocs, allowlist):
    """Cloud instance metadata (IMDS) access — SSRF / cloud-credential theft."""
    hosts = iocs.get("cloud_metadata", {}).get("hosts", [])
    for text in net_strings(tool_input):
        low = text.lower()
        for h in hosts:
            if h.lower() in low:
                return (f"cloud metadata endpoint (IMDS): {h}", "high", "cloud_metadata", None)
    return (None, None, None, None)


def check_config_write(tool_name, tool_input, iocs, allowlist):
    """Writing/editing a persistence or agent-config file (settings.json hooks,
    shell rc, .mcp.json, authorized_keys...). The content is not scanned; the
    target path is the signal."""
    if tool_name not in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return (None, None, None, None)
    pats = iocs.get("config_write_paths", {}).get("patterns", [])
    allowed = allowlist.get("paths", []) + iocs.get("allowlist", {}).get("paths", [])
    for t in target_paths(tool_input):
        if is_allowlisted_path(t, allowed):
            continue
        tn = _norm_path(t)
        for p in pats:
            if p.lower() in tn:
                return (f"writes to a persistence/config file: {p}", "high", "config_write", None)
    return (None, None, None, None)


def check_suspicious_network(tool_name, tool_input, iocs, allowlist):
    """Known-malicious / pastebin / raw-public-IP / high-abuse-TLD destinations,
    matched by host boundary (not substring)."""
    net = iocs.get("suspicious_network", {})
    known = net.get("known_malicious_domains", [])
    tlds = net.get("suspicious_tlds", [])
    pastebin = net.get("pastebin_style", [])
    raw_ip_rx = net.get("raw_ip_url_regex")
    allowed_domains = allowlist.get("domains", []) + iocs.get("allowlist", {}).get("domains", [])

    for text in net_strings(tool_input):
        hosts = extract_hosts(text)

        for h in hosts:
            for entry in known:
                dom = entry.get("domain", "")
                if _host_matches(h, dom):
                    return (f"known-malicious domain: {dom} ({entry.get('incident', 'confirmed incident')})",
                            "critical", "known_malicious", dom)

        # Per-host: an allowlisted host clears only itself, not the whole command.
        for h in hosts:
            if _is_allowlisted_host(h, allowed_domains):
                continue
            for ps in pastebin:
                if _host_matches(h, ps):
                    return (f"pastebin/exfil service: {ps}", "high", "suspicious_network", ps)
            for tld in tlds:
                if h.endswith(tld):
                    return (f"high-abuse TLD: {tld}", "high", "suspicious_network", None)

        if raw_ip_rx:
            m = re.search(raw_ip_rx, text)
            if m:
                ipm = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", m.group(0))
                ip = ipm.group(0) if ipm else None
                if ip and not _is_private_ip(ip) and not _is_allowlisted_host(ip, allowed_domains):
                    return ("raw public IP in URL (no domain)", "high", "suspicious_network", ip)

    return (None, None, None, None)


def check_dangerous_commands(tool_name, tool_input, iocs, allowlist):
    """Dangerous shell patterns (curl|bash, reverse shells, persistence), scanned
    only on command fields — never on file content being written."""
    patterns = iocs.get("dangerous_commands", {}).get("patterns", [])
    allowed_commands = allowlist.get("commands", [])
    for cmd in command_strings(tool_input):
        if any(a in cmd for a in allowed_commands):
            continue
        for rx in patterns:
            if re.search(rx, cmd):
                return (f"dangerous command pattern: /{rx}/", "critical", "dangerous_command", None)
    return (None, None, None, None)


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


_URL_HOST_RE = re.compile(r"https?://(?P<host>[^/\s:\"'<>]+)", re.I)
_BARE_HOST_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)\b", re.I)


def extract_hosts(text):
    """Pull candidate hostnames out of a string (URLs and bare domains).

    Returns lowercased hosts with any userinfo/port stripped. Over-extraction is
    harmless: matching is exact set membership against the feed, so non-domain
    tokens like "package.json" simply never match.
    """
    hosts = set()
    for m in _URL_HOST_RE.finditer(text):
        host = m.group("host").split("@")[-1].split(":")[0].lower().rstrip(".")
        if host:
            hosts.add(host)
    for m in _BARE_HOST_RE.finditer(text):
        hosts.add(m.group(1).lower().rstrip("."))
    return hosts


def check_feed_blocklist(tool_input, feed, allowed_domains):
    """Exact-host match against the auto-updated malware feed.

    ``allowed_domains`` is the merged user + iocs domain allowlist. Returns
    (reason, severity, category, entity). A hit is critical (hard deny), but
    unlike the hand-curated known_malicious list, a feed hit IS allowlist-
    overrideable — automated feeds can carry the occasional false positive.
    """
    if not feed:
        return (None, None, None, None)
    for text in net_strings(tool_input):
        for host in extract_hosts(text):
            if host in feed and not _is_allowlisted_host(host, allowed_domains):
                return (f"malware-feed host: {host} (URLhaus)", "critical", "feed_blocklist", host)
    return (None, None, None, None)


def decide(payload):
    """Given a PreToolUse payload, return (decision, reason, category, entity).

    Decision is one of: "allow", "deny", "ask", "warn".

    Severity / category -> decision mapping:
      category == "known_malicious"  -> deny  (hard, non-overrideable)
      other critical / high          -> ask   (user decides at the native prompt)
      medium                         -> warn  (proceeds, note added to context)

    ``category`` and ``entity`` describe the top finding so the PostToolUse hook
    can auto-remember an approved decision (only path/domain entities qualify).
    """
    iocs = load_iocs()
    allowlist = load_user_allowlist()

    tool_name = payload.get("tool_name") or payload.get("tool", "")
    tool_input = payload.get("tool_input") or payload.get("input") or {}

    checks = [
        check_sensitive_paths,
        check_sensitive_env,
        check_cloud_metadata,
        check_config_write,
        check_suspicious_network,
        check_dangerous_commands,
    ]

    severity_rank = {"medium": 1, "high": 2, "critical": 3}
    findings = []
    for fn in checks:
        reason, severity, category, entity = fn(tool_name, tool_input, iocs, allowlist)
        if severity:
            findings.append({
                "reason": reason,
                "severity": severity,
                "category": category,
                "entity": entity,
            })

    # Auto-updated malware feed (exact host match). Separate from the curated
    # checks because it needs the feed set and the merged domain allowlist.
    feed = load_feed_domains()
    if feed:
        allowed_domains = allowlist.get("domains", []) + iocs.get("allowlist", {}).get("domains", [])
        reason, severity, category, entity = check_feed_blocklist(tool_input, feed, allowed_domains)
        if severity:
            findings.append({
                "reason": reason,
                "severity": severity,
                "category": category,
                "entity": entity,
            })

    if not findings:
        return "allow", None, None, None

    # Confirmed-malicious / feed hits are hard denies, regardless of what else was
    # found. Never downgraded to "ask", never auto-remembered.
    for f in findings:
        if f["category"] in HARD_DENY_CATEGORIES:
            return "deny", f"[{f['severity'].upper()}] {f['reason']}", f["category"], f["entity"]

    top = max(findings, key=lambda f: severity_rank[f["severity"]])
    reason = f"[{top['severity'].upper()}] {top['reason']}"
    if top["severity"] in ("critical", "high"):
        return "ask", reason, top["category"], top["entity"]
    return "warn", reason, top["category"], top["entity"]


# Categories that hard-deny (never downgraded to "ask"). known_malicious is the
# hand-curated incident list (non-overrideable); feed_blocklist is the auto-
# updated malware feed (overrideable via the domain allowlist).
HARD_DENY_CATEGORIES = ("known_malicious", "feed_blocklist")

# Categories whose finding carries a precise, safe-to-trust entity (a concrete
# path or domain). Only these are eligible for "remember on approve" by the
# PostToolUse hook. Command/env findings and confirmed-malicious are excluded.
AUTO_REMEMBER_CATEGORIES = ("sensitive_path", "suspicious_network")


# ---------------------------------------------------------------------------
# Localisation. Messages are shown in Spanish when the user writes in Spanish,
# English otherwise. Detection runs only when a message is actually emitted
# (deny/ask/warn), never on the hot allow path. The technical "reason" token
# (e.g. "[CRITICAL] sensitive path: ...") stays as-is; only the framing is
# localised.
# ---------------------------------------------------------------------------

_SPANISH_CHARS = set("ñ¿¡áéíóúü")
_SPANISH_WORDS = {
    "que", "los", "las", "una", "unos", "unas", "para", "con", "por", "del",
    "como", "cómo", "qué", "está", "están", "más", "pero", "porque", "cuando",
    "muy", "esto", "esta", "este", "quiero", "gracias", "hola", "español",
    "usuario", "mensajes", "también", "puedes", "hacer", "desde", "sobre",
    "ahora", "vale", "según", "idioma", "nueva", "features",
}


def _looks_spanish(text):
    if not text:
        return False
    low = text.lower()
    if any(ch in low for ch in _SPANISH_CHARS):
        return True
    words = re.findall(r"[a-záéíóúñü]+", low)
    return sum(1 for w in words if w in _SPANISH_WORDS) >= 2


def _recent_user_text(transcript_path, max_prompts=5, hard_cap=8_000_000):
    """Return the concatenated text of the last few genuine user prompts.

    Reads up to the last ``hard_cap`` bytes of the transcript JSONL (whole file
    for typical sessions) so recent prompts aren't missed when big tool outputs
    dominate the tail. Only lines carrying a ``promptId`` are JSON-parsed, so the
    cost stays low even on a multi-MB read. Tool-result user messages and system
    interruption markers are skipped — we only want what the human typed.
    """
    if not transcript_path:
        return ""
    try:
        p = Path(transcript_path)
        size = p.stat().st_size
        with p.open("rb") as fh:
            if size > hard_cap:
                fh.seek(size - hard_cap)
                fh.readline()  # discard the partial first line after seeking
            data = fh.read().decode("utf-8", "replace")
    except Exception:
        return ""
    prompts = []
    for line in data.splitlines():
        # Fast pre-filter: genuine user prompts carry a promptId. Skipping the
        # (large) assistant/tool lines without parsing keeps this cheap.
        if '"promptId"' not in line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("type") != "user" or not obj.get("promptId"):
            continue
        content = obj.get("message", {}).get("content")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = " ".join(b.get("text", "") for b in content
                            if isinstance(b, dict) and b.get("type") == "text")
        else:
            text = ""
        text = text.strip()
        if text and not text.startswith("[Request interrupted"):
            prompts.append(text)
    return " ".join(prompts[-max_prompts:])


def detect_language(payload):
    """Pick 'es' or 'en'. SENTINEL_LANG overrides; else sniff the transcript."""
    override = os.environ.get("SENTINEL_LANG", "").strip().lower()
    if override in ("es", "en"):
        return override
    text = _recent_user_text(payload.get("transcript_path", ""))
    return "es" if _looks_spanish(text) else "en"


_MSG = {
    "deny_known": {
        "en": ("🛡️ MCP Sentinel blocked a {tool} call.\nReason: {reason}\n"
               "This is a confirmed-malicious indicator and cannot be allowlisted."),
        "es": ("🛡️ MCP Sentinel ha bloqueado una llamada de {tool}.\nMotivo: {reason}\n"
               "Es un indicador confirmado como malicioso y no se puede añadir a la lista de permitidos."),
    },
    "deny_feed": {
        "en": ("🛡️ MCP Sentinel blocked a {tool} call.\nReason: {reason}\n"
               "This host is on the URLhaus malware feed. If you are certain it is a false "
               "positive, add the domain to your allowlist and retry."),
        "es": ("🛡️ MCP Sentinel ha bloqueado una llamada de {tool}.\nMotivo: {reason}\n"
               "Este host está en el feed de malware de URLhaus. Si estás seguro de que es un "
               "falso positivo, añade el dominio a tu lista de permitidos y reinténtalo."),
    },
    "ask_remember": {
        "en": ("🛡️ MCP Sentinel flagged a {tool} call for your decision.\nReason: {reason}\n"
               "If you approve, MCP Sentinel will trust '{entity}' and stop asking about it. "
               "Deny to block this call."),
        "es": ("🛡️ MCP Sentinel ha marcado una llamada de {tool} para tu decisión.\nMotivo: {reason}\n"
               "Si la apruebas, MCP Sentinel confiará en '{entity}' y dejará de preguntar. "
               "Deniégala para bloquear esta llamada."),
    },
    "ask_generic": {
        "en": ("🛡️ MCP Sentinel flagged a {tool} call for your decision.\nReason: {reason}\n"
               "Approving allows this call; MCP Sentinel will ask again next time. Deny to block it."),
        "es": ("🛡️ MCP Sentinel ha marcado una llamada de {tool} para tu decisión.\nMotivo: {reason}\n"
               "Aprobarla permite esta llamada; MCP Sentinel volverá a preguntar la próxima vez. "
               "Deniégala para bloquearla."),
    },
    "warn": {
        "en": ("⚠️ MCP Sentinel: suspicious {tool} call allowed with warning.\nReason: {reason}"),
        "es": ("⚠️ MCP Sentinel: llamada de {tool} sospechosa permitida con aviso.\nMotivo: {reason}"),
    },
    "remembered": {
        "en": ("🛡️ MCP Sentinel: you approved a flagged {tool} call, so '{entity}' is now trusted "
               "and won't be flagged again. Remove it from {target} to undo."),
        "es": ("🛡️ MCP Sentinel: aprobaste una llamada marcada de {tool}, así que '{entity}' ahora es "
               "de confianza y no se volverá a marcar. Quítalo de {target} para deshacer."),
    },
}


def render(key, lang, **kw):
    """Format a localised message, falling back to English for unknown langs."""
    variants = _MSG[key]
    return variants.get(lang, variants["en"]).format(**kw)


def _state_path(session_id):
    """Per-session state file. SENTINEL_STATE_DIR overrides the location (tests)."""
    sid = re.sub(r"[^A-Za-z0-9_-]", "", str(session_id or "default"))[:64] or "default"
    base = os.environ.get("SENTINEL_STATE_DIR")
    base = Path(base) if base else (Path.home() / ".claude" / "sentinel-state")
    return base / f"{sid}.json"


def record_event(payload, decision, category, ai_tokens=0):
    """Tally a flagged decision into the per-session state file that the statusbar
    and stats command read. Only deny/ask/warn are recorded (allow is the silent
    hot path, never touched). Fully fail-safe: any error is swallowed so the hook
    is never broken by bookkeeping."""
    try:
        if decision == "allow":
            return
        sid = payload.get("session_id") or payload.get("sessionId") or "default"
        p = _state_path(sid)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            st = json.loads(p.read_text())
        except Exception:
            st = {}
        for k in ("deny", "ask", "warn", "escalated", "ai_tokens"):
            st.setdefault(k, 0)
        if decision in ("deny", "ask", "warn"):
            st[decision] += 1
        if ai_tokens:
            st["escalated"] += 1
            st["ai_tokens"] += int(ai_tokens)
        st["last"] = {"decision": decision, "category": category, "ts": int(time.time())}
        st["updated"] = st["last"]["ts"]
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(st))
        os.replace(tmp, p)
        # Feed the shared daily/totals telemetry too (best-effort, fail-open).
        try:
            import sentinel_stats
            d = {decision: 1} if decision in ("deny", "ask", "warn") else {}
            if ai_tokens:
                d["escalated"] = 1
                d["ai_out"] = int(ai_tokens)
            if d:
                sentinel_stats.bump(session_id=sid, **d)
        except Exception:
            pass
    except Exception:
        pass


def _read_stdin_payload():
    """Read and parse the tool-call payload from stdin, tolerant of a BOM.

    On native Windows the stdin handed to the hook can carry a UTF-8 BOM
    (EF BB BF). Plain text decoding leaves a leading U+FEFF that breaks
    json.loads, which would make the hook fail-open (allow) on EVERY call — the
    worst failure mode for a security tool. Reading raw bytes and decoding with
    utf-8-sig strips the BOM. Returns the parsed dict, or None if stdin is
    genuinely not JSON (caller fails open in that case).
    """
    raw_bytes = sys.stdin.buffer.read()
    try:
        raw = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raw = raw_bytes.decode("utf-8", errors="replace")
    raw = raw.lstrip("﻿").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def main():
    payload = _read_stdin_payload()
    if payload is None:
        # stdin is genuinely not JSON — err on the side of allowing, exit
        # silently (no stdout = implicit allow under the v2.1+ schema).
        return

    decision, reason, category, entity = decide(payload)

    # Optional AI escalation for AMBIGUOUS (ask) calls only. Opt-in
    # (SENTINEL_AI=on), off by default, never on the allow hot path. Sharpens a
    # vague "ask" into allow/ask/deny. Fail-open: any issue keeps the local "ask".
    if decision == "ask":
        try:
            import sentinel_ai
            if sentinel_ai.enabled():
                v = sentinel_ai.escalate(payload, reason or "", category or "")
                if v and v.get("decision") in ("allow", "ask", "deny"):
                    decision = v["decision"]
                    reason = f"{reason} | AI({v.get('model', '?')}): {v.get('reason', '')}"
        except Exception:
            pass

    if decision == "allow":
        # Silent allow: no stdout means the call proceeds normally without
        # adding any message to the conversation context.
        return

    # Only flagged calls (deny/ask/warn) reach here — record for the statusbar.
    record_event(payload, decision, category)

    tool_name = payload.get("tool_name") or payload.get("tool", "<unknown>")
    lang = detect_language(payload)
    if decision == "deny":
        key = "deny_feed" if category == "feed_blocklist" else "deny_known"
        message = render(key, lang, tool=tool_name, reason=reason)
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            },
        }))
    elif decision == "ask":
        rememberable = category in AUTO_REMEMBER_CATEGORIES and entity
        key = "ask_remember" if rememberable else "ask_generic"
        message = render(key, lang, tool=tool_name, reason=reason, entity=entity)
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": message,
            },
        }))
    else:  # warn
        message = render("warn", lang, tool=tool_name, reason=reason)
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "additionalContext": message,
            },
        }))


if __name__ == "__main__":
    main()
