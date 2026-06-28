#!/usr/bin/env python3
"""
MCP Sentinel — cross-server data-flow detection (v3, PostToolUse-driven).

A subtle multi-server attack: MCP server A returns sensitive data (a token, a
key, a private key), and the agent then passes that same value as an argument to
a DIFFERENT MCP server B — exfiltration laundered across servers. No single tool
call looks malicious; the danger is in the FLOW A -> B.

This module fingerprints secret-shaped values seen in a server's OUTPUT and, when
the same fingerprint shows up as INPUT to a different server, flags it. Only
credential-shaped tokens are fingerprinted (not arbitrary text), so it is precise
and never sees the plaintext secret again (only a short hash).

Off the hot path: fed by PostToolUse via the per-session state; deterministic,
fail-open.
"""

import hashlib
import re

_SECRET_SHAPES = [
    re.compile(r"(?i)\b(?:AKIA|ASIA)[A-Z0-9]{8,}\b"),                      # AWS key id
    re.compile(r"(?i)\b(?:gh[posru]|github_pat)_[A-Za-z0-9_]{10,}\b"),     # GitHub
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),                              # OpenAI/Stripe
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),                       # Slack
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),                     # PEM key
]


def fingerprints(text):
    """Short hashes of credential-shaped tokens in text (never store the secret)."""
    fps = set()
    if not isinstance(text, str) or not text:
        return fps
    for rx in _SECRET_SHAPES:
        for tok in rx.findall(text):
            tok = tok if isinstance(tok, str) else (tok[0] if tok else "")
            if len(tok) >= 10:
                fps.add(hashlib.sha256(tok.encode()).hexdigest()[:12])
    return fps


def detect_cross_server_flow(prior_outputs, dest_server, dest_text):
    """prior_outputs: {fingerprint: source_server}. Returns a finding if a secret
    that a DIFFERENT server output now appears as input to dest_server."""
    for fp in fingerprints(dest_text):
        src = prior_outputs.get(fp)
        if src and src != dest_server:
            return (f"secret from MCP server '{src}' flows as input to '{dest_server}' "
                    "(cross-server data-flow / laundered exfiltration)")
    return None


def record_outputs(prior_outputs, source_server, output_text):
    """Add fingerprints of a server's output to the rolling map (cap size)."""
    for fp in fingerprints(output_text):
        prior_outputs[fp] = source_server
    # keep the map bounded
    if len(prior_outputs) > 64:
        for k in list(prior_outputs)[:-64]:
            del prior_outputs[k]
    return prior_outputs
