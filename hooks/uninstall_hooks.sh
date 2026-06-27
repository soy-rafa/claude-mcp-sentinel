#!/usr/bin/env bash
# MCP Sentinel — uninstall runtime protection hooks.
#
# Removes sentinel_preflight.py (PreToolUse) and sentinel_postflight.py
# (PostToolUse) from Claude Code's settings. Leaves other hooks untouched.

set -euo pipefail

SCOPE="user"
for arg in "$@"; do
  case "$arg" in
    --user) SCOPE="user" ;;
    --project) SCOPE="project" ;;
    *) echo "Unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  echo "❌ jq is required." >&2; exit 1
fi

if [[ "$SCOPE" == "user" ]]; then
  SETTINGS_FILE="$HOME/.claude/settings.json"
else
  SETTINGS_FILE="$(pwd)/.claude/settings.json"
fi

if [[ ! -f "$SETTINGS_FILE" ]]; then
  echo "ℹ️  No settings file at $SETTINGS_FILE — nothing to uninstall."
  exit 0
fi

TMP="$(mktemp)"
jq '
  if .hooks.PreToolUse then
    .hooks.PreToolUse |= map(
      .hooks |= map(select((.command // "") | test("sentinel_preflight") | not))
    )
    | .hooks.PreToolUse |= map(select((.hooks // []) | length > 0))
  else . end
  | if .hooks.PostToolUse then
      .hooks.PostToolUse |= map(
        .hooks |= map(select((.command // "") | test("sentinel_postflight") | not))
      )
      | .hooks.PostToolUse |= map(select((.hooks // []) | length > 0))
    else . end
  | if .hooks.SessionStart then
      .hooks.SessionStart |= map(
        .hooks |= map(select((.command // "") | test("config_scan") | not))
      )
      | .hooks.SessionStart |= map(select((.hooks // []) | length > 0))
    else . end
' "$SETTINGS_FILE" > "$TMP"

mv "$TMP" "$SETTINGS_FILE"
echo "✅ MCP Sentinel runtime protection removed from $SETTINGS_FILE"
