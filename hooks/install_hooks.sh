#!/usr/bin/env bash
# MCP Sentinel — install runtime protection hooks.
#
# Registers two hooks in Claude Code:
#   - sentinel_preflight.py  as PreToolUse  (allow / deny / ask before a call)
#   - sentinel_postflight.py as PostToolUse ("remember on approve" persistence)
# Idempotent (running twice is safe). Reversible via uninstall_hooks.sh.
#
# Scope:
#   --user     (default) Install globally at ~/.claude/settings.json
#   --project  Install only for the current project at .claude/settings.json
#
# Requires: python3, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRE_PATH="$SCRIPT_DIR/sentinel_preflight.py"
POST_PATH="$SCRIPT_DIR/sentinel_postflight.py"
SCAN_PATH="$SCRIPT_DIR/../tools/config_scan.py"
SCOPE="user"

for arg in "$@"; do
  case "$arg" in
    --user) SCOPE="user" ;;
    --project) SCOPE="project" ;;
    -h|--help)
      echo "Usage: $0 [--user|--project]"
      exit 0
      ;;
    *)
      echo "Unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  echo "❌ jq is required. Install with: brew install jq  (macOS) or apt install jq (Linux)" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "❌ python3 is required but not found on PATH." >&2
  exit 1
fi
for p in "$PRE_PATH" "$POST_PATH" "$SCAN_PATH"; do
  if [[ ! -f "$p" ]]; then
    echo "❌ Could not find $p" >&2
    exit 1
  fi
done

chmod +x "$PRE_PATH" "$POST_PATH" "$SCAN_PATH"

if [[ "$SCOPE" == "user" ]]; then
  SETTINGS_FILE="$HOME/.claude/settings.json"
else
  SETTINGS_FILE="$(pwd)/.claude/settings.json"
fi
mkdir -p "$(dirname "$SETTINGS_FILE")"

# Initialize file if missing or empty
if [[ ! -s "$SETTINGS_FILE" ]]; then
  echo '{}' > "$SETTINGS_FILE"
fi

# Validate existing JSON
if ! jq empty "$SETTINGS_FILE" 2>/dev/null; then
  echo "❌ $SETTINGS_FILE is not valid JSON. Please fix it or remove it, then retry." >&2
  exit 1
fi

BACKUP="$SETTINGS_FILE.sentinel.bak.$(date +%s)"
cp "$SETTINGS_FILE" "$BACKUP"
echo "📦 Backup saved to $BACKUP"

PRE_COMMAND="python3 \"$PRE_PATH\""
POST_COMMAND="python3 \"$POST_PATH\""
SCAN_COMMAND="python3 \"$SCAN_PATH\" --session"

# Add or replace all three hooks. Any existing non-Sentinel hooks (e.g. gitnexus)
# are preserved — we only drop prior entries whose command matches ours.
TMP="$(mktemp)"
jq --arg pre "$PRE_COMMAND" --arg post "$POST_COMMAND" --arg scan "$SCAN_COMMAND" '
  .hooks //= {}
  | .hooks.PreToolUse //= []
  | .hooks.PostToolUse //= []
  | .hooks.SessionStart //= []
  | .hooks.PreToolUse |= (
      map(select(.hooks[]?.command != $pre))    # remove any stale Sentinel preflight
      + [{
          matcher: "",
          hooks: [{type: "command", command: $pre}]
        }]
    )
  | .hooks.PostToolUse |= (
      map(select(.hooks[]?.command != $post))   # remove any stale Sentinel postflight
      + [{
          matcher: "",
          hooks: [{type: "command", command: $post}]
        }]
    )
  | .hooks.SessionStart |= (
      map(select(.hooks[]?.command != $scan))   # remove any stale Sentinel config scan
      + [{
          hooks: [{type: "command", command: $scan}]
        }]
    )
' "$SETTINGS_FILE" > "$TMP"

mv "$TMP" "$SETTINGS_FILE"
echo "✅ MCP Sentinel runtime protection installed in $SETTINGS_FILE"
echo "   PreToolUse   -> sentinel_preflight.py  (allow / deny / ask)"
echo "   PostToolUse  -> sentinel_postflight.py (remember on approve)"
echo "   SessionStart -> config_scan.py --session (config/MCP scan + integrity, warn-only)"
echo ""
echo "Next time Claude Code runs a tool call, Sentinel will check it first."
echo "To verify: ask Claude to run a harmless command. You should see no friction."
echo "To uninstall: run uninstall_hooks.sh"
