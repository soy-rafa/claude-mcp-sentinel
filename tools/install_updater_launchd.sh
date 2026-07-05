#!/usr/bin/env bash
# Install a weekly macOS LaunchAgent that refreshes the MCP Sentinel malware
# blocklist and shows a desktop notification when it actually changes.
#
# Why launchd (not cron): on a laptop that sleeps/closes, cron silently SKIPS a
# missed run. launchd runs the missed weekly job the next time the Mac wakes.
# It runs at the OS level, independent of Claude Code being open.
#
#   bash tools/install_updater_launchd.sh              # install + run once now
#   bash tools/install_updater_launchd.sh --uninstall  # remove it
set -euo pipefail

LABEL="com.mcp-sentinel.blocklist"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
SKILL="$HOME/.claude/skills/mcp-sentinel"
SCRIPT="$SKILL/tools/update_blocklist.py"
PY="$(command -v python3 || echo /usr/bin/python3)"

if [[ "${1:-}" == "--uninstall" ]]; then
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  echo "✅ Removed $LABEL"
  exit 0
fi

[[ "$(uname)" == "Darwin" ]] || { echo "macOS-only (launchd). On Linux, use a cron entry calling update_blocklist.py --notify."; exit 1; }
[[ -f "$SCRIPT" ]] || { echo "❌ Not found: $SCRIPT"; exit 1; }
mkdir -p "$HOME/Library/LaunchAgents" "$HOME/.claude/sentinel"

cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PY</string>
    <string>$SCRIPT</string>
    <string>--notify</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key><integer>0</integer>
    <key>Hour</key><integer>12</integer>
    <key>Minute</key><integer>0</integer>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$HOME/.claude/sentinel/updater.log</string>
  <key>StandardErrorPath</key><string>$HOME/.claude/sentinel/updater.log</string>
</dict>
</plist>
PLISTEOF

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"
echo "✅ Installed weekly blocklist updater ($LABEL)."
echo "   Runs Sundays 12:00, catches up on the next wake if the Mac was asleep."
echo "   Notifies only when the malware list actually changes. Log: ~/.claude/sentinel/updater.log"
echo "   Uninstall: bash tools/install_updater_launchd.sh --uninstall"
