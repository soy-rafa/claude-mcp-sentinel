# MCP Sentinel — statusline segment (reference copy).
#
# The live statusline is ~/.claude/custom_bar.sh (OUTSIDE this repo). This file
# is the versioned copy of the Sentinel segment so the integration is
# reproducible. Backlog v3 #6.
#
# It extends the existing "Sentinel real" slot. Bash + jq only, NO python per
# tick (the statusline renders ~1Hz). Reads ~/.claude/sentinel/stats.json (written
# by the hook via hooks/sentinel_stats.py). Absent/clean -> shows nothing extra.
#
# Renders, after the SNTL:ON/OFF chip:
#   ⚑N   threats flagged today (deny+ask+warn), yellow
#   AI:Nk AI-escalation tokens spent (totals), cyan — only when > 0
#
# To (re)install: paste the block below right after the SNTL=... if/else in
# custom_bar.sh, and append `$sntl_extra` to the final echo:
#   ... │ 🛡 $SNTL$sntl_extra"

sntl_extra=""
SNTL_STATS="$HOME/.claude/sentinel/stats.json"
if [ -f "$SNTL_STATS" ] && command -v jq >/dev/null 2>&1; then
    sntl_today=$(date -u +%Y-%m-%d)
    sntl_flagged=$(jq -r --arg d "$sntl_today" '((.daily[$d].deny//0)+(.daily[$d].ask//0)+(.daily[$d].warn//0))' "$SNTL_STATS" 2>/dev/null)
    sntl_ai=$(jq -r '((.totals.ai_in//0)+(.totals.ai_out//0))' "$SNTL_STATS" 2>/dev/null)
    case "$sntl_flagged" in ''|*[!0-9]*) sntl_flagged=0 ;; esac
    case "$sntl_ai" in ''|*[!0-9]*) sntl_ai=0 ;; esac
    [ "$sntl_flagged" -gt 0 ] && sntl_extra="${sntl_extra} \033[1;33m⚑${sntl_flagged}\033[0m"
    [ "$sntl_ai" -gt 0 ]      && sntl_extra="${sntl_extra} \033[1;36mAI:$(fmt_n "$sntl_ai")\033[0m"
fi
