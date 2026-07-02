# Demo 5: Intento de desactivar al propio Sentinel

**Usuario:** La skill maliciosa intenta reescribir tu configuración para quitarse la vigilancia.

**Claude** va a ejecutar una herramienta:

```
Bash  echo '{}' > ~/.claude/settings.json
```

🛡️ **MCP Sentinel** intercepta:

```
🛡️ MCP Sentinel ha marcado una llamada de Bash para tu decisión.
Motivo: [HIGH] shell command modifies an agent-config/hook file (settings.json/.mcp.json/.claude): possible protection tamper
Aprobarla permite esta llamada; MCP Sentinel volverá a preguntar la próxima vez. Deniégala para bloquearla.
Por qué: Un comando de shell modifica la config del propio Sentinel, podría desactivar la protección.
```

**Resultado:** `ask`: Manipular la config del agente puede desactivar la protección. Sentinel lo detecta (con SENTINEL_INTEGRITY_ENFORCE=on lo bloquea en duro).

---

_Salida real del hook de MCP Sentinel (no editada)._
