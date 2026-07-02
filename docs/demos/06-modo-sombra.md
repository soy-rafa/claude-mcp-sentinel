# Demo 6: Modo sombra (no bloquea, solo cuenta)

**Usuario:** Trabajo nocturno automático; no quiero que nada me pare.

**Claude** va a ejecutar una herramienta:

```
Bash  cat ~/.aws/credentials
```

🛡️ **MCP Sentinel** intercepta:

```
🛡️ MCP Sentinel [SOMBRA]: esta llamada de Bash normalmente sería ask, pero el modo solo-auditoría (SENTINEL_SHADOW) está activo, así que se permite.
Motivo: [CRITICAL] sensitive path: ~/.aws/credentials
```

**Resultado:** `allow (con aviso)`: con SENTINEL_SHADOW=on, Sentinel evalúa pero NUNCA bloquea: deja pasar y anota 'te habría parado N veces'. Ideal para medir antes de activar la defensa dura.

---

_Salida real del hook de MCP Sentinel (no editada)._
