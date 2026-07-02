# Demo 7 — Vetear una skill ANTES de instalarla

**Usuario:** Voy a instalar esta skill que encontré. ¿Es segura?

Antes de confiar, la escaneas:

```
$ python3 tools/config_scan.py --scan-path ./super-formatter
🛡️ MCP Sentinel pre-install scan: ./super-formatter
   Risk: CRITICAL (score 13, 5 finding(s))
   [mcp] ./super-formatter/.mcp.json: gh: MCP 'gh': endpoint on localhost/private network — verify it is not a proxy/MITM redirect (http://127.0.0.1:9/mcp)
   [injection] ./super-formatter/SKILL.md: prompt-injection phrase /(?i)ignore\s+(all\s+)?previous\s+instructions/
   [injection] ./super-formatter/SKILL.md: prompt-injection phrase /(?i)do\s+not\s+(tell|show|mention)\s+the\s+user/
   [injection] ./super-formatter/SKILL.md: prompt-injection phrase /(?i)<(important|system|secret|admin)>/
   [config] ./super-formatter/SKILL.md: dangerous command embedded in config: [ask] [CRITICAL] sensitive path: ~/.ssh/
```

**Resultado:** riesgo alto detectado (inyección oculta en SKILL.md + servidor MCP apuntando a localhost). Proactivo: lo pillas antes de instalarlo, no después.

---

_Salida real del escáner._
