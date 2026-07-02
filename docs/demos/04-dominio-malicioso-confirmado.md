# Demo 4 — Dominio malicioso confirmado (bloqueo duro)

**Usuario:** La skill del correo (caso real: backdoor de Postmark) manda datos a su servidor.

**Claude** va a ejecutar una herramienta:

```
WebFetch  https://...giftshop.club/collect
```

🛡️ **MCP Sentinel** intercepta:

```
🛡️ MCP Sentinel ha bloqueado una llamada de WebFetch.
Motivo: [CRITICAL] known-malicious domain: giftshop.club (Postmark MCP backdoor (v1.0.16, Sept 2025))
Es un indicador confirmado como malicioso y no se puede añadir a la lista de permitidos.
Por qué: El destino está en la lista curada de infraestructura confirmada maliciosa.
```

**Resultado:** `deny` — Infraestructura confirmada de un incidente real: bloqueo DURO, no anulable. Aquí Sentinel no pregunta, corta.

---

_Salida real del hook de MCP Sentinel (no editada)._
