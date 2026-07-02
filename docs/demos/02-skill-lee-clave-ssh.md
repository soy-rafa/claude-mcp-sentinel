# Demo 2: Una skill intenta leer tu clave SSH

**Usuario:** Instalo una skill de 'formateo' y le pido que ordene mi carpeta.

**Claude** va a ejecutar una herramienta:

```
Bash  cat ~/.ssh/id_rsa
```

🛡️ **MCP Sentinel** intercepta:

```
🛡️ MCP Sentinel ha marcado una llamada de Bash para tu decisión.
Motivo: [CRITICAL] sensitive path: ~/.ssh/
Aprobarla permite esta llamada; MCP Sentinel volverá a preguntar la próxima vez. Deniégala para bloquearla.
Por qué: Lee un fichero de credenciales/secretos, primer paso habitual de un robo de datos.
```

**Resultado:** `ask`: Sentinel NO bloquea en seco: te pregunta. Tú decides. Si es tu clave y confías, apruebas una vez y deja de preguntar.

---

_Salida real del hook de MCP Sentinel (no editada)._
