# Diseño: auto-update firmado y multi-host

Dos items del roadmap que NO se construyen todavía porque dependen de algo externo
(una clave de firma, o el API de hooks de otros clientes). Aquí queda el diseño
concreto para ejecutarlos cuando decidas, sin medio-construir algo que no funcione.

## 1. Auto-update de reglas firmadas

### Qué es
Que Sentinel pueda bajarse un bundle de REGLAS nuevas (patrones de comando, frases
de inyección, IOCs) firmado por el mantenedor, verificarlo en local y aplicarlo solo
si la firma es válida y pasa el control de cordura. Como un antivirus baja firmas,
pero verificable y offline-first.

### Lo que YA existe (base)
- `update_blocklist.py`: descarga multi-fuente, dedupe, **control de cordura**
  (`passes_sanity`: rechaza un encogimiento >50%, señal de feed truncado/envenenado),
  metadatos de versión, y datos base64-at-rest (AV-safe).
- `config_scan.py`: baseline de integridad SHA-256 firmado en base64.

### Lo que falta (y por qué no se hace ahora)
- **Firma asimétrica.** Un bundle público debe ir firmado con clave privada del
  mantenedor y verificado con la pública embebida. La stdlib de Python NO trae
  verificación Ed25519/RSA. Opciones: (a) depender de `cryptography` (rompe el
  "cero dependencias"); (b) vendorizar un Ed25519 mínimo en Python puro (~200 líneas,
  auditables); (c) firmar con `minisign`/`age` y verificar llamando al binario si está.
  Recomendado: **(b) Ed25519 puro vendorizado**, coherente con local-first y sin deps.
- **Clave de firma del proyecto.** Hay que generar el par y publicar la pública en el
  repo. Decisión de Rafa (custodia de la privada).

### Diseño propuesto
1. Bundle = `rules.json` + `rules.sig` (firma detached Ed25519 sobre el sha256 del JSON).
2. `tools/update_rules.py`: descarga bundle, verifica firma con la pública embebida,
   valida schema, aplica `passes_sanity` (nunca REDUCIR cobertura en silencio: si el
   bundle nuevo elimina patrones, avisa y pide confirmación), y solo entonces reemplaza
   `iocs.json` + re-encoda `iocs.b64`. Fallback offline: si no hay red o la firma falla,
   se queda con lo que tiene y avisa.
3. Nunca auto-aplica una reducción de cobertura; nunca ejecuta nada del bundle.

## 2. Multi-host (Cursor, Windsurf, Continue, ...)

### Qué es
Correr el mismo motor de detección de Sentinel en otros clientes que usan MCP, no solo
Claude Code.

### Por qué es viable
El motor (`decide()` + scanners) es **agnóstico del host**: recibe un dict
`{tool_name, tool_input}` y devuelve un veredicto. Lo único específico de cada cliente es
(a) cómo se registra un hook pre-ejecución y (b) la forma del payload de la tool-call.

### Lo que falta (por qué no se hace a ciegas)
Cada cliente tiene su propio sistema de hooks y su propio esquema de payload, que hay
que conocer con exactitud para no entregar un adaptador que no engancha:
- **Claude Code** (hecho): PreToolUse/PostToolUse/SessionStart, payload `{tool_name, tool_input}` por stdin.
- **Cursor / Windsurf / Continue**: hooks y formato de evento propios (a confirmar con su doc actual).

### Diseño propuesto
1. Aislar un `adapters/` con una función por host: `to_sentinel_payload(raw_event) -> {tool_name, tool_input}`
   y `from_sentinel_verdict(decision) -> <formato del host>`.
2. `decide()` y los scanners no cambian.
3. `install_hooks.py` ya es genérico para editar un settings.json; por host = registrar
   en su ubicación/formato.
4. Empezar por UN host adicional real (el que más te interese), con su doc delante, y
   validarlo con sus payloads reales antes de anunciar soporte.

## Nota
Todo esto mantiene la línea: local, privado, auditable, cero dependencias por defecto,
y nunca reducir protección de forma silenciosa.
