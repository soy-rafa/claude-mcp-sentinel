# MCP Sentinel — hoja de ruta de producto

Estado: 2026-07-02. Nace de las propuestas de mejora tras la auditoría v3.1.0.

## Principio rector (no negociable)

**Cero tokens por defecto. Todo lo que consuma tokens es opt-in y desactivable.**
El motor de detección es determinista y offline. Cualquier cosa que gaste tokens
(la capa de IA, explicaciones enriquecidas) está apagada por defecto y se puede
apagar del todo. Un usuario que solo quiere protección local no paga nada, nunca.

## Estado de las 9 propuestas

### Implementadas en esta sesión (código + tests)

1. **Explicaciones cero-token y desactivables** — `SENTINEL_EXPLAIN=static|off|ai`.
   Cada veredicto puede llevar un "por qué" en lenguaje llano, texto ESTÁTICO local
   (nunca llama al modelo). `off` = mensajes mínimos; `ai` solo reusa el motivo de un
   veredicto de IA ya hecho. Resuelve la premisa de Rafa: nadie paga tokens por
   explicaciones salvo que lo pida explícitamente.
2. **Escaneo pre-instalación ("mira antes de confiar")** — `config_scan.py --scan-path
   <dir>`. Vetea una skill/MCP antes de instalarla; score + verdict LOW/MEDIUM/HIGH/
   CRITICAL. Cero tokens.
3. **Confianza adaptativa (anti fatiga de preguntas)** — `sentinel_suggest.py`.
   Convierte los `ask` repetidos en sugerencias de allowlist; `--apply` las confía de
   golpe. El usuario decide; solo path/domain, nunca comandos.
4. **Vigilante de deriva de capacidades** — el baseline de integridad ficha ahora los
   ajustes que EXPANDEN poderes (permisos, auto-approve, enable-all-MCP, servidores
   MCP) y marca lo nuevo. "Desconocido = sospechoso" para capacidades.
5. **Digest legible** — `sentinel_status.py --digest`. Resumen en lenguaje llano de lo
   que Sentinel ha hecho. Hace visible la protección invisible. Cero tokens.
6. **Estado unificado** — `sentinel_status.py` (de la auditoría): hooks, firmas, feed,
   baseline, modo, IA+presupuesto, telemetría, knobs.
7. **IA con endpoint local (privacidad)** — `SENTINEL_AI_ENDPOINT` apunta la capa de
   IA a un modelo local/self-hosted; nada sale a un tercero.

### Diseñadas (siguiente fase, requieren tu OK/tiempo)

8. **Lanzamiento público con confianza verificable** — repo público (cuando Rafa lo
   autorice; hoy PRIVADO), releases firmadas, `SECURITY.md` (hecho), `BENCHMARK.md`
   (hecho, prueba reproducible 69/0/0). La reproducibilidad ES el marketing.
9. **Auto-update avanzado de reglas firmadas + feeds MCP** — bundles de reglas
   firmados con control de cordura (nunca reducir cobertura en silencio), más feeds
   específicos (ToxicSkills, vulnerablemcp) y contribución de IOCs por PR. Diseño:
   firma con clave del proyecto, verificación local, fallback offline.
10. **Multi-host** — adaptadores de hook para Cursor/Windsurf/otros clientes MCP;
    mismo motor de detección, distinto pegamento. Amplía el mercado sin reescribir.
11. **Local-AI completo (ollama)** — el knob `SENTINEL_AI_ENDPOINT` ya permite un
    endpoint Anthropic-compatible; para ollama nativo falta un adaptador de formato
    (request/response). Pendiente de decidir si merece la pena vs un gateway compatible.

## Tabla de knobs (variables de entorno)

| Variable | Efecto | Coste tokens |
|----------|--------|--------------|
| `SENTINEL_SHADOW` | on = evalúa pero nunca bloquea (audit-only, cuenta would_block) | 0 |
| `SENTINEL_EXPLAIN` | static (def) / off (mínimo) / ai (reusa motivo IA) | 0 (salvo `ai`, que no gasta extra) |
| `SENTINEL_INTEGRITY_ENFORCE` | on = bloqueo duro del tamper de la propia config | 0 |
| `SENTINEL_AI` | on = escalado IA solo en casos dudosos (opt-in) | tokens (con presupuesto) |
| `SENTINEL_AI_MODEL` / `SENTINEL_AI_BUDGET` | modelo y tope diario de la capa IA | — |
| `SENTINEL_AI_ENDPOINT` | endpoint local/propio para la IA (privacidad) | — |
| `SENTINEL_LANG` | es / en (def: autodetección) | 0 |

## Comandos de usuario

- `python3 tools/sentinel_status.py` — estado. `--digest` para el resumen.
- `python3 tools/sentinel_suggest.py [--apply]` — confiar en lo recurrente.
- `python3 tools/config_scan.py --scan-path <dir>` — vetear antes de instalar.
- `python3 tools/config_scan.py --baseline` — fijar el baseline de integridad.
- `python3 tools/update_blocklist.py` — refrescar el feed de malware.
- `python3 hooks/install_hooks.py [--user|--project|--uninstall]` — instalar (multiplataforma).

## Prioridad recomendada para la siguiente fase
1. Confianza adaptativa + digest ya están; falta pulir el "trust this session".
2. Lanzamiento público (8): máxima palanca reputación, con `SECURITY.md` + `BENCHMARK.md` ya listos.
3. Auto-update firmado (9): el "advanced auto-update" que da resiliencia sin romper el modelo local.
