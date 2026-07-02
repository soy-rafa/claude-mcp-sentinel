# Auditoría MCP Sentinel v3.1.0: usabilidad y protección del usuario

Fecha: 2026-07-02. Método: lectura directa del código (evidencia con fichero:línea),
lente doble usabilidad + protección. El panel multi-agente se quedó sin cuota (límite
de 5h al 106%), así que esta pasada la hizo el hilo principal leyendo el código real.
Las afirmaciones marcadas "(a confirmar)" necesitan una prueba puntual antes de darlas
por ciertas.

## Veredicto general

El núcleo determinista es sólido y bien probado (90/90 suite, dos baterías red-team
69/0/0, FP=0 en corpus). La arquitectura de capas y el fail-open están pensados. Pero
la auditoría destapa un frente poco cubierto: **la auto-protección**. Sentinel vigila
las acciones de terceros, pero se defiende poco a sí mismo: su vigilante de integridad
no detecta que le BORREN su propio hook, y varias rutas permiten desactivarlo o dejarlo
ciego sin que salte nada. En usabilidad, la potencia de v3 (IA, modo sombra, telemetría)
está poco descubrible y la documentación de cara al usuario va por detrás del código.

## Protección del usuario (hallazgos)

### P1: El watcher de integridad NO detecta la ELIMINACIÓN de un hook (alto)
Evidencia: `tools/config_scan.py:321` `diff_baseline` solo itera el estado ACTUAL y
marca `NEW`/`CHANGED`; nunca recorre las claves del baseline ausentes en el actual.
Impacto: la forma más obvia de desarmar Sentinel (borrar su entrada `PreToolUse` de
`~/.claude/settings.json`) NO se detecta. El baseline vigila que no AÑADAN un hook
malicioso, pero no que QUITEN el bueno. Es el hueco de protección más serio.
Fix (S): en `diff_baseline`, recorrer también `old` y emitir `REMOVED hook/MCP: k`
cuando una clave del baseline desaparece del estado actual. Tratar la desaparición del
propio hook de Sentinel como severidad máxima.

### P2: Auto-desactivación vía reescritura de settings.json por shell (alto, a confirmar)
Evidencia: `check_config_write` marca WRITE/EDIT sobre `.claude/settings.json`
(`references/iocs.json` config_write_paths), pero opera sobre rutas de destino
(`target_paths`). Un `Bash` que reescribe el fichero (`jq 'del(.hooks.PreToolUse)' … > x
&& mv x settings.json`, o `sed -i`, o redirección) no expone una "ruta de destino"
estructurada, así que probablemente se cuela.
Impacto: un skill puede desactivar Sentinel con un comando de shell aparentemente
inocuo. Combinado con P1, el desarme es sigiloso.
Fix (M): en `check_dangerous_commands`/`command_strings`, detectar comandos que
escriben/mueven/editan sobre `settings.json`, `.mcp.json`, `.claude/` (redirecciones
`>`/`>>`, `mv`/`cp`/`tee`/`sed -i`/`jq … >` hacia esas rutas). Verificar antes con un
test inerte.

### P3: La comprobación de integridad es solo-SessionStart y solo-aviso (medio)
Evidencia: `install_hooks.sh:101` registra `config_scan.py --session` únicamente en
`SessionStart`; el modo es warn-only (documentado así). Impacto: manipulación a mitad de
sesión no se ve hasta reiniciar, y aun entonces solo avisa (no bloquea). Un atacante que
además quite el hook de SessionStart deja el chequeo mudo.
Fix (M): (a) decidir si el drift crítico (hook propio ausente/cambiado) DEBE bloquear en
vez de avisar; (b) re-verificar integridad periódicamente o en PreToolUse de forma barata
(hash cacheado), no solo al arrancar.

### P4: Fail-open silencioso si la base de IOCs no carga (medio)
Evidencia: `hooks/sentinel_preflight.py:84` `load_iocs` devuelve `{}` ante CUALQUIER
excepción; `load_feed_domains:116` devuelve `set()` igual. Impacto: si `iocs.b64` falta,
se corrompe, o un atacante lo trunca, Sentinel se queda sin firmas y **permite todo en
silencio**, sin avisar al usuario de que está desprotegido. El fail-open es razonable
para no romper el flujo, pero debe ser RUIDOSO.
Fix (S): si `load_iocs()` devuelve vacío (o el fichero esperado no existe), emitir un
aviso visible una vez por sesión ("Sentinel sin base de firmas: protección degradada").
Considerar incluir el hash de `iocs.b64` en el baseline de integridad.

### P5: La capa de IA envía contenido del tool SIN redactar a la API (medio)
Evidencia: `hooks/sentinel_ai.py` `build_prompt` mete `command`/`file_path`/`url`
(truncados a 300) en el prompt que va a `api.anthropic.com`. Es opt-in y off por defecto,
pero esos campos pueden contener secretos (un comando con un token, una API key).
Impacto: al activar la IA, datos potencialmente sensibles salen de la máquina; el usuario
podría no darse cuenta. Choca con la promesa "local y privado".
Fix (S): redactar antes de enviar reutilizando `sentinel_quarantine.redact()` sobre los
campos en `build_prompt`; y avisar/documentar en el momento de activar `SENTINEL_AI` que
se enviará contenido (redactado) a la API.

### P6: Sin patrones nativos de Windows en IOCs (bajo-medio)
Evidencia: `references/iocs.json` sensitive_paths usa formas Unix (`~/.ssh`, `~/.aws`).
La normalización de rutas (2.5.0) ayuda al matching, pero faltan objetivos Windows
(`%USERPROFILE%`, `%APPDATA%`, `*.ppk`, credential store). Impacto: menor cobertura en
Windows. Fix (M): añadir patrones nativos Windows.

## Usabilidad y experiencia (hallazgos)

### U1: Potencia de v3 poco descubrible; falta un comando de estado (alto para adopción)
Evidencia: la config vive en variables de entorno dispersas (`SENTINEL_AI`,
`SENTINEL_SHADOW`, `SENTINEL_AI_MODEL`, `SENTINEL_AI_BUDGET`, `SENTINEL_LANG`,
`SENTINEL_ALLOWLIST_PATH`…) sin un punto único que las muestre. `sentinel_stats.py`
imprime telemetría pero no está señalizado. Impacto: un usuario no sabe que existen el
modo sombra ni la capa de IA, ni cómo ver qué ha hecho Sentinel, ni cómo confiar en algo
de forma permanente. Fix (M): un comando `sentinel status` (o `config_scan.py --status`)
que muestre estado de hooks, modo (normal/sombra), IA on/off + presupuesto gastado,
tamaño del feed, fecha del baseline, y las variables disponibles con su valor actual.

### U2: La descripción de SKILL.md describe v2, no v3 (medio)
Evidencia: `SKILL.md` frontmatter `version: "3.1.0"` pero la descripción sigue diciendo
"v2 adds a real-time protection layer… hard-blocks confirmed-malicious tool calls"
(modelo de bloqueo duro), sin mencionar el modelo ask, la IA opcional, el modo sombra,
attack-chain, dataflow. Impacto: la primera impresión (y lo que un índice de skills
muestra) está desactualizada y subvende el producto. Fix (S): reescribir la descripción
a v3.

### U3: Instalador no multiplataforma; depende de jq (medio)
Evidencia: `install_hooks.sh:13,36` requiere `bash`+`jq`+`python3`; en Windows nativo el
tester tuvo que registrar el hook a mano (RELEASE_NOTES). Impacto: fricción/abandono en
Windows y en máquinas sin jq. Fix (M): `install_hooks.py` solo-stdlib (edita
settings.json en Python), multiplataforma; deja el .sh como atajo.

### U4: Falta guía "qué hago cuando Sentinel me pregunta" para no-devs (medio)
Evidencia: los mensajes del hook (`_MSG`) son claros pero no hay un onboarding corto que
explique al usuario final qué significa Allow/Deny, cómo confiar permanentemente, cómo
ver el historial, cómo desactivar temporalmente o ajustar un falso positivo. Fix (S):
media página en README + enlace desde el mensaje del hook.

## Falsos positivos (menores)
- `references/iocs.json` dangerous_commands: `(?i)crontab\s+-` marca también `crontab -l`
  (listar, benigno) → posible ask innecesario. Acotar a `crontab -e`/instalación.
- Append a rc-files (`>> ~/.zshrc`) es legítimo en muchos setups; hoy pide confirmación.
  Aceptable, pero documentarlo como esperado.

## Tabla priorizada (impacto vs esfuerzo)

| ID | Mejora | Tipo | Impacto | Esfuerzo |
|----|--------|------|---------|----------|
| P1 | Detectar hooks/MCP ELIMINADOS en el baseline | Protección | Alto | S |
| P4 | Aviso ruidoso si la base de IOCs no carga | Protección | Alto | S |
| P5 | Redactar campos antes de mandarlos a la IA | Privacidad | Alto | S |
| U2 | Descripción de SKILL.md a v3 | Usabilidad | Medio | S |
| U1 | Comando `sentinel status` | Usabilidad | Alto | M |
| P2 | Cerrar auto-desactivación por shell | Protección | Alto | M |
| U4 | Guía "qué hacer cuando pregunta" | Usabilidad | Medio | S |
| P3 | Integridad periódica + drift crítico bloqueante | Protección | Medio | M |
| U3 | Instalador multiplataforma en Python | Usabilidad | Medio | M |
| P6 | Patrones nativos Windows | Protección | Bajo | M |

## Quick wins (alto valor, esfuerzo S): orden sugerido
1. **P1** detectar eliminación en `diff_baseline` (+ regresión). El hueco más serio, arreglo pequeño. **[HECHO 2026-07-02]**
2. **P4** fail-open ruidoso cuando faltan firmas. **[HECHO 2026-07-02]**
3. **P5** redactar en `sentinel_ai.build_prompt` (reutiliza `redact()`). **[HECHO 2026-07-02]**
4. **U2** descripción de SKILL.md a v3. **[HECHO 2026-07-02]**

Los 4 quick wins están cerrados. Segunda tanda (M) también cerrada:
- **P2 [HECHO]** cerrar auto-desactivación por shell (`check_config_write` escanea comandos).
- **U1 [HECHO]** comando `tools/sentinel_status.py`.
- **P6 [HECHO]** paridad de credenciales Windows en `iocs.json`.
- **U3 [HECHO]** instalador multiplataforma `hooks/install_hooks.py`.
- **P3 [HECHO]** alarma prominente de auto-tamper en SessionStart + informe (se apoya en
  P1; detección en tiempo real del intento vía P2), MÁS refuerzo opt-in
  `SENTINEL_INTEGRITY_ENFORCE` (off por defecto): con él, manipular la config/hooks del
  propio Sentinel pasa de `ask` a deny duro, sin cambiar el fail-open por defecto ni
  bloquear el arranque de sesión. Se descarta el bloqueo automático de arranque por riesgo
  de lockout ante falso drift; el usuario que lo quiera lo activa con la variable.

Estado: **todos los hallazgos de la auditoría abordados.** Suite 108/108, precisión
FP=0/91, red-team 69/0/0.

## Nota de método
Cada hallazgo se apoya en código leído en esta pasada. P2 se marca "a confirmar" porque
requiere un test inerte (reescritura de settings.json por shell) antes de afirmarlo como
hueco cierto. El resto está verificado por lectura directa.
