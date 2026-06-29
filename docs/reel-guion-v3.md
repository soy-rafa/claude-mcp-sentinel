# Guion para reel — MCP Sentinel v3 ("lo nuevo")

Vertical, 45-60s. Voz = lo que dices; Texto = rótulo en pantalla; Plano = qué se ve.
Anglicismos explicados en pantalla la primera vez (token = clave de acceso;
backdoor = puerta trasera oculta).

## Versión completa (45-60s)

**Gancho (0-4s)**
- Voz: "Esta semana mi asistente de IA intentó robarme las contraseñas. 69 veces. Y lo paré todas."
- Texto: `69 ataques. 0 se colaron.`
- Plano: cara a cámara, corte rápido; de fondo terminal con un 🛡 parpadeando.

**El problema (4-13s)**
- Voz: "Los agentes como Claude Code instalan 'skills' y conectores que les dan superpoderes. Pero uno real, el de Postmark, escondió una sola línea que reenviaba todos tus emails a un desconocido. Mil quinientas personas afectadas."
- Texto: `Un plugin de confianza... con puerta trasera`
- Plano: titular de la noticia del backdoor, zoom a la línea maliciosa.

**La solución, lo nuevo (13-42s)** — cortes rápidos, uno por frase
- Voz: "Así que le puse un vigilante: Sentinel. Mira cada acción antes de que ocurra."
  - Texto: `Revisa ANTES de ejecutar`
- Voz: "Lo nuevo: ya no corta en seco. Te pregunta. Tú decides si confías."
  - Texto: `Permitir / Denegar` (graba el prompt nativo saltando)
- Voz: "Dices que sí una vez y deja de molestarte con eso."
- Voz: "Tiene un cerebro de inteligencia artificial opcional que solo se enciende en los casos dudosos, y te dice cuántos tokens gasta. Nada a tus espaldas."
  - Texto: `IA solo si hace falta · gasto a la vista`
- Voz: "Modo sombra: lo dejas mirar sin bloquear nada, y al final te dice 'te habría parado 12 veces'."
  - Texto: `would_block: 12`
- Voz: "Y se actualiza solo con las listas de malware conocidas."

**La prueba (42-52s)**
- Voz: "Lo metí en un campo de pruebas con 69 ataques reales recreados: backdoors, robo de credenciales, instrucciones ocultas dentro de un plugin. ¿Resultado? Cero se colaron. Cero falsas alarmas."
- Texto: `69/69 detectados · 0 falsos positivos`
- Plano: terminal escupiendo `attacks-missed=0  benign-FP=0`.

**Cierre / CTA (52-58s)**
- Voz: "Todo en tu máquina, privado, sin enviar nada fuera. Te dejo cómo montarlo."
- Texto: `🛡 Local · Privado · Gratis`
- Plano: cara a cámara + flecha a "guardar/seguir".

## Versión corta (30s)
Gancho: "Un plugin de IA puede robarte las claves sin que te enteres (le pasó a 1.500 personas con Postmark)."
→ "Le puse un vigilante que revisa cada acción y te PREGUNTA en vez de cortar."
→ "Lo probé con 69 ataques reales: 0 se colaron, 0 falsas alarmas."
→ "Local y privado. Te enseño cómo."

## Copy del post
> Tu asistente de IA puede instalar un plugin con puerta trasera y enterarte cuando ya es tarde. Le construí un guardaespaldas que vigila cada acción, te pregunta en vez de bloquear, y aprende en qué confías. Lo puse a prueba con 69 ataques reales recreados (backdoors, robo de credenciales, inyección oculta): ninguno se coló. Todo local y privado. 🛡

Hashtags: #IA #Ciberseguridad #ClaudeCode #MCP #seguridadinformatica #inteligenciaartificial #devsecops #privacidad

## Notas de grabación
- Frase más fuerte en los 3 primeros segundos (retención): el "69 veces" o el "te roba las claves sin enterarte". Prueba las dos.
- B-roll fácil: pon `SENTINEL_SHADOW=on`, trabaja normal y graba la barra subiendo el contador; luego corre `python3 tests/redteam_check.py` y graba el `0/0`.
- Todo lo mostrado es inerte (datos de prueba); ningún ataque real se ejecuta.
