# MCP Sentinel — demos (cómo actúa)

Material para enseñar cómo se comporta Sentinel. **Todo es salida REAL del hook**
(no editada): los `.md` y la animación se generaron feeding payloads reales al
hook y capturando su respuesta. Nada se ejecuta; solo se muestra el veredicto.

## Transcripciones (léelas o pégalas en un post)

| Archivo | Qué muestra | Veredicto |
|---------|-------------|-----------|
| `01-trabajo-normal-sin-friccion.md` | Trabajo legítimo | permite en silencio |
| `02-skill-lee-clave-ssh.md` | Skill intenta leer `~/.ssh/id_rsa` | pregunta (ask) |
| `03-reverse-shell.md` | Reverse shell (RCE) | pregunta (ask) |
| `04-dominio-malicioso-confirmado.md` | Dominio del backdoor de Postmark | **bloqueo duro (deny)** |
| `05-intento-desactivar-sentinel.md` | La skill intenta reescribir tu config | pregunta / bloquea con enforce |
| `06-modo-sombra.md` | `SENTINEL_SHADOW=on`: no bloquea, cuenta | permite + aviso |
| `07-vetear-antes-de-instalar.md` | Escaneo de una skill maliciosa antes de instalar | riesgo CRITICAL |

## Animación / vídeo

- **`demo.sh`** — demo en vivo en tu terminal (colores, pausas, output real).
  Ideal para **grabar la pantalla** para un reel:
  ```
  bash docs/demos/demo.sh            # ritmo normal
  DEMO_PACE=2 bash docs/demos/demo.sh   # más lento para grabar
  ```
- **`sentinel-demo.gif`** — animación lista para pegar en un post/reel (~25s, 2.7 MB,
  colores, salida real). Generada con `cast2gif.py` (Pillow + fuente Menlo).
- **`sentinel-demo.cast`** — animación en formato [asciinema](https://asciinema.org)
  (~26s). Reprodúcela, súbela o conviértela a GIF:
  ```
  asciinema play docs/demos/sentinel-demo.cast     # reproducir en terminal
  asciinema upload docs/demos/sentinel-demo.cast   # link embebible
  agg docs/demos/sentinel-demo.cast sentinel.gif   # a GIF (con 'agg')
  ```

## Regenerar
Los demos se regeneran driveando el hook real. Si cambia un mensaje, vuelve a
correr los generadores (`/tmp/sentinel-demo/capture.py` y `make_cast.py`) o pídelo.

_Nota: los payloads usan hosts/IPs de ejemplo o los documentados en incidentes
reales, siempre como DATOS. El hook los evalúa; nunca se ejecuta ninguno._
