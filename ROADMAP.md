# Hoja de ruta

Este documento sale de la **cuarta oleada** de agentes sobre el propio código
(2026-08-06). Los frentes se eligieron por la lección de la víspera —una
regresión propia dejó rojo a un repo consumidor sin que nadie se enterara—:
los arreglos recién hechos (`v0.16.0..v0.20.1`), el **contrato con quien la
usa** (lo que prometen el README, `action.yml` y los docs contra lo que el
código hace), el mini-YAML de `config.py` que ninguna oleada había mirado,
las **interacciones entre modos** y la robustez con repos feos.

Cada hallazgo de la primera sección fue **reproducido de punta a punta** por
un verificador adversarial independiente, con instrucciones de refutar
también lo que resultara compromiso deliberado. De diez verificados, **nueve
sobrevivieron y uno fue refutado**: el rechazo de la línea base en formato 1
resultó ser decisión documentada, no defecto. Los de la segunda sección traen
receta pero nadie los ha reproducido con adversario; **verificar antes de
arreglar**.

La regla para priorizar es la de siempre: *un guardián que aprueba todo es
peor que ninguno*. Primero los falsos negativos silenciosos, después los
veredictos que mienten, después la calibración, al final lo cosmético.

Las tres oleadas anteriores quedaron saldadas: v0.8.0–v0.12.0 (16 países),
v0.13.0–v0.16.0 (20 de 20) y v0.17.0–v0.20.1 (23 de 23).

---

## 1. Confirmado y reproducido

### La regresión de la víspera

- [x] **Un solo byte no-UTF-8 manda TODO el archivo a cp1252: mojibake que
  ciega a los detectores con contexto** — `src/garita/nucleo.py:280`. El
  reintento de v0.17.0 era por ARCHIVO, no por byte: bastaba una ñ Latin-1
  pegada en un export mezclado para que el archivo entero se leyera como
  cp1252, y ahí «Cédula» (UTF-8) se volvía «CÃ©dula». Ningún `_CONTEXTO`
  acentuado casaba, todo detector `exige_contexto` quedaba ciego y el archivo
  **seguía contando como revisado**. Antes, con `replace`, sólo el byte malo
  se volvía U+FFFD y los acentos del resto sobrevivían: el remedio contra
  Latin-1 abrió un falso negativo sobre UTF-8, que es el caso mayoritario.
  *(Saldado en v0.20.2: sólo se cae a cp1252 cuando el intento UTF-8 no
  rescata ninguna letra acentuada válida — que es exactamente el Latin-1
  puro que v0.17.0 quería leer.)*

### El contrato con quien la usa

- [x] **El README instala el hook fijado en `rev: v0.7.0`** — `README.md:153`
  y `:525`. El bloque de `.pre-commit-config.yaml` que el propio documento
  marca como «empieza por aquí» apuntaba trece releases atrás: sin los tres
  países nuevos, sin la lectura de UTF-16 sin BOM ni de Latin-1, sin el
  arreglo del CSV. La capa que el README declara más importante —bloquear
  antes del commit— quedaba anclada a la versión ciega. *(Saldado en v0.20.2
  en las dos secciones, es/en; el bump entra al ritual de release.)*

- [x] **El input `config` vacío se descarta en silencio y Garita aprueba con
  la configuración por omisión** — `scripts/ejecutar.py:51`. Con
  `config: ${{ vars.X }}` sin definir —el caso ordinario en CI— no se pasa
  `--config` y la CLI corre con lo que haya por omisión. Si el `.garita.yml`
  no vive en la raíz (justo el motivo para usar el input), no hay
  configuración: el detector `nombre` queda apagado, las exenciones y
  `paises` se ignoran, y el veredicto es 0 sobre un repo con el padrón a la
  vista. La CLI ya rechaza `--config ""` con código 2 desde v0.20.0 —«correr
  con otra configuración de la que se pidió es peor que no correr»—; el
  envoltorio de la Action, que es la superficie más usada, salta esa guardia.

- [x] **`solo-cambios` vuelve somero el clon del consumidor y se queda sin
  base de comparación** — `scripts/ejecutar.py:37`. El `git fetch --depth=1`
  escribe `.git/shallow` en un clon que se pidió con `fetch-depth: 0` y
  destruye el merge-base, así que `git diff origin/base...HEAD` falla, la
  lista sale vacía y `solo-cambios` cae SIEMPRE al escaneo completo en cuanto
  la rama base avanza — o sea, en todo PR normal. La entrada documentada
  («más rápido, pero ciego a lo que ya estaba») es inoperante, y el efecto
  persiste: un `--historial` posterior en el mismo job sale 2. Arreglo
  verificado: quitar `--depth=1` y traer la base con refspec explícita.

### El mini-YAML

- [x] **Un BOM UTF-8 en `.garita.yml` borra la PRIMERA clave en silencio** —
  `src/garita/config.py:183`. Se lee con `utf-8` y no `utf-8-sig`, así que el
  BOM sobrevive y la clave queda como `"﻿nombres"`: ningún `datos.get()`
  casa con ella. Con `nombres:` primero —el orden del ejemplo del README— la
  lista de nombres desaparece, el detector se omite sin decir nada y un
  padrón con nombres reales sale «nada que reportar». El BOM es el default de
  Notepad, del «UTF-8 with BOM» de VS Code y de PowerShell: el mismo público
  por el que v0.17.0 arregló Latin-1. Arreglo verificado: una palabra,
  `encoding="utf-8-sig"`, que también lee bien los archivos sin BOM.

- [x] **Una fuente de nombres que el parser no entiende se descarta en
  silencio y el detector desaparece** — `src/garita/config.py:190`. El filtro
  `isinstance(f, str)` tira sin avisar lo que no sea cadena, y basta el
  espacio tras los dos puntos —lo que la ortografía YAML pide— para que
  `- gen.py: PROHIBIDOS` se lea como mapa, se borre, y el detector de nombres
  deje de correr con código 0. `fuentes.py` declara esto inaceptable en tres
  docstrings («un guardián ciego que dice OK es peor que no tener guardián»):
  ahí una fuente rota es código 2. Arreglo: `ConfigInvalida` en vez de filtro
  mudo.

- [x] **Clave repetida: el último bloque pisa al primero sin avisar** —
  `src/garita/config.py:152`. Dos bloques `nombres:` —lo que sale de fusionar
  dos configuraciones o de un merge mal resuelto— dejan viva sólo la última
  fuente; dos `detectores:` reviven lo que el primero apagó. Sin mensaje, sin
  exención muerta, sin más rastro que el conteo de `--explicar`.

### Las interacciones

- [x] **`--linea-base` sobre un repo limpio es un no-op: la base rancia sigue
  perdonando datos NUEVOS** — `src/garita/cli.py:443`. `_congelar()` retorna
  0 sin tocar el archivo cuando `base.total == 0`: sólo imprime «bórralo». La
  base vieja queda en disco con sus conteos, que siguen perdonando hallazgos
  posteriores del mismo archivo/detector/severidad. El comando de
  regeneración que la propia herramienta documenta es justo el que no hace
  nada en ese estado, y sale 0. No es el hueco de SUSTITUCIÓN que el diseño
  acepta: ahí el total no cambia; aquí los hallazgos vivos pasan de 0 a 2 y
  se perdonan igual.

### La robustez

- [ ] **Un archivo ilegible sale como «binario o muy grande» y el repo
  aprueba con 0** — `src/garita/nucleo.py:403`. `leer()` devuelve `None` ante
  cualquier `OSError` —permiso denegado, E/S, un archivo que otro paso del
  runner reemplazó a media corrida— y `revisar()` lo trata como binario: se
  suma a `archivos_omitidos` sin nombrarlo y sin entrar en
  `omitidos_grandes`. El reporte remata con «N omitidos (binarios o muy
  grandes)», que es falso. Es el modo de falla que el docstring de
  `es_revisable` llama «el peor posible»; esa misma función ya calcula el
  motivo «ilegible» y también se descarta.

---

## 2. Plausible, sin verificar aún

*(Traen receta del buscador; nadie los ha reproducido con adversario.)*

### Veredictos que podrían mentir

- [x] **Un `.garita.yml` en cp1252/UTF-16, o con un booleano donde va una
  lista, revienta con traceback y código 1** — `cli.py:170`. El 1 es el de
  «hay hallazgos»: manda a buscar un dato que no existe.

- [x] **`off`/`0`/`n` no son booleanos: `fallar_en_aviso: off` reprueba el
  build** — `config.py:93`. YAML los acepta como falso; el mini-parser no.

- [x] **`--linea-base` con un directorio inexistente en `--linea-base-ruta`
  truena con traceback y sale 1** — `cli.py:450`. La misma clase que
  `_escribir_documento` cerró para `--salida`, sin aplicar aquí.

- [ ] **`--historial` reporta el hallazgo en la ruta de ORIGEN aunque ahí la
  propia regla lo suprima; la ruta real nunca se nombra** —
  `historial.py:396`.

### Calibración

- [ ] **`casa_ruta` no poda directorios: «datos/\*» deja de cubrir
  `datos/regiones/…`** — `nucleo.py:328`. En `.gitignore`, un patrón que casa
  un directorio excluye su contenido; aquí no. Verificar si conviene: toca la
  semántica recién estabilizada en v0.20.1, y esa ya se rompió una vez.

- [ ] **Cortar el token en la coma rompe las URLs con coma** —
  `_comun.py:80`. Hay URLs legítimas con comas; ahí el aviso se vuelve error.

- [ ] **«your» exigiendo separador deja fuera los marcadores camelCase con
  calificativo** — `secretos.py:141`. `yourDatabasePassword` se denuncia como
  credencial real. Sería la cuarta cara del posesivo: cualquier arreglo debe
  probarse contra las otras tres.

- [ ] **Exentar por el nombre de detector que el reporte IMPRIME no exenta
  nada y no avisa** — `nucleo.py:412`. El reporte dice `llave_privada`,
  `credencial_en_url`, `jwt`; la exención sólo entiende `secretos`. Quien
  copia lo que ve no consigue nada, y tampoco sale como exención muerta.

### Rendimiento

- [ ] **`dentro_de_url` es cuadrático: copia y rastrea todo el prefijo de la
  línea por cada coincidencia** — `_comun.py:77`. Medido: 2 MB en una sola
  línea, 76 segundos. Un guardián que cuelga el CI se desinstala igual que
  uno que grita.

- [ ] **`credencial_en_url`: el esquema sin cota vuelve cuadrática cualquier
  tirada larga de minúsculas con puntos** — `secretos.py:100`.

- [ ] **`e.cubre` recalcula `casa_ruta` una vez por detector** —
  `nucleo.py:412`. Seis exenciones duplican el tiempo de escaneo.

- [ ] **El buscador de país corre la búsqueda de contexto en TODA línea antes
  de saber si hay candidato** — `_comun.py:144`.

---

## Refutado, y por qué

- **«El formato 2 de la línea base deja rojo a todo consumidor»** —
  `linea_base.py:180`. El síntoma ocurre, pero el rechazo es **deliberado y
  documentado**: `cargar()` explica que la escribió otra versión y pide
  regenerarla, porque correr sin la línea base que se pidió daría un reporte
  inservible. Queda anotado como consecuencia conocida del salto de formato,
  no como defecto — `mifo` la sufrió el 2026-08-06 y necesita un
  `garita --linea-base`.

---

## Versiones propuestas

| Versión | Tema | Contenido |
|---------|------|-----------|
| v0.20.2 ✓ | Lo urgente | La regresión de cp1252 y el `rev:` del README |
| v0.21.0 ✓ | El contrato y el parser | `config` vacío, el clon somero, y los plausibles de veredicto que sobrevivan |
| ~~v0.22.0~~ | — | Entró completo en v0.21.0 |
| v0.23.0 | Lo que se dice de lo que no se revisó | El archivo ilegible, `--linea-base` no-op, la ruta del historial |
| continuo | Rendimiento | Los cuatro cuadráticos, con números antes y después |
