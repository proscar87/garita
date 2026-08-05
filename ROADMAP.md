# Hoja de ruta

Este documento sale de la segunda oleada de agentes sobre el propio código
(2026-08-05), enfocada en lo que se escribió durante los cinco releases del
día anterior (v0.8.0–v0.12.0). Cada hallazgo de la primera sección fue
**reproducido de punta a punta** por un verificador adversarial independiente
antes de entrar aquí — de diez verificados, diez sobrevivieron, cero
refutados. Los de la segunda sección quedaron fuera del cupo de verificación:
son plausibles y traen receta, pero nadie los ha reproducido con adversario;
verificar antes de arreglar.

La regla para priorizar es la de siempre: *un guardián que aprueba todo es
peor que ninguno*. Primero los falsos negativos silenciosos, después los
veredictos que mienten, después la calibración.

Dos hallazgos de la oleada ya quedaron saldados el mismo día (fuera de este
documento): la autorevisión rota tras v0.12.0 (`.garita.yml` sin exentar
`rif`/`ruc_py`/`nit_gt`) y la prueba de color que fallaba solo en CI porque
no aislaba `GITHUB_ACTIONS`.

---

## 1. Confirmado y reproducido

### Los silencios de los marcadores (secretos.py)

- [x] **`gh[opsur]_{36}` exacto pierde los refresh tokens `ghr_` de GitHub**
  — `src/garita/detectores/secretos.py:76`. Las variantes `ghp_/gho_/ghs_/ghu_`
  miden 36 tras el prefijo, pero los `ghr_` vigentes miden 76: con longitud
  exacta seguida de `\b` no casan jamás y el CLI aprueba con 0 un refresh
  token real. Arreglo verificado: `{36,}` en vez de `{36}` — el `\b` de
  cierre hace que el de 76 case entero y los de 36 sigan igual. Prueba con un
  `ghr_` sintético de 76.

- [x] **`_POSESIVO_ES_TODO` absuelve cualquier valor que empiece por
  tu/your** — `src/garita/detectores/secretos.py:137`. El `[_-]?` es opcional
  y el `\w+` traga el resto: «Turquesa9Fuerte42x» es marcador, y una URL de
  conexión con contraseña que arranque en «Tu» sale limpia con 0 (control: la
  misma URL con otra contraseña sí dispara `credencial_en_url`). Arreglo:
  acotar el `\w+` a sustantivos de marcador (clave, llave, secreto, password,
  secret, key, token…); los casos con separador ya los cubre MARCADORES.

- [x] **Los dígitos cuentan como frontera: un marcador entre dígitos absuelve
  llaves con formato de proveedor** — `src/garita/detectores/secretos.py:149`.
  `_marcador_delimitado` solo exige no-letra (`isalpha`), así que «fake» o
  «EXAMPLE» rodeados de dígitos dentro de una llave que sí casa
  `llave_proveedor` la absuelven en silencio. (Matiz honesto: v0.7.0 tenía el
  mismo boquete por otra vía; no es regresión, pero el mecanismo nuevo lo
  reimplementó.) Arreglo: conceder la frontera-dígito solo cuando el otro
  extremo del marcador toca el borde del valor — así la canónica
  `AKIA…7EXAMPLE` sigue exenta y el marcador interior deja de absolver.

- [x] **Regresión v0.9.0: los placeholders camelCase ya no se absuelven** —
  `src/garita/detectores/secretos.py:150`. «DummyPassword1234»,
  «FakeApiKey12345678» eran marcador en v0.7.0 y ahora emiten un aviso cada
  uno: la frontera no reconoce la transición minúscula→Mayúscula, el estilo
  de placeholder de media documentación JS/Java. Arreglo verificado: tratar
  `islower()→isupper()` como frontera por ambos lados — Dummy/Fake/Example
  vuelven a absolverse, `AKIA…7EXAMPLE` y «VirtualPass2024» no cambian.

### Detectores de país

- [x] **RIF con prefijo C (consejos comunales) es invisible** —
  `src/garita/detectores/paises/ve.py:26`. La clase del regex y `_LETRAS`
  omiten la C, que el SENIAT emite desde 2015 (más de 45 000 comunas migradas
  de J a C) y que vale 3 en el algoritmo, igual que J. Un RIF C válido con
  contexto y separadores ni siquiera casa: aprobación silenciosa. Arreglo:
  añadir C al regex, a `_LETRAS` (=3), al `fullmatch` y a los repetidos
  exentos; documentar en el docstring e IDENTIFICADORES.md.

### El canal de Actions y los veredictos

- [x] **El reporte humano imprime la ruta sin escapar: inyección de comandos
  de workflow** — `src/garita/reporte.py:109`. v0.10.0 blindó las
  anotaciones pero `imprimir()` vuelca `h.archivo` crudo en columna 0 del
  mismo stdout que GitHub parsea: un archivo llamado `::stop-commands::x`
  silencia todas las anotaciones que siguen, y la vía sirve para forjar
  `::error` apuntando a archivos que Garita nunca marcó. También sin escapar:
  líneas 67, 78, 171, 190 y las de `imprimir_historial`. Arreglo: un
  `_ruta()` que neutralice `::` bajo `_en_github()`, aplicado a toda ruta de
  origen externo del reporte humano; prueba con el archivo `::stop-commands::x`.

- [x] **`_salida_de_action` y `GITHUB_STEP_SUMMARY` abren sin proteger:
  traceback y código 1 en repo limpio** — `src/garita/cli.py:314` y `:277`.
  `_escribir_documento` se creó justo para esto y los dos `open()` hermanos
  quedaron desnudos: con `GITHUB_OUTPUT` o `GITHUB_STEP_SUMMARY` apuntando a
  ruta no escribible, Garita truena DESPUÉS de revisar y sale 1 —el código de
  «hay hallazgos»— sobre un repo limpio. Golpea igual a `--historial` (l.369).
  Arreglo: helper `_anexar()` espejo de `_escribir_documento`, y código 2
  cuando falle (es entorno, no hallazgo).

- [x] **`--explicar` se traga `--linea-base`, `--historial` y la lista de
  archivos en silencio** — `src/garita/cli.py:118`. `garita --linea-base
  --explicar` sale 0 sin congelar nada; `--explicar --historial` sale 0 sin
  auditar; `--explicar archivo-con-secreto` sale 0 donde la revisión da 1.
  La misma «orden aceptada y no cumplida» que la guardia de v0.10.0 dice
  cerrar, y que `_historial` sí rechaza con 2. Arreglo: guardia explícita
  junto a la de l.118 (argparse no alcanza: `archivos` es posicional).

### Historial

- [x] **`_ALCANCE` omite HEAD: commits en detached HEAD se aprueban sin
  revisar** — `src/garita/historial.py:96`. `--branches --tags --remotes` no
  cubre un commit alcanzable solo desde HEAD suelto (detach, bisect, rebase
  interrumpido): sus blobs jamás se piden y «el historial está limpio» sale
  con 0 — el mismo agujero que la guardia de shallow cierra para clones
  someros. Arreglo verificado por monkeypatch: un `_alcance(raiz)` que añada
  `HEAD` solo si `rev-parse --verify HEAD^{commit}` resuelve (en repo sin
  commits, HEAD pelón hace fallar a git), usado en los cuatro sitios.

---

## 2. Plausible, sin verificar aún

*(Vacía desde v0.16.0: los diez se verificaron uno por uno —cada uno se
reprodujo antes de tocarse— y los diez resultaron reales. La oleada cerró
20 de 20: symlinks y `--salida ""` en v0.14.0, rutas C-quoted y merges en
v0.15.0, y los seis de calibración en v0.16.0. Los seis de abajo quedan
con su nota de cierre.)*

### Calibración de exentos en los países nuevos

- [x] **`EXENTOS_RIF` no incluye los RIF oficiales que el propio módulo
  cita** — `ve.py:58`. G-20000303-0 (SENIAT) y J-00123072-6 (PDVSA) están en
  el docstring como vectores y no están exentos: citar la documentación del
  SENIAT produce un error. `py.py` sí exenta sus ejemplos; la asimetría
  delata la omisión.

- [x] **`EXENTOS_NIT` no incluye el vector 3602978-5 de la SAT** — `gt.py:54`.
  El docstring lo llama «el vector de toda la documentación» y el código no
  lo exenta.

- [x] **`EXENTOS_RUC` no cubre el relleno todo-ceros, que valida** —
  `py.py:34`. `00000-0` a `00000000-0` pasan el módulo 11 y no hay
  `_repetidos_validos()` como en ve.py y gt.py.

### Calibración de países tocados

- [x] **CIF: el espacio cuenta como refuerzo y dispara sin contexto** —
  `es.py:29`. Al admitir `\s` en el regex, el mismo espacio que permite el
  match satisface el refuerzo: «modelo A 1234567 4» es error sin palabra de
  contexto (~6.5 % de combinaciones al azar validan).

- [x] **NIT con base de 8 dígitos: folios de 9 dígitos junto a
  «factura»/«cc» disparan** — `co.py:25`. ~10 % de tiras de 9 dígitos pasan
  el dígito DIAN, y «cc» casa el «Cc:» de correos.

- [x] **El NIT de 8 dígitos caza RUTs chilenos** — `co.py:25`. La base de 8
  es la forma normal del RUT; ~9 % de RUTs válidos coinciden también en el DV
  colombiano y salen duplicados con país equivocado.

### CLI e historial

- [x] **Un symlink rastreado tumba el modo pre-commit con código 2** —
  `cli.py:216`. `resolve()` sigue el enlace: apuntando fuera del repo da
  «queda fuera del repositorio», roto da «no existe» (falso); el repo
  completo, en cambio, pasa con 0. *(Verificado y reproducido en v0.14.0:
  ahora se resuelve el directorio pero nunca el componente final, y el
  enlace se revisa —u omite diciéndolo— igual que en el modo completo.)*

- [x] **Rutas C-quoted de `git log --raw` no se des-quotan** —
  `historial.py:150`. `core.quotepath=false` no evita la cita de comillas,
  backslash, tab: el blob queda con una ruta real y una fantasma citada, que
  anula la relajación de pruebas, rompe exenciones y mutila el SARIF.
  *(Verificado y reproducido en v0.15.0: `_descitar()` en las dos pasadas
  de `log --raw`.)*

- [x] **`--salida` con cadena vacía burla las dos guardias** — `cli.py:258`.
  `if args.salida` es falso para `""` (el `$RUTA` sin definir de CI): no se
  rechaza, no se escribe archivo, el SARIF sale por stdout. *(Verificado y
  reproducido en v0.14.0: guardia explícita con código 2 antes que todas
  las demás.)*

- [x] **Secreto introducido en un commit de merge se reporta con commit «?» y
  fecha «?»** — `historial.py:204`. `git log --raw` sin `--diff-merges` no
  emite raw para merges: el hallazgo sí sale, pero sin el dato que quien
  limpia necesita, y «?» ordena mal en el sort. *(Verificado y reproducido
  en v0.15.0: `--diff-merges=first-parent` en ambas pasadas; el commit
  original de una rama lateral es más viejo y gana igual.)*

---

## Versiones propuestas

| Versión | Tema | Contenido |
|---------|------|-----------|
| v0.13.0 ✓ | Los silencios de los marcadores | Los cuatro de secretos.py + el RIF C |
| v0.14.0 ✓ | El canal de Actions y los veredictos | Inyección de rutas, los `open()` desnudos, `--explicar` mandón; los dos plausibles de CLI sobrevivieron y entraron |
| v0.15.0 ✓ | Historial completo | HEAD en el alcance; los dos plausibles de historial sobrevivieron y entraron |
| v0.16.0 ✓ | Calibración final | Los seis plausibles de país sobrevivieron: exentos oficiales de VE/GT/PY, CIF con guion, NIT colombiano en dos niveles |
